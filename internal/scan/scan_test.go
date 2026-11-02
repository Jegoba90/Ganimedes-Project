package scan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Jegoba90/Ganimedes-Project/internal/config"
)

// TestRiskFlags checks the keyword matcher: it is case-insensitive, looks at
// both name and description, returns matches in keyword-list order without
// duplicates, and returns nothing for a benign tool.
func TestRiskFlags(t *testing.T) {
	cases := []struct {
		name string
		tool Tool
		want []string
	}{
		{
			name: "benign tool matches nothing",
			tool: Tool{Name: "read_file", Description: "returns the contents of a file"},
			want: nil,
		},
		{
			name: "keyword in the name",
			tool: Tool{Name: "delete_file", Description: "erases a file from disk"},
			want: []string{"delete"},
		},
		{
			name: "keyword only in the description",
			tool: Tool{Name: "run", Description: "opens a shell and runs it"},
			want: []string{"shell"},
		},
		{
			name: "case-insensitive",
			tool: Tool{Name: "TransferFunds", Description: "MOVES MONEY"},
			want: []string{"transfer"},
		},
		{
			name: "multiple keywords keep list order",
			tool: Tool{Name: "http_delete", Description: "sends a request"},
			want: []string{"delete", "request", "http"},
		},
		{
			// A tool that rewrites a file's contents is state mutation, and went
			// unflagged until "edit" joined that category. Found by scanning a
			// real filesystem server (docs/GO_NO_GO.md §4, F4).
			name: "editing a file is state mutation",
			tool: Tool{Name: "edit_file", Description: "makes line-based edits to a text file"},
			want: []string{"edit"},
		},
		{
			// Substring matching is crude on purpose, and "credit" contains
			// "edit". The list errs toward surfacing, so this false positive is
			// accepted rather than worked around; it costs one glance, and a
			// tool moving money is worth the glance anyway.
			name: "accepted false positive: edit inside credit",
			tool: Tool{Name: "credit_card_charge", Description: "bills a customer"},
			want: []string{"edit", "charge"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := riskFlags(c.tool)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("riskFlags(%+v) = %v, want %v", c.tool, got, c.want)
			}
		})
	}
}

// TestRiskKeywordsNoSelfOverlap guards the invariant the keyword list documents:
// no keyword is a substring of another, so a tool is never double-flagged for two
// keywords that describe the same match. If someone adds an overlapping keyword,
// this fails and points at the pair.
func TestRiskKeywordsNoSelfOverlap(t *testing.T) {
	for i, a := range riskKeywords {
		for j, b := range riskKeywords {
			if i != j && strings.Contains(a, b) {
				t.Errorf("keyword %q contains %q; one is a substring of the other", a, b)
			}
		}
	}
}

// TestDiscover_HappyPath drives the handshake against an in-memory server (no
// subprocess) and checks the tools come back in the server's order.
func TestDiscover_HappyPath(t *testing.T) {
	tools := `[{"name":"read_file","description":"reads a file"},` +
		`{"name":"delete_file","description":"erases a file"}]`

	reqR, reqW := io.Pipe()
	respR, respW := io.Pipe()
	go serveTools(reqR, respW, tools)

	got, err := discover(reqW, respR)
	_ = reqW.Close() // let the fake server see EOF and finish
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	want := []Tool{
		{Name: "read_file", Description: "reads a file"},
		{Name: "delete_file", Description: "erases a file"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("discover tools = %+v, want %+v", got, want)
	}
}

// A dangerous tool on page two must be reported just like one on page one.
// Requests use the cursor verbatim, including the valid empty-string cursor.
func TestDiscover_Pagination(t *testing.T) {
	for _, cursor := range []string{"opaque+/=", ""} {
		t.Run(cursor, func(t *testing.T) {
			encoded, err := json.Marshal(cursor)
			if err != nil {
				t.Fatal(err)
			}
			input := fmt.Sprintf(initResultLine, "1") +
				`{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"read_file"}],"nextCursor":` + string(encoded) + "}}\n" +
				`{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"delete_file"}]}}` + "\n"
			var requests bytes.Buffer
			tools, err := discover(&requests, strings.NewReader(input))
			if err != nil || len(tools) != 2 || tools[1].Name != "delete_file" {
				t.Fatalf("tools=%+v, error=%v; want both pages", tools, err)
			}
			lines := strings.Split(strings.TrimSpace(requests.String()), "\n")
			if len(lines) != 4 {
				t.Fatalf("requests=%s", requests.String())
			}
			var last struct {
				ID     int               `json:"id"`
				Params map[string]string `json:"params"`
			}
			if err := json.Unmarshal([]byte(lines[3]), &last); err != nil {
				t.Fatal(err)
			}
			gotCursor, present := last.Params["cursor"]
			if last.ID != 3 || !present || gotCursor != cursor {
				t.Fatalf("last request=%s; want fresh id and opaque cursor", lines[3])
			}
		})
	}
}

func TestDiscover_PaginationFailsWithoutPartialReport(t *testing.T) {
	for name, second := range map[string]string{
		"cycle":        `{"result":{"tools":[],"nextCursor":"again"}}`,
		"server error": `{"error":{"code":-32602,"message":"bad cursor"}}`,
		"missing list": `{"result":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			input := fmt.Sprintf(initResultLine, "1") +
				`{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"read_file"}],"nextCursor":"again"}}` + "\n" +
				`{"jsonrpc":"2.0","id":3,` + second[1:] + "\n"
			tools, err := discover(io.Discard, strings.NewReader(input))
			if err == nil || tools != nil {
				t.Fatalf("tools=%+v, error=%v; want error with no partial results", tools, err)
			}
		})
	}
}

func TestDiscover_PageLimit(t *testing.T) {
	var input strings.Builder
	fmt.Fprintf(&input, initResultLine, "1")
	for page := 0; page < maxScanPages; page++ {
		fmt.Fprintf(&input, `{"jsonrpc":"2.0","id":%d,"result":{"tools":[],"nextCursor":"%d"}}`+"\n", page+2, page)
	}
	if tools, err := discover(io.Discard, strings.NewReader(input.String())); err == nil || tools != nil {
		t.Fatalf("tools=%+v, error=%v; want page limit", tools, err)
	}
}

func TestParseToolsPage(t *testing.T) {
	for _, input := range []string{
		`null`, `[]`, `{`, `{}`, `{"tools":null}`, `{"Tools":[]}`,
		`{"tools":[null]}`, `{"tools":[{}]}`, `{"tools":[1]}`,
		`{"tools":[{"Name":"delete_file"}]}`, `{"tools":[{"name":3}]}`,
		`{"tools":[{"name":"x","description":null}]}`,
		`{"tools":[{"name":"x","description":3}]}`,
		`{"tools":[],"nextCursor":null}`, `{"tools":[],"nextCursor":3}`,
	} {
		t.Run(input, func(t *testing.T) {
			if _, _, err := parseToolsPage(json.RawMessage(input)); err == nil {
				t.Fatal("accepted malformed tools/list result")
			}
		})
	}
	if tools, next, err := parseToolsPage(json.RawMessage(`{"tools":[]}`)); err != nil || len(tools) != 0 || next != nil {
		t.Fatalf("empty tools list: tools=%+v next=%v error=%v", tools, next, err)
	}
}

func TestReadResponse_RejectsAmbiguity(t *testing.T) {
	for _, input := range []string{
		`{"jsonrpc":"2.0","id":2,"result":{},"result":{"tools":[]}}`,
		`{"jsonrpc":"2.0","id":2,"result":{"tools":[],"x":"\ud800"}}`,
		`{"jsonrpc":"1.0","id":2,"result":{}}`,
		`{"jsonrpc":2,"id":2,"result":{}}`,
		`{"id":2,"result":{}}`,
		`{"jsonrpc":"2.0","id":2}`,
		`{"jsonrpc":"2.0","id":2,"result":{},"error":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","result":{}}`,
	} {
		t.Run(input, func(t *testing.T) {
			if _, err := readResponse(bufio.NewReader(strings.NewReader(input+"\n")), "2"); err == nil {
				t.Fatal("accepted ambiguous response")
			}
		})
	}
	input := "server log\n{}\n" + `{"jsonrpc":"2.0","id":99,"result":{}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}`
	if _, err := readResponse(bufio.NewReader(strings.NewReader(input)), "2"); err != nil {
		t.Fatalf("interleaved output/final line: %v", err)
	}
}

func TestReadResponse_MessageLimit(t *testing.T) {
	input := strings.NewReader(strings.Repeat("x", maxMessageBytes+1))
	if _, err := readResponse(bufio.NewReader(input), "2"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error=%v; want message size limit", err)
	}
}

type failingStream struct{}

func (failingStream) Read([]byte) (int, error)  { return 0, io.ErrClosedPipe }
func (failingStream) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

type shortWriter struct{}

func (shortWriter) Write(b []byte) (int, error) { return len(b) - 1, nil }

func TestScanStreamFailures(t *testing.T) {
	if _, err := readResponse(bufio.NewReader(failingStream{}), "1"); err == nil {
		t.Fatal("read error discarded")
	}
	if err := writeRequest(failingStream{}, "1", "initialize", nil); err == nil {
		t.Fatal("write error discarded")
	}
	if err := writeRequest(shortWriter{}, "1", "initialize", nil); err != io.ErrShortWrite && (err == nil || !strings.Contains(err.Error(), "short write")) {
		t.Fatalf("error=%v; want short write", err)
	}
	if err := writeRequest(io.Discard, "1", "initialize", make(chan int)); err == nil {
		t.Fatal("marshal error discarded")
	}
	if _, err := discover(failingStream{}, strings.NewReader("")); err == nil {
		t.Fatal("initialize write failure discarded")
	}
	if _, err := discover(io.Discard, strings.NewReader(`{"jsonrpc":"2.0","id":1,"error":{}}`)); err == nil {
		t.Fatal("initialize error discarded")
	}
}

// TestDiscover_ToolsListError: a server that answers tools/list with a JSON-RPC
// error surfaces as an error, not an empty (falsely reassuring) tool list.
func TestDiscover_ToolsListError(t *testing.T) {
	reqR, reqW := io.Pipe()
	respR, respW := io.Pipe()
	go func() {
		defer func() { _ = respW.Close() }() // cleanup of the in-memory server pipe
		br := bufio.NewReader(reqR)
		for {
			line, err := br.ReadBytes('\n')
			if id, method, ok := parseIDMethod(line); ok {
				switch method {
				case "initialize":
					if _, err := fmt.Fprintf(respW, initResultLine, id); err != nil {
						return
					}
				case "tools/list":
					if _, err := fmt.Fprintf(respW, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"tools not supported"}}`+"\n", id); err != nil {
						return
					}
				}
			}
			if err != nil {
				return
			}
		}
	}()

	_, err := discover(reqW, respR)
	_ = reqW.Close()
	if err == nil || !strings.Contains(err.Error(), "tools/list") {
		t.Fatalf("discover error = %v, want it to mention tools/list", err)
	}
}

// TestDiscover_EOFBeforeResponse: a server that reads the request but closes its
// output without answering fails with a clear error rather than hanging.
func TestDiscover_EOFBeforeResponse(t *testing.T) {
	reqR, reqW := io.Pipe()
	respR, respW := io.Pipe()
	go func() {
		br := bufio.NewReader(reqR)
		_, _ = br.ReadBytes('\n') // consume initialize, then answer nothing
		_ = respW.Close()
		_, _ = io.Copy(io.Discard, br) // keep draining so no write ever blocks
	}()

	_, err := discover(reqW, respR)
	_ = reqW.Close()
	if err == nil {
		t.Fatal("discover returned nil, want an error on premature EOF")
	}
}

// TestScan_EndToEnd runs Scan against a real subprocess: this test binary
// re-executed as a stand-in MCP server (TestHelperScanServer). It exercises
// spawning, the handshake, reaping, and the risk flagging together, with no
// external server (Constitution Art. 4.1).
func TestScan_EndToEnd(t *testing.T) {
	t.Setenv("GO_WANT_SCAN_SERVER", "1")

	cfg := config.Config{Command: os.Args[0], Args: []string{"-test.run=TestHelperScanServer"}}
	report, err := Scan(cfg)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if len(report.Findings) != 3 {
		t.Fatalf("got %d findings, want 3: %+v", len(report.Findings), report.Findings)
	}
	if report.Flagged() != 2 {
		t.Errorf("Flagged() = %d, want 2", report.Flagged())
	}

	byName := map[string]Finding{}
	for _, f := range report.Findings {
		byName[f.Tool.Name] = f
	}
	if f, ok := byName["read_file"]; !ok || f.Flagged() {
		t.Errorf("read_file should be present and unflagged, got %+v (ok=%v)", f, ok)
	}
	if f := byName["delete_file"]; !reflect.DeepEqual(f.Keywords, []string{"delete"}) {
		t.Errorf("delete_file keywords = %v, want [delete]", f.Keywords)
	}
	if f := byName["fetch_page"]; !reflect.DeepEqual(f.Keywords, []string{"fetch"}) {
		t.Errorf("fetch_page keywords = %v, want [fetch]", f.Keywords)
	}
}

// TestScan_NoCommand: with no server command there is nothing to scan.
func TestScan_NoCommand(t *testing.T) {
	if _, err := Scan(config.Config{}); err == nil {
		t.Fatal("Scan with no command returned nil, want an error")
	}
}

// TestScan_NonexistentServer: a command that cannot be started fails cleanly
// rather than panicking or hanging.
func TestScan_NonexistentServer(t *testing.T) {
	if _, err := Scan(config.Config{Command: "definitely-not-a-real-binary-xyz"}); err == nil {
		t.Fatal("Scan with a nonexistent server returned nil, want an error")
	}
}

func TestScan_TimeoutClosesPipes(t *testing.T) {
	t.Setenv("GO_WANT_SCAN_STALL", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := scanWithContext(ctx, config.Config{Command: os.Args[0], Args: []string{"-test.run=TestHelperScanStall"}})
	if err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("error=%v elapsed=%v; want bounded failure", err, time.Since(start))
	}
}

// A descendant may retain stdout after the direct child is killed. The scan
// deadline still has to end the read; waiting for the inherited handle to close
// makes CommandContext's process kill insufficient on its own.
func TestScan_TimeoutClosesInheritedOutput(t *testing.T) {
	t.Setenv("GO_WANT_SCAN_INHERITED", "parent")
	pidPath := filepath.Join(t.TempDir(), "descendant.pid")
	t.Setenv("GO_SCAN_DESCENDANT_PID", pidPath)
	t.Cleanup(func() {
		// On Windows a live descendant also holds the test executable open,
		// preventing go test from cleaning its temporary build directory.
		data, err := os.ReadFile(pidPath)
		if err != nil {
			return // the helper did not start a descendant
		}
		pid, err := strconv.Atoi(string(data))
		if err != nil {
			t.Errorf("invalid helper pid: %v", err)
			return
		}
		process, err := os.FindProcess(pid)
		if err == nil {
			_ = process.Kill()    // cleanup; it may already have exited
			_, _ = process.Wait() // join on Windows; non-child wait is unavailable on Unix
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	_, err := scanWithContext(ctx, config.Config{Command: os.Args[0], Args: []string{"-test.run=TestHelperScanInherited"}})
	if err == nil || time.Since(start) > 2500*time.Millisecond {
		t.Fatalf("error=%v elapsed=%v; inherited stdout outlived scan deadline", err, time.Since(start))
	}
}

func TestHelperScanInherited(t *testing.T) {
	switch os.Getenv("GO_WANT_SCAN_INHERITED") {
	case "child":
		time.Sleep(4 * time.Second)
		os.Exit(0)
	case "parent":
		child := exec.Command(os.Args[0], "-test.run=TestHelperScanInherited")
		child.Env = append(os.Environ(), "GO_WANT_SCAN_INHERITED=child")
		child.Stdout = os.Stdout
		if err := child.Start(); err != nil {
			os.Exit(3)
		}
		if err := os.WriteFile(os.Getenv("GO_SCAN_DESCENDANT_PID"), []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil {
			_ = child.Process.Kill() // do not leave an untracked test helper
			os.Exit(4)
		}
		time.Sleep(time.Minute)
		os.Exit(0)
	}
}

func TestHelperScanStall(t *testing.T) {
	if os.Getenv("GO_WANT_SCAN_STALL") != "1" {
		return
	}
	// A live timer keeps the stand-in asleep rather than triggering Go's
	// all-goroutines-asleep detector. Its parent must terminate this process.
	time.Sleep(time.Minute)
	os.Exit(0)
}

// TestRender covers the report formatting for a mixed report and the empty case.
func TestRender(t *testing.T) {
	var buf bytes.Buffer
	r := Report{Findings: []Finding{
		{Tool: Tool{Name: "read_file"}},
		{Tool: Tool{Name: "delete_file"}, Keywords: []string{"delete"}},
	}}
	if err := Render(&buf, r, "mock-server"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	for _, want := range []string{"Scanned 2 tool(s)", "mock-server", "FLAG", "delete_file", "matched: delete", "1 of 2 tool(s) flagged"} {
		if !strings.Contains(out, want) {
			t.Errorf("render output missing %q; got:\n%s", want, out)
		}
	}

	var empty bytes.Buffer
	if err := Render(&empty, Report{}, "mock-server"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(empty.String(), "no tools") {
		t.Errorf("empty render missing the no-tools note; got:\n%s", empty.String())
	}
}

func TestRender_EscapesUntrustedNames(t *testing.T) {
	var out bytes.Buffer
	err := Render(&out, Report{Findings: []Finding{
		{Tool: Tool{Name: "\x1b[2J\n    ok  harmless\u202e"}, Keywords: []string{"delete"}},
		{Tool: Tool{Name: "\rforged\trow"}},
	}}, "server")
	if err != nil {
		t.Fatal(err)
	}
	for _, control := range []string{"\x1b", "\r", "\t", "\u202e"} {
		if strings.Contains(out.String(), control) {
			t.Fatalf("report contains unescaped control %q", control)
		}
	}
	if !strings.Contains(out.String(), `\n    ok`) {
		t.Fatalf("embedded newline was not rendered visibly: %q", out.String())
	}
}

type failAfterWrites struct{ remaining int }

func (w *failAfterWrites) Write(b []byte) (int, error) {
	if w.remaining == 0 {
		return 0, io.ErrClosedPipe
	}
	w.remaining--
	return len(b), nil
}

func TestRender_OutputFailure(t *testing.T) {
	for _, report := range []Report{
		{},
		{Findings: []Finding{{Tool: Tool{Name: "read_file"}}}},
		{Findings: []Finding{{Tool: Tool{Name: "delete_file"}, Keywords: []string{"delete"}}}},
	} {
		for remaining := 0; remaining < len(report.Findings)+2; remaining++ {
			if err := Render(&failAfterWrites{remaining: remaining}, report, "server"); err == nil {
				t.Fatalf("discarded output failure after %d writes", remaining)
			}
		}
	}
}

// initResultLine is a canned successful initialize response with one %s slot for
// the request id, shared by the in-memory fake servers.
const initResultLine = `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2024-11-05","serverInfo":{"name":"mock","version":"0"},"capabilities":{}}}` + "\n"

// parseIDMethod pulls the JSON-RPC id (raw) and method from one message line,
// reporting whether it parsed as a message with a method.
func parseIDMethod(line []byte) (id json.RawMessage, method string, ok bool) {
	if len(bytes.TrimSpace(line)) == 0 {
		return nil, "", false
	}
	var m struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	if json.Unmarshal(line, &m) != nil || m.Method == "" {
		return nil, "", false
	}
	return m.ID, m.Method, true
}

// serveTools is an in-memory stand-in MCP server: it answers initialize with a
// canned result and tools/list with the given tools JSON array, ignoring the
// initialized notification. It runs until its input reaches EOF, then closes its
// output.
func serveTools(reqR io.Reader, respW io.WriteCloser, toolsJSON string) {
	defer func() { _ = respW.Close() }() // cleanup of the in-memory server pipe
	br := bufio.NewReader(reqR)
	for {
		line, err := br.ReadBytes('\n')
		if id, method, ok := parseIDMethod(line); ok {
			switch method {
			case "initialize":
				if _, err := fmt.Fprintf(respW, initResultLine, id); err != nil {
					return
				}
			case "tools/list":
				if _, err := fmt.Fprintf(respW, `{"jsonrpc":"2.0","id":%s,"result":{"tools":%s}}`+"\n", id, toolsJSON); err != nil {
					return
				}
			}
		}
		if err != nil {
			return
		}
	}
}

// TestHelperScanServer is not a real test. TestScan_EndToEnd re-executes the test
// binary with GO_WANT_SCAN_SERVER=1 to stand in for a real MCP server: it does
// the initialize + tools/list handshake over stdio and returns a fixed tool list
// (one benign, two that trip a risk keyword), then exits at EOF.
func TestHelperScanServer(t *testing.T) {
	if os.Getenv("GO_WANT_SCAN_SERVER") != "1" {
		return
	}
	const tools = `[` +
		`{"name":"read_file","description":"returns the contents of a file"},` +
		`{"name":"delete_file","description":"erases a file from disk"},` +
		`{"name":"fetch_page","description":"gets a document from a remote address"}` +
		`]`
	r := bufio.NewReader(os.Stdin)
	for {
		line, err := r.ReadBytes('\n')
		if id, method, ok := parseIDMethod(line); ok {
			switch method {
			case "initialize":
				fmt.Printf(initResultLine, id)
			case "tools/list":
				fmt.Printf(`{"jsonrpc":"2.0","id":%s,"result":{"tools":%s}}`+"\n", id, tools)
			}
		}
		if err != nil {
			break
		}
	}
	os.Exit(0)
}
