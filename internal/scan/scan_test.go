package scan

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

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

// TestDiscover_ToolsListError: a server that answers tools/list with a JSON-RPC
// error surfaces as an error, not an empty (falsely reassuring) tool list.
func TestDiscover_ToolsListError(t *testing.T) {
	reqR, reqW := io.Pipe()
	respR, respW := io.Pipe()
	go func() {
		defer respW.Close()
		br := bufio.NewReader(reqR)
		for {
			line, err := br.ReadBytes('\n')
			if id, method, ok := parseIDMethod(line); ok {
				switch method {
				case "initialize":
					fmt.Fprintf(respW, initResultLine, id)
				case "tools/list":
					fmt.Fprintf(respW, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"tools not supported"}}`+"\n", id)
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

// TestRender covers the report formatting for a mixed report and the empty case.
func TestRender(t *testing.T) {
	var buf bytes.Buffer
	r := Report{Findings: []Finding{
		{Tool: Tool{Name: "read_file"}},
		{Tool: Tool{Name: "delete_file"}, Keywords: []string{"delete"}},
	}}
	Render(&buf, r, "mock-server")
	out := buf.String()

	for _, want := range []string{"Scanned 2 tool(s)", "mock-server", "FLAG", "delete_file", "matched: delete", "1 of 2 tool(s) flagged"} {
		if !strings.Contains(out, want) {
			t.Errorf("render output missing %q; got:\n%s", want, out)
		}
	}

	var empty bytes.Buffer
	Render(&empty, Report{}, "mock-server")
	if !strings.Contains(empty.String(), "no tools") {
		t.Errorf("empty render missing the no-tools note; got:\n%s", empty.String())
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
	defer respW.Close()
	br := bufio.NewReader(reqR)
	for {
		line, err := br.ReadBytes('\n')
		if id, method, ok := parseIDMethod(line); ok {
			switch method {
			case "initialize":
				fmt.Fprintf(respW, initResultLine, id)
			case "tools/list":
				fmt.Fprintf(respW, `{"jsonrpc":"2.0","id":%s,"result":{"tools":%s}}`+"\n", id, toolsJSON)
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
