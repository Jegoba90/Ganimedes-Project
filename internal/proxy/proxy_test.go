package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Jegoba90/Ganimedes-Project/internal/audit"
	"github.com/Jegoba90/Ganimedes-Project/internal/config"
)

// TestRun_ForwardsBothDirections checks that Run transparently pipes the
// client's input to the server and the server's output back to the client with
// no audit log (log == nil, milestone 1 behavior). The "server" is this test
// binary re-executed as a helper (see TestHelperProcess) that echoes each line
// with a prefix, so the round trip is observable without an external MCP server.
func TestRun_ForwardsBothDirections(t *testing.T) {
	// The helper only activates when this variable is set. exec.Command
	// inherits the parent environment, so the subprocess will see it.
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")

	in := strings.NewReader("hello\nworld\n")
	var out bytes.Buffer

	cfg := config.Config{
		Command: os.Args[0],
		Args:    []string{"-test.run=TestHelperProcess"},
	}

	if err := Run(cfg, in, &out, nil); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	const want = "echo: hello\necho: world\n"
	if got := out.String(); got != want {
		t.Errorf("round trip mismatch:\n got: %q\nwant: %q", got, want)
	}
}

// TestRun_AuditsToolCalls checks the milestone 2 behavior: a tools/call and its
// response are recorded in the hash-chained log, while the client still sees the
// response forwarded verbatim. The "server" is TestHelperMCPServer, which
// answers any tools/call with a canned result echoing the request id.
func TestRun_AuditsToolCalls(t *testing.T) {
	t.Setenv("GO_WANT_MCP_SERVER", "1")

	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := audit.Open(logPath, "test-session")
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}

	// One tools/call, plus a tools/list that must NOT be audited (only
	// tools/call is in scope).
	req := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_files","arguments":{"q":"needle"}}}` + "\n"
	in := strings.NewReader(req)
	var out bytes.Buffer

	cfg := config.Config{Command: os.Args[0], Args: []string{"-test.run=TestHelperMCPServer"}}
	if err := Run(cfg, in, &out, log); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("log.Close: %v", err)
	}

	// The client must have received the server's response for id=2 verbatim.
	if !strings.Contains(out.String(), `"id":2`) {
		t.Errorf("client did not receive the tools/call response; got: %q", out.String())
	}

	// Exactly one entry (the tools/call), and it must verify.
	res, err := audit.Verify(logPath)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK || res.Entries != 1 {
		t.Fatalf("want 1 verified entry, got OK=%v entries=%d (%s)", res.OK, res.Entries, res.Reason)
	}

	// And its recorded tool name must be the one that was called.
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	var e struct {
		Tool string          `json:"tool"`
		Args json.RawMessage `json:"args"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(data), &e); err != nil {
		t.Fatalf("decode entry: %v", err)
	}
	if e.Tool != "search_files" {
		t.Errorf("tool = %q, want search_files", e.Tool)
	}
	if !strings.Contains(string(e.Args), "needle") {
		t.Errorf("args = %s, want them to contain the request arguments", e.Args)
	}
}

// TestHelperProcess is not a real test. TestRun_ForwardsBothDirections
// re-executes the test binary with GO_WANT_HELPER_PROCESS=1 to stand in for a
// real MCP server: it reads lines from stdin and writes each back to stdout with
// an "echo: " prefix, then exits at EOF.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		fmt.Printf("echo: %s\n", scanner.Text())
	}
	os.Exit(0)
}

// TestHelperMCPServer is not a real test either. It stands in for a real MCP
// server (GO_WANT_MCP_SERVER=1): for every tools/call request it reads, it
// writes back a JSON-RPC result echoing the request id; other messages get no
// reply. That is enough to exercise request/response correlation and auditing.
func TestHelperMCPServer(t *testing.T) {
	if os.Getenv("GO_WANT_MCP_SERVER") != "1" {
		return
	}
	r := bufio.NewReader(os.Stdin)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			var m struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
			}
			if json.Unmarshal(line, &m) == nil && m.Method == "tools/call" {
				fmt.Printf(`{"jsonrpc":"2.0","id":%s,"result":{"ok":true}}`+"\n", m.ID)
			}
		}
		if err != nil {
			break
		}
	}
	os.Exit(0)
}
