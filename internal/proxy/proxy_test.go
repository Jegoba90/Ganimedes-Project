package proxy

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Jegoba90/Ganimedes-Project/internal/audit"
	"github.com/Jegoba90/Ganimedes-Project/internal/config"
)

// testKeypair generates an Ed25519 keypair for driving the signed audit log in a
// test.
func testKeypair(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return priv, pub
}

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
	priv, pub := testKeypair(t)
	log, err := audit.Open(logPath, "test-session", priv)
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
	res, err := audit.Verify(logPath, pub)
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

// TestRun_DeniesBlockedTool checks the milestone 3 behavior: a tools/call to a
// tool on the deny-list is blocked (the client gets a JSON-RPC error, the server
// never sees it and never produces a result for it), while a call to an allowed
// tool flows through like milestone 2. Both attempts are recorded: the blocked
// one with decision=deny, the allowed one with decision=allow.
func TestRun_DeniesBlockedTool(t *testing.T) {
	t.Setenv("GO_WANT_MCP_SERVER", "1")

	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	priv, pub := testKeypair(t)
	log, err := audit.Open(logPath, "test-session", priv)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}

	req := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_tool","arguments":{"q":"ok"}}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"dangerous_tool","arguments":{"scope":"prod"}}}` + "\n"
	in := strings.NewReader(req)
	var out bytes.Buffer

	cfg := config.Config{
		Command: os.Args[0],
		Args:    []string{"-test.run=TestHelperMCPServer"},
		Deny:    []string{"dangerous_tool"},
	}
	if err := Run(cfg, in, &out, log); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("log.Close: %v", err)
	}

	got := parseResponses(t, out.Bytes())

	// id=1 (allowed): the server's result reached the client.
	if r, ok := got["1"]; !ok || r.Result == nil || r.Error != nil {
		t.Errorf("id=1 want a server result, got %+v (ok=%v)", r, ok)
	}
	// id=2 (denied): the client got our JSON-RPC error, not a server result. A
	// JSON-RPC error for this id can only be ours (the helper only ever emits
	// results), which proves the server never handled the blocked call.
	r2, ok := got["2"]
	if !ok || r2.Error == nil || r2.Result != nil {
		t.Fatalf("id=2 want a deny error and no result, got %+v (ok=%v)", r2, ok)
	}
	if !strings.Contains(string(r2.Error), "deny-list") {
		t.Errorf("id=2 error = %s, want it to mention the deny-list", r2.Error)
	}

	// The audit log holds both attempts and the chain is intact.
	res, err := audit.Verify(logPath, pub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK || res.Entries != 2 {
		t.Fatalf("want 2 verified entries, got OK=%v entries=%d (%s)", res.OK, res.Entries, res.Reason)
	}

	entries := readEntries(t, logPath)
	deny, allow := findByDecision(entries)
	if deny == nil {
		t.Fatal("no decision=deny entry in the log")
	}
	if deny.Tool != "dangerous_tool" || deny.Result != nil || deny.Error == nil {
		t.Errorf("deny entry = %+v, want tool=dangerous_tool, no result, an error", deny)
	}
	if allow == nil {
		t.Fatal("no decision=allow entry in the log")
	}
	if allow.Tool != "safe_tool" || allow.Result == nil {
		t.Errorf("allow entry = %+v, want tool=safe_tool with a result", allow)
	}
}

// TestRun_DeniesWithoutLog confirms enforcement does not depend on auditing: with
// log == nil a denied tool is still blocked and the client still gets the error.
func TestRun_DeniesWithoutLog(t *testing.T) {
	t.Setenv("GO_WANT_MCP_SERVER", "1")

	req := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"blocked","arguments":{}}}` + "\n"
	in := strings.NewReader(req)
	var out bytes.Buffer

	cfg := config.Config{
		Command: os.Args[0],
		Args:    []string{"-test.run=TestHelperMCPServer"},
		Deny:    []string{"blocked"},
	}
	if err := Run(cfg, in, &out, nil); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	got := parseResponses(t, out.Bytes())
	if r, ok := got["9"]; !ok || r.Error == nil || r.Result != nil {
		t.Fatalf("id=9 want a deny error and no result, got %+v (ok=%v)", r, ok)
	}
}

// rpcResp is one JSON-RPC response line as seen by the client.
type rpcResp struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

// parseResponses splits the client stream into JSON-RPC responses keyed by id
// (the raw id bytes, trimmed), so a test can look up the response for a request.
func parseResponses(t *testing.T, data []byte) map[string]rpcResp {
	t.Helper()
	out := make(map[string]rpcResp)
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var r rpcResp
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatalf("parse response line %q: %v", line, err)
		}
		out[string(bytes.TrimSpace(r.ID))] = r
	}
	return out
}

// logEntry is the subset of an audit entry the proxy tests assert on.
type logEntry struct {
	Tool     string          `json:"tool"`
	Decision string          `json:"decision"`
	Result   json.RawMessage `json:"result"`
	Error    json.RawMessage `json:"error"`
}

// readEntries reads every audit entry from the JSONL log at path.
func readEntries(t *testing.T, path string) []logEntry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	var entries []logEntry
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e logEntry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("decode entry %q: %v", line, err)
		}
		entries = append(entries, e)
	}
	return entries
}

// findByDecision returns the first deny entry and the first allow entry (or nil
// for whichever is absent), so a test need not assume their order in the log.
func findByDecision(entries []logEntry) (deny, allow *logEntry) {
	for i := range entries {
		switch entries[i].Decision {
		case "deny":
			if deny == nil {
				deny = &entries[i]
			}
		case "allow":
			if allow == nil {
				allow = &entries[i]
			}
		}
	}
	return deny, allow
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
