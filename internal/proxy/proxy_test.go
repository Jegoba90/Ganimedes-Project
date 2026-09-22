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

	"github.com/Jegoba90/Ganimedes-Project/internal/approval"
	"github.com/Jegoba90/Ganimedes-Project/internal/audit"
	"github.com/Jegoba90/Ganimedes-Project/internal/config"
	"github.com/Jegoba90/Ganimedes-Project/internal/policy"
)

// fakeApprover is a test Approver that returns a fixed outcome and records what
// it was asked, so the approval path can be exercised without an HTTP server.
// url stands in for the real page's address; an empty one exercises the
// fallback in timeoutMessage.
type fakeApprover struct {
	outcome  approval.Outcome
	url      string
	calls    int
	lastTool string
	lastArgs json.RawMessage
}

func (f *fakeApprover) Request(tool string, args json.RawMessage) approval.Outcome {
	f.calls++
	f.lastTool = tool
	f.lastArgs = args
	return f.outcome
}

func (f *fakeApprover) URL() string { return f.url }

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

	if err := Run(cfg, in, &out, nil, nil); err != nil {
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
	if err := Run(cfg, in, &out, log, nil); err != nil {
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
	if err := Run(cfg, in, &out, log, nil); err != nil {
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
	if err := Run(cfg, in, &out, nil, nil); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	got := parseResponses(t, out.Bytes())
	if r, ok := got["9"]; !ok || r.Error == nil || r.Result != nil {
		t.Fatalf("id=9 want a deny error and no result, got %+v (ok=%v)", r, ok)
	}
}

// TestRun_ApprovesHeldTool checks the milestone 4 happy path: a tools/call to a
// tool on the approval-list is held for the human, and when the approver returns
// Approved the call is forwarded to the server, the client gets the server's
// result, and the entry is audited with decision=approved. An allowed tool in the
// same session still records decision=allow.
func TestRun_ApprovesHeldTool(t *testing.T) {
	t.Setenv("GO_WANT_MCP_SERVER", "1")

	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	priv, pub := testKeypair(t)
	log, err := audit.Open(logPath, "test-session", priv)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}

	req := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_tool","arguments":{"q":"ok"}}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"email.send","arguments":{"to":"a@b.c"}}}` + "\n"
	in := strings.NewReader(req)
	var out bytes.Buffer

	appr := &fakeApprover{outcome: approval.Approved}
	cfg := config.Config{
		Command: os.Args[0],
		Args:    []string{"-test.run=TestHelperMCPServer"},
		Approve: []string{"email.send"},
	}
	if err := Run(cfg, in, &out, log, appr); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("log.Close: %v", err)
	}

	// The approver was consulted exactly once, about the held tool.
	if appr.calls != 1 || appr.lastTool != "email.send" {
		t.Errorf("approver calls=%d lastTool=%q, want 1 call about email.send", appr.calls, appr.lastTool)
	}

	// The approved call reached the server and its result reached the client.
	got := parseResponses(t, out.Bytes())
	if r, ok := got["2"]; !ok || r.Result == nil || r.Error != nil {
		t.Errorf("id=2 (approved) want a server result, got %+v (ok=%v)", r, ok)
	}

	res, err := audit.Verify(logPath, pub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK || res.Entries != 2 {
		t.Fatalf("want 2 verified entries, got OK=%v entries=%d (%s)", res.OK, res.Entries, res.Reason)
	}

	entries := readEntries(t, logPath)
	approved := firstWithDecision(entries, "approved")
	if approved == nil || approved.Tool != "email.send" || approved.Result == nil {
		t.Errorf("approved entry = %+v, want tool=email.send with a result", approved)
	}
	if allow := firstWithDecision(entries, "allow"); allow == nil || allow.Tool != "safe_tool" {
		t.Errorf("allow entry = %+v, want tool=safe_tool", allow)
	}
}

// TestRun_RejectsHeldTool checks that a human rejection blocks the call: the
// server never sees it, the client gets a JSON-RPC error naming the rejection,
// and the attempt is audited with decision=rejected.
func TestRun_RejectsHeldTool(t *testing.T) {
	t.Setenv("GO_WANT_MCP_SERVER", "1")

	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	priv, pub := testKeypair(t)
	log, err := audit.Open(logPath, "test-session", priv)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}

	req := `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"email.send","arguments":{"to":"a@b.c"}}}` + "\n"
	in := strings.NewReader(req)
	var out bytes.Buffer

	appr := &fakeApprover{outcome: approval.Rejected}
	cfg := config.Config{
		Command: os.Args[0],
		Args:    []string{"-test.run=TestHelperMCPServer"},
		Approve: []string{"email.send"},
	}
	if err := Run(cfg, in, &out, log, appr); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("log.Close: %v", err)
	}

	got := parseResponses(t, out.Bytes())
	r, ok := got["5"]
	if !ok || r.Error == nil || r.Result != nil {
		t.Fatalf("id=5 want a rejection error and no result, got %+v (ok=%v)", r, ok)
	}
	if !strings.Contains(string(r.Error), "rejected") {
		t.Errorf("id=5 error = %s, want it to mention the rejection", r.Error)
	}

	res, err := audit.Verify(logPath, pub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK || res.Entries != 1 {
		t.Fatalf("want 1 verified entry, got OK=%v entries=%d (%s)", res.OK, res.Entries, res.Reason)
	}
	rejected := firstWithDecision(readEntries(t, logPath), "rejected")
	if rejected == nil || rejected.Tool != "email.send" || rejected.Result != nil || rejected.Error == nil {
		t.Errorf("rejected entry = %+v, want tool=email.send, no result, an error", rejected)
	}
}

// TestRun_TimesOutHeldTool checks the fail-closed path (Art. 2.1): when the
// approver times out, the call is blocked just like a rejection and audited with
// decision=timeout. It also checks that the error carries the approval page's
// address: a timeout means the human never saw the request, and this error is
// the only channel that reaches them under a real MCP client.
func TestRun_TimesOutHeldTool(t *testing.T) {
	t.Setenv("GO_WANT_MCP_SERVER", "1")

	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	priv, pub := testKeypair(t)
	log, err := audit.Open(logPath, "test-session", priv)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}

	req := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"email.send","arguments":{}}}` + "\n"
	in := strings.NewReader(req)
	var out bytes.Buffer

	appr := &fakeApprover{outcome: approval.TimedOut, url: "http://127.0.0.1:8765/"}
	cfg := config.Config{
		Command: os.Args[0],
		Args:    []string{"-test.run=TestHelperMCPServer"},
		Approve: []string{"email.send"},
	}
	if err := Run(cfg, in, &out, log, appr); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("log.Close: %v", err)
	}

	got := parseResponses(t, out.Bytes())
	r, ok := got["7"]
	if !ok || r.Error == nil || r.Result != nil {
		t.Fatalf("id=7 want a timeout error and no result, got %+v (ok=%v)", r, ok)
	}
	if !strings.Contains(string(r.Error), appr.url) {
		t.Errorf("timeout error = %s, want it to name the approval page %q", r.Error, appr.url)
	}
	res, err := audit.Verify(logPath, pub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK || res.Entries != 1 {
		t.Fatalf("want 1 verified entry, got OK=%v entries=%d (%s)", res.OK, res.Entries, res.Reason)
	}
	timedOut := firstWithDecision(readEntries(t, logPath), "timeout")
	if timedOut == nil || timedOut.Tool != "email.send" || timedOut.Error == nil {
		t.Errorf("timeout entry = %+v, want tool=email.send with an error", timedOut)
	}
}

// TestTimeoutMessage pins both forms of the timeout reason. The address is the
// point of the message, so its presence is asserted rather than the exact
// sentence; the empty-url form guards the fallback, which must not leave the
// reader pointed at nothing.
//
// The "waiting" phrasing is asserted, not decorative. Its predecessor said
// "nobody answered at", which a real client read as a service that was down,
// so the message has to convey that the page was up and a person was what was
// missing.
func TestTimeoutMessage(t *testing.T) {
	withURL := timeoutMessage("email.send", "http://127.0.0.1:8765/")
	if !strings.Contains(withURL, "email.send") || !strings.Contains(withURL, "http://127.0.0.1:8765/") {
		t.Errorf("timeoutMessage with a url = %q, want it to name both the tool and the page", withURL)
	}
	if !strings.Contains(withURL, "waiting") {
		t.Errorf("timeoutMessage with a url = %q, want it to say the page was waiting, not that it was absent", withURL)
	}

	bare := timeoutMessage("email.send", "")
	if !strings.Contains(bare, "email.send") {
		t.Errorf("timeoutMessage without a url = %q, want it to name the tool", bare)
	}
	if strings.Contains(bare, "http") || strings.Contains(bare, "waiting for a human at") {
		t.Errorf("timeoutMessage without a url = %q, want no dangling reference to a page", bare)
	}
}

// TestIsJSONArray pins the discrimination handleRequest relies on: a batch
// (any syntactically valid JSON array, empty or not) must be told apart from
// every other shape a line could fail the single-message parse for, since the
// two get opposite treatment -- a batch is refused, anything else is still
// forwarded blind exactly as before.
func TestIsJSONArray(t *testing.T) {
	cases := []struct {
		name string
		line string
		want bool
	}{
		{"batch of one", `[{"jsonrpc":"2.0","id":1,"method":"tools/call"}]`, true},
		{"empty array", `[]`, true},
		{"single object", `{"jsonrpc":"2.0","id":1}`, false},
		{"not json at all", `not json`, false},
		{"bare number", `42`, false},
		{"bare string", `"hello"`, false},
	}
	for _, c := range cases {
		if got := isJSONArray([]byte(c.line)); got != c.want {
			t.Errorf("isJSONArray(%s) = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestBatchIDs checks that only elements which are both parseable and carry an
// id are recovered: a notification (no id) gets no reply under ordinary
// JSON-RPC batch semantics either, and an element that is not even a JSON
// object is skipped rather than aborting the whole extraction.
func TestBatchIDs(t *testing.T) {
	line := `[
		{"jsonrpc":"2.0","id":1,"method":"tools/call"},
		{"jsonrpc":"2.0","method":"notifications/progress"},
		{"jsonrpc":"2.0","id":"two","method":"tools/call"},
		"not an object"
	]`
	ids := batchIDs([]byte(line))
	if len(ids) != 2 {
		t.Fatalf("batchIDs = %d ids, want 2 (the notification and the malformed element skipped): %v", len(ids), ids)
	}
	if string(ids[0]) != "1" || string(ids[1]) != `"two"` {
		t.Errorf("batchIDs = [%s %s], want [1 \"two\"]", ids[0], ids[1])
	}
}

// TestWriteBatchRefusal checks both shapes writeBatchRefusal can send: an
// array of errors mirroring a batch's ids, and the single-object fallback used
// when no id could be recovered at all, so the client still gets an answer.
func TestWriteBatchRefusal(t *testing.T) {
	var buf bytes.Buffer
	if err := writeBatchRefusal(&buf, nil); err != nil {
		t.Fatalf("writeBatchRefusal with no ids: %v", err)
	}
	var single rpcErrorResponse
	if err := json.Unmarshal(buf.Bytes(), &single); err != nil {
		t.Fatalf("no-id fallback is not a single object: %v (%s)", err, buf.Bytes())
	}
	if string(single.ID) != "null" {
		t.Errorf("no-id fallback id = %s, want null", single.ID)
	}

	buf.Reset()
	ids := []json.RawMessage{json.RawMessage("1"), json.RawMessage(`"two"`)}
	if err := writeBatchRefusal(&buf, ids); err != nil {
		t.Fatalf("writeBatchRefusal with ids: %v", err)
	}
	var resp []rpcErrorResponse
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		t.Fatalf("response is not a JSON array: %v (%s)", err, buf.Bytes())
	}
	if len(resp) != 2 || string(resp[0].ID) != "1" || string(resp[1].ID) != `"two"` {
		t.Errorf("writeBatchRefusal response = %+v, want ids [1 \"two\"]", resp)
	}
}

// TestRun_ApprovalNilApproverFailsClosed: if a tool requires approval but no
// approver is wired (a defensive case the CLI never produces), the call fails
// closed to a denial rather than being allowed through.
func TestRun_ApprovalNilApproverFailsClosed(t *testing.T) {
	t.Setenv("GO_WANT_MCP_SERVER", "1")

	req := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"email.send","arguments":{}}}` + "\n"
	in := strings.NewReader(req)
	var out bytes.Buffer

	cfg := config.Config{
		Command: os.Args[0],
		Args:    []string{"-test.run=TestHelperMCPServer"},
		Approve: []string{"email.send"},
	}
	if err := Run(cfg, in, &out, nil, nil); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	got := parseResponses(t, out.Bytes())
	r, ok := got["3"]
	if !ok || r.Error == nil || r.Result != nil {
		t.Fatalf("id=3 want a fail-closed error and no result, got %+v (ok=%v)", r, ok)
	}
	if !strings.Contains(string(r.Error), "no approver") {
		t.Errorf("id=3 error = %s, want it to mention the missing approver", r.Error)
	}
}

// TestRun_RefusesJSONRPCBatch checks the fix for the most severe gap found in
// this proxy: JSON-RPC 2.0 allows sending several messages as one line (a
// top-level array, "batching"), and that line used to fail the proxy's
// single-message parse and fall through to "not JSON we understand, forward
// verbatim" -- so a tools/call hidden inside a batch reached the real server
// with no policy check and no audit record at all, deny-list and
// approval-list included. Batching is still legal on the wire for any client
// or server on MCP protocol 2024-11-05 or 2025-03-26 (it was only removed
// from the spec in 2025-06-18), so this was reachable, not theoretical.
//
// v0 has no way to judge a batch's elements individually (Decide and Append
// both work one call at a time), so the fix refuses the whole batch rather
// than forwarding it or splitting and re-judging it piecemeal. This proves
// both halves. Both ids in the batch come back carrying an error and no
// result, and an error for an id can only be ours, since TestHelperMCPServer
// answers a tools/call with a result and nothing else — the same reasoning
// TestRun_DeniesBlockedTool uses to show a blocked call never reached the
// server. And the refusal keeps the batch's own shape, one error per id in a
// single array, so a client can still correlate it.
func TestRun_RefusesJSONRPCBatch(t *testing.T) {
	t.Setenv("GO_WANT_MCP_SERVER", "1")

	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	priv, pub := testKeypair(t)
	log, err := audit.Open(logPath, "test-session", priv)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	defer log.Close() // idempotent; keeps an early t.Fatal from wedging TempDir cleanup

	batch := []map[string]any{
		{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "safe_tool", "arguments": map[string]any{}}},
		{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{"name": "dangerous_tool", "arguments": map[string]any{}}},
	}
	batchLine, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}

	// A batch on one line, then an ordinary call on the next: refusing the
	// batch must not take the rest of the session down with it.
	req := string(batchLine) + "\n" +
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"after_batch","arguments":{}}}` + "\n"
	in := strings.NewReader(req)
	var out bytes.Buffer

	// Neither tool in the batch is on a deny-list here: the point is that the
	// whole batch is refused unconditionally, without the policy engine ever
	// being asked what it contains.
	cfg := config.Config{Command: os.Args[0], Args: []string{"-test.run=TestHelperMCPServer"}}
	if err := Run(cfg, in, &out, log, nil); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("log.Close: %v", err)
	}

	lines := bytes.Split(bytes.TrimSpace(out.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("want 2 lines back (the batch refusal, then id=3's own response), got %d: %s", len(lines), out.Bytes())
	}

	var batchResp []rpcResp
	if err := json.Unmarshal(lines[0], &batchResp); err != nil {
		t.Fatalf("first response line is not a JSON array: %v (%s)", err, lines[0])
	}
	if len(batchResp) != 2 {
		t.Fatalf("batch refusal has %d entries, want 2 (one per id in the batch)", len(batchResp))
	}
	for i, want := range []string{"1", "2"} {
		if got := string(bytes.TrimSpace(batchResp[i].ID)); got != want {
			t.Errorf("batch refusal entry %d id = %q, want %q", i, got, want)
		}
		if batchResp[i].Error == nil || batchResp[i].Result != nil {
			t.Errorf("batch refusal entry %d = %+v, want an error and no result", i, batchResp[i])
		}
		if !strings.Contains(string(batchResp[i].Error), "batch") {
			t.Errorf("batch refusal entry %d error = %s, want it to mention the batch", i, batchResp[i].Error)
		}
	}

	// The call after the batch went through normally: refusing a batch does
	// not wedge the rest of the session.
	var after rpcResp
	if err := json.Unmarshal(lines[1], &after); err != nil {
		t.Fatalf("second response line: %v (%s)", err, lines[1])
	}
	if string(bytes.TrimSpace(after.ID)) != "3" || after.Result == nil {
		t.Errorf("after-batch response = %+v, want id=3 with a server result", after)
	}

	res, err := audit.Verify(logPath, pub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// One entry for the refused batch, one for the ordinary allowed call after it.
	if !res.OK || res.Entries != 2 {
		t.Fatalf("want 2 verified entries, got OK=%v entries=%d (%s)", res.OK, res.Entries, res.Reason)
	}

	entries := readEntries(t, logPath)
	batchEntry := firstWithDecision(entries, "deny")
	if batchEntry == nil || batchEntry.Tool != batchTool {
		t.Fatalf("no deny entry with tool %q in the log: %+v", batchTool, entries)
	}
	// The raw batch is captured verbatim for forensics: both tool names inside
	// it must be recoverable from the audit entry, even though neither call was
	// individually judged.
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if !bytes.Contains(raw, []byte("safe_tool")) || !bytes.Contains(raw, []byte("dangerous_tool")) {
		t.Errorf("audit log does not capture what the refused batch contained: %s", raw)
	}
}

// TestRun_RefusesBatchWithoutLog confirms the batch refusal does not depend on
// auditing being on, the same guarantee TestRun_DeniesWithoutLog pins for an
// ordinary deny. Deny carries an unrelated entry only to install handleReq
// (Run stays a raw passthrough with no policy and no log at all), matching how
// TestRun_DeniesWithoutLog is built.
func TestRun_RefusesBatchWithoutLog(t *testing.T) {
	t.Setenv("GO_WANT_MCP_SERVER", "1")

	batchLine, err := json.Marshal([]map[string]any{
		{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "anything"}},
	})
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}
	in := strings.NewReader(string(batchLine) + "\n")
	var out bytes.Buffer

	cfg := config.Config{
		Command: os.Args[0],
		Args:    []string{"-test.run=TestHelperMCPServer"},
		Deny:    []string{"irrelevant"},
	}
	if err := Run(cfg, in, &out, nil, nil); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if bytes.Contains(out.Bytes(), []byte(`"ok":true`)) {
		t.Fatalf("batch reached the real server with no log configured; client got: %s", out.Bytes())
	}
	var resp []rpcErrorResponse
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &resp); err != nil || len(resp) != 1 {
		t.Fatalf("want a one-entry batch refusal array, got err=%v body=%s", err, out.Bytes())
	}
}

// TestPending_Remember_RejectsCollision is the lowest-level test of the fix
// for the audit-correlation bug an id collision used to cause: remember
// silently overwrote an in-flight call's entry when a second call reused its
// JSON-RPC id before the first got a response, so whichever response arrived
// first was logged under the wrong tool and the other call left no audit
// record at all. remember now refuses to store a second entry under a key
// that is still occupied, and accepts it again once the first is cleared
// (i.e. once its response has been recorded).
func TestPending_Remember_RejectsCollision(t *testing.T) {
	p := newPending()
	id := json.RawMessage("1")

	if ok := p.remember(id, "first_tool", nil, audit.DecisionAllow); !ok {
		t.Fatal("first remember for a fresh id should succeed")
	}
	if ok := p.remember(id, "second_tool", nil, audit.DecisionAllow); ok {
		t.Fatal("second remember for the same in-flight id should be refused")
	}

	// The refused attempt must not have touched the first call's entry.
	p.mu.Lock()
	call := p.calls[idKey(id)]
	p.mu.Unlock()
	if call.tool != "first_tool" {
		t.Errorf("pending entry for id 1 = %+v, want it still holding first_tool", call)
	}

	// Once the first call's response is recorded, recordResponse deletes its
	// entry and the id is free again: non-overlapping reuse is not ambiguous.
	// The delete is done directly here so this stays a test of remember alone;
	// TestHandleRequest_RejectsIDReuse drives the real recordResponse path.
	p.mu.Lock()
	delete(p.calls, idKey(id))
	p.mu.Unlock()
	if ok := p.remember(id, "third_tool", nil, audit.DecisionAllow); !ok {
		t.Error("remember for an id whose earlier call already completed should succeed")
	}
}

// TestHandleRequest_RejectsIDReuse calls handleRequest directly (bypassing
// Run's concurrent goroutines) so the "still in flight" window is exact
// rather than a race against a real subprocess's response. Two allowed calls
// share one id; the second must be blocked, and the first must still
// complete correctly under its own tool name once its response arrives,
// proving the block protected the entry rather than corrupting it too.
func TestHandleRequest_RejectsIDReuse(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	priv, pub := testKeypair(t)
	log, err := audit.Open(logPath, "test-session", priv)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}

	// Close is idempotent, so the explicit Close below still reports a real
	// failure; this one only keeps an early t.Fatal from leaving the file open,
	// which on Windows makes TempDir cleanup fail and bury the actual error.
	defer log.Close()

	eng := policy.New(nil, nil) // default-allow: both calls clear policy
	p := newPending()
	var toClient bytes.Buffer

	first := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"first_tool","arguments":{}}}` + "\n")
	second := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"second_tool","arguments":{}}}` + "\n")

	if fwd := handleRequest(first, eng, p, nil, log, &toClient); !fwd {
		t.Fatal("first call with a fresh id should forward")
	}
	if fwd := handleRequest(second, eng, p, nil, log, &toClient); fwd {
		t.Fatal("second call reusing an in-flight id should be blocked")
	}
	if !strings.Contains(toClient.String(), `"id":1`) || !strings.Contains(toClient.String(), "reused") {
		t.Errorf("client did not get a policy error naming the reuse: %s", toClient.String())
	}

	// The first call's own response now arrives and must still complete
	// correctly, attributed to first_tool.
	p.recordResponse([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`+"\n"), log)
	if err := log.Close(); err != nil {
		t.Fatalf("log.Close: %v", err)
	}

	res, err := audit.Verify(logPath, pub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK || res.Entries != 2 {
		t.Fatalf("want 2 verified entries (the blocked reuse, the completed first call), got OK=%v entries=%d (%s)", res.OK, res.Entries, res.Reason)
	}

	entries := readEntries(t, logPath)
	deny, allow := findByDecision(entries)
	if deny == nil || deny.Tool != "second_tool" {
		t.Errorf("deny entry = %+v, want tool=second_tool", deny)
	}
	if allow == nil || allow.Tool != "first_tool" || allow.Result == nil {
		t.Errorf("allow entry = %+v, want tool=first_tool with a result", allow)
	}
}

// TestHandleRequest_AllowsIDReuseAfterCompletion checks that only overlapping
// reuse is refused: once a call's response has been recorded (its pending
// entry cleared), a later call is free to reuse the same id without being
// mistaken for a collision.
func TestHandleRequest_AllowsIDReuseAfterCompletion(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	priv, _ := testKeypair(t)
	log, err := audit.Open(logPath, "test-session", priv)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	defer log.Close()

	eng := policy.New(nil, nil)
	p := newPending()
	var toClient bytes.Buffer

	first := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"first_tool","arguments":{}}}` + "\n")
	if fwd := handleRequest(first, eng, p, nil, log, &toClient); !fwd {
		t.Fatal("first call should forward")
	}
	p.recordResponse([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`+"\n"), log)

	second := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"second_tool","arguments":{}}}` + "\n")
	if fwd := handleRequest(second, eng, p, nil, log, &toClient); !fwd {
		t.Fatal("reusing an id whose earlier call already completed should forward, not be blocked")
	}
}

// TestHandleApproval_RejectsIDReuse mirrors TestHandleRequest_RejectsIDReuse
// for the approval path: even a call a human approved must not be forwarded
// if its id collided with another in-flight call while the human was
// deciding (Art. 2.1: fails closed wherever there is still a live choice).
func TestHandleApproval_RejectsIDReuse(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	priv, _ := testKeypair(t)
	log, err := audit.Open(logPath, "test-session", priv)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	defer log.Close()

	p := newPending()
	// Occupy id=1 first, the way an already-forwarded allowed call would.
	if ok := p.remember(json.RawMessage("1"), "already_in_flight", nil, audit.DecisionAllow); !ok {
		t.Fatal("setup: first remember should succeed")
	}

	var toClient bytes.Buffer
	appr := &fakeApprover{outcome: approval.Approved}
	if fwd := handleApproval(&toClient, p, appr, log, json.RawMessage("1"), "email.send", json.RawMessage(`{}`)); fwd {
		t.Fatal("an approved call reusing an in-flight id should still be blocked")
	}
	if !strings.Contains(toClient.String(), "reused") {
		t.Errorf("client did not get a policy error naming the reuse: %s", toClient.String())
	}

	deny := firstWithDecision(readEntries(t, logPath), "deny")
	if deny == nil || deny.Tool != "email.send" {
		t.Errorf("deny entry = %+v, want tool=email.send", deny)
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

// firstWithDecision returns the first entry with the given decision, or nil if
// none, so a test need not assume the order of entries in the log.
func firstWithDecision(entries []logEntry, decision string) *logEntry {
	for i := range entries {
		if entries[i].Decision == decision {
			return &entries[i]
		}
	}
	return nil
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
