// Package proxy is the core of Ganimedes: a stdio proxy that sits between an
// MCP client and the real MCP server, forwarding JSON-RPC messages in both
// directions.
//
// Milestone 1 was a pure byte passthrough. Milestone 2 added the audit log: the
// proxy reads the stream as newline-delimited JSON so it can recognize
// `tools/call` requests and their responses, correlate them by JSON-RPC id, and
// append each completed call to the hash-chained log. Milestone 3 adds the
// deny-list: a `tools/call` whose tool is blocked by policy is never forwarded
// to the server; the client gets a JSON-RPC error and the blocked attempt is
// recorded with decision=deny.
//
// The bytes forwarded to the other side are always the exact bytes read, never a
// re-encoded copy, so inspecting a message can never change it on the wire
// (Constitution Art. 1.3). The one thing the proxy writes that did not come from
// the server is the deny error for a blocked call — the deliberate, documented
// exception where policy blocks a call (see docs/ARCHITECTURE.md, SEQUENCES.md).
package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"

	"github.com/Jegoba90/Ganimedes-Project/internal/approval"
	"github.com/Jegoba90/Ganimedes-Project/internal/audit"
	"github.com/Jegoba90/Ganimedes-Project/internal/config"
	"github.com/Jegoba90/Ganimedes-Project/internal/policy"
)

// Approver decides a tools/call that policy flagged for human review. Request
// blocks until a human approves or rejects it, or the wait times out, and returns
// the outcome. The proxy depends only on this interface, so tests can inject a
// fake without spinning up the real localhost page; internal/approval.Server is
// the production implementation. A timeout (approval.TimedOut) fails closed to a
// denial (Constitution Art. 2.1).
//
// URL is where a human answers. The proxy needs it for one reason: a call that
// times out is the only moment the gateway can tell a human it was waiting, and
// the error returned to the agent is the only channel that reaches them. The
// address is announced on stderr at startup, but an MCP client captures the
// server's stderr into a log its user does not read, so under a real client that
// announcement is invisible.
type Approver interface {
	Request(tool string, args json.RawMessage) approval.Outcome
	URL() string
}

// Run wraps the MCP server described by cfg and proxies a single client session
// to it. Client bytes are read from in and forwarded to the server's stdin; the
// server's stdout is forwarded back to out. The real server's stderr is passed
// through to Ganimedes' own stderr so its logs stay visible.
//
// cfg.Deny and cfg.Approve drive the policy engine: a tools/call to a denied tool
// is blocked before it reaches the server, and a tools/call to a tool on the
// approval-list is paused for a human via appr (milestone 4). If log is non-nil,
// every allowed, approved, and blocked tools/call is recorded; if log is nil, no
// audit is written. With empty lists and a nil log, Run is a transparent
// passthrough (milestone 1 behavior). Either way the forwarded wire bytes are
// verbatim.
//
// appr is consulted only for tools on the approval-list; it may be nil when the
// approval-list is empty. If a tool requires approval but appr is nil, the call
// fails closed to a denial (Constitution Art. 2.1).
//
// in and out are plain io.Reader/io.Writer (not hardcoded to os.Stdin/Stdout)
// so the proxy can be driven by in-memory streams in tests.
//
// Run blocks until the server closes its output (typically because it exited),
// then reaps the process. It returns the first error encountered, or nil on a
// clean shutdown.
func Run(cfg config.Config, in io.Reader, out io.Writer, log *audit.Logger, appr Approver) error {
	cmd := exec.Command(cfg.Command, cfg.Args...)
	cmd.Stderr = os.Stderr // out-of-band: surface the real server's logs

	serverIn, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("wiring server stdin: %w", err)
	}
	serverOut, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("wiring server stdout: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting server %q: %w", cfg.Command, err)
	}

	// The policy engine enforces the deny-list and the approval-list. With no
	// rules it allows everything (milestone-1/2 passthrough), and it runs whether
	// or not auditing is on: enforcement does not depend on the log.
	eng := policy.New(cfg.Deny, cfg.Approve)

	// The client-facing stream is written by two goroutines: the server->client
	// pump, and the deny path (which injects an error response for a blocked
	// call) running on the client->server goroutine. syncWriter serializes them
	// so their line writes never interleave (Constitution Art. 3.2; the -race
	// build in CI proves there is no data race).
	clientOut := &syncWriter{w: out}

	// Correlation state pairs a tools/call request with its response for the
	// audit entry; it is only needed when a log is present.
	var p *pending
	if log != nil {
		p = newPending()
	}

	// Direction 1 (client -> server): inspect BEFORE forwarding. A denied call
	// must be blocked before the server can see it; a call awaiting approval is
	// held here until the human answers; an allowed call is recorded as pending
	// before the server can answer, so the response side never races ahead of the
	// request side. The handler returns false to block forwarding. It is installed
	// only when there is something to inspect for (deny/approval rules or
	// auditing); otherwise this stays a raw byte passthrough (milestone 1).
	var handleReq func([]byte) bool
	if len(cfg.Deny) > 0 || len(cfg.Approve) > 0 || log != nil {
		handleReq = func(line []byte) bool {
			return handleRequest(line, eng, p, appr, log, clientOut)
		}
	}

	// Direction 2 (server -> client): forward FIRST, then inspect. Auditing is an
	// observer and must never delay delivery to the client. Installed only when
	// auditing.
	var handleResp func([]byte) bool
	if log != nil {
		handleResp = func(line []byte) bool {
			p.recordResponse(line, log)
			return true
		}
	}

	// Direction 1 runs in the background: a blocking read on the client must not
	// hold up the server's output. On a normal shutdown the client closes its
	// input, which unblocks this goroutine; closing the server's stdin then lets
	// it see EOF and shut down.
	go func() {
		_ = pump(in, serverIn, handleReq, true)
		_ = serverIn.Close()
	}()

	// Direction 2 is the one we wait on: the server closing its stdout signals
	// the session is over.
	if err := pump(serverOut, clientOut, handleResp, false); err != nil {
		return fmt.Errorf("forwarding server output: %w", err)
	}

	// All output has been read, so it is now safe to reap the process. Wait
	// closes the stdout pipe, so it must come after the copy above.
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("server exited with error: %w", err)
	}
	return nil
}

// pump reads newline-delimited messages from src and forwards each one verbatim
// to dst, giving an optional handler a chance to inspect (and, on the request
// direction, veto) each message. The bytes written to dst are always the exact
// bytes read, so inspection can never alter the wire.
//
// When inspectFirst is true (the request direction), handle is called before
// forwarding and its return value decides whether to forward: false means the
// message was handled (e.g. blocked by policy, with a substitute response
// already sent to the client) and must NOT be forwarded. When inspectFirst is
// false (the response direction), the message is forwarded first and handle is
// called afterwards purely to observe; its return value is ignored. A nil handle
// means "always forward" (raw passthrough).
//
// It reads with bufio.Reader.ReadBytes rather than bufio.Scanner because a tool
// result can be much larger than Scanner's 64KB token limit; ReadBytes grows as
// needed. A final chunk without a trailing newline (EOF mid-line) is still
// forwarded. pump returns nil at EOF (a normal session end) or the first read or
// write error.
func pump(src io.Reader, dst io.Writer, handle func([]byte) bool, inspectFirst bool) error {
	r := bufio.NewReader(src)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			if inspectFirst {
				forward := true
				if handle != nil {
					forward = handle(line)
				}
				if forward {
					if _, werr := dst.Write(line); werr != nil {
						return werr
					}
				}
			} else {
				if _, werr := dst.Write(line); werr != nil {
					return werr
				}
				if handle != nil {
					handle(line)
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// handleRequest inspects one client->server message and returns whether pump
// should forward it to the real server.
//
// It acts on the policy verdict for a tools/call:
//   - Deny: not forwarded; a JSON-RPC error goes back to the client and (when
//     auditing) the attempt is recorded with decision=deny.
//   - RequireApproval: the call is paused for a human (see handleApproval);
//     approval forwards it, rejection or timeout blocks it like a deny.
//   - Allow: forwarded verbatim, and remembered (when auditing) so its response
//     can complete the audit entry on the other direction.
//
// Every other message — another method, or anything that is not JSON we
// understand — is forwarded verbatim and not audited.
//
// A write or audit failure on a block path is reported to stderr and swallowed:
// the call is still blocked (fail-closed, Constitution Art. 2.1) and the proxy
// stays up rather than taking the agent down over a logging problem.
func handleRequest(line []byte, eng *policy.Engine, p *pending, appr Approver, log *audit.Logger, client io.Writer) (forward bool) {
	var msg struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		} `json:"params"`
	}
	if err := json.Unmarshal(line, &msg); err != nil {
		return true // not JSON we can read; forward verbatim, do not audit
	}
	// Only a correlated tools/call is in scope. A tools/call always carries an id
	// because it expects a response; without one there is nothing to correlate
	// and nothing to answer.
	if msg.Method != "tools/call" || len(msg.ID) == 0 {
		return true
	}

	tool, args := msg.Params.Name, msg.Params.Arguments
	switch eng.Decide(tool) {
	case policy.Deny:
		return blockCall(client, log, msg.ID, args, tool, audit.DecisionDeny, denyMessage(tool))
	case policy.RequireApproval:
		return handleApproval(client, p, appr, log, msg.ID, tool, args)
	default: // policy.Allow
		// Remember it so recordResponse can complete the entry when the server
		// answers. Only needed when auditing.
		if p != nil {
			p.remember(msg.ID, tool, args, audit.DecisionAllow)
		}
		return true
	}
}

// handleApproval pauses a tools/call for a human decision and acts on the result.
// Approved: the call is remembered with decision=approved (so its response
// completes the audit entry on the other direction) and forwarded. Rejected or
// timed out: the client gets a JSON-RPC error, the attempt is audited from the
// request side, and the call is not forwarded. A nil approver cannot reach a
// definitive approval, so it fails closed to a denial (Art. 2.1).
func handleApproval(client io.Writer, p *pending, appr Approver, log *audit.Logger, id json.RawMessage, tool string, args json.RawMessage) (forward bool) {
	if appr == nil {
		return blockCall(client, log, id, args, tool, audit.DecisionDeny, noApproverMessage(tool))
	}
	switch appr.Request(tool, args) {
	case approval.Approved:
		if p != nil {
			p.remember(id, tool, args, audit.DecisionApproved)
		}
		return true
	case approval.Rejected:
		return blockCall(client, log, id, args, tool, audit.DecisionRejected, rejectMessage(tool))
	default: // approval.TimedOut, and any unknown value: fail closed
		return blockCall(client, log, id, args, tool, audit.DecisionTimeout, timeoutMessage(tool, appr.URL()))
	}
}

// blockCall handles a tools/call that will not be forwarded: it sends a JSON-RPC
// error to the client, records the attempt from the request side with the given
// decision (there is no server response to wait for), and returns false so pump
// does not forward it. Deny, human rejection, and approval timeout all funnel
// through here. Write and audit failures are reported to stderr and swallowed:
// the call stays blocked (fail-closed, Art. 2.1) and the proxy stays up.
func blockCall(client io.Writer, log *audit.Logger, id, args json.RawMessage, tool, decision, message string) (forward bool) {
	if err := writePolicyError(client, id, message); err != nil {
		fmt.Fprintf(os.Stderr, "ganimedes: writing policy error failed: %v\n", err)
	}
	if log != nil {
		if _, err := log.Append(tool, args, nil, policyErrorObject(message), decision); err != nil {
			fmt.Fprintf(os.Stderr, "ganimedes: audit append failed: %v\n", err)
		}
	}
	return false // blocked: the real server never sees this call
}

// policyCode is the JSON-RPC error code returned for any policy block (deny,
// human rejection, or approval timeout). JSON-RPC 2.0 reserves -32000..-32099 for
// implementation-defined server errors, which a policy block is.
const policyCode = -32000

// denyMessage, rejectMessage, and timeoutMessage are the reasons shown to the
// agent for a blocked call. Each names Ganimedes and the tool so the cause is
// unambiguous, and distinguishes why the call did not go through.
func denyMessage(tool string) string {
	return fmt.Sprintf("blocked by Ganimedes policy: tool %q is on the deny-list", tool)
}

func rejectMessage(tool string) string {
	return fmt.Sprintf("blocked by Ganimedes: a human rejected the call to tool %q", tool)
}

// timeoutMessage names the page the call was waiting on, because a timeout is
// the one outcome nobody chose: a deny was configured and a rejection was
// clicked, but a timeout means the human never saw the request. Telling them
// where it was waiting is what turns the next attempt into a decision instead of
// a repeat. An empty url (an Approver that was never started) falls back to the
// bare reason rather than pointing at nothing.
//
// "It was waiting for a human at" is deliberate, and replaced an earlier
// "nobody answered at" that a real client read exactly wrong: an agent shown
// that wording concluded the approval service was probably not running and
// offered to start it, when the page was up and serving and the only thing
// missing was a person. The sentence has to say both that the page existed and
// that the decision is the reader's to make.
func timeoutMessage(tool, url string) string {
	if url == "" {
		return fmt.Sprintf("blocked by Ganimedes: approval for tool %q timed out", tool)
	}
	return fmt.Sprintf("blocked by Ganimedes: approval for tool %q timed out; it was waiting for a human at %s", tool, url)
}

// noApproverMessage is the fail-closed reason when a tool requires approval but
// no approver is configured. In production this path is unreachable (the CLI only
// omits the approver when the approval-list is empty), so it is a defensive
// guarantee (Art. 2.1) rather than a routine outcome.
func noApproverMessage(tool string) string {
	return fmt.Sprintf("blocked by Ganimedes: tool %q requires approval but no approver is configured", tool)
}

// rpcErrorBody is the "error" member of a JSON-RPC error response.
type rpcErrorBody struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// policyErrorObject returns the JSON-RPC error member recorded in the audit log
// for a blocked call, so the log shows exactly what the client was told.
func policyErrorObject(message string) json.RawMessage {
	b, err := json.Marshal(rpcErrorBody{Code: policyCode, Message: message})
	if err != nil {
		// rpcErrorBody holds only a string and an int, so Marshal cannot fail;
		// this keeps the audit record valid JSON even in the impossible case.
		return json.RawMessage(`{"code":-32000,"message":"blocked by Ganimedes policy"}`)
	}
	return b
}

// writePolicyError writes a complete JSON-RPC error response for a blocked call
// to the client. Marshaling (rather than string formatting) guarantees valid
// JSON and correct escaping of the message. The id is echoed verbatim so the
// client can correlate the error with its request.
func writePolicyError(client io.Writer, id json.RawMessage, message string) error {
	resp := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   rpcErrorBody    `json:"error"`
	}{
		JSONRPC: "2.0",
		ID:      id,
		Error:   rpcErrorBody{Code: policyCode, Message: message},
	}
	b, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("encoding policy error response: %w", err)
	}
	b = append(b, '\n')
	if _, err := client.Write(b); err != nil {
		return fmt.Errorf("writing policy error response: %w", err)
	}
	return nil
}

// syncWriter serializes writes to an io.Writer shared by more than one goroutine.
// In the proxy the client-facing stream is written by the server->client pump
// and, for a blocked call, by the deny path on the client->server goroutine;
// guarding it keeps their line writes from interleaving. Every write in the proxy
// is a single full line, so serialized writes are also atomic per message.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// pendingCall is a tools/call seen on the request side, waiting for its
// response to arrive on the other direction so the pair can be logged together.
// decision records how the call was cleared to reach the server (allow by
// default, or approved by a human) so recordResponse logs the right verdict.
type pendingCall struct {
	tool     string
	args     json.RawMessage
	decision string
}

// pending correlates tools/call requests with their responses by JSON-RPC id.
// The request side (remember) and the response side (recordResponse) run on
// different goroutines, so access is guarded by a mutex.
type pending struct {
	mu    sync.Mutex
	calls map[string]pendingCall
}

func newPending() *pending {
	return &pending{calls: make(map[string]pendingCall)}
}

// remember stores a cleared tools/call keyed by its id so the matching response
// can complete it on the other direction. decision is the verdict that cleared it
// (allow or approved), carried through to the audit entry.
func (p *pending) remember(id json.RawMessage, tool string, args json.RawMessage, decision string) {
	p.mu.Lock()
	p.calls[idKey(id)] = pendingCall{tool: tool, args: args, decision: decision}
	p.mu.Unlock()
}

// recordResponse inspects one server->client message. If its id matches a
// pending tools/call, the pair is appended to the log and the pending entry is
// cleared. A JSON-RPC response carries either a result or an error, never both.
//
// An audit write failure is reported to stderr and swallowed: the proxy's job is
// to forward the agent's traffic, and a full disk or a permissions problem on
// the log must not take the agent down. Losing an audit record is the lesser
// harm and is made visible on stderr.
func (p *pending) recordResponse(line []byte, log *audit.Logger) {
	var msg struct {
		ID     json.RawMessage `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(line, &msg); err != nil {
		return
	}
	if len(msg.ID) == 0 {
		return // a notification or something without an id: not a response we track
	}

	key := idKey(msg.ID)
	p.mu.Lock()
	call, ok := p.calls[key]
	if ok {
		delete(p.calls, key)
	}
	p.mu.Unlock()
	if !ok {
		return // a response to something that was not a tracked tools/call
	}

	// A response reaching here was for a call the proxy forwarded: either allowed
	// by default or approved by a human (blocked calls are never forwarded, so the
	// server never answers them). call.decision carries which one it was.
	if _, err := log.Append(call.tool, call.args, msg.Result, msg.Error, call.decision); err != nil {
		fmt.Fprintf(os.Stderr, "ganimedes: audit append failed: %v\n", err)
	}
}

// idKey turns a JSON-RPC id (a number or a string) into a map key. The raw JSON
// bytes are used directly so a numeric id and a string id that look alike (1 vs
// "1") stay distinct; surrounding whitespace is trimmed so the request and
// response forms of the same id compare equal.
func idKey(id json.RawMessage) string {
	return string(bytes.TrimSpace(id))
}
