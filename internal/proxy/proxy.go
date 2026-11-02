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
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/Jegoba90/Ganimedes-Project/internal/approval"
	"github.com/Jegoba90/Ganimedes-Project/internal/audit"
	"github.com/Jegoba90/Ganimedes-Project/internal/config"
	"github.com/Jegoba90/Ganimedes-Project/internal/jsoncheck"
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
// completed allowed/approved calls and blocked attempts are appended to the log;
// append failures are reported on stderr. If log is nil, no audit is written.
// With empty lists and a nil log, Run is a bounded byte passthrough (milestone 1
// behavior). Either way the forwarded wire bytes are verbatim.
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
	return run(cfg, in, out, log, appr, shutdownGrace)
}

func run(cfg config.Config, in io.Reader, out io.Writer, log *audit.Logger, appr Approver, grace time.Duration) error {
	cmd := exec.Command(cfg.Command, cfg.Args...)
	cmd.Stderr = os.Stderr // out-of-band: surface the real server's logs

	serverIn, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("wiring server stdin: %w", err)
	}
	// Own the stdout pipe ourselves. StdoutPipe lets Wait close its reader before
	// unread data has drained, while an in-process pipe would hide stdout EOF
	// until the process exited. A supplied *os.File has neither problem: Wait
	// does not own its reader, and the read side sees the actual child's EOF.
	serverOut, serverOutput, err := os.Pipe()
	if err != nil {
		_ = serverIn.Close() // no child was started and no protocol data exists
		return fmt.Errorf("wiring server stdout: %w", err)
	}
	cmd.Stdout = serverOutput

	if err := cmd.Start(); err != nil {
		_ = serverIn.Close()  // no child owns these descriptors after Start failed
		_ = serverOut.Close() // no protocol data exists after Start failed
		_ = serverOutput.Close()
		return fmt.Errorf("starting server %q: %w", cfg.Command, err)
	}
	defer func() {
		// Cleanup is best-effort after the session's result has been chosen; an
		// already closed pipe or reaped process cannot change that result.
		_ = serverIn.Close()
		_ = serverOut.Close()
		_ = serverOutput.Close()
		_ = cmd.Process.Kill()
	}()
	if err := serverOutput.Close(); err != nil {
		_ = cmd.Process.Kill() // cleanup must reap the child even before pumps start
		_ = cmd.Wait()         // the descriptor error is the primary failure
		return fmt.Errorf("closing parent copy of server stdout: %w", err)
	}
	waited := make(chan error, 1)
	outputDone := make(chan struct{})
	drainTimedOut := make(chan struct{})
	go func() {
		err := cmd.Wait()
		waited <- err
		// A descendant can inherit stdout after the direct child exits. Give
		// buffered output a bounded chance to drain, then release the reader;
		// killing only the already exited child cannot close that descriptor.
		timer := time.NewTimer(grace)
		defer timer.Stop()
		select {
		case <-outputDone:
		case <-timer.C:
			close(drainTimedOut)
			_ = serverOut.Close() // interrupt a read held open by inherited stdout
		}
	}()

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
	defer clientOut.close()

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

	// Input failure terminates the session instead of silently discarding the
	// error. EOF gives the server a short grace period to drain its output and
	// exit; a server that ignores EOF must not keep a disconnected session alive.
	inputDone := make(chan struct{})
	inputFailure := make(chan error, 1)
	go func() {
		defer close(inputDone)
		defer func() { _ = serverIn.Close() }() // EOF is the normal shutdown signal
		if err := pump(in, serverIn, handleReq, true); err != nil {
			select {
			case <-outputDone:
				return // closing session input can itself interrupt a blocked read
			default:
				inputFailure <- err
				_ = cmd.Process.Kill() // unblock output after input failed
			}
		}
	}()
	go func() {
		select {
		case <-outputDone:
			return
		case <-inputDone:
		}
		timer := time.NewTimer(grace)
		defer timer.Stop()
		select {
		case <-outputDone:
		case <-timer.C:
			_ = cmd.Process.Kill() // an uncooperative child must not outlive EOF
		}
	}()

	// Direction 2 is the one we wait on: the server closing its stdout signals
	// the session is over.
	outputErr := pump(serverOut, clientOut, handleResp, false)
	close(outputDone)
	if outputErr != nil {
		_ = cmd.Process.Kill() // reap even when writing to the client failed
	}
	// A closable input can be released when the server exits. An arbitrary
	// io.Reader cannot be interrupted; callers supplying one own that lifecycle.
	if closer, ok := in.(io.Closer); ok {
		_ = closer.Close() // session input is no longer needed after server EOF
	}
	// Closing stdout also ends a session when the child remains alive. Waiting
	// on the process without a deadline here would turn that EOF into a hang.
	var waitErr error
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case waitErr = <-waited:
	case <-timer.C:
		_ = cmd.Process.Kill() // stdout ended but the child did not shut down
		waitErr = <-waited
	}
	if outputErr != nil {
		select {
		case <-drainTimedOut:
			return fmt.Errorf("server exited while its output stayed open: %w", exec.ErrWaitDelay)
		default:
		}
		return fmt.Errorf("forwarding server output: %w", outputErr)
	}
	select {
	case err := <-inputFailure:
		return fmt.Errorf("forwarding client input: %w", err)
	default:
	}
	if waitErr != nil {
		return fmt.Errorf("server exited with error: %w", waitErr)
	}
	return nil
}

const (
	maxMessageBytes = 16 << 20
	shutdownGrace   = 5 * time.Second
)

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
// ReadSlice permits messages larger than Scanner's 64KB default while enforcing
// a 16 MiB ceiling before any part of an oversized message is forwarded. A final
// chunk without a trailing newline (EOF mid-line) is still forwarded. pump
// returns nil at EOF or the first framing, read or write error.
func pump(src io.Reader, dst io.Writer, handle func([]byte) bool, inspectFirst bool) error {
	r := bufio.NewReader(src)
	for {
		line, err := readMessage(r)
		if len(line) > 0 {
			if inspectFirst {
				forward := true
				if handle != nil {
					forward = handle(line)
				}
				if forward {
					if werr := writeMessage(dst, line); werr != nil {
						return werr
					}
				}
			} else {
				if werr := writeMessage(dst, line); werr != nil {
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

// readMessage accumulates bounded fragments rather than allocating until an
// attacker eventually sends a newline. An oversized message is never forwarded
// partially; the session is terminated because continuing mid-frame is unsafe.
func readMessage(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		fragment, err := r.ReadSlice('\n')
		if len(fragment) > maxMessageBytes-len(line) {
			return nil, fmt.Errorf("message exceeds %d-byte limit", maxMessageBytes)
		}
		line = append(line, fragment...)
		if err != bufio.ErrBufferFull {
			return line, err
		}
	}
}

func writeMessage(dst io.Writer, line []byte) error {
	n, err := dst.Write(line)
	if err != nil {
		return err
	}
	if n != len(line) {
		return io.ErrShortWrite
	}
	return nil
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
//     can complete the audit entry on the other direction — unless this id is
//     already waiting on another in-flight call, in which case it is refused
//     like a deny instead of overwriting that call's pending entry (see
//     pending.remember and idReuseMessage).
//
// Valid messages for other methods are forwarded verbatim. Invalid JSON,
// ambiguous field spellings, malformed envelopes and batches are refused rather
// than handed to a server whose parser might interpret them as a tools/call.
// These checks are installed only when policy or auditing is active; the mode
// with neither remains a bounded byte passthrough. See inspectRequest and
// blockBatch for why ambiguity must not become permission.
//
// A write or audit failure on a block path is reported to stderr and swallowed:
// the call is still blocked (fail-closed, Constitution Art. 2.1) and the proxy
// stays up rather than taking the agent down over a logging problem.
func handleRequest(line []byte, eng *policy.Engine, p *pending, appr Approver, log *audit.Logger, client io.Writer) (forward bool) {
	return inspectRequest(line, eng, p, appr, log, client)
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
		// A human said yes, but that does not settle whether this id can be
		// trusted for correlation: if it collided with another in-flight call
		// while the human was deciding, forwarding now would still produce an
		// unaudited or misattributed entry. The approval stands on its own
		// merits and does not override that (Art. 2.1: fails closed wherever
		// there is still a live choice to make).
		if p != nil {
			if err := p.remember(id, tool, args, audit.DecisionApproved); err != nil {
				return blockCall(client, log, id, args, tool, audit.DecisionDeny, pendingMessage(tool, err))
			}
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

// isJSONArray distinguishes a JSON-RPC batch from other invalid request shapes.
// Checking the first byte matters because decoding JSON null into a Go slice
// also succeeds, although null is not an array and has no batch elements.
func isJSONArray(line []byte) bool {
	var probe []json.RawMessage
	trimmed := bytes.TrimSpace(line)
	return len(trimmed) > 0 && trimmed[0] == '[' && json.Unmarshal(line, &probe) == nil
}

// blockBatch refuses an entire JSON-RPC batch request outright. v0's policy
// engine and audit log both work one tools/call at a time (Decide, Append), so
// there is no way to inspect a batch's elements individually; forwarding one
// verbatim, the previous behavior, meant anything it carried reached the real
// server with no policy check and no audit record at all, regardless of what
// deny or approval rules were configured. That is a hole in the two pillars
// this project is sold on, not a missing feature, so it is closed the same way
// any other ambiguous call is (Art. 2.1: fails closed): the whole batch is
// blocked rather than silently allowed, or silently split and re-encoded
// (new, untested surface this proxy does not otherwise have, for a wire form
// the MCP spec itself removed in 2025-06-18). Every id found in the batch gets
// its own JSON-RPC error so a spec-compliant client can still correlate the
// refusal, and the raw batch is captured verbatim in the audit entry (when
// auditing) so a reviewer can see exactly what was attempted.
func blockBatch(client io.Writer, log *audit.Logger, line []byte) (forward bool) {
	if err := writeBatchRefusal(client, batchIDs(line)); err != nil {
		fmt.Fprintf(os.Stderr, "ganimedes: writing batch refusal failed: %v\n", err)
	}
	if log != nil {
		args := json.RawMessage(line)
		if jsoncheck.Validate(line) != nil {
			args = rawRequest(line)
		}
		if _, err := log.Append(batchTool, args, nil, policyErrorObject(batchMessage), audit.DecisionDeny); err != nil {
			fmt.Fprintf(os.Stderr, "ganimedes: audit append failed: %v\n", err)
		}
	}
	return false // blocked: the real server never sees any part of this batch
}

// batchTool is the synthetic tool name a refused batch is recorded under: not
// a real tool, but the audit format requires one (checkShape rejects a tool
// call entry without it), and this name reads unambiguously as what it is.
const batchTool = "(batch)"

// batchMessage is the reason given for refusing a JSON-RPC batch, both to the
// client and in the audit log.
const batchMessage = "blocked by Ganimedes: JSON-RPC batch requests are not supported; send each tools/call as its own message"

// batchIDs extracts the id of every element in a JSON-RPC batch that has one.
// A batch may mix requests (which expect a response) with notifications
// (which do not, and carry no id); only the former get an error back, which is
// what a spec-compliant client already expects for any batch response. Elements
// that are not themselves valid JSON, or that carry no id, are skipped rather
// than aborting the whole extraction: a best-effort list of the ids that can be
// answered is more useful than none at all.
func batchIDs(line []byte) []json.RawMessage {
	var elems []json.RawMessage
	if err := json.Unmarshal(line, &elems); err != nil {
		return nil
	}
	ids := make([]json.RawMessage, 0, len(elems))
	for _, e := range elems {
		var msg map[string]json.RawMessage
		if jsoncheck.Validate(e) == nil && json.Unmarshal(e, &msg) == nil && validID(msg["id"]) && !hasFieldAlias(msg, "id") {
			ids = append(ids, msg["id"])
		}
	}
	return ids
}

// writeBatchRefusal writes the response to a refused batch: one JSON-RPC error
// object per id in ids, sent back as a single JSON array, mirroring the shape
// of the batch that was refused so a client correlates each error the way it
// would any other batch response. If no id could be recovered at all (a batch
// that was not, itself, parseable element by element), a single ordinary error
// with a null id is sent instead, so the client still receives an answer.
func writeBatchRefusal(client io.Writer, ids []json.RawMessage) error {
	if len(ids) == 0 {
		return writePolicyError(client, json.RawMessage("null"), batchMessage)
	}
	resp := make([]rpcErrorResponse, len(ids))
	for i, id := range ids {
		resp[i] = rpcErrorResponse{JSONRPC: "2.0", ID: id, Error: rpcErrorBody{Code: policyCode, Message: batchMessage}}
	}
	b, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("encoding batch refusal: %w", err)
	}
	b = append(b, '\n')
	if err := writeMessage(client, b); err != nil {
		return fmt.Errorf("writing batch refusal: %w", err)
	}
	return nil
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

// idReuseMessage is the fail-closed reason when a tools/call's JSON-RPC id is
// already waiting on a response for another in-flight call. Two overlapping
// calls sharing one id cannot both be correlated to their own response — the
// wire gives no way to tell which response belongs to which — so accepting
// the second would silently overwrite the first's pending entry (see
// pending.remember): whichever response arrives first would be logged under
// the wrong tool, and the other call would complete with no audit record at
// all. A well-behaved MCP client never reuses an id before it is answered;
// this is refused rather than resolved by guessing.
func idReuseMessage(tool string) string {
	return fmt.Sprintf("blocked by Ganimedes: tool %q reused a request id that is still waiting on a response; JSON-RPC ids must stay unique until answered", tool)
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

// rpcErrorResponse is a complete JSON-RPC error response: what the client gets
// back for one blocked call. writeBatchRefusal reuses the same shape to answer
// a batch, one of these per id, sent back as an array.
type rpcErrorResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   rpcErrorBody    `json:"error"`
}

// writePolicyError writes a complete JSON-RPC error response for a blocked call
// to the client. Marshaling (rather than string formatting) guarantees valid
// JSON and correct escaping of the message. The id is echoed verbatim so the
// client can correlate the error with its request.
func writePolicyError(client io.Writer, id json.RawMessage, message string) error {
	resp := rpcErrorResponse{JSONRPC: "2.0", ID: id, Error: rpcErrorBody{Code: policyCode, Message: message}}
	b, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("encoding policy error response: %w", err)
	}
	b = append(b, '\n')
	if err := writeMessage(client, b); err != nil {
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
	mu     sync.Mutex
	w      io.Writer
	closed bool
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, io.ErrClosedPipe
	}
	return s.w.Write(p)
}

func (s *syncWriter) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
}

// pendingCall reserves a client request id until its response arrives. An empty
// tool marks a non-tool request: it reserves its id but produces no audit entry.
// For tools/call, decision records how it was cleared (allow or human approval)
// so recordResponse logs the right verdict with the corresponding result.
type pendingCall struct {
	tool     string
	args     json.RawMessage
	decision string
	size     int
}

// pending correlates client requests with their responses by JSON-RPC id.
// The request side (remember) and the response side (recordResponse) run on
// different goroutines, so access is guarded by a mutex.
type pending struct {
	mu    sync.Mutex
	calls map[string]pendingCall
	bytes int
}

// These bounds keep an unanswered server from retaining an unlimited history
// of call arguments. Releasing entries by age would permit late responses to be
// attributed to a newer call, so capacity exhaustion refuses new work instead.
const (
	maxPendingCalls = 1024
	maxPendingBytes = 64 << 20
)

var (
	errPendingIDReuse = errors.New("request id already in flight")
	errPendingFull    = errors.New("pending audit capacity exhausted")
)

func pendingMessage(tool string, err error) string {
	if errors.Is(err, errPendingIDReuse) {
		return idReuseMessage(tool)
	}
	return fmt.Sprintf("blocked by Ganimedes: pending audit capacity exhausted for tool %q (maximum %d requests or %d bytes); wait for outstanding responses", tool, maxPendingCalls, maxPendingBytes)
}

func newPending() *pending {
	return &pending{calls: make(map[string]pendingCall)}
}

// remember reserves a client request's id so the matching response can complete
// it on the other direction. For tools/call, decision is the verdict that cleared
// it (allow or approved), carried through to the audit entry.
//
// It returns an error, and stores nothing, if id already has an entry: that means
// another call sharing the same JSON-RPC id is still in flight, waiting on its
// own response, and a second entry under the same key would silently overwrite
// the first rather than queue behind it — there is no way to tell, from the
// wire alone, which of two responses to the same id belongs to which request,
// so the caller must refuse the second call rather than guess. Once the first
// call's response arrives (recordResponse deletes the entry), the id is free
// again and an unrelated later call may reuse it without issue: only
// overlapping use is ambiguous.
//
// The cost of that, stated rather than hidden: an entry is only ever cleared
// by its response, so a call the server never answers holds its id for the
// rest of the session, and a later call reusing that id is refused too. No
// expiry is used because a TTL short enough to release a stuck id is also
// short enough to release one whose response is merely slow, which would put
// the misattribution this guards against back on the table. Clients that keep
// ids unique avoid reuse collisions, but unanswered calls still consume the
// bounded pending capacity until the session ends.
func (p *pending) remember(id json.RawMessage, tool string, args json.RawMessage, decision string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := idKey(id)
	if _, inFlight := p.calls[key]; inFlight {
		return errPendingIDReuse
	}
	size := len(key) + len(tool) + len(args)
	if len(p.calls) >= maxPendingCalls || size > maxPendingBytes-p.bytes {
		return errPendingFull
	}
	p.calls[key] = pendingCall{tool: tool, args: args, decision: decision, size: size}
	p.bytes += size
	return nil
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
	var msg map[string]json.RawMessage
	if jsoncheck.Validate(line) != nil || json.Unmarshal(line, &msg) != nil {
		return
	}
	if !isResponse(msg) || !validID(msg["id"]) {
		return // server requests and ambiguous messages cannot finish a client call
	}

	key := idKey(msg["id"])
	p.mu.Lock()
	call, ok := p.calls[key]
	if ok {
		delete(p.calls, key)
		p.bytes -= call.size
	}
	p.mu.Unlock()
	if !ok || call.tool == "" {
		return // a response to something that was not a tracked tools/call
	}

	// A response reaching here was for a call the proxy forwarded: either allowed
	// by default or approved by a human (blocked calls are never forwarded, so the
	// server never answers them). call.decision carries which one it was.
	if _, err := log.Append(call.tool, call.args, msg["result"], msg["error"], call.decision); err != nil {
		fmt.Fprintf(os.Stderr, "ganimedes: audit append failed: %v\n", err)
	}
}
