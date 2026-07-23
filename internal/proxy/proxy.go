// Package proxy is the core of Ganimedes: a stdio proxy that sits between an
// MCP client and the real MCP server, forwarding JSON-RPC messages in both
// directions.
//
// Milestone 1 was a pure byte passthrough. Milestone 2 adds the audit log:
// the proxy now reads the stream as newline-delimited JSON so it can recognize
// `tools/call` requests and their responses, correlate them by JSON-RPC id, and
// append each completed call to the hash-chained log. The bytes written to the
// other side are always the exact bytes read, never a re-encoded copy, so
// inspecting a message can never change it on the wire (see docs/ARCHITECTURE.md).
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

	"github.com/Jegoba90/Ganimedes-Project/internal/audit"
	"github.com/Jegoba90/Ganimedes-Project/internal/config"
)

// Run wraps the MCP server described by cfg and proxies a single client session
// to it. Client bytes are read from in and forwarded to the server's stdin; the
// server's stdout is forwarded back to out. The real server's stderr is passed
// through to Ganimedes' own stderr so its logs stay visible.
//
// If log is non-nil, every `tools/call` and its result are appended to it; if
// log is nil, Run is a transparent passthrough (milestone 1 behavior). Either
// way the wire bytes are forwarded verbatim.
//
// in and out are plain io.Reader/io.Writer (not hardcoded to os.Stdin/Stdout)
// so the proxy can be driven by in-memory streams in tests.
//
// Run blocks until the server closes its output (typically because it exited),
// then reaps the process. It returns the first error encountered, or nil on a
// clean shutdown.
func Run(cfg config.Config, in io.Reader, out io.Writer, log *audit.Logger) error {
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

	// Auditing is wired only when a log is provided. inspectReq records a
	// pending call; inspectResp matches its response and appends the entry.
	// Both close over one pending map, shared across the two directions.
	var inspectReq, inspectResp func([]byte)
	if log != nil {
		p := newPending()
		inspectReq = func(line []byte) { p.recordRequest(line) }
		inspectResp = func(line []byte) { p.recordResponse(line, log) }
	}

	// Direction 1 (client -> server): forward everything the client sends, then
	// close the server's stdin so it sees EOF and can shut down. It runs in the
	// background because a blocking read on the client must not hold up the
	// server's output; on a normal shutdown the client closes its input, which
	// unblocks this goroutine.
	//
	// Requests are inspected BEFORE they are forwarded (inspectFirst = true):
	// the pending call must be recorded before the server can possibly see the
	// request and answer it, otherwise the response could arrive on the other
	// goroutine before we know to expect it.
	go func() {
		_ = pump(in, serverIn, inspectReq, true)
		_ = serverIn.Close()
	}()

	// Direction 2 (server -> client): the direction we wait on, since the server
	// closing its stdout is what signals the session is over. Responses are
	// forwarded FIRST and inspected after (inspectFirst = false): auditing is an
	// observer and must never delay delivery to the client.
	if err := pump(serverOut, out, inspectResp, false); err != nil {
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
// to dst. When inspect is non-nil it is also handed the message bytes: before
// forwarding if inspectFirst is true, after forwarding otherwise. The bytes
// written to dst are always the exact bytes read, so inspection can never alter
// the wire. pump returns nil at EOF (a normal session end) or the first read or
// write error.
//
// It reads with bufio.Reader.ReadBytes rather than bufio.Scanner because a tool
// result can be much larger than Scanner's 64KB token limit; ReadBytes grows as
// needed. A final chunk without a trailing newline (EOF mid-line) is still
// forwarded.
func pump(src io.Reader, dst io.Writer, inspect func([]byte), inspectFirst bool) error {
	r := bufio.NewReader(src)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			if inspect != nil && inspectFirst {
				inspect(line)
			}
			if _, werr := dst.Write(line); werr != nil {
				return werr
			}
			if inspect != nil && !inspectFirst {
				inspect(line)
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

// pendingCall is a tools/call seen on the request side, waiting for its
// response to arrive on the other direction so the pair can be logged together.
type pendingCall struct {
	tool string
	args json.RawMessage
}

// pending correlates tools/call requests with their responses by JSON-RPC id.
// The request side (recordRequest) and the response side (recordResponse) run
// on different goroutines, so access is guarded by a mutex.
type pending struct {
	mu    sync.Mutex
	calls map[string]pendingCall
}

func newPending() *pending {
	return &pending{calls: make(map[string]pendingCall)}
}

// recordRequest inspects one client->server message. If it is a `tools/call`
// with an id, it remembers the call keyed by that id so the matching response
// can complete it. Any other message (or anything that is not JSON we
// understand) is ignored: this is best-effort observation, never a gate.
func (p *pending) recordRequest(line []byte) {
	var msg struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		} `json:"params"`
	}
	if err := json.Unmarshal(line, &msg); err != nil {
		return // not a JSON object we can read; forwarded verbatim, not audited
	}
	// Only tools/call is in scope (see docs/SEQUENCES.md). A tools/call always
	// carries an id because it expects a response; a missing id means there is
	// nothing to correlate.
	if msg.Method != "tools/call" || len(msg.ID) == 0 {
		return
	}

	key := idKey(msg.ID)
	p.mu.Lock()
	p.calls[key] = pendingCall{tool: msg.Params.Name, args: msg.Params.Arguments}
	p.mu.Unlock()
}

// recordResponse inspects one server->client message. If its id matches a
// pending tools/call, the pair is appended to the log and the pending entry is
// cleared. A JSON-RPC response carries either a result or an error, never both.
//
// An audit write failure is reported to stderr and swallowed: the proxy's job
// is to forward the agent's traffic, and a full disk or a permissions problem
// on the log must not take the agent down. Losing an audit record is the lesser
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

	// Milestone 2 has no policy engine, so every observed call was allowed
	// through by default.
	if _, err := log.Append(call.tool, call.args, msg.Result, msg.Error, audit.DecisionAllow); err != nil {
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
