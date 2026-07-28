// Package scan is Ganimedes' pre-flight risk scanner. It connects to a wrapped
// MCP server, performs the initialize + tools/list handshake, and reports every
// tool the server exposes, flagging the ones whose name or description matches a
// risky keyword.
//
// scan takes no enforcement action and writes no audit log: it is a diagnostic
// helper for writing the deny-list, the same way `verify` is a diagnostic helper
// for the audit log (docs/DESIGN.md §3, §7). Writing a good deny-list requires
// knowing what a wrapped server can actually do; scan answers that question
// before any deny rule is written. The keyword match is deterministic substring
// matching with a fixed list, no scoring and no ML, which keeps this a small
// helper rather than a second product.
package scan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Jegoba90/Ganimedes-Project/internal/config"
)

// scanTimeout bounds the whole handshake so a server that never answers cannot
// hang the scan (Constitution Art. 3.4). It covers process start plus the
// initialize and tools/list round trips; a local MCP server needs far less.
const scanTimeout = 15 * time.Second

// protocolVersion is the MCP protocol version scan advertises in initialize. It
// is the widely-supported baseline; a server negotiates its own version in the
// response, and scan only needs the tools/list that follows, so an exact match
// is not required. Made configurable later if a server rejects it.
const protocolVersion = "2024-11-05"

// clientName/clientVersion identify the scanner in the initialize handshake so a
// server's logs show who connected.
const (
	clientName    = "ganimedes-scan"
	clientVersion = "0.0.0-dev"
)

// JSON-RPC ids for the two requests scan sends. Fixed values are enough: the
// exchange is strictly sequential (one request, then its response) so there is
// never more than one outstanding request to correlate.
const (
	initializeID = "1"
	toolsListID  = "2"
)

// Tool is one tool discovered from a wrapped server's tools/list response. Only
// the fields scan reasons about are decoded; a tool's inputSchema and any other
// fields are ignored.
type Tool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Finding is a discovered Tool paired with the risk keywords it matched.
type Finding struct {
	Tool Tool
	// Keywords are the risk keywords found in the tool's name or description, in
	// the order they appear in the keyword list, without duplicates. Empty when
	// nothing matched.
	Keywords []string
}

// Flagged reports whether the tool matched at least one risk keyword.
func (f Finding) Flagged() bool { return len(f.Keywords) > 0 }

// Report is the result of scanning a wrapped server: every discovered tool, in
// the order the server listed them, each with its risk keywords (if any).
type Report struct {
	Findings []Finding
}

// Flagged returns how many findings matched at least one risk keyword.
func (r Report) Flagged() int {
	n := 0
	for _, f := range r.Findings {
		if f.Flagged() {
			n++
		}
	}
	return n
}

// riskKeywords is the fixed, deterministic list of substrings that mark a tool
// as worth a closer look before it goes on (or off) the deny-list. Matching is
// case-insensitive substring matching over the tool's name and description, with
// no scoring and no ML (docs/DESIGN.md §7, "Risk scanner").
//
// The list is deliberately crude and errs toward surfacing: a false positive
// costs one glance, a false negative is a dangerous tool that slips past review.
// No entry here is a substring of another, so a single tool is never double-
// flagged for two keywords that mean the same match. Refinements (word-boundary
// matching, an editable per-project list) are deferred; see DESIGN.md.
var riskKeywords = []string{
	// Destructive data operations.
	"delete", "remove", "destroy", "drop", "truncate", "wipe", "purge",
	// Code / command execution.
	"exec", "eval", "shell", "spawn", "subprocess", "command",
	// State mutation.
	"write", "create", "insert", "update", "rename", "chmod", "chown",
	// Money movement.
	"payment", "transfer", "charge", "purchase", "refund", "invoice", "billing", "withdraw",
	// Network egress.
	"fetch", "download", "upload", "request", "webhook", "http", "curl",
	// Secret access and privilege.
	"secret", "credential", "password", "token", "apikey", "admin", "sudo", "root", "grant", "privilege",
}

// riskFlags returns the risk keywords matched by a tool's name or description,
// in keyword-list order (so the output is stable) and without duplicates (each
// keyword appears once in the list, so iterating it once cannot repeat one).
func riskFlags(t Tool) []string {
	haystack := strings.ToLower(t.Name + " " + t.Description)
	var matched []string
	for _, kw := range riskKeywords {
		if strings.Contains(haystack, kw) {
			matched = append(matched, kw)
		}
	}
	return matched
}

// Scan spawns the MCP server described by cfg, performs the initialize +
// tools/list handshake, and returns a Report of every discovered tool with its
// risk flags. cfg.Deny is ignored: scan is what you run to decide what belongs
// on the deny-list, before there is one.
//
// The server's stderr is passed through to Ganimedes' own stderr so its startup
// logs and errors stay visible while scanning. The whole exchange is bounded by
// scanTimeout; the server is reaped before Scan returns whether the handshake
// succeeded or not, so no child process is left behind.
func Scan(cfg config.Config) (Report, error) {
	if cfg.Command == "" {
		return Report{}, errors.New("no server command to scan")
	}

	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, cfg.Command, cfg.Args...)
	cmd.Stderr = os.Stderr // out-of-band: surface the real server's logs

	serverIn, err := cmd.StdinPipe()
	if err != nil {
		return Report{}, fmt.Errorf("wiring server stdin: %w", err)
	}
	serverOut, err := cmd.StdoutPipe()
	if err != nil {
		return Report{}, fmt.Errorf("wiring server stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return Report{}, fmt.Errorf("starting server %q: %w", cfg.Command, err)
	}

	tools, derr := discover(serverIn, serverOut)

	// The tools list is all scan needs. Signal EOF to the server, then force it
	// down (cancel) and reap it: its exit status is not the scan's concern, and
	// killing a still-running helper keeps the command from lingering once the
	// answer is in hand. A kill makes Wait return an error, which is expected
	// here and deliberately ignored.
	_ = serverIn.Close()
	cancel()
	_ = cmd.Wait()

	if derr != nil {
		return Report{}, derr
	}

	findings := make([]Finding, 0, len(tools))
	for _, t := range tools {
		findings = append(findings, Finding{Tool: t, Keywords: riskFlags(t)})
	}
	return Report{Findings: findings}, nil
}

// discover drives the MCP handshake over an already-started server's stdio: it
// writes initialize to w, reads the response from r, sends the initialized
// notification, requests tools/list, and returns the decoded tools. It is split
// out from Scan (which owns the process) so the protocol logic can be tested
// against an in-memory server with no subprocess.
func discover(w io.Writer, r io.Reader) ([]Tool, error) {
	br := bufio.NewReader(r)

	// 1. initialize: establish the session before asking for anything.
	if err := writeRequest(w, initializeID, "initialize", initializeParams()); err != nil {
		return nil, err
	}
	initResp, err := readResponse(br, initializeID)
	if err != nil {
		return nil, err
	}
	if len(initResp.Error) > 0 {
		return nil, fmt.Errorf("server rejected initialize: %s", initResp.Error)
	}

	// 2. initialized: some servers gate tools/list on receiving this notification.
	// It carries no id and expects no response.
	if err := writeNotification(w, "notifications/initialized"); err != nil {
		return nil, err
	}

	// 3. tools/list: the actual question scan asks.
	if err := writeRequest(w, toolsListID, "tools/list", struct{}{}); err != nil {
		return nil, err
	}
	listResp, err := readResponse(br, toolsListID)
	if err != nil {
		return nil, err
	}
	if len(listResp.Error) > 0 {
		return nil, fmt.Errorf("server returned an error for tools/list: %s", listResp.Error)
	}

	var result struct {
		Tools []Tool `json:"tools"`
	}
	if err := json.Unmarshal(listResp.Result, &result); err != nil {
		return nil, fmt.Errorf("parsing tools/list result: %w", err)
	}
	return result.Tools, nil
}

// initParams is the initialize request's params. Ganimedes advertises no
// capabilities of its own here: scan is a read-only observer that only needs the
// server's tool list.
type initParams struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ClientInfo      clientInfo     `json:"clientInfo"`
}

// clientInfo identifies the scanner to the server.
type clientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func initializeParams() initParams {
	return initParams{
		ProtocolVersion: protocolVersion,
		Capabilities:    map[string]any{},
		ClientInfo:      clientInfo{Name: clientName, Version: clientVersion},
	}
}

// rpcMessage is a JSON-RPC 2.0 request or notification scan sends to the server.
// A notification omits ID (and usually Params); omitempty drops both when unset.
type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  any             `json:"params,omitempty"`
}

// rpcResponse is a JSON-RPC 2.0 response from the server. A response carries
// either a result or an error, never both.
type rpcResponse struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

// writeRequest sends a JSON-RPC request with the given id, method, and params.
func writeRequest(w io.Writer, id, method string, params any) error {
	return writeMessage(w, rpcMessage{JSONRPC: "2.0", ID: json.RawMessage(id), Method: method, Params: params})
}

// writeNotification sends a JSON-RPC notification (no id, no response expected).
func writeNotification(w io.Writer, method string) error {
	return writeMessage(w, rpcMessage{JSONRPC: "2.0", Method: method})
}

// writeMessage marshals one message and writes it as a single newline-terminated
// line, the framing MCP's stdio transport uses.
func writeMessage(w io.Writer, m rpcMessage) error {
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("encoding %s message: %w", m.Method, err)
	}
	b = append(b, '\n')
	if _, err := w.Write(b); err != nil {
		return fmt.Errorf("sending %s: %w", m.Method, err)
	}
	return nil
}

// readResponse reads newline-delimited messages until it finds a response whose
// id matches wantID, and returns it. Lines that are not JSON, carry no id, or
// carry a different id (a notification, a log line, or an unrelated response) are
// skipped, so scan stays in sync even if the server interleaves other output.
// EOF before a match means the server closed its output without answering.
func readResponse(br *bufio.Reader, wantID string) (rpcResponse, error) {
	for {
		line, err := br.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			var resp rpcResponse
			if json.Unmarshal(line, &resp) == nil &&
				len(resp.ID) > 0 &&
				string(bytes.TrimSpace(resp.ID)) == wantID {
				return resp, nil
			}
		}
		if err != nil {
			if err == io.EOF {
				return rpcResponse{}, fmt.Errorf("server closed its output before answering request %s (crashed or timed out?)", wantID)
			}
			return rpcResponse{}, fmt.Errorf("reading server response: %w", err)
		}
	}
}

// Render writes a human-readable report to w: one line per tool, flagged tools
// marked and annotated with the keywords they matched, and a closing summary
// that reminds the reader scan enforces nothing. server is the wrapped command,
// shown for context. Output goes to stdout in the CLI, as it is the command's
// product (like `verify`'s result line), not protocol traffic.
func Render(w io.Writer, r Report, server string) {
	fmt.Fprintf(w, "Scanned %d tool(s) via %q.\n\n", len(r.Findings), server)
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "The server exposed no tools.")
		return
	}

	width := 0
	for _, f := range r.Findings {
		if n := len(f.Tool.Name); n > width {
			width = n
		}
	}

	for _, f := range r.Findings {
		// Flagged rows pad the name to a common width so their "matched:" columns
		// line up; unflagged rows have nothing after the name, so they are left
		// unpadded to avoid trailing whitespace.
		if f.Flagged() {
			fmt.Fprintf(w, "  FLAG  %-*s  matched: %s\n", width, f.Tool.Name, strings.Join(f.Keywords, ", "))
		} else {
			fmt.Fprintf(w, "    ok  %s\n", f.Tool.Name)
		}
	}

	fmt.Fprintf(w, "\n%d of %d tool(s) flagged for review.\n", r.Flagged(), len(r.Findings))
	fmt.Fprintln(w, `scan reports only; nothing is blocked. Add the tools you want blocked to the "deny" list in your config, then run "ganimedes run --config ...".`)
}
