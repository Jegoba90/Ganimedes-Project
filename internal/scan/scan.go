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
	"strconv"
	"strings"
	"time"

	"github.com/Jegoba90/Ganimedes-Project/internal/config"
	"github.com/Jegoba90/Ganimedes-Project/internal/jsoncheck"
)

// scanTimeout bounds the whole handshake so a server that never answers cannot
// hang the scan (Constitution Art. 3.4). It covers process start plus the
// initialize and tools/list round trips; a local MCP server needs far less.
const scanTimeout = 15 * time.Second

// A server controls both the size and number of discovery responses. Bound the
// whole exchange as well as each line: a timeout alone still permits allocating
// an arbitrarily large line before the timer fires (Art. 3.4).
const (
	maxMessageBytes = 16 << 20
	maxScanBytes    = 64 << 20
	maxScanPages    = 1024
)

// protocolVersion is the MCP protocol version scan advertises in initialize. It
// is the widely-supported baseline; a server negotiates its own version in the
// response, and scan only needs the tools/list that follows, so an exact match
// is not required. Made configurable later if a server rejects it.
const protocolVersion = "2024-11-05"

// clientName identifies the scanner in the initialize handshake so a server's
// logs show who connected.
const clientName = "ganimedes-scan"

// clientVersion is the other half of that identity. It is a var, not a const, so
// the release workflow can stamp the real tag into it at link time, the same way
// it stamps internal/cli.version: a scanner announcing itself to a server should
// not claim to be a dev build when it is a released one (Art. 2.4).
var clientVersion = "0.0.0-dev"

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
	"write", "create", "edit", "insert", "update", "rename", "chmod", "chown",
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
	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()
	return scanWithContext(ctx, cfg)
}

func scanWithContext(ctx context.Context, cfg config.Config) (Report, error) {
	if cfg.Command == "" {
		return Report{}, errors.New("no server command to scan")
	}

	ctx, cancel := context.WithCancel(ctx)
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
	// Killing the direct child does not close a pipe inherited by a descendant.
	// Close our endpoints on expiry too, so discovery's blocked read/write cannot
	// outlive the advertised deadline. The wrapped process is still reaped below.
	stopClosing := context.AfterFunc(ctx, func() {
		_ = serverIn.Close()  // cancellation cleanup; no further request is sent
		_ = serverOut.Close() // unblock a read even if a descendant holds stdout
	})
	defer stopClosing()

	tools, derr := discover(serverIn, serverOut)

	// The tools list is all scan needs. Signal EOF to the server, then force it
	// down (cancel) and reap it: its exit status is not the scan's concern, and
	// killing a still-running helper keeps the command from lingering once the
	// answer is in hand. A kill makes Wait return an error, which is expected
	// here and deliberately ignored.
	_ = serverIn.Close() // cleanup; the process is killed and reaped regardless
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
	br := bufio.NewReader(io.LimitReader(r, maxScanBytes))

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

	// tools/list is paginated. Reporting only its first page can hide precisely
	// the destructive tool the user ran scan to find. Cursors remain opaque and
	// every page gets a fresh request id, so an old response cannot fill a new one.
	var tools []Tool
	seen := make(map[string]bool)
	cursor := ""
	for page := 0; page < maxScanPages; page++ {
		id := strconv.Itoa(page + 2)
		params := map[string]string{}
		if page > 0 {
			params["cursor"] = cursor
		}
		if err := writeRequest(w, id, "tools/list", params); err != nil {
			return nil, err
		}
		resp, err := readResponse(br, id)
		if err != nil {
			return nil, err
		}
		if len(resp.Error) > 0 {
			return nil, fmt.Errorf("server returned an error for tools/list: %s", resp.Error)
		}
		pageTools, next, err := parseToolsPage(resp.Result)
		if err != nil {
			return nil, err
		}
		tools = append(tools, pageTools...)
		if next == nil {
			return tools, nil
		}
		if seen[*next] {
			return nil, errors.New("tools/list repeated a pagination cursor")
		}
		seen[*next] = true
		cursor = *next
	}
	return nil, fmt.Errorf("tools/list exceeded %d pages", maxScanPages)
}

// Parse exact member names instead of Go's case-insensitive struct matching.
// An absent/null tool list is a protocol error, not evidence of zero tools.
func parseToolsPage(raw json.RawMessage) ([]Tool, *string, error) {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(raw, &result); err != nil || result == nil {
		return nil, nil, errors.New("tools/list result must be an object")
	}
	list := bytes.TrimSpace(result["tools"])
	if len(list) == 0 || list[0] != '[' {
		return nil, nil, errors.New("tools/list result must contain a tools array")
	}
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(list, &items); err != nil {
		return nil, nil, fmt.Errorf("parsing tools/list result: %w", err)
	}
	tools := make([]Tool, 0, len(items))
	for _, item := range items {
		var tool Tool
		if err := json.Unmarshal(item["name"], &tool.Name); err != nil || tool.Name == "" {
			return nil, nil, errors.New("tools/list contains a tool without a nonempty name")
		}
		if description, ok := item["description"]; ok {
			if bytes.Equal(bytes.TrimSpace(description), []byte("null")) {
				return nil, nil, errors.New("tool description must be a string")
			}
			if err := json.Unmarshal(description, &tool.Description); err != nil {
				return nil, nil, fmt.Errorf("parsing tool description: %w", err)
			}
		}
		tools = append(tools, tool)
	}
	var next *string
	if rawCursor, ok := result["nextCursor"]; ok {
		if err := json.Unmarshal(rawCursor, &next); err != nil || next == nil {
			return nil, nil, errors.New("tools/list nextCursor must be a string")
		}
	}
	return tools, next, nil
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
	if n, err := w.Write(b); err != nil {
		return fmt.Errorf("sending %s: %w", m.Method, err)
	} else if n != len(b) {
		return fmt.Errorf("sending %s: %w", m.Method, io.ErrShortWrite)
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
		line, err := readLine(br)
		if err != nil && err != io.EOF {
			return rpcResponse{}, fmt.Errorf("reading server response: %w", err)
		}
		if len(bytes.TrimSpace(line)) > 0 {
			var fields map[string]json.RawMessage
			if json.Unmarshal(line, &fields) == nil &&
				string(bytes.TrimSpace(fields["id"])) == wantID {
				if err := jsoncheck.Validate(line); err != nil {
					return rpcResponse{}, fmt.Errorf("invalid server response: %w", err)
				}
				var version string
				_ = json.Unmarshal(fields["jsonrpc"], &version) // wrong types fail the version check
				result, hasResult := fields["result"]
				rpcErr, hasError := fields["error"]
				if version != "2.0" || hasResult == hasError || fields["method"] != nil {
					return rpcResponse{}, errors.New("invalid JSON-RPC response envelope")
				}
				return rpcResponse{ID: fields["id"], Result: result, Error: rpcErr}, nil
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

func readLine(br *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		part, err := br.ReadSlice('\n')
		if len(line)+len(part) > maxMessageBytes {
			return nil, fmt.Errorf("server message exceeds %d bytes", maxMessageBytes)
		}
		line = append(line, part...)
		if err != bufio.ErrBufferFull {
			return line, err
		}
	}
}

// Render writes a human-readable report to w: one line per tool, flagged tools
// marked and annotated with the keywords they matched, and a closing summary
// that reminds the reader scan enforces nothing. server is the wrapped command,
// shown for context. Output goes to stdout in the CLI, as it is the command's
// product (like `verify`'s result line), not protocol traffic.
func Render(w io.Writer, r Report, server string) error {
	if _, err := fmt.Fprintf(w, "Scanned %d tool(s) via %q.\n\n", len(r.Findings), server); err != nil {
		return fmt.Errorf("writing scan report: %w", err)
	}
	if len(r.Findings) == 0 {
		_, err := fmt.Fprintln(w, "The server exposed no tools.")
		return err
	}

	width := 0
	for _, f := range r.Findings {
		if n := len(strconv.QuoteToGraphic(f.Tool.Name)); n > width {
			width = n
		}
	}

	for _, f := range r.Findings {
		// Tool metadata comes from the server. Quote controls and invisible
		// format characters so a name cannot erase or forge rows in the report.
		name := strconv.QuoteToGraphic(f.Tool.Name)
		// Flagged rows pad the name to a common width so their "matched:" columns
		// line up; unflagged rows have nothing after the name, so they are left
		// unpadded to avoid trailing whitespace.
		var err error
		if f.Flagged() {
			_, err = fmt.Fprintf(w, "  FLAG  %-*s  matched: %s\n", width, name, strings.Join(f.Keywords, ", "))
		} else {
			_, err = fmt.Fprintf(w, "    ok  %s\n", name)
		}
		if err != nil {
			return fmt.Errorf("writing scan report: %w", err)
		}
	}

	// The count invites the reader to treat the rest as cleared, which it is not.
	// Naming what the keyword list covers also names what it leaves out, and the
	// gap that matters most is reading: a tool that only pulls data out of a
	// system matches nothing here, and can still be the one that costs you.
	_, err := fmt.Fprintf(w, "\n%d of %d tool(s) flagged for review.\n"+
		"An \"ok\" means no keyword matched, not that a tool is safe. The list covers\n"+
		"destruction, execution, state change, money, network egress and secrets, so a\n"+
		"tool that only reads your data matches none of it.\n"+
		"scan reports only; nothing is blocked. Add the tools you want blocked to the \"deny\" list in your config, then run \"ganimedes run --config ...\".\n",
		r.Flagged(), len(r.Findings))
	return err
}
