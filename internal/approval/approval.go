// Package approval implements Ganimedes' human-in-the-loop gate: a small
// localhost web page where a person approves or rejects a tool call that policy
// flagged for review (milestone 4).
//
// It is a leaf package like policy and audit: it knows how to serve HTTP and how
// to wait for a human, but nothing about JSON-RPC or MCP framing. The proxy hands
// it the tool name and arguments already extracted from the wire and blocks on
// Request until the human decides or the wait times out. The timeout fails closed
// (it returns TimedOut, which the proxy treats as a denial), per Constitution
// Art. 2.1 and 3.4.
//
// Local-first, zero exfiltration (Art. 2.2): the server binds to a loopback
// address only; New rejects any non-loopback host. There is no authentication in
// v0, so anyone who can reach the port on this machine can approve or reject; that
// is a documented limitation (Art. 2.4), acceptable for a local developer tool.
package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Outcome is the result of an approval request.
type Outcome int

const (
	// TimedOut is the zero value on purpose: a request that is never resolved (the
	// wait expired, the server torn down) fails closed to a non-approval, which the
	// proxy treats as a denial (Constitution Art. 2.1).
	TimedOut Outcome = iota
	// Approved means a human allowed the call to proceed to the real server.
	Approved
	// Rejected means a human blocked the call.
	Rejected
)

// String renders an Outcome for logs and diagnostics. These are human-facing
// words; the audit log's own decision vocabulary lives in package audit and the
// proxy maps between the two explicitly.
func (o Outcome) String() string {
	switch o {
	case Approved:
		return "approved"
	case Rejected:
		return "rejected"
	default:
		return "timeout"
	}
}

// pending is one call waiting for a human decision. ch is buffered (cap 1) so a
// human decision delivered by resolve never blocks, even if Request has already
// stopped waiting (a timeout that fired at the same instant).
type pending struct {
	id   uint64
	tool string
	args json.RawMessage
	seen time.Time
	ch   chan Outcome
}

// Server hosts the localhost approval page and blocks callers in Request until a
// human decides or the wait times out. The zero value is not usable; build one
// with New and Start it before calling Request.
type Server struct {
	addr    string
	timeout time.Duration

	httpSrv *http.Server
	url     string

	mu       sync.Mutex
	nextID   uint64
	pendings map[uint64]*pending
}

// New builds an approval Server that will listen on addr (which must be a
// loopback address, Art. 2.2) and give each request at most timeout to be
// answered before it fails closed. It does not start listening; call Start.
func New(addr string, timeout time.Duration) (*Server, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("approval: invalid address %q: %w", addr, err)
	}
	if !isLoopback(host) {
		return nil, fmt.Errorf("approval: address %q is not loopback; the approval page must stay local (Art. 2.2)", addr)
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("approval: timeout must be positive, got %s", timeout)
	}
	return &Server{
		addr:     addr,
		timeout:  timeout,
		pendings: make(map[uint64]*pending),
	}, nil
}

// isLoopback reports whether host refers to the local machine only. An empty host
// (e.g. from ":8765", which binds every interface) is not loopback and is
// rejected, so exposing the page beyond localhost has to be a deliberate choice
// the code does not offer in v0.
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Start binds the listener and serves the approval page in a background
// goroutine. Binding happens synchronously, so an unavailable address is
// reported here rather than swallowed in the goroutine. URL is valid after Start
// returns nil.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("approval: listening on %q: %w", s.addr, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/decision", s.handleDecision)

	s.url = "http://" + ln.Addr().String() + "/"
	s.httpSrv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second, // bound the header read (gosec G112)
	}
	go func() {
		// Serve blocks until Close, which makes it return ErrServerClosed; that is
		// the normal shutdown path, so it is intentionally ignored here.
		_ = s.httpSrv.Serve(ln)
	}()
	return nil
}

// URL is the address of the approval page, valid after Start. Log it to stderr
// (never stdout, Art. 3.1) so a human knows where to review pending calls.
func (s *Server) URL() string { return s.url }

// Request registers a pending approval for a tool call and blocks until a human
// approves or rejects it on the page, or the configured timeout elapses. A
// timeout returns TimedOut, which the proxy treats as a denial (fail-closed,
// Art. 2.1). The pending entry is removed before Request returns, so the page
// only ever shows calls still waiting.
func (s *Server) Request(tool string, args json.RawMessage) Outcome {
	s.mu.Lock()
	s.nextID++
	id := s.nextID
	p := &pending{
		id:   id,
		tool: tool,
		args: args,
		seen: time.Now(),
		ch:   make(chan Outcome, 1),
	}
	s.pendings[id] = p
	s.mu.Unlock()

	timer := time.NewTimer(s.timeout)
	defer timer.Stop()

	var out Outcome
	select {
	case out = <-p.ch:
	case <-timer.C:
		out = TimedOut
	}

	// Remove the pending in all cases: a resolved one is done, a timed-out one must
	// disappear from the page. A concurrent resolve may have deleted it already;
	// deleting a missing key is a no-op.
	s.mu.Lock()
	delete(s.pendings, id)
	s.mu.Unlock()
	return out
}

// resolve delivers a decision to a waiting Request by pending id. It is a no-op
// for an unknown id (already resolved, or timed out and removed), so a stray or
// double click cannot panic or block.
func (s *Server) resolve(id uint64, out Outcome) {
	s.mu.Lock()
	p, ok := s.pendings[id]
	if ok {
		delete(s.pendings, id)
	}
	s.mu.Unlock()
	if !ok {
		return
	}
	p.ch <- out // buffered (cap 1): never blocks, even if Request already gave up
}

// Close shuts the HTTP server down gracefully, bounded by ctx. After Close the
// Server must not be reused. It is safe to call even if Start was never reached.
func (s *Server) Close(ctx context.Context) error {
	if s.httpSrv == nil {
		return nil
	}
	return s.httpSrv.Shutdown(ctx)
}

// handleIndex renders the list of pending approvals. Tool names and arguments are
// written through html/template, which auto-escapes them, so a hostile tool name
// or argument cannot inject script into the page.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	s.mu.Lock()
	items := make([]pageItem, 0, len(s.pendings))
	for _, p := range s.pendings {
		items = append(items, pageItem{
			ID:   p.id,
			Tool: p.tool,
			Args: prettyJSON(p.args),
			Age:  time.Since(p.seen).Truncate(time.Second).String(),
		})
	}
	s.mu.Unlock()
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Best-effort render: the template is static and validated at init, and the
	// model holds only strings/ints, so Execute does not fail in practice; if the
	// client disconnects mid-write there is nothing useful to do about it.
	_ = pageTemplate.Execute(w, pageData{Items: items})
}

// handleDecision resolves one pending approval from the page's form POST and
// redirects back to the list. An unknown or already-resolved id is harmless
// (resolve is a no-op), so a late click just returns to an updated page.
func (s *Server) handleDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	id, err := strconv.ParseUint(r.FormValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	var out Outcome
	switch r.FormValue("action") {
	case "approve":
		out = Approved
	case "reject":
		out = Rejected
	default:
		http.Error(w, "bad action", http.StatusBadRequest)
		return
	}
	s.resolve(id, out)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// pageData is the template model for the approval page.
type pageData struct {
	Items []pageItem
}

// pageItem is one pending call as shown on the page.
type pageItem struct {
	ID   uint64
	Tool string
	Args string
	Age  string
}

// prettyJSON indents JSON arguments for display. Empty arguments render as a
// placeholder; input that is somehow not valid JSON is shown verbatim rather than
// dropped, so the reviewer always sees what the call carried.
func prettyJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "(no arguments)"
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return string(raw)
	}
	return buf.String()
}

// pageTemplate is parsed once at init. Must panics on a malformed template, which
// would be a programming error caught immediately rather than per request.
var pageTemplate = template.Must(template.New("page").Parse(pageHTML))

// pageHTML is the approval page. It refreshes every 2 seconds (a meta refresh, no
// JavaScript) so a newly paused call appears without the reviewer reloading, and
// an approved or rejected one drops off the list on the next tick.
const pageHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="2">
<title>Ganimedes - pending approvals</title>
<style>
 body{font-family:system-ui,-apple-system,sans-serif;max-width:52rem;margin:2rem auto;padding:0 1rem;color:#1a1a1a}
 h1{font-size:1.25rem}
 .empty{color:#666}
 .call{border:1px solid #ddd;border-radius:8px;padding:1rem;margin:1rem 0}
 .tool{font-weight:600;font-size:1.05rem}
 .age{color:#888;font-size:.85rem;float:right}
 pre{background:#f6f6f6;border-radius:6px;padding:.75rem;overflow-x:auto;font-size:.85rem}
 form{display:inline}
 button{font-size:.95rem;padding:.4rem .9rem;border-radius:6px;border:1px solid #ccc;cursor:pointer;margin-right:.5rem}
 .approve{background:#e6f4ea;border-color:#9ccaa9}
 .reject{background:#fbe9e7;border-color:#e0a49c}
</style>
</head>
<body>
<h1>Ganimedes - pending approvals</h1>
{{if .Items}}
{{range .Items}}
<div class="call">
 <span class="age">waiting {{.Age}}</span>
 <div class="tool">{{.Tool}}</div>
 <pre>{{.Args}}</pre>
 <form method="post" action="/decision">
  <input type="hidden" name="id" value="{{.ID}}">
  <button class="approve" name="action" value="approve">Approve</button>
  <button class="reject" name="action" value="reject">Reject</button>
 </form>
</div>
{{end}}
{{else}}
<p class="empty">No calls are waiting for approval.</p>
{{end}}
</body>
</html>
`
