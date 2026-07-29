package approval

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// idPattern scrapes the pending id out of the rendered page's hidden form field.
var idPattern = regexp.MustCompile(`name="id" value="(\d+)"`)

// waitForPendingID polls the index page (via httptest, no socket) until a pending
// call shows up and returns its id, failing the test if none appears in time.
func waitForPendingID(t *testing.T, s *Server) uint64 {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rec := httptest.NewRecorder()
		s.handleIndex(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if m := idPattern.FindStringSubmatch(rec.Body.String()); m != nil {
			id, err := strconv.ParseUint(m[1], 10, 64)
			if err != nil {
				t.Fatalf("scraped bad id %q: %v", m[1], err)
			}
			return id
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no pending call appeared in time")
	return 0
}

// postDecision drives handleDecision with a form POST, returning the recorder.
func postDecision(t *testing.T, s *Server, id, action string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"id": {id}, "action": {action}}
	req := httptest.NewRequest(http.MethodPost, "/decision", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.handleDecision(rec, req)
	return rec
}

// indexBody renders the index page and returns its HTML.
func indexBody(t *testing.T, s *Server) string {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleIndex(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	return rec.Body.String()
}

func TestOutcomeString(t *testing.T) {
	cases := map[Outcome]string{
		Approved:    "approved",
		Rejected:    "rejected",
		TimedOut:    "timeout",
		Outcome(99): "timeout", // any unknown value reads as the fail-closed word
	}
	for o, want := range cases {
		if got := o.String(); got != want {
			t.Errorf("Outcome(%d).String() = %q, want %q", o, got, want)
		}
	}
}

// TestNew_Validation covers the loopback guard (Art. 2.2) and the timeout guard:
// only a loopback host with a positive timeout builds a Server.
func TestNew_Validation(t *testing.T) {
	ok := []string{"127.0.0.1:8765", "localhost:0", "[::1]:0", "127.0.0.1:0"}
	for _, addr := range ok {
		if _, err := New(addr, time.Second); err != nil {
			t.Errorf("New(%q) errored, want ok: %v", addr, err)
		}
	}

	bad := []string{"0.0.0.0:8765", ":8765", "8.8.8.8:80", "noport", ""}
	for _, addr := range bad {
		if _, err := New(addr, time.Second); err == nil {
			t.Errorf("New(%q) succeeded, want an error", addr)
		}
	}

	for _, d := range []time.Duration{0, -time.Second} {
		if _, err := New("127.0.0.1:0", d); err == nil {
			t.Errorf("New with timeout %s succeeded, want an error", d)
		}
	}
}

func TestPrettyJSON(t *testing.T) {
	if got := prettyJSON(nil); got != "(no arguments)" {
		t.Errorf("prettyJSON(nil) = %q, want the placeholder", got)
	}
	if got := prettyJSON(json.RawMessage(`{"a":1}`)); !strings.Contains(got, "\"a\": 1") {
		t.Errorf("prettyJSON of valid JSON = %q, want it indented", got)
	}
	if got := prettyJSON(json.RawMessage(`not json`)); got != "not json" {
		t.Errorf("prettyJSON of invalid JSON = %q, want it verbatim", got)
	}
}

// TestRequest_Approved runs the full loop: a blocked Request, the call shown on
// the page, an approve POST, and Request returning Approved. Afterwards the page
// is empty again.
func TestRequest_Approved(t *testing.T) {
	s, err := New("127.0.0.1:0", 2*time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	outcome := make(chan Outcome, 1)
	go func() { outcome <- s.Request("email.send", json.RawMessage(`{"to":"a@b.c"}`)) }()

	id := waitForPendingID(t, s)
	if body := indexBody(t, s); !strings.Contains(body, "email.send") {
		t.Errorf("page should show the held tool, got: %s", body)
	}

	rec := postDecision(t, s, strconv.FormatUint(id, 10), "approve")
	if rec.Code != http.StatusSeeOther {
		t.Errorf("decision status = %d, want 303", rec.Code)
	}
	if got := <-outcome; got != Approved {
		t.Errorf("Request outcome = %v, want Approved", got)
	}
	if body := indexBody(t, s); !strings.Contains(body, "No calls") {
		t.Errorf("page should be empty after approval, got: %s", body)
	}
}

// TestRequest_Rejected is the same loop with a reject decision.
func TestRequest_Rejected(t *testing.T) {
	s, err := New("127.0.0.1:0", 2*time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	outcome := make(chan Outcome, 1)
	go func() { outcome <- s.Request("payment.execute", json.RawMessage(`{"amount":100}`)) }()

	id := waitForPendingID(t, s)
	if rec := postDecision(t, s, strconv.FormatUint(id, 10), "reject"); rec.Code != http.StatusSeeOther {
		t.Errorf("decision status = %d, want 303", rec.Code)
	}
	if got := <-outcome; got != Rejected {
		t.Errorf("Request outcome = %v, want Rejected", got)
	}
}

// TestRequest_TimedOut checks the fail-closed path: with a short timeout and no
// human decision, Request returns TimedOut and the pending is removed.
func TestRequest_TimedOut(t *testing.T) {
	s, err := New("127.0.0.1:0", 30*time.Millisecond)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := s.Request("slow.tool", nil); got != TimedOut {
		t.Errorf("Request outcome = %v, want TimedOut", got)
	}
	if body := indexBody(t, s); !strings.Contains(body, "No calls") {
		t.Errorf("timed-out pending should be gone, got: %s", body)
	}
}

// TestHandleIndex covers the empty page and the not-found path.
func TestHandleIndex(t *testing.T) {
	s, err := New("127.0.0.1:0", time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if body := indexBody(t, s); !strings.Contains(body, "No calls are waiting") {
		t.Errorf("empty page = %s, want the empty message", body)
	}

	rec := httptest.NewRecorder()
	s.handleIndex(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /nope status = %d, want 404", rec.Code)
	}
}

// TestHandleDecision_Errors covers the rejected inputs and the harmless
// unknown-id case (resolve is a no-op, so a late click just redirects).
func TestHandleDecision_Errors(t *testing.T) {
	s, err := New("127.0.0.1:0", time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Wrong method.
	rec := httptest.NewRecorder()
	s.handleDecision(rec, httptest.NewRequest(http.MethodGet, "/decision", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /decision status = %d, want 405", rec.Code)
	}

	// Bad id and bad action are 400.
	if rec := postDecision(t, s, "abc", "approve"); rec.Code != http.StatusBadRequest {
		t.Errorf("bad id status = %d, want 400", rec.Code)
	}
	if rec := postDecision(t, s, "1", "maybe"); rec.Code != http.StatusBadRequest {
		t.Errorf("bad action status = %d, want 400", rec.Code)
	}

	// Unknown (but well-formed) id: resolve is a no-op, still a redirect.
	if rec := postDecision(t, s, "99999", "approve"); rec.Code != http.StatusSeeOther {
		t.Errorf("unknown-id status = %d, want 303", rec.Code)
	}
}

// TestStartServeClose exercises the real listener path: Start binds, URL serves a
// live page over HTTP, and Close shuts it down.
func TestStartServeClose(t *testing.T) {
	s, err := New("127.0.0.1:0", time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Close(ctx)
	})

	if s.URL() == "" {
		t.Fatal("URL empty after Start")
	}
	resp, err := http.Get(s.URL())
	if err != nil {
		t.Fatalf("GET %s: %v", s.URL(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), "No calls") {
		t.Errorf("empty page = %s, want the empty message", body)
	}
}

// TestStart_AddressInUse covers Start's bind-failure path by occupying the port
// first.
func TestStart_AddressInUse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	s, err := New(ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Start(); err == nil {
		_ = s.Close(context.Background())
		t.Fatal("Start on an occupied port should fail")
	}
}

// TestClose_BeforeStart: Close is safe even if Start was never reached.
func TestClose_BeforeStart(t *testing.T) {
	s, err := New("127.0.0.1:0", time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Close(context.Background()); err != nil {
		t.Errorf("Close before Start = %v, want nil", err)
	}
}
