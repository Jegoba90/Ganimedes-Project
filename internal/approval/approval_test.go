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
	"strings"
	"testing"
	"time"
)

// idPattern scrapes the pending id out of the rendered page's hidden form
// field. IDs are random hex (newPendingID), not decimal, since M4.1.
var idPattern = regexp.MustCompile(`name="id" value="([0-9a-f]+)"`)

// waitForPendingID polls the index page (via httptest, no socket) until a pending
// call shows up and returns its id, failing the test if none appears in time.
func waitForPendingID(t *testing.T, s *Server) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rec := httptest.NewRecorder()
		s.handleIndex(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if m := idPattern.FindStringSubmatch(rec.Body.String()); m != nil {
			return m[1]
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no pending call appeared in time")
	return ""
}

// postDecision drives handleDecision with a form POST carrying the server's own
// CSRF token, the way a click on the real page would. Returns the recorder.
func postDecision(t *testing.T, s *Server, id, action string) *httptest.ResponseRecorder {
	t.Helper()
	return postDecisionWithToken(t, s, id, action, s.csrfToken)
}

// postDecisionWithToken is postDecision with an explicit (possibly wrong or
// missing) CSRF token, for exercising the rejection path a forged cross-site
// POST would take.
func postDecisionWithToken(t *testing.T, s *Server, id, action, token string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"id": {id}, "action": {action}, "csrf_token": {token}}
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

	rec := postDecision(t, s, id, "approve")
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
	if rec := postDecision(t, s, id, "reject"); rec.Code != http.StatusSeeOther {
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

	// Bad action is 400.
	if rec := postDecision(t, s, "deadbeef", "maybe"); rec.Code != http.StatusBadRequest {
		t.Errorf("bad action status = %d, want 400", rec.Code)
	}

	// Unknown id (never issued, or a stale one from an earlier call): ids are
	// opaque random strings, so there is no "malformed" shape to reject up
	// front; resolve is simply a no-op and the request still redirects.
	if rec := postDecision(t, s, "deadbeefdeadbeefdeadbeefdeadbeef", "approve"); rec.Code != http.StatusSeeOther {
		t.Errorf("unknown-id status = %d, want 303", rec.Code)
	}
}

// TestNew_CSRFToken checks New generates a token that looks like 32 random
// bytes (64 lowercase hex chars) and that two servers do not share one: a
// constant or predictable token would defeat the whole point of checking it.
func TestNew_CSRFToken(t *testing.T) {
	a, err := New("127.0.0.1:0", time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(a.csrfToken) != csrfTokenSize*2 {
		t.Errorf("csrfToken length = %d, want %d hex chars", len(a.csrfToken), csrfTokenSize*2)
	}
	if !regexp.MustCompile(`^[0-9a-f]+$`).MatchString(a.csrfToken) {
		t.Errorf("csrfToken = %q, want lowercase hex", a.csrfToken)
	}

	b, err := New("127.0.0.1:0", time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.csrfToken == b.csrfToken {
		t.Error("two servers got the same csrfToken, want independent random values")
	}
}

// TestRequest_PendingIDsAreRandom checks that consecutive calls get
// unpredictable ids, not the old 1, 2, 3... counter: a blind forged POST
// should not be able to guess its way to a real pending id by incrementing.
func TestRequest_PendingIDsAreRandom(t *testing.T) {
	s, err := New("127.0.0.1:0", 2*time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var ids []string
	for i := 0; i < 5; i++ {
		go func() { s.Request("tool", nil) }()
		ids = append(ids, waitForPendingID(t, s))
		// Resolve it immediately so the next Request's id is scraped cleanly
		// off an otherwise-empty page.
		postDecision(t, s, ids[len(ids)-1], "reject")
	}

	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("id %q repeated across requests, want each unique", id)
		}
		seen[id] = true
		if id == "1" || id == "2" || id == "3" || id == "4" || id == "5" {
			t.Fatalf("id %q looks like the old sequential counter, want random", id)
		}
	}
}

// TestHandleIndex_OrdersByArrival checks that, now that ids no longer sort
// into arrival order on their own, the page still lists the longest-waiting
// call first (handleIndex sorts by the pending's timestamp, not its id).
func TestHandleIndex_OrdersByArrival(t *testing.T) {
	s, err := New("127.0.0.1:0", 2*time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	go func() { s.Request("first.tool", nil) }()
	waitForPendingID(t, s)
	time.Sleep(20 * time.Millisecond) // force a clearly later timestamp
	go func() { s.Request("second.tool", nil) }()

	// Poll until both are visible; waitForPendingID would return as soon as
	// first.tool's own (already-present) id matches, without waiting for the
	// second call to actually land.
	deadline := time.Now().Add(2 * time.Second)
	var body string
	for time.Now().Before(deadline) {
		body = indexBody(t, s)
		if strings.Contains(body, "second.tool") {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	firstAt := strings.Index(body, "first.tool")
	secondAt := strings.Index(body, "second.tool")
	if firstAt == -1 || secondAt == -1 {
		t.Fatalf("expected both tools on the page, got: %s", body)
	}
	if firstAt > secondAt {
		t.Errorf("first.tool (older) should be listed before second.tool (newer), got: %s", body)
	}
}

// TestHandleIndex_CarriesCSRFToken checks the rendered form embeds the
// server's token, since that is the only channel a legitimate click has to
// prove it came from this page.
func TestHandleIndex_CarriesCSRFToken(t *testing.T) {
	s, err := New("127.0.0.1:0", 2*time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	go func() { s.Request("email.send", nil) }()
	waitForPendingID(t, s)

	body := indexBody(t, s)
	if !strings.Contains(body, `name="csrf_token" value="`+s.csrfToken+`"`) {
		t.Errorf("rendered page does not embed the server's CSRF token, got: %s", body)
	}
}

// TestHandleDecision_CSRF is the attack this defends against: a POST to
// /decision that never saw the real page (a forged cross-site request, or a
// stale token from a previous run) must be refused, and the pending call must
// stay pending, exactly as if the request had never arrived.
func TestHandleDecision_CSRF(t *testing.T) {
	s, err := New("127.0.0.1:0", 2*time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	outcome := make(chan Outcome, 1)
	go func() { outcome <- s.Request("payment.execute", json.RawMessage(`{"amount":100}`)) }()
	id := waitForPendingID(t, s)

	for _, tc := range []struct {
		name  string
		token string
	}{
		{"wrong token", "0000000000000000000000000000000000000000000000000000000000000000"},
		{"empty token", ""},
		{"truncated real token", s.csrfToken[:len(s.csrfToken)-1]},
	} {
		rec := postDecisionWithToken(t, s, id, "approve", tc.token)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: status = %d, want 403", tc.name, rec.Code)
		}
	}

	// None of the forged attempts should have resolved the call: it must still
	// be sitting on the page, unresolved, waiting for the real decision.
	select {
	case got := <-outcome:
		t.Fatalf("Request resolved to %v from a forged POST, want it still pending", got)
	default:
	}
	if body := indexBody(t, s); !strings.Contains(body, "payment.execute") {
		t.Errorf("call should still be pending after forged POSTs, got: %s", body)
	}

	// The real token still works, proving the 403s above were specifically
	// about the token and not some other breakage.
	if rec := postDecision(t, s, id, "approve"); rec.Code != http.StatusSeeOther {
		t.Errorf("decision with real token status = %d, want 303", rec.Code)
	}
	if got := <-outcome; got != Approved {
		t.Errorf("Request outcome = %v, want Approved", got)
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
