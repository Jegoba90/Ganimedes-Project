package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Jegoba90/Ganimedes-Project/internal/approval"
	"github.com/Jegoba90/Ganimedes-Project/internal/audit"
	"github.com/Jegoba90/Ganimedes-Project/internal/config"
	"github.com/Jegoba90/Ganimedes-Project/internal/policy"
)

// These requests used to escape inspection because decoding into a Go struct
// either accepted a second, case-insensitive field or returned a type error.
// A server using exact field names or first-member-wins parsing can still see
// the denied call. The gateway must resolve that disagreement by refusing it.
func TestHandleRequest_RefusesAmbiguousToolCalls(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"missing id", `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"denied"}}`},
		{"null id", `{"jsonrpc":"2.0","id":null,"method":"tools/call","params":{"name":"safe"}}`},
		{"object id", `{"jsonrpc":"2.0","id":{},"method":"tools/call","params":{"name":"safe"}}`},
		{"overflowing id", `{"jsonrpc":"2.0","id":1e999,"method":"tools/call","params":{"name":"safe"}}`},
		{"method case alias", `{"jsonrpc":"2.0","id":1,"method":"tools/call","METHOD":"initialize","params":{"name":"denied"}}`},
		{"typed method alias", `{"jsonrpc":"2.0","id":1,"method":"tools/call","METHOD":3,"params":{"name":"denied"}}`},
		{"params case alias", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"denied"},"PARAMS":{"name":"safe"}}`},
		{"name case alias", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"denied","NAME":"safe"}}`},
		{"duplicate method", `{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"initialize","params":{"name":"denied"}}`},
		{"duplicate name", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"denied","name":"safe"}}`},
		{"escaped duplicate name", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"denied","\u006eame":"safe"}}`},
		{"missing name", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`},
		{"null name", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":null}}`},
		{"nonstring name", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":3}}`},
		{"nonobject params", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":[]}`},
		{"nonobject arguments", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe","arguments":[]}}`},
		{"invalid surrogate", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe\ud800"}}`},
		{"invalid utf8", "{\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"safe\xff\"}}"},
		{"not JSON", `not JSON`},
		{"null", `null`},
		{"number", `3`},
		{"string", `"tools/call"`},
		{"two values", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"denied"}} {}`},
		{"empty envelope", `{}`},
		{"missing version", `{"id":1,"method":"initialize"}`},
		{"wrong version", `{"jsonrpc":"1.0","id":1,"method":"initialize"}`},
		{"bad method", `{"jsonrpc":"2.0","id":1,"method":3}`},
		{"request with result", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe"},"result":{}}`},
		{"request with error", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe"},"error":{"code":-1,"message":"bad"}}`},
		{"scalar other params", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":3}`},
		{"invalid other id", `{"jsonrpc":"2.0","id":false,"method":"initialize"}`},
		{"null response error", `{"jsonrpc":"2.0","id":1,"error":null}`},
		{"fractional error code", `{"jsonrpc":"2.0","id":1,"error":{"code":-1.5,"message":"bad"}}`},
		{"null error code", `{"jsonrpc":"2.0","id":1,"error":{"code":null,"message":"bad"}}`},
		{"null error message", `{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":null}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			appr := &fakeApprover{outcome: approval.Approved}
			if handleRequest([]byte(tc.line), policy.New([]string{"denied"}, nil), newPending(), appr, nil, &out) {
				t.Fatal("ambiguous call would reach the real server")
			}
			var resp rpcResp
			if err := json.Unmarshal(out.Bytes(), &resp); err != nil || resp.Error == nil {
				t.Fatalf("want a valid policy refusal, got %s (error %v)", out.Bytes(), err)
			}
			if appr.calls != 0 {
				t.Fatal("ambiguous call must be refused before human approval")
			}
		})
	}
}

// Both peers can originate JSON-RPC requests. A server request using the same
// id as an outstanding client call is a separate namespace, not that call's
// response; accepting it would erase the pending record without its result.
func TestPending_OnlyResponsesCompleteCalls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	priv, pub := testKeypair(t)
	log, err := audit.Open(path, "test", priv)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := log.Close(); err != nil {
			t.Errorf("closing audit log: %v", err)
		}
	}()
	p := newPending()
	if err := p.remember(json.RawMessage(`"same"`), "original", nil, audit.DecisionAllow); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		`{"jsonrpc":"2.0","id":"same","method":"roots/list"}`,
		`{"jsonrpc":"2.0","id":"same"}`,
		`{"jsonrpc":"2.0","id":"same","result":{},"error":{}}`,
		`{"jsonrpc":"2.0","id":"same","result":{},"RESULT":{}}`,
		`{"jsonrpc":"2.0","id":"same","result":{},"result":null}`,
		`{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}`,
	} {
		p.recordResponse([]byte(line), log)
		if len(p.calls) != 1 {
			t.Fatalf("non-response consumed the pending call: %s", line)
		}
	}
	p.recordResponse([]byte(`{"jsonrpc":"2.0","id":"\u0073ame","result":{"ok":true}}`), log)
	if len(p.calls) != 0 || p.bytes != 0 {
		t.Fatal("valid response failed to release its reservation")
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := audit.Verify(path, pub)
	if err != nil || !result.OK || result.Entries != 1 {
		t.Fatalf("want exactly the real response in the signed log, got %+v (%v)", result, err)
	}
}

func TestHandleRequest_ReservesOtherRequestIDs(t *testing.T) {
	for _, firstMethod := range []string{"initialize", "tools/call"} {
		t.Run(firstMethod, func(t *testing.T) {
			p := newPending()
			var out bytes.Buffer
			first := `{"jsonrpc":"2.0","id":1,"method":"` + firstMethod + `","params":{"name":"safe"}}`
			if !handleRequest([]byte(first), nil, p, nil, nil, &out) {
				t.Fatal("first request blocked")
			}
			secondMethod := "tools/call"
			if firstMethod == "tools/call" {
				secondMethod = "initialize"
			}
			second := `{"jsonrpc":"2.0","id":1,"method":"` + secondMethod + `","params":{"name":"safe"}}`
			if handleRequest([]byte(second), nil, p, nil, nil, &out) {
				t.Fatal("request could consume another method's pending response")
			}
			if !strings.Contains(out.String(), "reused") {
				t.Fatalf("missing collision reason: %s", out.Bytes())
			}
		})
	}
	p := newPending()
	var out bytes.Buffer
	request := []byte(`{"jsonrpc":"2.0","id":2,"method":"initialize"}`)
	if !handleRequest(request, nil, p, nil, nil, &out) {
		t.Fatal("initialize blocked")
	}
	p.recordResponse([]byte(`{"jsonrpc":"2.0","id":2,"result":{}}`), nil)
	if !handleRequest(request, nil, p, nil, nil, &out) {
		t.Fatal("answered non-tool request did not release its id")
	}
}

func TestPending_BoundsRetainedCalls(t *testing.T) {
	p := newPending()
	for i := 0; i < maxPendingCalls; i++ {
		if err := p.remember(json.RawMessage(strconv.Itoa(i)), "safe", nil, audit.DecisionAllow); err != nil {
			t.Fatalf("capacity exhausted early at %d: %v", i, err)
		}
	}
	if err := p.remember(json.RawMessage(`"overflow"`), "safe", nil, audit.DecisionAllow); !errors.Is(err, errPendingFull) {
		t.Fatalf("unanswered server retained too many calls: %v", err)
	}
	var out bytes.Buffer
	if handleRequest([]byte(`{"jsonrpc":"2.0","id":"new","method":"tools/call","params":{"name":"safe"}}`), nil, p, nil, nil, &out) {
		t.Fatal("capacity failure must block before forwarding")
	}
	if !strings.Contains(out.String(), "capacity exhausted") {
		t.Fatalf("capacity refusal misdiagnosed: %s", out.Bytes())
	}
	p = newPending()
	args := json.RawMessage(`{"payload":"` + strings.Repeat("x", 1<<20) + `"}`)
	for i := 0; ; i++ {
		err := p.remember(json.RawMessage(strconv.Itoa(i)), "safe", args, audit.DecisionAllow)
		if errors.Is(err, errPendingFull) {
			break
		}
		if err != nil || i >= maxPendingBytes/(1<<20) {
			t.Fatalf("arguments retained beyond the byte bound: %v", err)
		}
	}
	if len(p.calls) >= maxPendingCalls {
		t.Fatal("byte limit must apply before the request-count limit")
	}
}

func TestHandleRequest_PreservesRefusedBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	priv, pub := testKeypair(t)
	log, err := audit.Open(path, "test", priv)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := log.Close(); err != nil {
			t.Errorf("closing audit log: %v", err)
		}
	}()
	line := []byte("{\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"denied\",\"name\":\"safe\xff\"}}\n")
	var out bytes.Buffer
	if handleRequest(line, nil, newPending(), nil, log, &out) {
		t.Fatal("ambiguous request forwarded")
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var entry struct {
		Arguments struct {
			RawBase64 string `json:"raw_base64"`
		} `json:"args"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(entry.Arguments.RawBase64)
	if err != nil || !bytes.Equal(raw, line) {
		t.Fatalf("forensic bytes changed: %q (%v)", raw, err)
	}
	result, err := audit.Verify(path, pub)
	if err != nil || !result.OK || result.Entries != 1 {
		t.Fatalf("refusal missing from signed audit: %+v (%v)", result, err)
	}
}

func TestPump_BoundsFramesWithoutPartialForwarding(t *testing.T) {
	for _, inspectFirst := range []bool{true, false} {
		var out bytes.Buffer
		input := "before\n" + strings.Repeat("x", maxMessageBytes) + "\n"
		err := pump(strings.NewReader(input), &out, nil, inspectFirst)
		if err == nil || !strings.Contains(err.Error(), "limit") {
			t.Fatalf("oversized message accepted: %v", err)
		}
		if out.String() != "before\n" {
			t.Fatalf("oversized frame partially forwarded: %d bytes", out.Len())
		}
	}
}

func TestPump_LargeCRLFAndFinalUnterminatedFrame(t *testing.T) {
	input := strings.Repeat("x", 128<<10) + "\r\nlast frame"
	for _, inspectFirst := range []bool{true, false} {
		var out bytes.Buffer
		if err := pump(strings.NewReader(input), &out, func([]byte) bool { return true }, inspectFirst); err != nil {
			t.Fatal(err)
		}
		if out.String() != input {
			t.Fatal("large frame or final bytes changed")
		}
	}
}

type shortWriter struct{}

func (shortWriter) Write(b []byte) (int, error) { return len(b) - 1, nil }

func TestPump_ReportsShortWrites(t *testing.T) {
	for _, inspectFirst := range []bool{true, false} {
		if err := pump(strings.NewReader("message\n"), shortWriter{}, nil, inspectFirst); !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("short write lost protocol bytes silently: %v", err)
		}
	}
	if err := writePolicyError(shortWriter{}, json.RawMessage(`1`), "denied"); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short policy response ignored: %v", err)
	}
	if err := writeBatchRefusal(shortWriter{}, []json.RawMessage{json.RawMessage(`1`)}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short batch response ignored: %v", err)
	}
}

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, errors.New("client read failed") }

type brokenWriter struct{ failedAt time.Time }

func (w *brokenWriter) Write([]byte) (int, error) {
	w.failedAt = time.Now()
	return 0, errors.New("client write failed")
}

func TestRun_PropagatesInputFailure(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	cfg := config.Config{Command: os.Args[0], Args: []string{"-test.run=^TestHelperProcess$"}}
	err := Run(cfg, brokenReader{}, io.Discard, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "client read failed") {
		t.Fatalf("input error silently discarded: %v", err)
	}
}

func TestRun_ReapsAfterOutputFailure(t *testing.T) {
	t.Setenv("GO_WANT_PROXY_LIFECYCLE_HELPER", "wait")
	cfg := config.Config{Command: os.Args[0], Args: []string{"-test.run=^TestHelperProxyLifecycle$"}}
	input, inputWriter := io.Pipe()
	defer func() { _ = inputWriter.Close() }() // io.Pipe cleanup has no buffered data to lose
	out := &brokenWriter{}
	err := run(cfg, input, out, nil, nil, 200*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "client write failed") {
		t.Fatalf("output error lost: %v", err)
	}
	if out.failedAt.IsZero() || time.Since(out.failedAt) > 2*time.Second {
		t.Fatal("output failure did not terminate and reap the server")
	}
}

type readyWriter struct {
	once  sync.Once
	ready chan struct{}
	at    time.Time
}

func (w *readyWriter) Write(b []byte) (int, error) {
	w.once.Do(func() { w.at = time.Now(); close(w.ready) })
	return len(b), nil
}

func TestRun_BoundsShutdownAfterClientEOF(t *testing.T) {
	t.Setenv("GO_WANT_PROXY_LIFECYCLE_HELPER", "wait")
	cfg := config.Config{Command: os.Args[0], Args: []string{"-test.run=^TestHelperProxyLifecycle$"}}
	input, inputWriter := io.Pipe()
	defer func() { _ = inputWriter.Close() }() // io.Pipe cleanup has no buffered data to lose
	out := &readyWriter{ready: make(chan struct{})}
	go func() {
		<-out.ready // begin the EOF deadline after the helper actually started
		_ = inputWriter.Close()
	}()
	err := run(cfg, input, out, nil, nil, 200*time.Millisecond)
	if err == nil {
		t.Fatal("server ignored EOF but was reported as a clean shutdown")
	}
	if out.at.IsZero() || time.Since(out.at) > 2*time.Second {
		t.Fatal("server ignored EOF beyond the shutdown deadline")
	}
}

func TestRun_BoundsInheritedServerOutput(t *testing.T) {
	t.Setenv("GO_WANT_PROXY_LIFECYCLE_HELPER", "descendant")
	cfg := config.Config{Command: os.Args[0], Args: []string{"-test.run=^TestHelperProxyLifecycle$"}}
	input, inputWriter := io.Pipe()
	defer func() { _ = inputWriter.Close() }() // io.Pipe cleanup has no buffered data to lose
	started := time.Now()
	err := run(cfg, input, io.Discard, nil, nil, 200*time.Millisecond)
	if !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("expected inherited output to hit WaitDelay, got %v", err)
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("descendant held proxy output open after the server exited")
	}
}

func TestRun_BoundsClosedServerOutput(t *testing.T) {
	t.Setenv("GO_WANT_PROXY_LIFECYCLE_HELPER", "close-output")
	cfg := config.Config{Command: os.Args[0], Args: []string{"-test.run=^TestHelperProxyLifecycle$"}}
	input, inputWriter := io.Pipe()
	defer func() { _ = inputWriter.Close() }() // no buffered data remains after Run
	out := &readyWriter{ready: make(chan struct{})}
	err := run(cfg, input, out, nil, nil, 200*time.Millisecond)
	if err == nil {
		t.Fatal("server closed stdout but remained alive beyond its shutdown grace")
	}
	if out.at.IsZero() || time.Since(out.at) > 2*time.Second {
		t.Fatal("server closing stdout did not release the proxy while client input stayed open")
	}
}

func TestHelperProxyLifecycle(t *testing.T) {
	switch os.Getenv("GO_WANT_PROXY_LIFECYCLE_HELPER") {
	case "wait":
		_, _ = os.Stdout.WriteString("server ready\n") // test process exits below
		time.Sleep(4 * time.Second)
		os.Exit(0)
	case "close-output":
		_, _ = os.Stdout.WriteString("server ready\n") // test process exits below
		_ = os.Stdout.Close()                          // deliberately end the stream before the process
		time.Sleep(4 * time.Second)
		os.Exit(0)
	case "descendant":
		cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProxyLifecycle$")
		cmd.Env = append(os.Environ(), "GO_WANT_PROXY_LIFECYCLE_HELPER=hold")
		cmd.Stdout = os.Stdout
		if err := cmd.Start(); err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	case "hold":
		time.Sleep(500 * time.Millisecond)
		os.Exit(0)
	}
}

func TestHandleRequest_PreservesOtherTraffic(t *testing.T) {
	for _, line := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"name":3}}`,
		`{"jsonrpc":"2.0","method":"notifications/progress","params":[]}`,
		`{"jsonrpc":"2.0","id":1,"result":{"name":3}}`,
		`{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}`,
	} {
		var out bytes.Buffer
		if !handleRequest([]byte(line), policy.New([]string{"denied"}, nil), nil, nil, nil, &out) {
			t.Errorf("unrelated traffic blocked: %s", line)
		}
		if out.Len() != 0 {
			t.Errorf("unexpected authored response: %s", out.Bytes())
		}
	}
}

func TestPending_RecognizesEquivalentIDs(t *testing.T) {
	for _, ids := range [][2]string{
		{`1`, `1.0`},
		{`1`, `1e0`},
		{`0`, `-0`},
		{`"same"`, `"\u0073ame"`},
	} {
		t.Run(strings.Join(ids[:], " versus "), func(t *testing.T) {
			p := newPending()
			if err := p.remember(json.RawMessage(ids[0]), "first", nil, "allow"); err != nil {
				t.Fatal("first id refused")
			}
			if err := p.remember(json.RawMessage(ids[1]), "second", nil, "allow"); err == nil {
				t.Fatal("equivalent id overwrote or duplicated an in-flight call")
			}
		})
	}
	if idKey(json.RawMessage(`1`)) == idKey(json.RawMessage(`"1"`)) {
		t.Fatal("number and string ids must stay distinct")
	}
}
