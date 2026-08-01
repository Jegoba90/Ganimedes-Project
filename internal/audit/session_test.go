package audit

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// signLine seals p with priv exactly as the Logger does and returns the JSONL
// line. It lets a test put a deliberately malformed but genuinely signed entry
// in front of Verify, which is the only way to reach the shape check: the hash
// and signature checks run first and would reject anything hand-edited.
func signLine(t *testing.T, p payload, priv ed25519.PrivateKey) []byte {
	t.Helper()
	c, err := p.canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	e := Entry{
		payload: p,
		Hash:    digest(c),
		Sig:     base64.StdEncoding.EncodeToString(ed25519.Sign(priv, c)),
	}
	line, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return append(line, '\n')
}

// TestAppendSessionHeader_RecordsTheConditionsAndVerifies: the header states the
// conditions of the session, sits at the head of the same chain as the calls, and
// the first call links to it. That link is what stops a friendlier set of rules
// from being swapped in afterwards without breaking verification.
func TestAppendSessionHeader_RecordsTheConditionsAndVerifies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	priv, pub := newTestKey(t)

	l := openLog(t, path, "sess-1", priv)
	if _, err := l.AppendSessionHeader(SessionInfo{
		Version: "1.2.3",
		Command: "npx",
		Args:    []string{"-y", "server-filesystem"},
		Deny:    []string{"move_file"},
		Approve: []string{"write_file"},
	}); err != nil {
		t.Fatalf("AppendSessionHeader: %v", err)
	}
	appendCall(t, l, "read_file", `{"path":"a.txt"}`, `{"ok":true}`)
	l.Close()

	lines := readLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2", len(lines))
	}

	var head Entry
	if err := json.Unmarshal(lines[0], &head); err != nil {
		t.Fatalf("decode header: %v", err)
	}
	if head.Kind != KindSession {
		t.Errorf("kind = %q, want %q", head.Kind, KindSession)
	}
	if head.Info == nil {
		t.Fatal("header carries no session_info, so it states nothing")
	}
	if head.Info.Version != "1.2.3" || head.Info.Command != "npx" {
		t.Errorf("session_info = %+v", *head.Info)
	}
	if head.Tool != "" || head.Decision != "" {
		t.Errorf("header carries call fields: tool=%q decision=%q", head.Tool, head.Decision)
	}
	if head.Seq != 1 || head.PrevHash != genesisHash {
		t.Errorf("header seq/prev_hash = %d/%q, want 1/genesis", head.Seq, head.PrevHash)
	}

	var call Entry
	if err := json.Unmarshal(lines[1], &call); err != nil {
		t.Fatalf("decode call: %v", err)
	}
	if call.PrevHash != head.Hash {
		t.Errorf("call.prev_hash = %s, want the header's hash %s", short(call.PrevHash), short(head.Hash))
	}

	res, err := Verify(path, pub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("Verify: entry %d, %s", res.BadEntry, res.Reason)
	}
}

// TestAppendSessionHeader_EmptyPolicyIsVisible: a run with no rules must say so
// out loud. If the empty lists were omitted, "nothing was denied" and "no policy
// was ever loaded" would look identical in the file, which is the ambiguity the
// header exists to remove.
func TestAppendSessionHeader_EmptyPolicyIsVisible(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	priv, _ := newTestKey(t)

	l := openLog(t, path, "sess-1", priv)
	if _, err := l.AppendSessionHeader(SessionInfo{Version: "1.2.3", Command: "srv"}); err != nil {
		t.Fatalf("AppendSessionHeader: %v", err)
	}
	l.Close()

	line := string(readLines(t, path)[0])
	for _, want := range []string{`"deny":[]`, `"approve":[]`, `"args":[]`} {
		if !strings.Contains(line, want) {
			t.Errorf("header is missing %s: %s", want, line)
		}
	}
}

// TestVerify_RejectsEntriesItCannotJudge: every entry below is correctly hashed
// and correctly signed, so nothing here is tampering. They are records this
// build cannot classify, and a verifier that cannot say what an entry claims to
// be must not vouch for it.
func TestVerify_RejectsEntriesItCannotJudge(t *testing.T) {
	priv, pub := newTestKey(t)
	info := &SessionInfo{Version: "1", Command: "srv", Args: []string{}, Deny: []string{}, Approve: []string{}}
	noArgs := json.RawMessage("null")

	cases := []struct {
		name string
		p    payload
		want string
	}{
		{"unknown kind", payload{Kind: "future", Tool: "read_file", Args: noArgs, Decision: DecisionAllow}, "unknown entry kind"},
		{"header without session_info", payload{Kind: KindSession}, "without session_info"},
		{"header carrying a call", payload{Kind: KindSession, Info: info, Tool: "read_file", Decision: DecisionAllow}, "carrying tool-call fields"},
		{"call without a tool name", payload{Args: noArgs, Decision: DecisionAllow}, "without a tool name"},
		{"call without a decision", payload{Tool: "read_file", Args: noArgs}, "without a decision"},
		{"call carrying session_info", payload{Tool: "read_file", Args: noArgs, Decision: DecisionAllow, Info: info}, "carrying session_info"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			p := tc.p
			p.Seq, p.Session, p.Time, p.PrevHash = 1, "sess-1", "2026-07-31T12:00:00Z", genesisHash

			if err := os.WriteFile(path, signLine(t, p, priv), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			res, err := Verify(path, pub)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if res.OK {
				t.Fatal("Verify accepted an entry it cannot judge")
			}
			if !strings.Contains(res.Reason, tc.want) {
				t.Errorf("reason = %q, want it to mention %q", res.Reason, tc.want)
			}
		})
	}
}

// legacyEntry is a record in the shape written before session headers existed:
// no kind, no session_info. Its keys are already in RFC 8785 order and it holds
// no whitespace, so these bytes are exactly what was hashed and signed, and the
// test builds the line without borrowing this package's canonicalization.
const legacyEntry = `{"args":{"path":"a.txt"},"decision":"allow","prev_hash":"","seq":1,"session":"legacy01","tool":"read_file","ts":"2026-07-31T12:00:00Z"}`

// TestVerify_AcceptsALogWrittenBeforeSessionHeaders freezes the old format.
// Adding a field that is written even when empty, or dropping an omitempty,
// changes how such a record re-serializes, its recomputed hash stops matching,
// and every log anyone already holds becomes unverifiable. This test fails first.
func TestVerify_AcceptsALogWrittenBeforeSessionHeaders(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("seeded key did not yield an ed25519 public key")
	}

	sum := sha256.Sum256([]byte(legacyEntry))
	line := legacyEntry[:len(legacyEntry)-1] +
		`,"hash":"` + hex.EncodeToString(sum[:]) +
		`","sig":"` + base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(legacyEntry))) + "\"}\n"

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	res, err := Verify(path, pub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("a log written before session headers no longer verifies: entry %d, %s", res.BadEntry, res.Reason)
	}
}
