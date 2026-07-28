package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestKey generates a fresh Ed25519 keypair for a test.
func newTestKey(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return priv, pub
}

// openLog opens a signed logger for a test, failing on error.
func openLog(t *testing.T, path, session string, priv ed25519.PrivateKey) *Logger {
	t.Helper()
	l, err := Open(path, session, priv)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return l
}

// appendCall is a tiny helper: append one allowed tool call and fail the test
// if the write errors.
func appendCall(t *testing.T, l *Logger, tool, args, result string) Entry {
	t.Helper()
	e, err := l.Append(tool, json.RawMessage(args), json.RawMessage(result), nil, DecisionAllow)
	if err != nil {
		t.Fatalf("Append(%q): %v", tool, err)
	}
	return e
}

// TestAppendAndVerify writes a few entries and confirms the chain verifies and
// that each entry links to the one before it.
func TestAppendAndVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	priv, pub := newTestKey(t)
	l := openLog(t, path, "sess-1", priv)

	e1 := appendCall(t, l, "read_file", `{"path":"a.txt"}`, `{"bytes":10}`)
	e2 := appendCall(t, l, "write_file", `{"path":"b.txt"}`, `{"ok":true}`)
	e3 := appendCall(t, l, "list_dir", `{"path":"."}`, `{"n":3}`)
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Sequence numbers count from 1 and each entry links to the previous hash.
	if e1.Seq != 1 || e2.Seq != 2 || e3.Seq != 3 {
		t.Errorf("seq = %d,%d,%d, want 1,2,3", e1.Seq, e2.Seq, e3.Seq)
	}
	if e1.PrevHash != genesisHash {
		t.Errorf("first entry prev_hash = %q, want genesis", e1.PrevHash)
	}
	if e2.PrevHash != e1.Hash || e3.PrevHash != e2.Hash {
		t.Errorf("chain links broken: e2.prev=%q e1.hash=%q / e3.prev=%q e2.hash=%q",
			e2.PrevHash, e1.Hash, e3.PrevHash, e2.Hash)
	}
	// Every entry carries a signature.
	if e1.Sig == "" || e2.Sig == "" || e3.Sig == "" {
		t.Error("an entry is missing its signature")
	}

	res, err := Verify(path, pub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK || res.Entries != 3 {
		t.Fatalf("Verify = %+v, want OK with 3 entries", res)
	}
}

// TestVerify_DetectsContentEdit confirms that editing a recorded entry's fields
// (without recomputing its hash, as a tamperer would) is caught.
func TestVerify_DetectsContentEdit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	priv, pub := newTestKey(t)
	l := openLog(t, path, "sess-1", priv)
	appendCall(t, l, "read_file", `{"path":"a.txt"}`, `{"bytes":10}`)
	appendCall(t, l, "delete_all", `{"scope":"prod"}`, `{"ok":true}`)
	l.Close()

	// Rewrite history: pretend the dangerous call targeted "test" instead of
	// "prod", leaving the stored hash untouched.
	tamper(t, path, `"scope":"prod"`, `"scope":"test"`)

	res, err := Verify(path, pub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.OK {
		t.Fatal("Verify said OK, want tamper detected")
	}
	if res.BadEntry != 2 {
		t.Errorf("BadEntry = %d, want 2", res.BadEntry)
	}
	if !strings.Contains(res.Reason, "modified") {
		t.Errorf("Reason = %q, want it to mention modification", res.Reason)
	}
}

// TestVerify_DetectsForgedEntry is the signature's reason for being: an attacker
// who can write to the log but does not hold the signing key edits an entry AND
// correctly recomputes its hash (so the chain check would pass), then re-signs it
// with their own key. The hash chain alone would accept this; the signature check
// catches it.
func TestVerify_DetectsForgedEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	priv, pub := newTestKey(t)
	l := openLog(t, path, "sess-1", priv)
	appendCall(t, l, "read_file", `{"path":"a"}`, `{"ok":true}`)
	appendCall(t, l, "delete_all", `{"scope":"test"}`, `{"ok":true}`)
	l.Close()

	attackerPriv, _ := newTestKey(t)
	lines := readLines(t, path)

	var e Entry
	if err := json.Unmarshal(lines[1], &e); err != nil {
		t.Fatalf("unmarshal entry 2: %v", err)
	}
	e.Args = json.RawMessage(`{"scope":"prod"}`) // the forgery
	c, err := e.payload.canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	sum := sha256.Sum256(c)
	e.Hash = hex.EncodeToString(sum[:]) // fix the hash so the chain check passes
	e.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(attackerPriv, c))
	forged, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal forged: %v", err)
	}
	lines[1] = forged
	writeLines(t, path, lines)

	res, err := Verify(path, pub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.OK {
		t.Fatal("Verify said OK; a re-hashed forgery signed by another key must be caught")
	}
	if res.BadEntry != 2 {
		t.Errorf("BadEntry = %d, want 2", res.BadEntry)
	}
	if !strings.Contains(res.Reason, "signature") {
		t.Errorf("Reason = %q, want it to mention the signature", res.Reason)
	}
}

// TestVerify_WrongKey: a well-formed, correctly-signed log does not verify under
// a public key that does not match its signing key.
func TestVerify_WrongKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	priv, _ := newTestKey(t)
	_, wrongPub := newTestKey(t)
	l := openLog(t, path, "sess-1", priv)
	appendCall(t, l, "read_file", `{}`, `{}`)
	l.Close()

	res, err := Verify(path, wrongPub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.OK {
		t.Fatal("Verify said OK under the wrong public key")
	}
	if res.BadEntry != 1 || !strings.Contains(res.Reason, "signature") {
		t.Errorf("res = %+v, want failure at entry 1 mentioning the signature", res)
	}
}

// TestVerify_DetectsDeletion confirms that removing an earlier entry breaks the
// chain at the entry that used to follow it.
func TestVerify_DetectsDeletion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	priv, pub := newTestKey(t)
	l := openLog(t, path, "sess-1", priv)
	appendCall(t, l, "one", `{}`, `{}`)
	appendCall(t, l, "two", `{}`, `{}`)
	appendCall(t, l, "three", `{}`, `{}`)
	l.Close()

	// Delete the middle entry (the one that called "two").
	lines := readLines(t, path)
	kept := append(lines[:1:1], lines[2:]...)
	writeLines(t, path, kept)

	res, err := Verify(path, pub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.OK {
		t.Fatal("Verify said OK, want broken chain")
	}
	// Entry 1 still checks out; the break shows up at the new entry 2 (old #3),
	// whose prev_hash points at the deleted entry.
	if res.BadEntry != 2 {
		t.Errorf("BadEntry = %d, want 2", res.BadEntry)
	}
}

// TestResumeChain confirms that reopening an existing log with the same signing
// key continues its chain (seq keeps counting, prev_hash keeps linking) instead
// of starting over, and the whole thing still verifies.
func TestResumeChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	priv, pub := newTestKey(t)

	l1 := openLog(t, path, "sess-1", priv)
	appendCall(t, l1, "one", `{}`, `{}`)
	last := appendCall(t, l1, "two", `{}`, `{}`)
	l1.Close()

	l2 := openLog(t, path, "sess-2", priv) // a second run, same file and key
	resumed := appendCall(t, l2, "three", `{}`, `{}`)
	l2.Close()

	if resumed.Seq != 3 {
		t.Errorf("resumed seq = %d, want 3", resumed.Seq)
	}
	if resumed.PrevHash != last.Hash {
		t.Errorf("resumed prev_hash = %q, want %q (continue the chain)", resumed.PrevHash, last.Hash)
	}

	res, err := Verify(path, pub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK || res.Entries != 3 {
		t.Fatalf("Verify = %+v, want OK with 3 entries", res)
	}
}

// TestAppend_RecordsErrorResponses confirms a failed tool call (JSON-RPC error,
// no result) is recorded and verifies.
func TestAppend_RecordsErrorResponses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	priv, pub := newTestKey(t)
	l := openLog(t, path, "sess-1", priv)

	e, err := l.Append("risky", json.RawMessage(`{"x":1}`), nil,
		json.RawMessage(`{"code":-32000,"message":"boom"}`), DecisionAllow)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	l.Close()

	if e.Result != nil {
		t.Errorf("Result = %s, want nil for an errored call", e.Result)
	}
	if !strings.Contains(string(e.Error), "boom") {
		t.Errorf("Error = %s, want the rpc error recorded", e.Error)
	}

	if res, _ := Verify(path, pub); !res.OK || res.Entries != 1 {
		t.Fatalf("Verify = %+v, want OK with 1 entry", res)
	}
}

// TestAppend_NilArgsBecomeNull confirms a call with no arguments stores valid
// JSON (null) rather than producing an invalid empty value.
func TestAppend_NilArgsBecomeNull(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	priv, pub := newTestKey(t)
	l := openLog(t, path, "sess-1", priv)
	if _, err := l.Append("no_args", nil, json.RawMessage(`{}`), nil, DecisionAllow); err != nil {
		t.Fatalf("Append: %v", err)
	}
	l.Close()

	data := bytes.TrimSpace(readFile(t, path))
	var e struct {
		Args json.RawMessage `json:"args"`
	}
	if err := json.Unmarshal(data, &e); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(e.Args) != "null" {
		t.Errorf("args = %s, want null", e.Args)
	}
	if res, _ := Verify(path, pub); !res.OK {
		t.Error("Verify not OK for a null-args entry")
	}
}

// TestOpen_RequiresKey: a Logger never writes unsigned records, so Open rejects a
// nil signing key rather than silently producing an unsigned log.
func TestOpen_RequiresKey(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "a.jsonl"), "s", nil); err == nil {
		t.Fatal("Open with a nil key returned nil error, want rejection")
	}
}

// TestVerify_RequiresKey: Verify needs a usable public key to check signatures.
func TestVerify_RequiresKey(t *testing.T) {
	if _, err := Verify(filepath.Join(t.TempDir(), "a.jsonl"), nil); err == nil {
		t.Fatal("Verify with a nil key returned nil error, want rejection")
	}
}

// TestVerify_MissingFile: verifying a log that does not exist is an error, not a
// silent OK ("there is nothing here to verify").
func TestVerify_MissingFile(t *testing.T) {
	_, pub := newTestKey(t)
	if _, err := Verify(filepath.Join(t.TempDir(), "nope.jsonl"), pub); err == nil {
		t.Fatal("Verify on a missing file returned nil error, want an error")
	}
}

// TestVerify_EmptyFile: an existing but empty log verifies as OK with 0 entries.
func TestVerify_EmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, pub := newTestKey(t)
	res, err := Verify(path, pub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK || res.Entries != 0 {
		t.Fatalf("Verify = %+v, want OK with 0 entries", res)
	}
}

// --- small file helpers -------------------------------------------------------

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	return b
}

func readLines(t *testing.T, path string) [][]byte {
	t.Helper()
	return bytes.Split(bytes.TrimRight(readFile(t, path), "\n"), []byte("\n"))
}

func writeLines(t *testing.T, path string, lines [][]byte) {
	t.Helper()
	out := bytes.Join(lines, []byte("\n"))
	out = append(out, '\n')
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// tamper replaces the first occurrence of oldStr with newStr in the file at
// path, simulating an after-the-fact edit that leaves the stored hash stale.
func tamper(t *testing.T, path, oldStr, newStr string) {
	t.Helper()
	data := readFile(t, path)
	edited := bytes.Replace(data, []byte(oldStr), []byte(newStr), 1)
	if bytes.Equal(edited, data) {
		t.Fatalf("tamper: %q not found in log", oldStr)
	}
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}
