package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
	l, err := Open(path, "sess-1")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

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

	res, err := Verify(path)
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
	l, _ := Open(path, "sess-1")
	appendCall(t, l, "read_file", `{"path":"a.txt"}`, `{"bytes":10}`)
	appendCall(t, l, "delete_all", `{"scope":"prod"}`, `{"ok":true}`)
	l.Close()

	// Rewrite history: pretend the dangerous call targeted "test" instead of
	// "prod", leaving the stored hash untouched.
	tamper(t, path, `"scope":"prod"`, `"scope":"test"`)

	res, err := Verify(path)
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

// TestVerify_DetectsDeletion confirms that removing an earlier entry breaks the
// chain at the entry that used to follow it.
func TestVerify_DetectsDeletion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := Open(path, "sess-1")
	appendCall(t, l, "one", `{}`, `{}`)
	appendCall(t, l, "two", `{}`, `{}`)
	appendCall(t, l, "three", `{}`, `{}`)
	l.Close()

	// Delete the middle entry (the one that called "two").
	lines := readLines(t, path)
	kept := append(lines[:1:1], lines[2:]...)
	writeLines(t, path, kept)

	res, err := Verify(path)
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

// TestResumeChain confirms that reopening an existing log continues its chain
// (seq keeps counting, prev_hash keeps linking) instead of starting over.
func TestResumeChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")

	l1, _ := Open(path, "sess-1")
	appendCall(t, l1, "one", `{}`, `{}`)
	last := appendCall(t, l1, "two", `{}`, `{}`)
	l1.Close()

	l2, err := Open(path, "sess-2") // a second run, same file
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	resumed := appendCall(t, l2, "three", `{}`, `{}`)
	l2.Close()

	if resumed.Seq != 3 {
		t.Errorf("resumed seq = %d, want 3", resumed.Seq)
	}
	if resumed.PrevHash != last.Hash {
		t.Errorf("resumed prev_hash = %q, want %q (continue the chain)", resumed.PrevHash, last.Hash)
	}

	res, err := Verify(path)
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
	l, _ := Open(path, "sess-1")

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

	if res, _ := Verify(path); !res.OK || res.Entries != 1 {
		t.Fatalf("Verify = %+v, want OK with 1 entry", res)
	}
}

// TestAppend_NilArgsBecomeNull confirms a call with no arguments stores valid
// JSON (null) rather than producing an invalid empty value.
func TestAppend_NilArgsBecomeNull(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := Open(path, "sess-1")
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
	if res, _ := Verify(path); !res.OK {
		t.Error("Verify not OK for a null-args entry")
	}
}

// TestVerify_MissingFile: verifying a log that does not exist is an error, not a
// silent OK ("there is nothing here to verify").
func TestVerify_MissingFile(t *testing.T) {
	if _, err := Verify(filepath.Join(t.TempDir(), "nope.jsonl")); err == nil {
		t.Fatal("Verify on a missing file returned nil error, want an error")
	}
}

// TestVerify_EmptyFile: an existing but empty log verifies as OK with 0 entries.
func TestVerify_EmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	res, err := Verify(path)
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
