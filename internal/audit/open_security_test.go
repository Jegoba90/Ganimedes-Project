package audit

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Independent Loggers used to read the same head and append separate seq=1
// records. O_APPEND prevents overwriting bytes, but does not serialize a chain.
func TestOpenRejectsConcurrentWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	priv, pub := newTestKey(t)
	first := openLog(t, path, "first", priv)
	second, err := Open(filepath.Join(filepath.Dir(path), ".", filepath.Base(path)), "second", priv)
	if err == nil {
		closeLog(t, second)
		t.Fatal("second writer opened the same log")
	}
	appendCall(t, first, "read_file", `null`, `{"ok":true}`)
	closeLog(t, first)
	second = openLog(t, path, "second", priv)
	appendCall(t, second, "read_file", `null`, `{"ok":true}`)
	closeLog(t, second)
	res, err := Verify(path, pub)
	if err != nil || !res.OK || res.Entries != 2 {
		t.Fatalf("resumed log: %+v, %v", res, err)
	}
}

// A hard link is a second name for the same file. A lock keyed by pathname let
// a writer through each name; the kernel lock belongs to the file itself.
func TestOpenRejectsWriterThroughHardLink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	alias := filepath.Join(dir, "alias.jsonl")
	priv, _ := newTestKey(t)
	first := openLog(t, path, "first", priv)
	if err := os.Link(path, alias); err != nil {
		t.Skipf("hard links unavailable here: %v", err)
	}
	second, err := Open(alias, "second", priv)
	if err == nil {
		closeLog(t, second)
		t.Fatal("second writer opened the log through a hard link")
	}
	closeLog(t, first)
}

// Windows byte-range locks are mandatory, so a lock over the log's content
// would make `ganimedes verify` fail on a log in use. Verify must keep working
// while the writer holds its lock.
func TestVerifyWhileWriterHoldsLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	priv, pub := newTestKey(t)
	l := openLog(t, path, "session", priv)
	appendCall(t, l, "read_file", `null`, `{"ok":true}`)
	res, err := Verify(path, pub)
	if err != nil || !res.OK || res.Entries != 1 {
		t.Fatalf("verify of a log in use: %+v, %v", res, err)
	}
	appendCall(t, l, "read_file", `null`, `{"ok":true}`)
	closeLog(t, l)
}

// MCP clients routinely kill the servers they launch, and a killed process runs
// no deferred cleanup. The lock must die with its holder: an earlier sidecar
// lock survived the kill and refused every later start until it was deleted by
// hand. The holder is this test binary re-executed, so the kill is a real one.
func TestOpenAfterWriterIsKilled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	priv, pub := newTestKey(t)

	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperHoldLog$")
	cmd.Env = append(os.Environ(),
		"GANIMEDES_HOLD_LOG="+path,
		"GANIMEDES_HOLD_KEY="+hex.EncodeToString(priv.Seed()))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting holder: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = stdin.Close()
	})
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "locked\n" {
		t.Fatalf("holder did not report its lock: %q, %v", line, err)
	}

	if l, err := Open(path, "intruder", priv); err == nil {
		closeLog(t, l)
		t.Fatal("a second process opened a log another process holds")
	}

	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("killing holder: %v", err)
	}
	_ = cmd.Wait() // a killed process reports its signal as an error

	l := openLog(t, path, "after-kill", priv)
	appendCall(t, l, "read_file", `null`, `{"ok":true}`)
	closeLog(t, l)
	res, err := Verify(path, pub)
	if err != nil || !res.OK || res.Entries != 2 {
		t.Fatalf("chain after the holder was killed: %+v, %v", res, err)
	}
}

// TestHelperHoldLog is the process TestOpenAfterWriterIsKilled kills. It opens
// the log, appends one entry, announces the lock and waits on stdin, which the
// parent never closes before the kill.
func TestHelperHoldLog(t *testing.T) {
	path := os.Getenv("GANIMEDES_HOLD_LOG")
	if path == "" {
		return
	}
	seed, err := hex.DecodeString(os.Getenv("GANIMEDES_HOLD_KEY"))
	if err != nil {
		t.Fatalf("decoding key: %v", err)
	}
	l, err := Open(path, "holder", ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	appendCall(t, l, "read_file", `null`, `{"ok":true}`)
	if _, err := os.Stdout.WriteString("locked\n"); err != nil {
		t.Fatalf("announcing lock: %v", err)
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
}

// A crash fragment, tampered entry, or missing line delimiter must be repaired
// offline rather than silently becoming the base of a newly signed history.
func TestOpenRejectsDamagedHistory(t *testing.T) {
	for _, name := range []string{"partial JSON", "missing LF", "modified content", "wrong key"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			priv, _ := newTestKey(t)
			l := openLog(t, path, "original", priv)
			appendCall(t, l, "read_file", `null`, `{"ok":true}`)
			closeLog(t, l)
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			modified := string(original)
			switch name {
			case "partial JSON":
				modified += "{\"seq\":\n"
			case "missing LF":
				modified = strings.TrimSuffix(modified, "\n")
			case "modified content":
				modified = strings.Replace(modified, "read_file", "changed", 1)
			case "wrong key":
				priv, _ = newTestKey(t)
			}
			if err := os.WriteFile(path, []byte(modified), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			reopened, err := Open(path, "next", priv)
			if err == nil {
				closeLog(t, reopened)
				t.Fatal("damaged history was accepted for appending")
			}
			if err := lockReleased(path); err != nil {
				t.Fatalf("failed Open kept its writer lock: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != modified {
				t.Fatalf("failed Open changed history: %v", err)
			}
		})
	}
}

// Open must refuse rather than continue unlocked when it cannot open the path.
func TestOpenRefusesUnusablePaths(t *testing.T) {
	dir := t.TempDir()
	priv, _ := newTestKey(t)
	for name, path := range map[string]string{
		"directory":      dir,
		"missing parent": filepath.Join(dir, "missing", "audit.jsonl"),
	} {
		t.Run(name, func(t *testing.T) {
			if l, err := Open(path, "session", priv); err == nil {
				closeLog(t, l)
				t.Fatal("Open succeeded")
			}
		})
	}
}

// A handle that cannot be locked must report an error. Returning nil would let
// Open append without exclusivity, which is the failure the lock exists to stop.
func TestLockFileRefusesUnusableHandles(t *testing.T) {
	if err := lockFile(nil); err == nil {
		t.Error("nil handle reported as locked")
	}
	f, err := os.Create(filepath.Join(t.TempDir(), "closed.jsonl"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := lockFile(f); err == nil {
		t.Error("closed handle reported as locked")
	}
}

// lockReleased reports whether a fresh handle can take the writer lock, which
// is the only way to observe a kernel lock left behind.
func lockReleased(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	return errors.Join(lockFile(f), f.Close())
}

func TestAppendRejectsUnsupportedRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	priv, _ := newTestKey(t)
	l := openLog(t, path, "session", priv)
	for _, p := range []payload{
		{Tool: "", Decision: DecisionAllow},
		{Tool: "read_file"},
		{Tool: "read_file", Decision: "unknown"},
		{Tool: "read_file", Decision: DecisionAllow, Result: json.RawMessage(`null`), Error: json.RawMessage(`null`)},
		{Kind: "unknown", Tool: "read_file", Decision: DecisionAllow},
	} {
		if _, err := l.appendPayload(p); err == nil {
			t.Fatal("Logger wrote an entry its verifier cannot judge")
		}
	}
	for _, args := range []string{`{"name":1,"name":2}`, `{"name":"\ud800"}`} {
		if _, err := l.Append("read_file", json.RawMessage(args), nil, nil, DecisionAllow); err == nil {
			t.Fatal("Logger sealed ambiguous arguments")
		}
	}
	e := appendCall(t, l, "read_file", `null`, `{"ok":true}`)
	if e.Seq != 1 {
		t.Fatalf("failed appends advanced sequence to %d", e.Seq)
	}
	closeLog(t, l)
	if _, err := l.Append("read_file", nil, nil, nil, DecisionAllow); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("append after Close = %v, want os.ErrClosed", err)
	}
	closeLog(t, l)
}

func TestVerifyRejectsSignedUnsupportedFields(t *testing.T) {
	priv, pub := newTestKey(t)
	raw := strings.TrimSuffix(legacyEntry, "}") + `,"future":"unknown"}`
	c, err := canonicalizeJSON([]byte(raw))
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	line := strings.TrimSuffix(raw, "}") + `,"hash":"` + digest(c) +
		`","sig":"` + base64.StdEncoding.EncodeToString(ed25519.Sign(priv, c)) + "\"}\n"
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	res, err := Verify(path, pub)
	if err != nil || res.OK || !strings.Contains(res.Reason, "unsupported") {
		t.Fatalf("signed unknown schema: %+v, %v", res, err)
	}
}
