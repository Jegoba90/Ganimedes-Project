package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/Jegoba90/Ganimedes-Project/internal/audit"
)

// quiet redirects os.Stdout/os.Stderr to the null device for the duration of a
// test, so the CLI's usage and error output does not clutter the test log. It is
// restored on cleanup. Tests here do not run in parallel, so swapping the global
// streams is safe.
func quiet(t *testing.T) {
	t.Helper()
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = devnull, devnull
	t.Cleanup(func() {
		os.Stdout, os.Stderr = oldOut, oldErr
		_ = devnull.Close()
	})
}

// TestRun_TopLevel covers the subcommand dispatch and its exit codes.
func TestRun_TopLevel(t *testing.T) {
	quiet(t)
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no args shows help", nil, 0},
		{"version", []string{"version"}, 0},
		{"version -v", []string{"-v"}, 0},
		{"version --version", []string{"--version"}, 0},
		{"help", []string{"help"}, 0},
		{"help -h", []string{"-h"}, 0},
		{"unknown command", []string{"frobnicate"}, 2},
		{"init not implemented", []string{"init"}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Run(c.args); got != c.want {
				t.Errorf("Run(%v) = %d, want %d", c.args, got, c.want)
			}
		})
	}
}

// TestRunCommand_Usage covers the run subcommand's flag-parsing error paths, all
// of which must return the usage exit code (2) without touching the filesystem.
func TestRunCommand_Usage(t *testing.T) {
	quiet(t)
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no command at all", []string{"run"}, 2},
		{"--log without a path", []string{"run", "--log"}, 2},
		{"--config without a path", []string{"run", "--config"}, 2},
		{"--signing-key without a path", []string{"run", "--signing-key"}, 2},
		{"--approval-addr without a value", []string{"run", "--approval-addr"}, 2},
		{"--approval-timeout without a value", []string{"run", "--approval-timeout"}, 2},
		{"--approval-timeout invalid duration", []string{"run", "--approval-timeout", "notaduration"}, 2},
		{"-- with no command after it", []string{"run", "--"}, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Run(c.args); got != c.want {
				t.Errorf("Run(%v) = %d, want %d", c.args, got, c.want)
			}
		})
	}
}

// TestRunCommand_ConfigNotFound: a --config path that does not exist fails (1).
func TestRunCommand_ConfigNotFound(t *testing.T) {
	quiet(t)
	missing := filepath.Join(t.TempDir(), "nope.json")
	if got := Run([]string{"run", "--config", missing, "--", "x"}); got != 1 {
		t.Errorf("Run with missing config = %d, want 1", got)
	}
}

// TestRunCommand_NonexistentServer: a well-formed invocation whose wrapped server
// binary does not exist gets past parsing, key-open, and log-open, then fails to
// start the proxy (1). --signing-key points at a temp path so the test never
// writes a key into the working directory.
func TestRunCommand_NonexistentServer(t *testing.T) {
	quiet(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "signing.key")
	args := []string{"run", "--log", logPath, "--signing-key", keyPath, "--", "definitely-not-a-real-binary-xyz"}
	if got := Run(args); got != 1 {
		t.Errorf("Run with nonexistent server = %d, want 1", got)
	}
}

// TestRunCommand_ConfigProvidesCommand: the wrapped command may come from the
// config file rather than the command line. A config pointing at a nonexistent
// binary still gets past loading and fails at proxy start (1), proving the
// config's command is used when no "--" tail overrides it.
func TestRunCommand_ConfigProvidesCommand(t *testing.T) {
	quiet(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "ganimedes.json")
	if err := os.WriteFile(cfgPath, []byte(`{"command":"definitely-not-a-real-binary-xyz","deny":["x"]}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "signing.key")
	if got := Run([]string{"run", "--config", cfgPath, "--log", logPath, "--signing-key", keyPath}); got != 1 {
		t.Errorf("Run with config command = %d, want 1", got)
	}
}

// TestRunCommand_ApprovalWiring: a config with an approval-list stands up the
// approval page (on an ephemeral loopback port) and hands the proxy an approver;
// the run then fails only because the wrapped server binary does not exist (1),
// which exercises the approval New/Start/Close wiring around a normal run.
func TestRunCommand_ApprovalWiring(t *testing.T) {
	quiet(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "ganimedes.json")
	if err := os.WriteFile(cfgPath, []byte(`{"approve":["email.send"]}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	args := []string{
		"run",
		"--config", cfgPath,
		"--log", filepath.Join(dir, "audit.jsonl"),
		"--signing-key", filepath.Join(dir, "signing.key"),
		"--approval-addr", "127.0.0.1:0",
		"--approval-timeout", "5s",
		"--", "definitely-not-a-real-binary-xyz",
	}
	if got := Run(args); got != 1 {
		t.Errorf("run with approval wiring = %d, want 1", got)
	}
}

// TestRunCommand_ApprovalBadAddr: a non-loopback --approval-addr with an
// approval-list is rejected by approval.New before the proxy starts (1).
func TestRunCommand_ApprovalBadAddr(t *testing.T) {
	quiet(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "ganimedes.json")
	if err := os.WriteFile(cfgPath, []byte(`{"approve":["email.send"]}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	args := []string{
		"run",
		"--config", cfgPath,
		"--log", filepath.Join(dir, "audit.jsonl"),
		"--signing-key", filepath.Join(dir, "signing.key"),
		"--approval-addr", "0.0.0.0:8765",
		"--", "x",
	}
	if got := Run(args); got != 1 {
		t.Errorf("run with non-loopback approval addr = %d, want 1", got)
	}
}

// TestRunCommand_ApprovalAddrInUse: when the approval address is already bound,
// Start fails and run exits 1 before proxying.
func TestRunCommand_ApprovalAddrInUse(t *testing.T) {
	quiet(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "ganimedes.json")
	if err := os.WriteFile(cfgPath, []byte(`{"approve":["email.send"]}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	args := []string{
		"run",
		"--config", cfgPath,
		"--log", filepath.Join(dir, "audit.jsonl"),
		"--signing-key", filepath.Join(dir, "signing.key"),
		"--approval-addr", ln.Addr().String(),
		"--", "x",
	}
	if got := Run(args); got != 1 {
		t.Errorf("run with occupied approval addr = %d, want 1", got)
	}
}

// TestScanCommand_Usage covers scan's flag-parsing error paths (exit 2), which
// must all fail before spawning anything.
func TestScanCommand_Usage(t *testing.T) {
	quiet(t)
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no command at all", []string{"scan"}, 2},
		{"--config without a path", []string{"scan", "--config"}, 2},
		{"-- with no command after it", []string{"scan", "--"}, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Run(c.args); got != c.want {
				t.Errorf("Run(%v) = %d, want %d", c.args, got, c.want)
			}
		})
	}
}

// TestScanCommand_ConfigNotFound: a --config path that does not exist fails (1).
func TestScanCommand_ConfigNotFound(t *testing.T) {
	quiet(t)
	missing := filepath.Join(t.TempDir(), "nope.json")
	if got := Run([]string{"scan", "--config", missing, "--", "x"}); got != 1 {
		t.Errorf("scan with missing config = %d, want 1", got)
	}
}

// TestScanCommand_NonexistentServer: a well-formed invocation whose wrapped
// server binary does not exist gets past parsing, then fails to start (1).
func TestScanCommand_NonexistentServer(t *testing.T) {
	quiet(t)
	if got := Run([]string{"scan", "--", "definitely-not-a-real-binary-xyz"}); got != 1 {
		t.Errorf("scan with nonexistent server = %d, want 1", got)
	}
}

// TestScanCommand_HappyPath runs scan end to end through the CLI against this
// test binary re-executed as a stand-in MCP server (TestHelperScanServer),
// exercising scanCommand's success path: spawn, handshake, render, exit 0.
func TestScanCommand_HappyPath(t *testing.T) {
	quiet(t)
	t.Setenv("GO_WANT_SCAN_SERVER", "1")
	args := []string{"scan", "--", os.Args[0], "-test.run=TestHelperScanServer"}
	if got := Run(args); got != 0 {
		t.Errorf("scan happy path = %d, want 0", got)
	}
}

// TestHelperScanServer is not a real test. TestScanCommand_HappyPath re-executes
// the test binary with GO_WANT_SCAN_SERVER=1 to stand in for a real MCP server:
// it answers initialize and tools/list over stdio, then exits at EOF.
func TestHelperScanServer(t *testing.T) {
	if os.Getenv("GO_WANT_SCAN_SERVER") != "1" {
		return
	}
	r := bufio.NewReader(os.Stdin)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			var m struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
			}
			if json.Unmarshal(line, &m) == nil {
				switch m.Method {
				case "initialize":
					fmt.Printf(`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2024-11-05","capabilities":{}}}`+"\n", m.ID)
				case "tools/list":
					fmt.Printf(`{"jsonrpc":"2.0","id":%s,"result":{"tools":[`+
						`{"name":"read_file","description":"reads a file"},`+
						`{"name":"delete_all","description":"erases everything"}]}}`+"\n", m.ID)
				}
			}
		}
		if err != nil {
			break
		}
	}
	os.Exit(0)
}

// TestVerifyCommand covers the verify subcommand against a real signed log: an
// intact log passes (0); a content edit, a missing log, and an unreadable public
// key each fail (1); and --pubkey with no path is a usage error (2).
func TestVerifyCommand(t *testing.T) {
	quiet(t)
	// makeLog builds a signed log and returns its path plus the path of the
	// public key that verifies it.
	makeLog := func(t *testing.T) (logPath, pubPath string) {
		t.Helper()
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "signing.key")
		priv, _, err := audit.LoadOrCreateSigningKey(keyPath)
		if err != nil {
			t.Fatalf("LoadOrCreateSigningKey: %v", err)
		}
		logPath = filepath.Join(dir, "audit.jsonl")
		l, err := audit.Open(logPath, "sess", priv)
		if err != nil {
			t.Fatalf("audit.Open: %v", err)
		}
		if _, err := l.Append("read_file", json.RawMessage(`{"path":"a"}`), json.RawMessage(`{"ok":true}`), nil, audit.DecisionAllow); err != nil {
			t.Fatalf("Append: %v", err)
		}
		if err := l.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		return logPath, audit.PublicKeyPath(keyPath)
	}

	t.Run("intact log", func(t *testing.T) {
		logPath, pubPath := makeLog(t)
		if got := Run([]string{"verify", "--pubkey", pubPath, logPath}); got != 0 {
			t.Errorf("verify intact = %d, want 0", got)
		}
	})

	t.Run("tampered log", func(t *testing.T) {
		logPath, pubPath := makeLog(t)
		data, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		edited := bytes.Replace(data, []byte(`"path":"a"`), []byte(`"path":"b"`), 1)
		if bytes.Equal(edited, data) {
			t.Fatal("tamper had no effect")
		}
		if err := os.WriteFile(logPath, edited, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if got := Run([]string{"verify", "--pubkey", pubPath, logPath}); got != 1 {
			t.Errorf("verify tampered = %d, want 1", got)
		}
	})

	t.Run("missing log", func(t *testing.T) {
		_, pubPath := makeLog(t)
		missing := filepath.Join(t.TempDir(), "nope.jsonl")
		if got := Run([]string{"verify", "--pubkey", pubPath, missing}); got != 1 {
			t.Errorf("verify missing = %d, want 1", got)
		}
	})

	t.Run("unreadable pubkey", func(t *testing.T) {
		logPath, _ := makeLog(t)
		badPub := filepath.Join(t.TempDir(), "nope.pub")
		if got := Run([]string{"verify", "--pubkey", badPub, logPath}); got != 1 {
			t.Errorf("verify with missing pubkey = %d, want 1", got)
		}
	})

	t.Run("--pubkey without a path", func(t *testing.T) {
		if got := Run([]string{"verify", "--pubkey"}); got != 2 {
			t.Errorf("verify --pubkey without a path = %d, want 2", got)
		}
	})
}

// TestResolveSigningKeyPath covers the precedence: explicit flag, then the env
// var, then the default path.
func TestResolveSigningKeyPath(t *testing.T) {
	if got := resolveSigningKeyPath("flag.key"); got != "flag.key" {
		t.Errorf("flag precedence: got %q, want flag.key", got)
	}
	t.Setenv(signingKeyEnv, "env.key")
	if got := resolveSigningKeyPath(""); got != "env.key" {
		t.Errorf("env fallback: got %q, want env.key", got)
	}
	t.Setenv(signingKeyEnv, "")
	if got := resolveSigningKeyPath(""); got != defaultSigningKeyPath {
		t.Errorf("default: got %q, want %q", got, defaultSigningKeyPath)
	}
}

// TestResolvePublicKey covers how verify finds the public key: an explicit
// --pubkey, then the default .pub next to the signing key, then deriving it from
// the signing key, then a clear error when none of those exist. The default and
// derive cases read the current directory, so the test runs inside a temp dir.
func TestResolvePublicKey(t *testing.T) {
	// Explicit path wins.
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "k.key")
	priv, _, err := audit.LoadOrCreateSigningKey(keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateSigningKey: %v", err)
	}
	pub, err := resolvePublicKey(audit.PublicKeyPath(keyPath))
	if err != nil || !pub.Equal(priv.Public()) {
		t.Fatalf("explicit --pubkey: pub=%v err=%v", pub, err)
	}

	// Switch into a scratch dir so default-name lookups are deterministic.
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	scratch := t.TempDir()
	if err := os.Chdir(scratch); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })

	// Default .pub next to the signing key.
	priv2, _, err := audit.LoadOrCreateSigningKey(defaultSigningKeyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateSigningKey(default): %v", err)
	}
	pub, err = resolvePublicKey("")
	if err != nil || !pub.Equal(priv2.Public()) {
		t.Fatalf("default .pub: pub=%v err=%v", pub, err)
	}

	// With the .pub gone but the private key present, derive from the private key.
	if err := os.Remove(audit.PublicKeyPath(defaultSigningKeyPath)); err != nil {
		t.Fatalf("Remove .pub: %v", err)
	}
	pub, err = resolvePublicKey("")
	if err != nil || !pub.Equal(priv2.Public()) {
		t.Fatalf("derive from private: pub=%v err=%v", pub, err)
	}

	// With neither present, a clear error.
	if err := os.Remove(defaultSigningKeyPath); err != nil {
		t.Fatalf("Remove .key: %v", err)
	}
	if _, err := resolvePublicKey(""); err == nil {
		t.Error("resolvePublicKey with no key found returned nil error")
	}
}
