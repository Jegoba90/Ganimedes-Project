package cli

import (
	"bytes"
	"encoding/json"
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
// binary does not exist gets past parsing and log-open, then fails to start the
// proxy (1). This exercises the command-line command path end to end.
func TestRunCommand_NonexistentServer(t *testing.T) {
	quiet(t)
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	args := []string{"run", "--log", logPath, "--", "definitely-not-a-real-binary-xyz"}
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
	if got := Run([]string{"run", "--config", cfgPath, "--log", logPath}); got != 1 {
		t.Errorf("Run with config command = %d, want 1", got)
	}
}

// TestVerifyCommand covers the verify subcommand: an intact log passes (0), a
// tampered log fails (1), and a missing log fails (1).
func TestVerifyCommand(t *testing.T) {
	quiet(t)
	makeLog := func(t *testing.T) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		l, err := audit.Open(path, "sess")
		if err != nil {
			t.Fatalf("audit.Open: %v", err)
		}
		if _, err := l.Append("read_file", json.RawMessage(`{"path":"a"}`), json.RawMessage(`{"ok":true}`), nil, audit.DecisionAllow); err != nil {
			t.Fatalf("Append: %v", err)
		}
		if err := l.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		return path
	}

	t.Run("intact log", func(t *testing.T) {
		if got := Run([]string{"verify", makeLog(t)}); got != 0 {
			t.Errorf("verify intact = %d, want 0", got)
		}
	})

	t.Run("tampered log", func(t *testing.T) {
		path := makeLog(t)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		edited := bytes.Replace(data, []byte(`"path":"a"`), []byte(`"path":"b"`), 1)
		if bytes.Equal(edited, data) {
			t.Fatal("tamper had no effect")
		}
		if err := os.WriteFile(path, edited, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if got := Run([]string{"verify", path}); got != 1 {
			t.Errorf("verify tampered = %d, want 1", got)
		}
	})

	t.Run("missing log", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "nope.jsonl")
		if got := Run([]string{"verify", missing}); got != 1 {
			t.Errorf("verify missing = %d, want 1", got)
		}
	})
}
