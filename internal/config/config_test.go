package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// write drops content into a temp file and returns its path.
func write(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// TestLoad_Full parses a complete config (command, args, deny, approve) and
// checks every field round-trips.
func TestLoad_Full(t *testing.T) {
	path := write(t, `{
		"command": "npx",
		"args": ["-y", "server-filesystem", "/data"],
		"deny": ["fs.delete", "db.dropTable"],
		"approve": ["email.send", "payment.execute"]
	}`)

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Command != "npx" {
		t.Errorf("Command = %q, want npx", c.Command)
	}
	if len(c.Args) != 3 || c.Args[0] != "-y" || c.Args[2] != "/data" {
		t.Errorf("Args = %v, want [-y server-filesystem /data]", c.Args)
	}
	if len(c.Deny) != 2 || c.Deny[0] != "fs.delete" || c.Deny[1] != "db.dropTable" {
		t.Errorf("Deny = %v, want [fs.delete db.dropTable]", c.Deny)
	}
	if len(c.Approve) != 2 || c.Approve[0] != "email.send" || c.Approve[1] != "payment.execute" {
		t.Errorf("Approve = %v, want [email.send payment.execute]", c.Approve)
	}
}

// TestLoad_DenyOnly is the common milestone-3 shape: deny rules in the file, the
// command supplied elsewhere (on the CLI). Command may legitimately be empty.
func TestLoad_DenyOnly(t *testing.T) {
	path := write(t, `{"deny": ["payment.execute"]}`)

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Command != "" {
		t.Errorf("Command = %q, want empty", c.Command)
	}
	if len(c.Deny) != 1 || c.Deny[0] != "payment.execute" {
		t.Errorf("Deny = %v, want [payment.execute]", c.Deny)
	}
}

// TestLoad_UnknownFieldRejected is the safety property: a mistyped key must fail
// loudly, not silently leave the deny-list empty (every tool allowed).
func TestLoad_UnknownFieldRejected(t *testing.T) {
	path := write(t, `{"denny": ["fs.delete"]}`) // typo: "denny"

	if _, err := Load(path); err == nil {
		t.Fatal("Load accepted an unknown field, want an error")
	}
}

// TestLoad_MalformedJSON: broken JSON is an error, not an empty config.
func TestLoad_MalformedJSON(t *testing.T) {
	path := write(t, `{"deny": [`)

	if _, err := Load(path); err == nil {
		t.Fatal("Load accepted malformed JSON, want an error")
	}
}

// TestLoad_TrailingData: two concatenated objects (a copy-paste mistake) must be
// rejected rather than silently using only the first.
func TestLoad_TrailingData(t *testing.T) {
	path := write(t, `{"command":"a"}{"command":"b"}`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load accepted trailing data, want an error")
	}
	if !strings.Contains(err.Error(), "unexpected data") {
		t.Errorf("error = %v, want it to mention unexpected trailing data", err)
	}
}

// TestLoad_MissingFile: a config path that does not exist is an error.
func TestLoad_MissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("Load on a missing file returned nil error, want an error")
	}
}
