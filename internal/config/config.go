// Package config defines Ganimedes' configuration type and its JSON loader.
//
// Two things feed a run: which real MCP server to spawn, and the deny-list of
// tools to block (milestone 3). Both can come from a JSON config file (Load) or
// from the CLI; the CLI decides how the two sources combine (see internal/cli).
//
// Why JSON and not YAML: Ganimedes is stdlib-only (Constitution Art. 1.1), and
// YAML has no standard-library parser while JSON does (encoding/json). The
// README once said "YAML"; the config format is JSON. See DESIGN.md decision log.
package config

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Config describes how Ganimedes should run: which downstream MCP server to
// spawn, with what arguments, and which tool names to block or hold for approval.
//
// The JSON tags are the on-disk field names. Command/Args may be omitted in the
// file and supplied on the command line instead; Deny is the tool deny-list and
// Approve the human-in-the-loop list (both default-allow: only the names listed
// are treated specially).
type Config struct {
	// Command is the executable of the real MCP server to wrap.
	Command string `json:"command"`
	// Args are the arguments passed to Command.
	Args []string `json:"args"`
	// Deny lists tool names that are blocked at call time. A tools/call whose
	// name is in this list never reaches the real server; the client gets a
	// JSON-RPC error and the attempt is recorded in the audit log. Everything
	// not listed is allowed (default-allow); see docs/DESIGN.md.
	Deny []string `json:"deny"`
	// Approve lists tool names that require human approval before they reach the
	// real server (milestone 4). A tools/call whose name is in this list is
	// paused and shown on the local approval page; the human's decision (or a
	// timeout) is recorded in the audit log. Everything not listed is allowed
	// (default-allow), and a tool on both lists is denied (deny wins, the
	// stricter verdict); see docs/DESIGN.md and internal/policy.
	Approve []string `json:"approve"`
}

// Load reads and parses a JSON config file at path.
//
// Unknown fields are rejected (DisallowUnknownFields): in a security tool a
// mistyped key such as "denny" must fail loudly rather than silently leave the
// deny-list empty and every tool allowed. Load does not require Command to be
// set — the CLI may supply it instead — so validation of the final, merged
// configuration is the caller's job.
func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("opening config %q: %w", path, err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()

	var c Config
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("parsing config %q: %w", path, err)
	}
	// Reject trailing content after the JSON object so a file that is two
	// concatenated objects (a likely copy-paste mistake) is an error, not a
	// silently-ignored second half.
	if _, err := dec.Token(); err != io.EOF {
		return Config{}, fmt.Errorf("parsing config %q: unexpected data after the JSON object", path)
	}
	return c, nil
}
