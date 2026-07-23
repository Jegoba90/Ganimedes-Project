// Package audit is Ganimedes' tamper-evident record of what an agent did.
//
// Every tool call the proxy observes is appended to an append-only JSONL file
// as one Entry. Each Entry carries the SHA-256 hash of the previous Entry
// (prev_hash) and its own hash covers that link, so the file forms a chain:
// editing, reordering, or deleting any past Entry breaks every hash after it,
// which Verify (see verify.go) detects.
//
// What the chain does and does not give you: it makes *after-the-fact edits*
// to recorded history detectable. It does not stop someone who controls the
// file from rewriting the whole chain from scratch, and it cannot detect that
// entries were truncated from the very end (there is no external anchor in v0;
// publishing the head hash somewhere is a later feature). The honest claim is
// "you can prove the log was not altered after the fact", which is exactly what
// the README promises.
//
// Design decisions (from docs/DESIGN.md, decided 2026-07-23):
//   - Each Entry stores the FULL call (tool, arguments, result) so the log is
//     useful for debugging ("what did my agent do?"), not just verification.
//   - The hash is computed over the canonical JSON of the Entry-minus-its-hash,
//     including prev_hash.
//   - Storage is a JSONL file; the DB comes later, if ever.
//
// This package knows nothing about JSON-RPC or MCP framing: the proxy parses
// messages and hands this package already-extracted fields. That keeps the
// audit logic pure and testable without spawning a subprocess.
package audit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Decision records why a call was allowed to reach the real server (or not).
// v0 milestone 2 has no policy engine yet, so every recorded call is
// DecisionAllow; the deny/approval values arrive with the policy engine in
// later milestones. They live here, next to the on-disk format, so the field's
// vocabulary has a single source of truth.
const (
	DecisionAllow    = "allow"    // default: no policy blocked it (milestone 2)
	DecisionDeny     = "deny"     // milestone 3: blocked by the deny-list
	DecisionApproved = "approved" // milestone 4: a human approved it
	DecisionRejected = "rejected" // milestone 4: a human rejected it
	DecisionTimeout  = "timeout"  // milestone 4: no human answered in time
)

// genesisHash is the prev_hash of the very first entry in a log. An empty
// string reads clearly in the file ("this entry starts the chain") and Verify
// checks the first entry against it.
const genesisHash = ""

// payload is the part of an Entry that the hash covers: everything except the
// hash itself. It is a separate (embedded) struct for one reason: hashing an
// entry means "serialize it without its own hash and take SHA-256 of that".
// With payload embedded in Entry, json flattens its fields into the same
// object, so json.Marshal(entry.payload) is exactly the entry minus its hash,
// with no field list duplicated between the two.
//
// Field order here is significant: json.Marshal emits struct fields in
// declaration order, which is what makes the serialization deterministic and
// therefore the hash reproducible. Do not reorder these fields without
// understanding that it changes every hash computed afterwards.
type payload struct {
	Seq      uint64          `json:"seq"`              // 1-based position in this file
	Time     string          `json:"ts"`               // RFC3339 nanosecond UTC timestamp
	Session  string          `json:"session"`          // groups entries from one proxy run
	Tool     string          `json:"tool"`             // the tools/call name
	Args     json.RawMessage `json:"args"`             // arguments, verbatim JSON from the wire
	Result   json.RawMessage `json:"result,omitempty"` // present on a successful call
	Error    json.RawMessage `json:"error,omitempty"`  // present on a failed call
	Decision string          `json:"decision"`         // one of the Decision* constants
	PrevHash string          `json:"prev_hash"`        // hash of the previous entry (chain link)
}

// Entry is one audited tool call as stored on disk: a payload plus the SHA-256
// hash that seals it. It is written as a single JSON object per line (JSONL).
//
// Args, Result, and Error are kept as json.RawMessage so the exact JSON that
// crossed the wire is preserved rather than being decoded and re-encoded
// through Go types (which could drop or reshape fields). The JSON encoder
// compacts each RawMessage deterministically when marshaling, so the same input
// always produces the same stored bytes and therefore the same hash.
type Entry struct {
	payload
	Hash string `json:"hash"`
}

// hash computes an Entry's seal: the hex SHA-256 of the canonical JSON of its
// payload (everything but the hash). "Canonical" here means "deterministically
// serialized": payload is a struct with no maps, so json.Marshal emits its
// fields in a fixed order, and it compacts the RawMessage fields, so the same
// payload always yields identical bytes. This is byte-canonicalization of the
// stored record, not semantic JSON canonicalization: it seals exactly what was
// recorded, which is what tamper-evidence needs.
func (p payload) hash() (string, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("hashing audit entry: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Logger appends entries to one append-only, hash-chained JSONL file. It is
// safe for concurrent use: Append serializes writers under a mutex so the chain
// advances one entry at a time. In the proxy only a single goroutine (the
// server->client direction, where results arrive) ever calls Append, but the
// mutex keeps Logger correct as a standalone component regardless.
type Logger struct {
	mu       sync.Mutex
	f        *os.File
	session  string
	seq      uint64 // sequence number of the last entry written
	prevHash string // hash of the last entry written (next entry links to it)
}

// Open opens the log file at path for appending, creating it if it does not
// exist. If the file already holds entries, Open reads the last one so new
// entries continue its chain (seq keeps counting, prev_hash keeps linking)
// instead of forking a second chain in the same file. session labels every
// entry this Logger writes; use NewSession to generate one per proxy run.
func Open(path, session string) (*Logger, error) {
	// Resume from any existing content first, so a re-opened log continues its
	// chain rather than restarting it. A missing file is not an error here: it
	// just means we start a fresh chain.
	seq, prev, err := lastState(path)
	if err != nil {
		return nil, err
	}

	// 0o600: the log can contain tool arguments and results, which may include
	// secrets or PII (a documented v0 tradeoff; redaction is a later feature).
	// Owner-only permissions are the least we can do about that on disk.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening audit log %q: %w", path, err)
	}

	return &Logger{f: f, session: session, seq: seq, prevHash: prev}, nil
}

// Append records one completed tool call and returns the stored Entry.
//
// args, result, and rpcErr are the raw JSON values from the MCP messages;
// result and rpcErr are mutually exclusive in JSON-RPC (a response carries one
// or the other), and either may be empty. decision is one of the Decision*
// constants. The chain advances only after the line is durably written, so a
// failed write leaves the Logger's state unchanged and the next Append reuses
// the same prev_hash.
func (l *Logger) Append(tool string, args, result, rpcErr json.RawMessage, decision string) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	p := payload{
		Seq:      l.seq + 1,
		Time:     time.Now().UTC().Format(time.RFC3339Nano),
		Session:  l.session,
		Tool:     tool,
		Args:     orNull(args),
		Result:   result,
		Error:    rpcErr,
		Decision: decision,
		PrevHash: l.prevHash,
	}

	h, err := p.hash()
	if err != nil {
		return Entry{}, err
	}
	e := Entry{payload: p, Hash: h}

	line, err := json.Marshal(e)
	if err != nil {
		return Entry{}, fmt.Errorf("encoding audit entry: %w", err)
	}
	line = append(line, '\n')
	if _, err := l.f.Write(line); err != nil {
		return Entry{}, fmt.Errorf("writing audit entry: %w", err)
	}

	// Only now, after the entry is on disk, advance the chain.
	l.seq = p.Seq
	l.prevHash = h
	return e, nil
}

// Close closes the underlying file. After Close, the Logger must not be used.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

// NewSession returns a short random hex id used to group all entries written by
// one proxy run. It is not a security token, just a label to tell sessions
// apart in the log, so 8 random bytes are plenty. If the system RNG fails (all
// but impossible), it falls back to a timestamp so a session is never unlabeled.
func NewSession() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// orNull normalizes an empty RawMessage to nil so it marshals as JSON null.
// A zero-length, non-nil RawMessage is invalid JSON and would make json.Marshal
// fail; Args must always be present in the record, so this guarantees a valid
// value (null) when a tool was called with no arguments.
func orNull(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	return raw
}
