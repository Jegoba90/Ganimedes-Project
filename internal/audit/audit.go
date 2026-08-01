// Package audit is Ganimedes' tamper-evident record of what an agent did.
//
// Every tool call the proxy observes is appended to an append-only JSONL file
// as one Entry. Each Entry carries the SHA-256 hash of the previous Entry
// (prev_hash) and its own hash covers that link, so the file forms a chain:
// editing, reordering, or deleting any past Entry breaks every hash after it,
// which Verify (see verify.go) detects. On top of the chain, every Entry is
// Ed25519-signed, so a verifier can also prove the entries were produced by the
// holder of a specific key, not just that history was not edited.
//
// The digest and signature are taken over the RFC 8785 (JSON Canonicalization
// Scheme) form of the entry's payload (see canonical.go), so the exact bytes
// that were hashed and signed can be reproduced by any RFC 8785 implementation
// from the stored JSON plus the public key. That is what makes the log
// independently verifiable offline (Constitution Art. 2.3).
//
// What the chain does and does not give you: it makes *after-the-fact edits* to
// recorded history detectable, and the signature proves authorship. Neither
// stops someone who controls BOTH the log and the signing key from rewriting the
// whole chain from scratch, and neither detects entries truncated from the very
// end (there is no external anchor in v0; publishing the head hash somewhere is a
// later feature). The honest claim is "you can prove the log was not altered
// after the fact, and that it was signed by this key" (Art. 2.4).
//
// Design decisions (from docs/DESIGN.md, decided 2026-07-23 and 2026-07-24):
//   - Each Entry stores the FULL call (tool, arguments, result) so the log is
//     useful for debugging ("what did my agent do?"), not just verification.
//   - The hash and signature are computed over the RFC 8785 canonical JSON of
//     the Entry-minus-its-seal (everything but hash and sig), including prev_hash.
//   - Storage is a JSONL file; the DB comes later, if ever.
//
// This package knows nothing about JSON-RPC or MCP framing: the proxy parses
// messages and hands this package already-extracted fields. That keeps the
// audit logic pure and testable without spawning a subprocess.
package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// Decision records why a call was allowed to reach the real server (or not).
// Allow (milestone 2) and Deny (milestone 3, the deny-list) are both in use; the
// approval values arrive with human-in-the-loop (milestone 4). They live here,
// next to the on-disk format, so the field's vocabulary has a single source of
// truth.
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

// Kind distinguishes the two things a log line can be. A tool call carries no
// kind at all, which is deliberate: it keeps a call's bytes identical to what
// every version before session headers wrote, so logs written by an older
// Ganimedes still verify against this one.
//
// An unknown kind is not ignored. A verifier that cannot say what an entry
// claims to be cannot vouch for it, so Verify refuses the whole log rather than
// waving through a record it does not understand.
const KindSession = "session"

// SessionInfo is what a session header records: the conditions every call in
// that session was judged under. Without it a log answers "what happened" but
// not "under what rules", and a `decision` of allow is the same bytes whether a
// policy examined the call and permitted it or no policy was ever loaded.
//
// Deny and Approve carry no omitempty on purpose. An empty list must appear as
// [] rather than vanish, because "the deny-list was empty" is precisely the
// fact a reader needs and the fact its absence would hide.
type SessionInfo struct {
	Version string   `json:"version"` // the gateway build that wrote this session
	Command string   `json:"command"` // the wrapped MCP server's executable
	Args    []string `json:"args"`    // arguments it was launched with
	Deny    []string `json:"deny"`    // tools blocked outright, [] if none
	Approve []string `json:"approve"` // tools held for a human, [] if none
}

// normalize replaces nil slices with empty ones so they serialize as [] and not
// null. Both are distinguishable from an absent field, but [] is what a reader
// expects for "this list was empty".
func (s *SessionInfo) normalize() {
	if s.Args == nil {
		s.Args = []string{}
	}
	if s.Deny == nil {
		s.Deny = []string{}
	}
	if s.Approve == nil {
		s.Approve = []string{}
	}
}

// payload is the part of an Entry that the hash covers: everything except the
// hash itself. It is a separate (embedded) struct for one reason: hashing an
// entry means "serialize it without its own hash and take SHA-256 of that".
// With payload embedded in Entry, json flattens its fields into the same
// object, so json.Marshal(entry.payload) is exactly the entry minus its hash,
// with no field list duplicated between the two.
//
// Field order here does not affect the seal, despite how it looks: json.Marshal
// emits fields in declaration order, but canonical() then runs the result
// through RFC 8785, which sorts object members by their UTF-16 code units. Both
// the writer and Verify canonicalize, so they agree whatever the order is here.
// What does change every hash is renaming a field, changing whether it is
// omitted when empty, or changing the value that reaches it.
type payload struct {
	Seq      uint64          `json:"seq"`                    // 1-based position in this file
	Time     string          `json:"ts"`                     // RFC3339 nanosecond UTC timestamp
	Session  string          `json:"session"`                // groups entries from one proxy run
	Kind     string          `json:"kind,omitempty"`         // KindSession on a header; absent on a tool call
	Info     *SessionInfo    `json:"session_info,omitempty"` // present only on a session header
	Tool     string          `json:"tool,omitempty"`         // the tools/call name
	Args     json.RawMessage `json:"args,omitempty"`         // arguments, verbatim JSON from the wire
	Result   json.RawMessage `json:"result,omitempty"`       // present on a successful call
	Error    json.RawMessage `json:"error,omitempty"`        // present on a failed call
	Decision string          `json:"decision,omitempty"`     // one of the Decision* constants
	PrevHash string          `json:"prev_hash"`              // hash of the previous entry (chain link)
}

// checkShape reports whether an entry is one of the two things this format
// defines, with the fields that kind requires and none that contradict it. It
// runs after the hash and signature check, so reaching it means the entry was
// genuinely written by the holder of the signing key: a failure here says the
// log came from a version this build cannot judge, not that someone edited it.
func (p payload) checkShape() error {
	switch p.Kind {
	case KindSession:
		if p.Info == nil {
			return errors.New("session header without session_info")
		}
		if p.Tool != "" || len(p.Args) > 0 || len(p.Result) > 0 || len(p.Error) > 0 || p.Decision != "" {
			return errors.New("session header carrying tool-call fields")
		}
	case "":
		if p.Tool == "" {
			return errors.New("tool call without a tool name")
		}
		if p.Decision == "" {
			return errors.New("tool call without a decision")
		}
		if p.Info != nil {
			return errors.New("tool call carrying session_info")
		}
	default:
		return fmt.Errorf("unknown entry kind %q", p.Kind)
	}
	return nil
}

// Entry is one record as stored on disk, either an audited tool call or the
// session header that opens a run: a payload plus its seal, the hex SHA-256 hash
// and the base64 Ed25519 signature. It is written as a single JSON object per
// line (JSONL). Both kinds sit in the same chain, so the header is as
// tamper-evident as the calls it introduces.
//
// Args, Result, and Error are kept as json.RawMessage so the exact JSON that
// crossed the wire is preserved rather than being decoded and re-encoded through
// Go types (which could drop or reshape fields). The verbatim bytes stay in the
// file; canonicalization (below) is applied only when computing the seal.
type Entry struct {
	payload
	Hash string `json:"hash"`
	Sig  string `json:"sig"`
}

// canonical returns the RFC 8785 canonical JSON of the payload (everything but
// the hash and signature). It is the single byte sequence the digest and the
// signature are both taken over, and the single thing Verify re-derives to check
// them, so writer and verifier agree by construction (Constitution Art. 2.3).
//
// The payload is marshaled with the standard encoder first (which embeds the
// verbatim Args/Result/Error), then run through the canonicalizer, so nested
// values inside the call are canonicalized too, not just the outer fields.
func (p payload) canonical() ([]byte, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshaling audit entry: %w", err)
	}
	c, err := canonicalizeJSON(b)
	if err != nil {
		return nil, fmt.Errorf("canonicalizing audit entry: %w", err)
	}
	return c, nil
}

// digest is the hex SHA-256 of canonical payload bytes: the chain link stored as
// an entry's hash and referenced by the next entry's prev_hash. Append and Verify
// both call it on the bytes returned by canonical, so the two agree by
// construction.
func digest(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

// Logger appends entries to one append-only, hash-chained JSONL file. It is
// safe for concurrent use: Append serializes writers under a mutex so the chain
// advances one entry at a time. Since milestone 3 both proxy directions call
// Append — the server->client goroutine records allowed calls when their result
// arrives, and the client->server goroutine records a denied call the moment it
// is blocked — so the mutex is what serializes the chain (not a single-writer
// property). CI's -race build proves there is no data race.
type Logger struct {
	mu       sync.Mutex
	f        *os.File
	priv     ed25519.PrivateKey // signs every entry (Art. 2.3)
	session  string
	seq      uint64 // sequence number of the last entry written
	prevHash string // hash of the last entry written (next entry links to it)
}

// Open opens the log file at path for appending, creating it if it does not
// exist. If the file already holds entries, Open reads the last one so new
// entries continue its chain (seq keeps counting, prev_hash keeps linking)
// instead of forking a second chain in the same file. session labels every entry
// this Logger writes; use NewSession to generate one per proxy run. priv signs
// every entry and is required: a Logger never writes unsigned records, so a nil
// key is a programming error, reported rather than silently downgraded.
func Open(path, session string, priv ed25519.PrivateKey) (*Logger, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("audit: Open requires a valid ed25519 signing key")
	}

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

	return &Logger{f: f, priv: priv, session: session, seq: seq, prevHash: prev}, nil
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
	return l.appendPayload(payload{
		Tool:     tool,
		Args:     orNull(args),
		Result:   result,
		Error:    rpcErr,
		Decision: decision,
	})
}

// AppendSessionHeader records what this session is: the gateway's version, the
// server it wrapped, and the deny and approval lists in force for every call
// that follows. It belongs at the start of a session, before any traffic, and
// there is one per run rather than one per file, because a log is appended to
// across runs and each run has its own conditions to declare.
//
// It goes through the same seal and the same chain as a tool call, so it cannot
// be swapped for a friendlier set of rules after the fact without breaking
// verification.
func (l *Logger) AppendSessionHeader(info SessionInfo) (Entry, error) {
	info.normalize()
	return l.appendPayload(payload{Kind: KindSession, Info: &info})
}

// appendPayload stamps p with the fields only the Logger can know (its position
// in the chain, the time, the session label, the link to the previous entry),
// seals it and writes the line. Callers supply what the record is; this supplies
// where it sits.
func (l *Logger) appendPayload(p payload) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	p.Seq = l.seq + 1
	p.Time = time.Now().UTC().Format(time.RFC3339Nano)
	p.Session = l.session
	p.PrevHash = l.prevHash

	// Canonicalize once, then both seal it (hash for the chain) and sign it
	// (Ed25519 for authenticity) over the exact same bytes.
	c, err := p.canonical()
	if err != nil {
		return Entry{}, err
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(l.priv, c))
	e := Entry{payload: p, Hash: digest(c), Sig: sig}

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
	l.prevHash = e.Hash
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

// orNull normalizes an empty RawMessage to the literal JSON null. A
// zero-length, non-nil RawMessage is invalid JSON and would make json.Marshal
// fail; Args must always be present in a recorded call, so this guarantees a
// valid value (null) when a tool was called with no arguments.
//
// The literal matters now that Args is omitempty. Returning nil would let the
// field vanish, and "called with no arguments" would become indistinguishable
// from "arguments were not recorded" — the same reason SessionInfo keeps its
// empty lists visible. Written this way the field is omitted only where it has
// no meaning at all, on a session header, and a call's bytes stay identical to
// what every earlier version wrote.
func orNull(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("null")
	}
	return raw
}
