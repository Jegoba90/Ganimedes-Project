package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// VerifyResult is the outcome of walking a log's hash chain end to end.
//
// OK is true only if every entry's stored hash matches a fresh recomputation
// AND every entry links to the previous one's hash. On the first failure, OK is
// false and BadEntry (1-based) and Reason say where and why the chain broke;
// Entries counts how many entries were read before stopping.
type VerifyResult struct {
	Entries  int    // entries read (up to and including the failing one)
	OK       bool   // whole chain intact
	BadEntry int    // 1-based position of the first broken entry, 0 if OK
	Reason   string // human-readable cause of the break, empty if OK
}

// Verify reads the JSONL log at path and checks its integrity: each entry is
// re-hashed and compared to its stored hash (catches content edits), and each
// entry's prev_hash is compared to the previous entry's hash (catches
// reordering, insertion, or deletion of earlier entries).
//
// Verify returns an error only for problems reading the file itself (missing
// file, unreadable, malformed JSON on a line). A structurally sound file whose
// chain does not hold is reported through VerifyResult.OK == false, not through
// an error: a broken chain is a finding, not a failure to run.
//
// Known limit (documented, not a bug): truncating entries from the END of the
// file leaves a shorter but internally consistent chain, so Verify cannot detect
// it without an external anchor. Edits and deletions anywhere before the end are
// detected.
func Verify(path string) (VerifyResult, error) {
	f, err := os.Open(path)
	if err != nil {
		// A missing log is a usage error worth surfacing directly ("there is
		// nothing here to verify"), not a silent OK.
		return VerifyResult{}, fmt.Errorf("opening audit log %q: %w", path, err)
	}
	defer f.Close()

	var (
		res      VerifyResult
		prevHash = genesisHash
		prevSeq  uint64
	)

	err = scanLines(f, func(line []byte) error {
		res.Entries++
		pos := res.Entries

		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			// A line we cannot parse is a read-level problem, not a chain
			// finding: we can't judge a chain we can't decode.
			return fmt.Errorf("entry %d: not valid JSON: %w", pos, err)
		}

		// 1. Content check: does the stored hash still match the payload?
		want, err := e.payload.hash()
		if err != nil {
			return fmt.Errorf("entry %d: %w", pos, err)
		}
		if e.Hash != want {
			res.fail(pos, fmt.Sprintf("content was modified (hash mismatch: stored %s, recomputed %s)", short(e.Hash), short(want)))
			return errStop
		}

		// 2. Chain check: does this entry link to the previous one?
		if e.PrevHash != prevHash {
			reason := fmt.Sprintf("broken chain link (prev_hash %s, expected %s)", short(e.PrevHash), short(prevHash))
			if pos == 1 {
				reason = fmt.Sprintf("first entry does not start the chain (prev_hash %s, expected genesis)", short(e.PrevHash))
			}
			res.fail(pos, reason)
			return errStop
		}

		// 3. Sequence check: an extra guard that seq counts 1,2,3... A gap
		// usually shows up as a chain break above first; this catches an entry
		// whose seq was tampered with while keeping the hash self-consistent.
		if e.Seq != prevSeq+1 {
			res.fail(pos, fmt.Sprintf("sequence out of order (seq %d, expected %d)", e.Seq, prevSeq+1))
			return errStop
		}

		prevHash = e.Hash
		prevSeq = e.Seq
		return nil
	})

	// errStop is our internal "stop early, the result is already recorded"
	// signal; anything else is a genuine read error.
	if err != nil && err != errStop {
		return VerifyResult{}, err
	}

	if res.BadEntry == 0 {
		res.OK = true
	}
	return res, nil
}

// fail records the first broken entry. Later calls are ignored so BadEntry/Reason
// always describe the earliest failure, but in practice scanning stops on the
// first one via errStop.
func (r *VerifyResult) fail(pos int, reason string) {
	if r.BadEntry == 0 {
		r.BadEntry = pos
		r.Reason = reason
	}
}

// errStop is a sentinel used to stop scanLines once a chain break is found; it
// never escapes Verify.
var errStop = errors.New("audit: stop scanning")

// scanLines calls fn for each non-empty line of r, without a fixed line-length
// limit. bufio.Scanner caps tokens at 64KB by default and a single tool result
// (a file's contents, an API response) can easily exceed that, so this reads
// with bufio.Reader.ReadBytes instead, which grows as needed. Trailing \r and
// \n are trimmed so a log edited on Windows (CRLF) still parses.
func scanLines(r io.Reader, fn func(line []byte) error) error {
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadBytes('\n')
		trimmed := bytes.TrimRight(line, "\r\n")
		if len(trimmed) > 0 {
			if ferr := fn(trimmed); ferr != nil {
				return ferr
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("reading audit log: %w", err)
		}
	}
}

// lastState returns the seq and hash of the last entry in the log at path, so a
// re-opened Logger can continue the chain. A missing file yields (0, genesis):
// a fresh chain. It reads only the fields it needs and tolerates a trailing
// partial line (e.g. a crash mid-write) by keeping the last fully-parsed entry.
func lastState(path string) (seq uint64, prevHash string, err error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, genesisHash, nil
		}
		return 0, "", fmt.Errorf("reading audit log %q: %w", path, err)
	}
	defer f.Close()

	seq, prevHash = 0, genesisHash
	scanErr := scanLines(f, func(line []byte) error {
		var e struct {
			Seq  uint64 `json:"seq"`
			Hash string `json:"hash"`
		}
		if err := json.Unmarshal(line, &e); err != nil {
			// Ignore an unparseable trailing line rather than refusing to open
			// the log at all; Verify is the tool that judges integrity.
			return nil
		}
		seq, prevHash = e.Seq, e.Hash
		return nil
	})
	if scanErr != nil {
		return 0, "", scanErr
	}
	return seq, prevHash, nil
}

// short trims a hash to its first 12 hex chars for readable messages. The full
// hashes stay in the file; this is only for the CLI's one-line report.
func short(h string) string {
	if h == "" {
		return "<genesis>"
	}
	if len(h) > 12 {
		return h[:12] + "…"
	}
	return h
}
