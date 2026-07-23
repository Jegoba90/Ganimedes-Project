# Ganimedes - Internal Architecture & Development Plan

> Living document. Companion to [`DESIGN.md`](DESIGN.md) (the what/why and the
> build order) and [`SEQUENCES.md`](SEQUENCES.md) (the wire-protocol view).
> This file is the internal, Go-level design: how the packages connect, what
> the core types look like, and the concrete task list to start coding
> milestone 1.

## 1. Package responsibilities and how they connect

```
cmd/ganimedes/main.go
        │  os.Exit(cli.Run(os.Args[1:]))
        ▼
internal/cli
        │  parses the subcommand, loads config, calls proxy.Run
        ▼
internal/proxy  ◀── internal/config (what to spawn, deny/approval lists)
        │       ◀── internal/policy (milestone 3+: ALLOW/DENY/REQUIRE_APPROVAL)
        │       ──▶ internal/audit  (milestone 2+: append-only hash-chained log)
        ▼
  the real MCP server (subprocess, spawned via os/exec)
```

`proxy` is the only package that talks to the outside world (stdio to the
client, a subprocess to the real server). `policy` and `audit` are pure
logic/IO packages with no knowledge of JSON-RPC framing; `proxy` calls into
them. This keeps each package testable on its own, without spawning a real
subprocess or a real MCP client.

## 2. Milestone 1 design: transparent passthrough

**Decision: raw line forwarding, no JSON parsing yet.** Milestone 1 only has
to prove the pipe works: spawn the real server, shuttle bytes both ways
without corrupting anything. Parsing JSON-RPC is not needed to prove that, and
skipping it keeps milestone 1 small. Parsing gets introduced in milestone 2,
when the audit log needs to read `tool`/`args`/`result` out of each message.
When it is introduced, the **original raw bytes are still what gets
forwarded** (never a re-marshaled copy), so nothing we do to inspect a message
can accidentally change it on the wire.

### Core types

`internal/config` owns the configuration type; `internal/proxy` consumes it:

```go
// package config
type Config struct {
    Command string   // executable of the real MCP server to wrap
    Args    []string // arguments passed to Command
}

// package proxy
//
// Run wires a client (reading from in, writing to out) to the MCP server
// described by cfg. in/out are plain io.Reader/io.Writer, not hardcoded to
// os.Stdin/Stdout, so tests can drive it with in-memory streams. It blocks
// until the server closes its output, then reaps the process.
func Run(cfg config.Config, in io.Reader, out io.Writer) error
```

### Concurrency model

MCP over stdio is two independent byte streams. `Run` spawns the real server
with `os/exec`, wires its `StdinPipe()`/`StdoutPipe()`, and starts **two
goroutines**, one per direction:

```
goroutine 1:  in (client)        --verbatim (io.Copy)-->  server's stdin
goroutine 2:  server's stdout    --verbatim (io.Copy)-->  out (client)
```

For milestone 1 each direction is a plain `io.Copy` (raw byte passthrough): no
line framing, no parsing, and no maximum-line-length limit to worry about.
`Run` waits on the server->client copy to finish (the server closing its stdout
is what ends the session), then calls `cmd.Wait()` to reap the process. Line
framing, needed to inspect individual messages, is introduced in milestone 2,
which forwards the original bytes regardless.

**Forward note (resolved in [§4](#4-milestone-2-design-the-audit-log)):** the
hash chain requires writes in a strict order (each entry's hash depends on the
previous one). Milestone 2 solves this by writing every audit entry from a
single direction — the server->client goroutine, where results arrive — so the
appends are naturally serialized without a channel or a shared-file mutex. See
§4 for the details.

## 3. Milestone 1 task list

Status: **milestone 1 code complete** (2026-07-23). Steps reflect what was
actually built; where it diverged from the original plan, the note says why.

1. ✅ **`internal/config`**: `Config` struct defined. The YAML `Load` was
   **deferred to milestone 3**: milestone 1 needs only which server to spawn,
   which the CLI takes from its arguments, so no config file (and no file
   format) is needed yet. When the file arrives in milestone 3 it will be JSON
   (stdlib, keeps the zero-dependency promise), not YAML.
2. ✅ **`internal/proxy`**: `Run(cfg, in, out) error` implemented. Spawns the
   subprocess, wires its pipes, runs one goroutine per direction, waits on the
   server->client direction, then reaps the process. Uses `io.Copy` (raw byte
   passthrough) rather than line reading; line framing lands in milestone 2.
3. ✅ **`internal/cli`**: `run` wired to `runCommand`, which parses
   `ganimedes run -- <server-cmd> [args]` and calls
   `proxy.Run(cfg, os.Stdin, os.Stdout)`.
4. ⏳ **Manual test** (user-driven): point an MCP client at Ganimedes wrapping a
   real MCP server and confirm the agent behaves as if talking to the server
   directly. Pending; runs in the user's environment.
5. ✅ **Automated test**: `proxy_test.go` drives `Run` with an in-memory reader
   and the test binary re-executed as an echo "server" (the standard
   `TestHelperProcess` pattern), so CI needs no external MCP server. proxy
   package coverage: 72.2%. An additional manual smoke wrapping the real `sort`
   binary confirmed end-to-end passthrough.

Milestone 1's acceptance (the agent works transparently through the proxy) is
met for the automated path; the manual test against a real MCP server (step 4)
remains for the user to run.

## 4. Milestone 2 design: the audit log

**Goal:** every `tools/call` and its result are appended to a hash-chained
JSONL file, the client sees nothing different, and `ganimedes verify` proves the
file was not altered after the fact. This is build-order step 2 in
[`DESIGN.md`](DESIGN.md#5-build-order); the wire behavior is diagram 2 in
[`SEQUENCES.md`](SEQUENCES.md#2-audit-log).

### From byte passthrough to line framing

Milestone 1 forwarded with `io.Copy` (raw bytes, no parsing). To recognize a
`tools/call`, the proxy now reads the stream as **newline-delimited JSON** with
`bufio.Reader.ReadBytes('\n')` — not `bufio.Scanner`, whose 64KB token limit a
single tool result (a file's contents, an API payload) can easily exceed;
`ReadBytes` grows as needed.

**The wire bytes never change.** Each message is forwarded as the exact bytes
that were read; parsing happens on a separate pass purely to observe. Nothing we
do to inspect a message can reshape it on the way through, which is the whole
trust story of an inline proxy.

### Ordering: inspect-first vs forward-first

The two directions treat the inspect step differently, on purpose:

- **client -> server (requests): inspect BEFORE forwarding.** The pending call
  must be recorded before the server can possibly receive the request and
  answer it; otherwise the response could reach the other goroutine before we
  know to expect it (a lost audit record, and a race).
- **server -> client (responses): forward BEFORE inspecting.** Auditing is an
  observer and must never delay delivery to the client. The pending entry is
  already recorded, so the append can safely happen after the client has its
  result.

### Correlation and the single-writer property

A `tools/call` request (direction 1) and its response (direction 2) run on
different goroutines. They are matched by JSON-RPC `id` through a small
mutex-guarded map: the request side stores `{id -> tool, args}`, the response
side takes it back out when a matching `id` returns.

The append itself only ever happens on the **response** side, so **all** audit
writes come from one goroutine and the hash chain is serialized for free — this
is what resolves §2's forward note. `audit.Logger` still takes a mutex around
each append so it is correct as a standalone component, but the proxy does not
rely on that mutex for ordering.

### The hash chain (package `audit`)

Each line is one `Entry`: a `payload` (seq, timestamp, session, tool, args,
result/error, decision, `prev_hash`) plus the `hash` that seals it.

- **`hash = SHA-256(json.Marshal(payload))`, hex-encoded.** `payload` is a
  struct with no maps, so `json.Marshal` emits its fields in a fixed order and
  the serialization is deterministic. `args`/`result`/`error` are kept as
  `json.RawMessage`: the encoder compacts each one deterministically, so the
  same input always yields the same bytes and therefore the same hash. This is
  byte-canonicalization of the stored record, not semantic JSON
  canonicalization — it seals exactly what was recorded.
- **Why a separate `payload` struct embedded in `Entry`:** hashing an entry
  means "serialize it without its own hash". Embedding flattens `payload`'s
  fields into `Entry`, so `json.Marshal(entry.payload)` *is* the entry minus its
  hash, with no field list written twice.
- **Chain link:** each entry's `prev_hash` is the previous entry's `hash`; the
  first entry's is the genesis value (empty string). `Verify` recomputes every
  hash (catching content edits) and checks every `prev_hash` against the prior
  entry (catching reordering, insertion, or deletion).
- **Resume:** `Open` reads the last entry so a re-opened log continues its chain
  (seq keeps counting, `prev_hash` keeps linking) instead of forking a second
  chain in the same file.

### Honest limits (documented, not bugs)

- **Tail truncation is not detectable.** Removing entries from the *end* leaves a
  shorter but internally consistent chain. Detecting that needs an external
  anchor (publishing the head hash), which is a later feature. Edits and
  deletions anywhere before the end are caught.
- **The log may contain secrets.** Full args and results can include tokens or
  PII, so the file is written `0o600` and redaction is a planned later feature.
- **Auditing fails open.** If an append fails (full disk, permissions), the
  proxy logs to stderr and keeps forwarding the agent's traffic. Losing a record
  is the lesser harm; taking the agent down is not the proxy's call to make.

## 5. Milestone 2 task list

Status: **milestone 2 code complete** (2026-07-23).

1. ✅ **`internal/audit`**: `Entry`/`payload` types, `Logger` (`Open`, `Append`,
   `Close`, `NewSession`), the SHA-256 chain, and `Verify` + `VerifyResult`.
   Unit tests cover append/verify, content-edit and deletion detection, chain
   resume, error responses, and null args (coverage ~79%).
2. ✅ **`internal/proxy`**: line-framed forwarding with verbatim wire bytes,
   `tools/call` request/response correlation by id, and one append per completed
   call. Test drives `Run` end to end against a JSON-RPC helper server and
   verifies the resulting log (coverage ~81%).
3. ✅ **`internal/cli`**: `run` gained `--log <path>`; `verify [path]` walks the
   chain and exits non-zero on a break.
4. ✅ **Manual smoke** (done): built the binary, wrapped a fake MCP server, ran
   two `tools/call`s (a `tools/list` was correctly *not* audited), confirmed the
   client got both responses verbatim, `verify` reported the chain intact, and a
   hand-edit to the log made `verify` report the tampered entry and exit 1.
