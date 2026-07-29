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

In milestone 2 the append only ever happened on the **response** side, so all
audit writes came from one goroutine and the hash chain was serialized for free
— this is what resolved §2's forward note. `audit.Logger` still takes a mutex
around each append so it is correct as a standalone component.

> **Updated in milestone 3 (see §6):** the deny-list records a blocked call from
> the **request** side, the moment the call is denied (there is no response to
> wait for). Both directions now call `Append`, so the single-writer property no
> longer holds and the `audit.Logger` mutex — not the proxy's structure — is what
> serializes the chain. CI's `-race` build proves there is no data race. This
> still satisfies Constitution Art. 3.2, whose requirement is that writes are
> *serialized* (through a channel or a mutex), which the mutex provides.

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

## 6. Milestone 3 design: the deny-list

**Goal:** a `tools/call` to a tool the operator has blocked never reaches the
real server; the client gets a clean JSON-RPC error, and the blocked attempt is
recorded. This is build-order step 3 in [`DESIGN.md`](DESIGN.md#5-build-order);
the wire behavior is diagram 3 in [`SEQUENCES.md`](SEQUENCES.md#3-deny-list).

### Two new pure packages, wired by the proxy

Following the §1 layering, the decision and the config are pure packages the
proxy calls into; neither knows about JSON-RPC framing or the audit format.

- **`internal/config`** grew a JSON `Load(path)` and a `Deny []string` field.
  JSON, not YAML, keeps the Zero-Dependency Policy (Art. 1.1). `Load` uses
  `DisallowUnknownFields`: in a security tool a mistyped key like `"denny"` must
  fail loudly, not silently leave the deny-list empty (every tool allowed). It
  also rejects trailing data after the object. `Load` does **not** require
  `Command` — the CLI may supply it — so final validation is the caller's job.
- **`internal/policy`** is the decision engine: `New(deny)` builds an `Engine`,
  `Decide(tool)` returns `Allow` or `Deny`. It is default-allow (only listed
  names are blocked), exact-match, deterministic, no ML. A nil `Engine` and an
  empty list both allow everything, so passthrough is the natural zero value.
  `REQUIRE_APPROVAL` is deliberately **not** a `Decision` value yet: nothing in
  v0 returns or enforces it, and adding it early would claim more than the code
  does (Art. 2.4). It arrives with milestone 4.

### Enforcement in the proxy (the delicate part)

The block happens on the **request** direction, before forwarding:

- `pump`'s inspect callback now returns a `bool`: for the request direction it
  decides whether to forward. `handleRequest` parses the line; for a `tools/call`
  on the deny-list it returns `false` (do not forward), and instead synthesizes a
  JSON-RPC error response (`code -32000`, a message naming the tool and the
  deny-list) straight back to the client. An allowed call is remembered for
  correlation and forwarded, exactly as in milestone 2.
- **The client stream now has two writers.** The server->client `pump` writes
  server responses; the deny path writes the error from the *other* goroutine.
  A `syncWriter` (a mutex around the client `io.Writer`) serializes them. Every
  proxy write is one full line, so serialized writes are also atomic per message
  — no interleaving. This is the Art. 3.2 concurrency guarantee; `-race` proves
  it.
- **Wire transparency (Art. 1.3) is preserved for everything not blocked.** The
  deny error is the single message on the client stream that Ganimedes authors
  rather than forwards, and it is exactly the documented policy exception ("except
  where a policy deliberately blocks or pauses a call"). A blocked request is
  never forwarded, so the server's view stays consistent (it never sees the call
  and never answers it).
- **Audit from both directions.** A denied call is appended with `decision=deny`
  from the request goroutine (there is no server response to wait for); allowed
  calls are still appended from the response goroutine. The `audit.Logger` mutex
  serializes the chain across both (see the §4 update). Enforcement does not
  depend on auditing: with `log == nil`, a denied call is still blocked.

### Config / command precedence (CLI)

`ganimedes run [--config <path>] [--log <path>] -- <server-cmd> [args]`. The
server command may come from the config file or the `--` tail; when both give
one, the **explicit command line wins**. The deny-list comes from `--config`.
With no `--config` and no deny rules, `run` is milestone-2 behavior (audit-only
passthrough).

## 7. Milestone 3 task list

Status: **deny-list core, `scan`, and the audit RFC 8785 + Ed25519 upgrade are
all code-complete** (deny 2026-07-26; scan and the seal upgrade 2026-07-28). Only
the user-driven manual smoke (item 5) remains before this milestone is fully done
(see [`DESIGN.md`](DESIGN.md) §5, §7).

1. ✅ **`internal/config`**: JSON `Load`, `Deny` field, `DisallowUnknownFields`,
   trailing-data rejection. Tests cover full/deny-only/typo/malformed/trailing/
   missing (coverage 100%).
2. ✅ **`internal/policy`**: `Engine`, `New`, `Decide` (Allow/Deny), default-allow,
   nil-safe. Table-driven tests, including case-sensitivity and no
   substring/prefix matching (coverage 100%).
3. ✅ **`internal/proxy`**: request-side policy check, block-and-inject with a
   `syncWriter`, deny audit with `decision=deny`. Tests cover a blocked call
   (client gets the error, server never sees it, both attempts audited and the
   chain verifies) and a block with `log == nil` (coverage ~82%).
4. ✅ **`internal/cli`**: `run --config`, command/deny precedence, and — closing
   the milestone-2 gap flagged in [`TESTING.md`](TESTING.md) — full unit coverage
   of dispatch, flag parsing, exit codes, and `verify` (coverage ~94%).
5. ⏳ **Manual smoke** (user-driven): wrap a real MCP server with a `--config`
   deny-list, confirm a blocked tool returns the error to the agent while allowed
   tools work, and `verify` shows the deny entry. Runs in the user's environment.
6. ✅ **`internal/scan` + `ganimedes scan`**: spawns the wrapped server, runs the
   `initialize` + `tools/list` handshake, and flags each tool by risky keyword
   (reporting-only, stdlib-only, deterministic, no ML). Tests cover keyword
   matching and its no-self-overlap invariant, the handshake against an in-memory
   server (happy path, tools/list error, premature EOF), an end-to-end scan
   against a subprocess stand-in, and rendering (coverage ~87%).
7. ✅ **Audit RFC 8785 + Ed25519 upgrade**: `internal/audit/canonical.go` (a
   hand-rolled, stdlib-only RFC 8785 canonicalizer, validated against the spec's
   §3.2.3 example) plus `keys.go` (Ed25519 keypair generate/load as PEM). Every
   entry's hash and signature are taken over the canonical payload; `verify`
   checks the signature against the public key alongside the hash and chain.
   Keys auto-generate on first `run` (0600), overridable via `--signing-key`/
   `GANIMEDES_SIGNING_KEY`; `verify` takes `--pubkey` for offline checks. Tests
   cover the RFC vectors, a forged-and-re-signed entry, the wrong key, and the
   key round-trip (audit coverage ~82%, cli ~94%).

## 8. Milestone 4 design: human-in-the-loop

**Goal:** a `tools/call` to a tool the operator flagged for review is paused; a
human approves or rejects it on a local page before it reaches the real server,
and the decision (or a timeout) is recorded. This is build-order step 4 in
[`DESIGN.md`](DESIGN.md#5-build-order); the wire behavior is diagram 4 in
[`SEQUENCES.md`](SEQUENCES.md#4-human-in-the-loop).

### One new leaf package, wired by the proxy

Following the §1 layering, the approval mechanism is a pure package the proxy
calls into; it knows about HTTP and about waiting for a human, but nothing about
JSON-RPC framing or the audit format.

- **`internal/approval`** hosts the localhost page and blocks a caller until a
  decision arrives. `New(addr, timeout)` validates that `addr` is loopback
  (Art. 2.2) and that the timeout is positive; `Start` binds the listener and
  serves `GET /` (the pending list, rendered with `html/template` so hostile tool
  names/args cannot inject script) and `POST /decision` (approve/reject).
  `Request(tool, args)` registers a pending call, blocks on a per-call buffered
  channel, and returns `Approved`, `Rejected`, or `TimedOut` (the fail-closed zero
  value). Stdlib only: `net/http`, `html/template`, `sync`, `time`.
- **`internal/policy`** grew a third verdict, `RequireApproval`, and an
  `approve` set alongside `deny`. `Decide` checks deny first, so a tool on both
  lists is denied (the stricter verdict). Everything else is unchanged and still
  default-allow.
- **`internal/config`** grew an `Approve []string` field (the same shape and
  `DisallowUnknownFields` safety as `Deny`).

### Enforcement in the proxy

The pause happens on the **request** direction, before forwarding, reusing the
milestone-3 machinery:

- `handleRequest` now switches on the policy verdict. `RequireApproval` calls
  `handleApproval`, which consults the `Approver` (an interface the proxy defines
  and `approval.Server` satisfies, so tests inject a fake and never open a
  socket). On `Approved` the call is remembered with `decision=approved` and
  forwarded, so its response completes the audit entry on the other direction,
  exactly like an allowed call but with the approved verdict. On `Rejected` or
  `TimedOut` the call is blocked like a deny: a JSON-RPC error (`code -32000`) is
  written back through the same `syncWriter`, and the attempt is audited from the
  request side with `decision=rejected` / `decision=timeout`.
- **Deny, reject, and timeout share one block path.** `blockCall` writes the
  policy error and appends the request-side audit entry; `writePolicyError` /
  `policyErrorObject` (generalized from milestone 3's deny-specific helpers)
  produce the message. Each block reason has its own wording so the agent can tell
  a deny from a rejection from a timeout.
- **Fail-closed on a missing approver.** If a call requires approval but no
  approver is wired (unreachable from the CLI, which only omits the approver when
  the approval-list is empty), the call is denied, never allowed (Art. 2.1).

### Concurrency: serial approvals (a deliberate v0 limitation)

The request-direction pump blocks inside `handleApproval` while the human decides,
so v0 handles approvals **serially**: at most one call is pending at a time and
the page shows one item. This is head-of-line blocking, acceptable for the v0
target (a single local client wrapping one server) and simpler than a queued
model ("simplicity over cleverness", Art. 1.2). The `audit.Logger` mutex still
serializes the chain across both directions (unchanged from §4's milestone-3
update); the approval wait adds no new shared state the `-race` build does not
already cover. The independent client-side timeout noted in
[`DESIGN.md`](DESIGN.md) §7 still applies: a very slow human can trip the MCP
client's own timer.

### CLI

`ganimedes run [--config <path>] [--log <path>] [--signing-key <path>]
[--approval-addr <host:port>] [--approval-timeout <dur>] -- <server-cmd> [args]`.
The approval page is started only when the config's `approve` list is non-empty;
otherwise `run` is exactly milestone-3 behavior (no page, a nil approver). The
page URL is logged to **stderr** (stdout is the protocol channel, Art. 3.1).

## 9. Milestone 4 task list

Status: **human-in-the-loop is code-complete** (2026-07-29). Only the user-driven
manual smoke (item 6) remains before this milestone is fully done (see
[`DESIGN.md`](DESIGN.md) §5, §7).

1. ✅ **`internal/config`**: `Approve []string` field, same JSON safety as `Deny`.
   Round-trip test extended to cover it (coverage 100%).
2. ✅ **`internal/policy`**: `RequireApproval` verdict, `approve` set, deny-wins
   precedence, nil-safe. Table-driven tests cover all three verdicts and the
   precedence (coverage 100%).
3. ✅ **`internal/approval`**: `Server` (`New` with loopback + timeout validation,
   `Start`/`URL`/`Close`), `Request` (blocks, fail-closed on timeout), the
   `GET /` and `POST /decision` handlers, and the auto-escaping page template.
   Tests cover the approve/reject/timeout outcomes, the loopback guard, the
   handler error paths, and the real listener via `httptest` and one live
   `Start`/`Close` (coverage ~97%).
4. ✅ **`internal/proxy`**: request-side `RequireApproval` handling via the
   `Approver` interface, `decision=approved` carried through pending correlation,
   `rejected`/`timeout` blocks reusing the deny path, fail-closed on a nil
   approver. Tests inject a fake approver for the approved/rejected/timeout paths
   and the nil-approver case (coverage ~85%, up from ~82%).
5. ✅ **`internal/cli`**: `--approval-addr` / `--approval-timeout` flags, and the
   wiring that stands up the page only when the approval-list is non-empty. Tests
   cover flag parsing, the non-loopback and address-in-use failures, and the
   happy-path wiring (coverage ~95%).
6. ⏳ **Manual smoke** (user-driven): wrap a real MCP server with a `--config`
   approval-list, trigger a flagged tools/call, open the page, and confirm
   Approve forwards the call while Reject and a timeout return the error to the
   agent; `verify` shows the `approved`/`rejected`/`timeout` entries. Runs in the
   user's environment.
