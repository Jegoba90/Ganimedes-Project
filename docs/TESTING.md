# Ganimedes - Test Plan

> Living document. Companion to [`DESIGN.md`](DESIGN.md) (what we're building)
> and [`SEQUENCES.md`](SEQUENCES.md) (the runtime behavior each layer below
> checks against). Describes what gets tested, at which layer, and with what
> tool — and, just as important, why the usual API-testing tools (Postman,
> Swagger) don't apply to most of this project.

## 0. Why not Postman

Postman (and the Swagger-paste workflow used on CryptoCapi) tests **HTTP
endpoints**: request in, JSON response out. Ganimedes v0 has no HTTP surface to
point it at — the proxy speaks **MCP over stdio** (newline-delimited JSON-RPC
2.0 over a subprocess's stdin/stdout), and the CLI is invoked directly, not
called over a network.

The one place an HTTP surface will exist is **milestone 4's human-in-the-loop
approval page** (`net/http` on localhost, per `DESIGN.md` §6 open decisions).
Whether that page also exposes a small JSON API (`GET /pending`,
`POST /approve/:id`) that Postman could drive is a **design decision deferred to
milestone 4**, not something v0 needs. Tracked as a forward note here; revisit
when M4 starts.

Until then, every test in this plan is either a Go `testing` package test or a
process-level smoke check — no separate testing framework, consistent with the
Zero-Dependency Policy (Constitution Art. 1.1).

## 1. Test layers

### L1 — Unit tests (package-level, in-process)

**What:** pure logic, exercised by calling package functions directly — no
subprocess, no real binary. This is where the hash chain, the JSON-RPC
correlation logic, and the CLI's argument parsing get their fastest, most
precise feedback.

**Tool:** Go's standard `testing` package only (no testify — Constitution Art.
1.1 zero-dependency policy). Table-driven tests where the cases are
homogeneous; the test binary itself standing in for an MCP server via
`TestMain`/helper-process re-exec (already used in `proxy_test.go`) rather than
a mocking library.

**Status:**

| Package | Coverage | Notes |
|---|---|---|
| `internal/audit` | 83.1% | append/verify, content-edit + deletion detection, chain resume, error responses, null args; RFC 8785 canonicalization (spec §3.2.3 vectors, ES6 numbers, key order) and Ed25519 signing (valid, forged-and-re-signed, wrong-key) + keypair generate/load round-trip |
| `internal/proxy` | 84.5% | passthrough, tools/call correlation + audit append, the M3 deny path (blocked call errored + audited, block without a log), and the M4 approval path (approved forwards, rejected/timeout block, nil approver fails closed) via the in-process helper-process pattern |
| `internal/approval` | 96.7% | approve/reject/timeout outcomes, the loopback guard in `New`, handler error paths, and a live listener via `httptest`; the fake `Approver` in the proxy tests keeps them socket-free |
| `internal/cli` | 94.8% | dispatch + exit codes, `run` flag parsing (`--log`, `--config`, `--signing-key`, `--approval-addr`, `--approval-timeout`, `--`, command precedence), `verify` intact/tampered/missing/`--pubkey` resolution, `scan` usage/config/nonexistent/happy-path, `init`/usage paths |
| `internal/scan` | 86.8% | keyword matching + its no-self-overlap invariant, the `initialize`+`tools/list` handshake against an in-memory server (happy path, tools/list error, premature EOF), an end-to-end scan against a subprocess stand-in, and report rendering |
| `internal/config` | 100% | JSON `Load`: full, deny-only, unknown-field rejection, malformed, trailing data, missing file |
| `internal/policy` | 100% | `Decide` decision table: deny-list hits, default-allow, case-sensitivity, nil engine |

**Gap closed (2026-07-26):** `internal/cli` went from 0% to 94.2% with the M3
work — its branching logic (flag parsing, error paths, exit codes) is now
covered. `Run([]string) int` is designed to be called in-process (no `os.Exit`
inside it), so these are same-shape L1 tests, not a new layer.

### L2 — Component tests (black-box binary, still no external MCP server)

**What:** build the actual `ganimedes` binary and run it as a **real
subprocess** (not by calling Go functions in-process), wrapping a fake MCP
server (also a real subprocess). This is the layer that catches bugs L1 can't:
wrong flag wiring in `main.go`/`cli.go`, `os.Exit` codes, stdio actually
connected end to end through two real process boundaries instead of in-memory
`io.Reader`/`io.Writer`.

This formalizes, as a repeatable test, what has been checked by hand each sprint.
Most recently (2026-07-28) the full path was smoked against the real binary: `run`
generated a signing key and wrote a signed entry, `verify` reported OK, a content
edit was caught as a hash mismatch, and verifying with the wrong public key
failed — all exercised manually, including the RFC 8785 + Ed25519 seal.

**Tool:** a Go test in a new `cmd/ganimedes` test file (or a small
`internal/e2e` test package) using `os/exec` to invoke the **compiled binary**
under test — `go build` it into a temp dir in `TestMain`, then drive it via
`exec.Command` with real pipes. Still stdlib-only.

**Status:** ⬜ not written yet. Currently exists only as an ad hoc manual
PowerShell session, not committed, not repeatable in CI.

### L3 — E2E (a real MCP server, not our stand-in)

**What:** wrap an actual third-party MCP server (not the test binary's
echo/canned-response helper) and confirm an agent talking to it **through**
Ganimedes behaves identically to talking to it directly — the acceptance bar
stated in Constitution Art. 1.3 and `ARCHITECTURE.md`'s milestone 1 task list.

This is the layer `ARCHITECTURE.md` already flagged as a **pending manual
step** for milestone 1 ("point an MCP client at Ganimedes wrapping a real MCP
server... runs in the user's environment") — it was never automated, and
still isn't.

**Tool options, not yet decided:**
- Manual: point Claude Desktop (or another real MCP client) at Ganimedes
  wrapping a real reference server, eyeball the behavior. Zero engineering
  cost, but not repeatable in CI and depends on the user's machine.
- Semi-automated: a minimal Go test client that speaks just enough MCP
  (`initialize` → `tools/list` → `tools/call`) against a known reference
  server (e.g. a filesystem MCP server), run both directly and through
  Ganimedes, diff the two transcripts byte-for-byte.

**Status:** ⬜ undecided which approach to invest in; recommend staying manual
(matching the existing M1 precedent) unless a regression in this area actually
happens — building a full reference MCP client is real effort for a one-person
project with "no rush" as the stated goal ([[project_ganimedes_goal_seed_not_wealth]]
equivalent: craftsmanship over velocity, but also not gold-plating a harness
nobody asked for).

### L4 — Adversarial / security-property tests

**What:** the properties that matter *because this is a security tool*, tested
deliberately rather than incidentally.

| Case | Status |
|---|---|
| Content edit breaks the hash chain | ✅ `TestVerify_DetectsContentEdit` |
| Deleting an entry breaks the chain | ✅ `TestVerify_DetectsDeletion` |
| Forged entry: content edited, hash recomputed, re-signed with another key | ✅ `TestVerify_DetectsForgedEntry` |
| Log verified against the wrong public key | ✅ `TestVerify_WrongKey` |
| Chain resumes correctly across log reopen | ✅ `TestResumeChain` |
| Error responses (no result) recorded correctly | ✅ `TestAppend_RecordsErrorResponses` |
| Malformed/garbage JSON-RPC line (not valid JSON) | ⬜ not tested — `pump`/`recordRequest`/`recordResponse` silently ignore unparseable lines by design, but there's no test proving that behavior (forward, don't crash, don't audit) |
| A single message larger than 64KB | ⬜ not tested — `ReadBytes` was deliberately chosen over `bufio.Scanner` to avoid this limit, but no test exercises a large payload to prove it |
| The wrapped server process dies mid-session | ⬜ not tested |
| Audit log write fails (disk full / permissions) mid-session | ⬜ not tested — code path exists (`proxy.go`'s `recordResponse` logs to stderr and swallows the error per the fail-open design), no test proves the proxy keeps running |
| CRLF-terminated log lines still parse | ✅ implicitly via `scanLines`' `TrimRight(line, "\r\n")`, but no explicit test |

**Gap to close:** the malformed-input, oversized-message, and crashed-subprocess
cases are the highest-value additions here — they're exactly the kind of thing
that's easy to get wrong silently in a proxy, and L1 already has the harness
(`TestHelperMCPServer`-style helper processes) to add them cheaply.

### L5 — Smoke tests

**What:** the fast, shallow "is anything on fire" check — build succeeds,
`ganimedes version`/`help` return 0, one full wrap-run-verify happy path
completes. Meant to be the first signal on every push, before the fuller L1-L4
suite.

**Tool:** could be a `-short`-tagged subset of the existing `go test` suite
(Go's built-in convention: `testing.Short()`), or a tiny separate smoke test
file. Doesn't need a new tool.

**Status:** ⬜ not separated out yet — right now everything runs as one
`go test ./...` pass in CI (see `.github/workflows/ci.yml`). Worth doing only
if the full suite gets slow enough that a fast first-signal matters; at the
current size (seconds, not minutes) this is a nice-to-have, not urgent.

### Cross-platform

**What:** `os/exec` and file permissions behave differently across Windows,
Linux, and macOS, and Ganimedes ships as a binary for all three.

**Status:** ✅ already wired — CI builds and runs the full test suite on all
three OSes; the race detector runs on Linux/macOS only (needs cgo, unavailable
on the Windows runner and on this dev machine).

## 2. Where Postman *might* re-enter (forward note, not a decision)

The open question was: if milestone 4's approval page exposed JSON endpoints
alongside its HTML form, that surface would be real HTTP and Postman would become
a legitimate manual smoke-check tool for it, the same paste-the-JSON-back workflow
already used for CryptoCapi.

**Answered 2026-07-30, now that M4 is built: no.** `internal/approval` serves
exactly two routes, `GET /` and `POST /decision`, and the only content type it
ever writes is `text/html`. The decision arrives as an HTML form submission
(`application/x-www-form-urlencoded`), not JSON, so there is no JSON surface for
Postman to exercise. The approval flow is smoke-checked by clicking the page,
which is F5 in [`GO_NO_GO.md`](GO_NO_GO.md). Postman stays out. This would only
reopen if a later version adds a machine-facing approval API (a webhook, a desktop
client), which is not in v0.

## 3. Summary: what to build next, in order of leverage

1. ✅ **`internal/cli` unit tests (L1).** Done 2026-07-26 with the M3 work
   (0% → 94.2%): flag parsing, exit codes, and `verify` outcomes are covered.
2. **Adversarial cases for the proxy (L4).** Malformed JSON, oversized message,
   crashed subprocess — the harness already exists, these are incremental
   additions.
3. **Black-box binary test (L2).** Turns last session's manual PowerShell smoke
   check into a repeatable, CI-covered test.
4. **E2E against a real MCP server (L3).** Lowest leverage for now — stays
   manual, revisit only if a real regression shows up in this area.
5. **Smoke-test split (L5)**: still deferred until the suite is slow enough for
   a fast first signal to matter. **M4's Postman question** is no longer on this
   list: it was answered "no" on 2026-07-30 (§2).

None of items 2-5 block the v0 release. They are leverage, not gates: the release
gate is [`GO_NO_GO.md`](GO_NO_GO.md), and the plan for reaching it is step 5 of
`DESIGN.md` §5. Item 2 (adversarial cases) is the one worth doing first once v0 is
out, because it covers failure modes a security tool is judged on.
