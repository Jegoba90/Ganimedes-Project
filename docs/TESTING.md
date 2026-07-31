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
| `internal/cli` | 94.9% | dispatch + exit codes, `run` flag parsing (`--log`, `--config`, `--signing-key`, `--approval-addr`, `--approval-timeout`, `--`, command precedence), `verify` intact/tampered/missing/`--pubkey` resolution, `scan` usage/config/nonexistent/happy-path, `init`/usage paths; plus which stream the help lands on (stdout when requested, stderr with the error, never split) and the wording of the tamper report (names the failing entry, never states a total it does not know, admits the rest went unchecked) |
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

**Status:** ⬜ not written yet, and now run by hand twice. On 2026-07-31 the
**published** `v0.1.0` binary was driven through exactly this shape: a throwaway
Go MCP server as a real subprocess, the release binary wrapping it as another,
with a deny-list. The denied call was blocked with `-32000` and, checked against
what the fake server recorded, never reached it; the allowed one did; the log
verified; a hand edit was caught. That is L2's whole point, and each time it has
been done the harness has been thrown away afterwards. Committing it is the gap.

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

**Status:** ⬜ still not automated, but no longer undecided. The semi-automated
option was written and used twice, and it cost about 160 lines of stdlib Go, far
less than the "real effort" this section assumed. The remaining objection is not
the client, it is that nothing about this runs in CI: it needs `npx`, a network,
and for the approval outcomes a human at a browser. What is written below is
therefore a record of runs, not a suite.

#### Run of 2026-07-31, against the published `v0.2.0` binary

Everything here used `ganimedes_v0.2.0_windows_amd64.exe` downloaded from the
release page by a third party's machine, checksum-matched and
`gh attestation verify`-clean, wrapping the official
`@modelcontextprotocol/server-filesystem` via `npx` on Windows 11. The agent was
a throwaway Go client over stdio. It matters that the binary was the published
one: every earlier smoke had used a local build, so nobody had confirmed that
what people download behaves like what we compile.

| Behavior | Evidence |
|---|---|
| `scan` against a real server | 14 tools discovered, 4 flagged: `write_file`, `edit_file`, `create_directory`, `move_file`. `edit_file` is there because of the one-word keyword fix; it used to slip through |
| Deny blocks, and blocks *before* the server | `write_file` denied: agent got `-32000`, and the file **did not exist** on disk afterwards. Nothing to undo, because nothing was done |
| Deny does not break the session | The next call, `create_directory`, succeeded and the directory really existed |
| Passthrough is untouched | The allowed call's response reached the agent verbatim, server text included |
| The chain holds | 2 entries, `chain intact and signatures valid`, exit 0 |
| Tampering is caught | Changing `"decision":"deny"` to `"allo"`, four characters, produced `TAMPERED: entry 1` with the stored and recomputed hashes side by side, exit 1 |
| Approval, approved | A human clicked Approve on the local page. The call went through and the file was really written, 30 bytes with the expected content. Logged as `approved`, **not** `allow` |
| Approval, rejected | A human clicked Reject. The agent got `-32000` reading `a human rejected the call`, distinct from the deny-list wording; the file was absent from a directory created fresh for the run; the session continued normally. Logged as `rejected` |
| Approval, timed out | ⬜ not re-run against this binary. Same code path as reject with a different trigger |

The three decisions land in the log as three different words, `deny`, `approved`
and `rejected`, which is the point of recording them at all: months later the
file distinguishes a rule that fired from a person who said no.

One behavior worth stating because it was mistaken for a fault: **the approval
page lives exactly as long as the session**. It is served by `run`, so when the
client disconnects the process exits and the port is released. Reloading the page
afterwards fails, correctly. Nothing is left listening on a developer's machine.

The harness has now been thrown away three times. That, not the difficulty, is
the gap.

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
three OSes; the race detector runs on **Linux only**. It needs cgo, which the
Windows runner has no compiler for and which produces a macOS test binary that
hits the LC_UUID/dyld abort, so Linux is the one platform where a cgo test binary
builds and runs cleanly. Data races are not OS-specific, so that single platform
is enough to catch them, and the cgo-free run covers the other two functionally.

### Release artifacts — verified after publishing, not assumed

The layers above test the code. This one tests the thing a stranger actually
downloads, which is not the same object: it was cross-compiled by a machine none
of us watched, from a commit, and served from a page anyone could in principle
replace. First run in full against `v0.1.0` on 2026-07-31, and it is the reason
`v0.2.0` exists.

| Check | What it proves | Tool |
|---|---|---|
| Download every asset anonymously | The published URLs work for someone with no token | `curl -sL -w '%{http_code}'` |
| `sha256sum -c SHA256SUMS` | The bytes match what the release says it published | stdlib |
| `go version -m <binary>` | The commit (`vcs.revision`), a clean tree (`vcs.modified=false`), `-trimpath`, `CGO_ENABLED=0`, and a `GOOS`/`GOARCH` matching the filename. Works on **every** target from any host | Go toolchain |
| `file <binary>` | The real format matches the name: no ELF shipped as `.exe`, no arm64 labelled amd64 | `file` |
| Grep for build paths | No `/home/runner`, no local username, i.e. `-trimpath` did its job | `grep -aF` |
| Rebuild the tagged commit | The published bytes are what this source produces | clean clone + `GOTOOLCHAIN=<the version in the buildinfo>` |
| `gh attestation verify` | The binary came out of this repository's workflow | `gh` |
| Run the binary | The version stamp is real and the documented behavior is the shipped behavior | the binary itself |

Two traps worth writing down, both of which produced a false green before being
caught:

- **`gh attestation verify` prints nothing and exits 0 outside a TTY.** Read the
  exit code, not the screen, and confirm with a negative control: append one byte
  to a binary and the same command must fail with HTTP 404, because no attestation
  exists for that digest.
- **A rebuild will not be byte-identical, and that is not a failure.** Go embeds a
  build ID whose leading components hash the host toolchain, so a Linux runner and
  a Windows workstation differ there by design. What must match is the build ID's
  **last component, the content ID**, plus every other byte. For `v0.1.0` that came
  to 40 differing bytes out of ~7 MB on five targets, and 72 on darwin/arm64, where
  Go adds an ad-hoc code signature and the build ID lives in the page whose hash
  the signature covers.

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
