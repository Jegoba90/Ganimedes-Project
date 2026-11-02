# Ganimedes - Test Plan

> Living document. Companion to [`DESIGN.md`](DESIGN.md) (what we're building)
> and [`SEQUENCES.md`](SEQUENCES.md) (the runtime behavior each layer below
> checks against). Describes what gets tested, at which layer, and with what
> tool — and, just as important, why the usual API-testing tools (Postman,
> Swagger) don't apply to most of this project.

## 0. Why not Postman

Postman (and the Swagger-paste workflow used on CryptoCapi) tests **HTTP
endpoints**: request in, JSON response out. The gateway speaks **MCP over stdio** (newline-delimited JSON-RPC
2.0 over a subprocess's stdin/stdout), and the CLI is invoked directly, not
called over a network.

The **human-in-the-loop approval page** is an HTTP surface: `GET /` and form
`POST /decision` on loopback. It is tested through `net/http/httptest` and live
local listeners, including Host, CSRF, framing headers and body limits. It has
no JSON `/pending` or `/approve/:id` API.

Every automated test in this plan is either a Go `testing` package test or a
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

Updated 2026-11-02 from the full Windows/amd64 suite on Go 1.26.10. The measured
pre-change and final values, mutation evidence and execution limits are in
[`AUDITORIA_2026-11-02.md`](AUDITORIA_2026-11-02.md). CI checks these floors through
`.github/coverage-baseline.json`; an artificial 100% to 0% regression was verified
to fail the checker.

| Package | Coverage | Notes |
|---|---|---|
| `internal/jsoncheck` | 96.0% | shared strict JSON validation: duplicate/escaped names, Unicode, trailing values and nesting bounds |
| `internal/audit` | 86.3% | append/verify, content-edit + deletion detection, chain resume, error responses, null args; RFC 8785 canonicalization (spec §3.2.3 vectors, ES6 numbers, key order) and Ed25519 signing (valid, forged-and-re-signed, wrong-key) + keypair generate/load round-trip |
| `internal/proxy` | 92.4% | passthrough, tools/call correlation + audit append, the M3 deny path (blocked call errored + audited, block without a log), and the M4 approval path (approved forwards, rejected/timeout block, nil approver fails closed) via the in-process helper-process pattern |
| `internal/approval` | 96.7% | approve/reject/timeout outcomes, the loopback guard in `New`, handler error paths, and a live listener via `httptest`; the fake `Approver` in the proxy tests keeps them socket-free |
| `internal/cli` | 95.7% | dispatch + exit codes, `run` flag parsing (`--log`, `--config`, `--signing-key`, `--approval-addr`, `--approval-timeout`, `--`, command precedence), `verify` intact/tampered/missing/`--pubkey` resolution, `scan` usage/config/nonexistent/happy-path, `init`/usage paths; plus which stream the help lands on (stdout when requested, stderr with the error, never split) and the wording of the tamper report (names the failing entry, never states a total it does not know, admits the rest went unchecked) |
| `internal/scan` | 96.3% | keyword matching + its no-self-overlap invariant, the `initialize`+`tools/list` handshake against an in-memory server (happy path, tools/list error, premature EOF), an end-to-end scan against a subprocess stand-in, and report rendering |
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

#### Run of 2026-08-01, under a real MCP client

The first run driven by a real MCP client. Every run before it used a throwaway
Go client, so the one scenario every user starts with had never been exercised.
Setup: the published `v0.2.0` Windows binary, declared in a Claude Code project's
`.mcp.json` exactly as the README documents, wrapping
`@modelcontextprotocol/server-filesystem` through `npx`, with the log and signing
key pinned to absolute paths outside the directory the server could reach.

| Behavior | Evidence |
|---|---|
| The client sees an ordinary server | `/mcp` listed the wrapped server as `✓ Connected`, and the agent used it with no sign the gateway was in the path |
| Connecting is not acting | After connecting and before any request, `audit.jsonl` existed and held zero entries: `initialize` and `tools/list` are not tool calls |
| Keys land where they were pinned | `signing.key` and `signing.pub` appeared beside the log at the given paths, not in the client's working directory |
| An agent's own choices are logged | One plain-language request produced 3 entries, `list_allowed_directories`, `write_file` and `read_text_file`, carrying the arguments the agent picked rather than any a human typed |
| The chain holds under a real client | `verify --pubkey`: 3 entries, `chain intact and signatures valid`, exit 0 |

**What it found.** The wrapped server was handed one directory on its command
line and worked in the Claude Code project directory instead. That server asks
the client for MCP Roots and prefers them over its own arguments; the throwaway
client offers none, which is why every earlier run saw the argument respected.
`scan` had been printing the server's own words for this all along and nobody
read them: `Client does not support MCP Roots, using allowed directories set from
server args`.

Two consequences, both recorded as TD-4 in [TECH_DEBT.md](TECH_DEBT.md). A
wrapped server's scope can change after launch and the log does not record it:
here it is in the file only because the agent happened to call
`list_allowed_directories` first. And the effective directory held the
`.mcp.json` that configures the gateway, so the supervised server could write to
the file describing its own supervision.

Pulling that thread found something wider than the run itself, and it is why
this log format now opens each run with a session header: the file recorded what
happened without recording the rules it happened under. That half is fixed
(`DESIGN.md` §7); the scope renegotiation is what TD-4 still tracks.

The harness was thrown away three times, and the fourth run needed none, because
a real client is the harness. That the semi-automated client keeps being
rewritten is still the gap for the runs that cannot use one.

#### Run of 2026-08-03, walking the flow to find where it snags

Not a release check. The question was whether someone else can get through the
flow, so the target was a local build of the working tree driven by a throwaway
Go client, and the interesting part was the error paths rather than the happy one.
The happy path held: `scan` found 14 tools and flagged 4, `deny` returned `-32000`
without the file ever appearing, `verify` reported 3 entries intact, and an
approval left unanswered failed closed.

| Behavior | Evidence |
|---|---|
| Config mistakes explain themselves | A typo'd key gave `unknown field "denny"`, malformed JSON named the offending character, and a non-loopback `--approval-addr` was refused citing Art. 2.2 |
| A second wrapped server cannot take the port | With `127.0.0.1:8765` already held, `run` exits 1 at startup. A client shows this only as a server that would not start, so `run` now adds a line naming `--approval-addr` |
| A timeout reaches the human | The startup line with the page's address goes to stderr, which a client files in a log nobody opens. The timeout error the agent receives now carries the address, verified to be the one actually bound (`8799` in the run, not the default) |
| `verify` in the wrong directory misdiagnoses | With neither log nor key present it reports `no public key found`, never that there is no log there. Known, not fixed |
| An aborted run still leaves a header | The session header is written before the approval page binds, so a run that dies at startup leaves a log declaring rules for a session that proxied nothing. Known, not fixed |

**What it found beyond the two fixes.** The README omitted the one thing Art. 2.5
requires stating plainly, that the log holds whatever crossed the wire and is as
sensitive as that traffic. It was written in `SECURITY.md`, `DESIGN.md` and
`GO_NO_GO.md`, and absent from the only document a person reads before deciding
where to put the file. That is the same shape as the three README failures before
it: the fact was true, written down, and not where the reader was.

**Second half, under a real client.** Putting the address in the timeout error
rests on an assumption a throwaway client cannot test: that a client shows the
`message` of a tool error to the person sitting there. So the same build went
into a Claude Code project's `.mcp.json`, wrapping `server-filesystem` with
`read_file` and `read_text_file` denied, `write_file` held for approval, and a
20-second timeout.

| Behavior | Evidence |
|---|---|
| The deny reason reaches the screen | `MCP error -32000: blocked by Ganimedes policy: tool "read_text_file" is on the deny-list`, shown verbatim and unfolded, and the agent restated it in its own words |
| The timeout reason reaches the screen, address included | `MCP error -32000: blocked by Ganimedes: approval for tool "write_file" timed out; it was waiting for a human at http://127.0.0.1:8765/`. The assumption holds: the error is a usable channel to a human |
| Fail-closed, confirmed against the disk | The agent listed the directory afterwards. `notes.md` was never created |
| A bypass exists and was not taken | Offered the native write tool as an alternative, the agent declined to use it unprompted, on the grounds that it would skip a control someone had put there deliberately |
| Both attempts are in the chain | 5 entries (3 session headers, `decision=deny`, `decision=timeout`), `chain intact and signatures valid` |

**What that run corrected in the wording.** The message first read `nobody
answered at <url>`, and the agent concluded from it that the approval service was
probably not running, offering to start it. The page was up and serving; a person
was the missing part. A sentence about an address that goes unanswered reads as a
dead service, and it pushed the reader toward the one action that was not needed.
It now reads `it was waiting for a human at <url>`, which states that the page
existed and that the decision was the reader's. That replacement was re-run
against the real server before it was committed, and again against the published
binary once `v0.3.1` shipped (see the artifact run below), because a message is
only true of what people can download.

**And a boundary worth naming.** The first attempt at the deny test asked the
agent in plain language to read a file, and the log recorded nothing at all: the
client answered with its own built-in read tool and never touched the wrapped
server. Naming the MCP tool explicitly was what routed the call through the
gateway. A wrapped server competes with whatever the client can already do
itself, so an empty log does not mean an idle agent; it can mean an agent that
worked outside MCP entirely. The README says the log covers "only the server it
wraps", which is true and reads like a note about scope rather than the practical
warning this is.

#### Run of 2026-11-02, before tagging `v1.0.0`

The first real-client run since the 2026-11-02 audit changed the request path,
the log format and the approval page. The target was a local build of `main` at
`7897c6a`, built with the release workflow's flags and stamped `v1.0.0-smoke`,
wrapping `@modelcontextprotocol/server-filesystem@2026.8.31` through `npx` on
Windows 11. The policy denied `move_file` and held `write_file` for approval. The
agent was Claude Code 2.1.314 in print mode, given only that server
(`--strict-mcp-config`), only its MCP tools, and the sandbox directory as its
working directory so that the MCP Roots it offered matched the server argument.

| Behavior | Evidence |
|---|---|
| `scan` against the real server | 14 tools, 4 flagged, the same as July. The first attempt failed; see below |
| Allowed calls pass untouched | `read_text_file` returned the file's text verbatim to the agent |
| Deny blocks before the server | The agent quoted `blocked by Ganimedes policy: tool "move_file" is on the deny-list`; `notes.txt` was not moved |
| Approve in a browser | The file was written, logged `approved` |
| Reject in a browser | The client got `-32000` `a human rejected the call to tool "write_file"`, the file never existed, logged `rejected`. Also checked by a scripted POST of the form, with the same result |
| Host check in a real browser | `http://localhost:8767/` showed `unexpected Host; use the advertised approval URL` while `127.0.0.1:8767` served the page |
| Anti-framing headers | `Content-Security-Policy: frame-ancestors 'none'`, `X-Frame-Options: DENY` and `Cache-Control: no-store` on the live page. Framing itself was not attempted |
| New records are bound | Every call record carried `content_hash`; the 6-entry log verified intact |
| Tampering is caught | `"decision":"deny"` edited to `"allow"` gave `TAMPERED: entry 3`, exit 1 |
| `verify` refuses two logs | exit 2, naming both paths |

**What it found.** The first `scan` ran while `npx -y` was still downloading
the server, overran the 15-second deadline and failed, which is correct. Its
message was not: `reading server response: read |0: file already closed`.
Closing the pipes on expiry, the audit's fix for an inherited stdout, had turned
the deadline into a bare read error. v0.3.3 at least asked "crashed or timed
out?". The message now says the deadline passed and names the likely first-run
download. `TestScan_TimeoutClosesInheritedOutput` asserts that wording, and
`TestScan_ExitWithoutAnswerIsNotADeadline` asserts a crash is not blamed on the
deadline. Each was seen to fail with its half of the check removed.

**And one thing that was not a defect.** In the first approval run both writes
went through. The log said `approved` twice, the two writes were 66 seconds
apart, and the tester confirmed clicking Approve on the second. The log recorded
exactly the click it received. Reject was then exercised in the browser as
above.

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
| Malformed/ambiguous client frames, tool notifications and invalid Unicode | ✅ adversarial request tables in `request_security_test.go`; refused with exact base64 evidence |
| Large frames and memory bounds | ✅ messages over 64KB within the 16 MiB ceiling pass intact; frames beyond the ceiling fail before forwarding; pending count/byte caps tested |
| The wrapped server process dies or ignores EOF | ✅ helper-process lifecycle tests cover input errors, output errors, forced shutdown and inherited stdout |
| A killed writer's lock blocks the next start, or a second writer forks the chain | ✅ `TestOpenAfterWriterIsKilled` (a re-executed test binary holds the log and is killed for real), `TestOpenRejectsConcurrentWriter`, `TestOpenRejectsWriterThroughHardLink`, `TestVerifyWhileWriterHoldsLock`. Seen to fail with no lock, with the former O_EXCL sidecar, with the Windows lock over the content, and with a write-only handle. Windows only so far; `flock` runs first in CI |
| Audit log write fails (disk full / permissions) mid-session | ⬜ not tested — code path exists (`proxy.go`'s `recordResponse` logs to stderr and swallows the error per the fail-open design), no test proves the proxy keeps running |
| CRLF-terminated log lines still parse | ✅ implicitly via `scanLines`' `TrimRight(line, "\r\n")`, but no explicit test |
| A `tools/call` smuggled inside a JSON-RPC batch reaches the server unjudged | ✅ `TestRun_RefusesJSONRPCBatch`, `TestRun_RefusesBatchWithoutLog`, plus `TestIsJSONArray` / `TestBatchIDs` / `TestWriteBatchRefusal` (added 2026-09-22, `v0.3.3`) |
| Two overlapping calls reusing one JSON-RPC id corrupt the audit pairing | ✅ `TestPending_Remember_RejectsCollision`, `TestHandleRequest_RejectsIDReuse`, `TestHandleApproval_RejectsIDReuse`, and `TestHandleRequest_AllowsIDReuseAfterCompletion` for the reuse that must stay allowed (added 2026-09-22, `v0.3.3`) |
| A cross-site form POST decides a held approval | ✅ `TestHandleDecision_CSRF` (forged, empty and truncated tokens all rejected, call stays pending), with `TestNew_CSRFToken` and `TestHandleIndex_CarriesCSRFToken` (added 2026-09-22, `v0.3.2`) |
| Pending approval ids are guessable | ✅ `TestRequest_PendingIDsAreRandom`, plus `TestHandleIndex_OrdersByArrival` for the ordering the random ids displaced (added 2026-09-22, `v0.3.2`) |

**Both 2026-09-22 sets were checked against a deliberate break** of the code they
cover — the collision check removed from `remember`, the batch branch removed
from `handleRequest` — and each failed as it should before the fix was restored.
A security test that has never been seen to fail is a test whose ability to fail
is an assumption (the practice `TestVerify_AcceptsALogWrittenBeforeSessionHeaders`
established on 2026-08-01).

**Not covered, and worth saying plainly:** none of the 2026-09-22 fixes have been
exercised under a real MCP client (no L3 run accompanied them). The batch path in
particular is proven against `TestHelperMCPServer`, which ignores a batch line
rather than executing it the way a real server on protocol `2024-11-05` would —
so the tests prove the *gateway* refuses the batch, not what a real server would
have done with one had it arrived. The refusal is the property that matters here,
but the asymmetry is real and is the first thing to close if an L3 session is run.

**2026-11-02 audit:** malformed-input, frame-size, pending-state and subprocess
shutdown cases now have hermetic regressions. Shared JSON validation covers
duplicate members, escaped duplicate names, invalid UTF-8, unpaired surrogates,
trailing values and excessive depth. Scanner regressions cover pagination,
cursor cycles, malformed results, output failures, terminal controls and a
descendant retaining stdout after the direct child exits.

Each new security property was checked against a deliberate mutation or against
the vulnerable original implementation, then restored and retested. The audit
report records the mutation evidence and final gate results. No real-browser
DNS-rebinding/clickjacking exercise or real MCP-client smoke was run in this
audit; handler tests establish the controls, not browser interoperability.

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
builds and runs cleanly. Linux exercises shared concurrency paths; platform-
specific races still need an appropriate supported runner to investigate. The
cgo-free runs cover the other two platforms functionally. This audit ran on
Windows and did not run the race detector.

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

#### Run of 2026-08-03, against the published `v0.3.1` artifacts

The whole table, run within the hour of publishing. It is also the first time this
was done for a release since `v0.2.0`: **`v0.3.0` shipped and was never checked
from outside**, which is a gap in a section whose title says these things are
verified rather than assumed, and is written here rather than quietly skipped.

| Check | Evidence |
|---|---|
| Anonymous download | HTTP 200 on all seven assets, six binaries plus `SHA256SUMS`, with no token |
| Checksums | `sha256sum -c`: 6 of 6 `OK`. Negative control: one byte appended to a copy gives `FAILED`, so the check is checking |
| Buildinfo | All six carry `vcs.revision=b66f5c2db347...`, the exact tagged commit, with `vcs.modified=false`, `-trimpath=true`, `CGO_ENABLED=0`, and a `GOOS`/`GOARCH` pair matching the filename. Toolchain `go1.22.12` |
| Real format | Mach-O for darwin, ELF for linux, PE32+ for windows, each with the architecture its name claims. The linux binary is `statically linked, stripped` |
| Leaked paths | Zero occurrences of `/home/runner` or a Windows user directory in any of the six |
| Attestation | `gh attestation verify` exits 0 on all six. Negative control: the one-byte-longer copy fails with HTTP 404, since no attestation exists for that digest |
| Reproducible | The tag rebuilt from a fresh clone with the runner's toolchain differs from the published linux/amd64 binary in **39 bytes**, all inside the build ID's host components. The content ID is identical (`0ge-jHa7G2wDs2y-ZVDL`), which is the `v0.1.0` result again |
| Version stamp | The published `.exe` prints `ganimedes v0.3.1`, and the session header it writes carries `"version":"v0.3.1"`, with the `v`, because the workflow stamps `GITHUB_REF_NAME` |
| Shipped behavior | The published binary was driven against a real MCP server: the timeout error reads `it was waiting for a human at http://127.0.0.1:8811/`, naming the port actually bound rather than the default; the deny reason is unchanged; no file was created; `verify` reports 3 entries with the chain intact |

That last row is the one worth having. The wording it confirms was written, tested
and re-checked locally the same day, but a message is only true of the binary
people can download, and until this run nothing had established that the sentence
in the README was the sentence in the release.

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
2. ✅ **Adversarial cases for the proxy (L4).** Batch, id reuse and CSRF landed
   in September. The 2026-11-02 audit added malformed/ambiguous input, large
   frames, pending bounds and subprocess failure/shutdown cases. See §L4 and
   the audit report for the mutation evidence and remaining execution limits.
3. **Black-box binary test (L2).** Turns last session's manual PowerShell smoke
   check into a repeatable, CI-covered test.
4. **E2E against a real MCP server (L3).** Lowest leverage for now — stays
   manual, revisit only if a real regression shows up in this area.
5. **Smoke-test split (L5)**: still deferred until the suite is slow enough for
   a fast first signal to matter. **M4's Postman question** is no longer on this
   list: it was answered "no" on 2026-07-30 (§2).

Items 1 and 2 are complete. Items 3-5 did not block the original v0 release: its
gate is [`GO_NO_GO.md`](GO_NO_GO.md), and the plan for reaching it is step 5 of
`DESIGN.md` §5. Future releases still require their own current quality evidence.
