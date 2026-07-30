# Ganimedes v0 GO / NO-GO

> Release-readiness gate for the **v0 public release**: tagging v0 and making the
> repository public. This is a living checklist: mark an item WIP before
> touching it, flip it to a status only when the evidence exists. Honest by rule
> (Constitution Art. 2.4, 6.3): a criterion is GO only when it is enforced and
> checked, never because it is expected to pass.

**Current verdict (2026-07-30): GO, and shipped.** v0.1.0 is tagged (`c57ace8`),
its six binaries and `SHA256SUMS` are published by the pipeline rather than by
hand, and the repository is public. Every criterion in this gate was met before
the tag, not argued after it: CI green on all three OSes, the release pipeline
rehearsed on a dry run, the manual smokes F1-F5 passed against a real MCP server
(§4), and the license settled. This gate is now closed; what follows v0 belongs to
a new one.

## Progress toward GO: 100%

Weighted by remaining effort to a v0 public release. Engineering, decisions,
verification and publication are all done.

| Component | Weight | Progress | Contribution |
|-----------|:------:|:--------:|:------------:|
| v0 engineering (M1-M4 code-complete, on `main`) | 55% | ✅ 100% | 55.0 |
| Documentation (spec, architecture, go/no-go, behavior sync) | 10% | ✅ 100% | 10.0 |
| CI green on Linux/macOS/Windows | 10% | ✅ 100% (green on `1bd3ce7`, 2026-07-30) | 10.0 |
| Manual smokes F1-F5 (user-driven) | 15% | ✅ 100% (all five pass, 2026-07-30) | 15.0 |
| License chosen | 5% | ✅ 100% (Apache-2.0, 2026-07-30) | 5.0 |
| Verifiable release artifacts | 5% | ✅ 100% (six binaries + `SHA256SUMS` published for `v0.1.0`, 2026-07-30) | 5.0 |
| **Total** | **100%** | | **100%** |

Progress bar: `████████████████████` 100% (each block is 5%, so the bar rounds
down; it never shows more progress than the table supports).

## 1. Verdict summary

| Area | Criterion | Status |
|------|-----------|--------|
| Build order | M1 passthrough, M2 audit, M3 deny+scan+seal, M4 approval all code-complete | ✅ code-complete |
| CI gate | build, vet, gofmt, golangci-lint, go test (-race on Linux), govulncheck, Gitleaks, CodeQL green on Linux/macOS/Windows | ✅ green on `1bd3ce7` (CI #15, 2026-07-30) |
| Coverage ratchet | no package coverage decreases (Art. 4.2) | ✅ held/improved locally |
| Zero-dependency | standard library only, single static binary (Art. 1.1, 5.1) | ✅ verified |
| Docs-code sync | DESIGN / ARCHITECTURE / SEQUENCES / README describe actual behavior (Art. 6.2) | ✅ synced for M4 |
| Manual smokes | passthrough, audit+verify, deny, scan, approval (approve/reject/timeout) confirmed against a real MCP server | ✅ all five pass (2026-07-30) |
| Security posture | fail-closed, local-first, stdout-sacred, tamper-evident audit, loopback-only approval (Art. 2.x, 3.x) | ✅ by construction and smoke-confirmed |
| Non-goals | out-of-scope items explicitly listed and not shipped (README, USE_CASES) | ✅ documented |
| Release artifacts | six cross-compiled binaries + `SHA256SUMS` published for the tag (Art. 5.2) | ✅ published for `v0.1.0` (2026-07-30) |
| License | a license chosen before the repo goes public | ✅ Apache-2.0, `LICENSE` at the root |

Legend: ✅ GO, ⏳ in progress / not yet verified, ⛔ NO-GO blocker.

## 2. Scope of this gate

v0 is one gateway binary wrapping a single MCP server over stdio. "Release" means:
tag a v0, publish verifiable release artifacts (cross-compiled binaries plus
checksums, Art. 5.2), and open the repository. It does **not** mean feature parity
with any competitor or a hosted tier; those are explicitly out of v0 (README,
`TECH_DEBT.md` TD-3).

## 3. Hard gates (all must be GO before tag)

- **G1 - Full CI green on all three OSes.** `go build`, `go vet`, `gofmt`,
  `golangci-lint` (no suppressions), `go test` (with `-race` where the runner has
  cgo, i.e. Linux), `govulncheck`, Gitleaks, CodeQL. No `[skip ci]`, no bypass
  (Art. 4.3). *Status: ✅ satisfied. CI #15 was confirmed green on all three OSes
  for `1bd3ce7` on 2026-07-30, and `release.yml` was rehearsed on that same commit
  (Release #2, `workflow_dispatch`), so the release pipeline is no longer
  unexercised. The tag itself went on `c57ace8`, one docs-only commit further on,
  whose tests were re-run by `release.yml` at tag time: that step runs before
  anything is built or published, so a broken commit could not have shipped. Worth
  stating plainly rather than glossing: the three-OS confirmation is `1bd3ce7`'s,
  and `c57ace8` carries a single-platform re-test on top of it.*
- **G2 - Coverage ratchet.** No package decreases vs. its prior baseline
  (Art. 4.2). *Status locally:* config 100%, policy 100%, approval 96.7% (new),
  audit 83.1% (=), cli 94.8% (up from 93.6), proxy 84.5% (up from 82.4), scan 86.8%
  (=). No decrease.
- **G3 - Zero-dependency, single static binary.** `go.mod` has no third-party
  requires; `CGO_ENABLED=0 go build` produces a self-contained binary (Art. 1.1,
  5.1). *Status: verified.*
- **G4 - Docs-code synchronization.** Every behavior in `SEQUENCES.md` has a test,
  and the design docs match the code (Art. 6.2). *Status: M4 diagram, DESIGN §5/§7,
  ARCHITECTURE §8/§9, README updated in the same change.*

## 4. Functional acceptance (manual smokes, user-driven)

Each runs against a real MCP server in the user's environment; automated
equivalents already pass in CI (Art. 4.1). **Status: all five pass (2026-07-30).**

Bench: the official `@modelcontextprotocol/server-filesystem` (v0.2.0, 14 tools),
wrapped by a local build of `main` at `275335a`, driven over stdio by a throwaway
stdlib-only Go MCP client, on Windows 11. Every assertion below is on observed
output, a file's presence or absence on disk, and the audit log.

- **F1 - Transparent passthrough.** ✅ The same script (initialize, tools/list,
  write_file, read_text_file, list_directory) ran twice: once against the server
  directly, once through Ganimedes. The protocol responses were byte-identical
  (Art. 1.3, 6.1).
- **F2 - Audit + verify.** ✅ The three `tools/call` were logged and `verify`
  reported the chain intact and signatures valid, both with the default key and
  offline with only `--pubkey`. Editing one entry's content failed with a hash
  mismatch; deleting a middle entry failed with a broken chain link; both exited 1.
  Truncating the tail still verified OK, so the limitation recorded in §6 behaves
  exactly as documented (Art. 2.3, 2.4).
- **F3 - Deny.** ✅ `write_file` on the deny-list returned JSON-RPC `-32000` to the
  agent, the target file was never created (the call never reached the server), and
  the entry was audited `decision=deny`. An allowed call afterwards in the same
  session succeeded, so a block does not poison the session.
- **F4 - Scan.** ✅ Listed all 14 tools, flagged 3 (`write_file`,
  `create_directory`, `move_file`), took no enforcement action, and wrote neither an
  audit log nor a signing key. It also surfaced one false negative, `edit_file`
  going unflagged, fixed before the tag by adding `edit` to the keyword list.
- **F5 - Approval (M4).** ✅ All three outcomes, each with the call held and listed
  on the loopback page. **Approve** forwarded it, the server really wrote the file,
  the agent received the server's own result, audited `decision=approved`.
  **Reject** returned `-32000` ("a human rejected the call"), no file, audited
  `decision=rejected`. **Timeout** returned `-32000` ("approval ... timed out"), no
  file, audited `decision=timeout`. Fail-closed holds: when the runs were over, the
  only files in the sandbox were the passthrough one and the approved one.

## 5. Security posture (Constitution-derived, GO by construction)

- **Fail-closed enforcement (Art. 2.1):** deny, rejection, approval timeout, and a
  missing approver all resolve to a block; ambiguity never resolves to allow.
- **Local-first, zero exfiltration (Art. 2.2):** nothing is transmitted off the
  machine; the approval page binds to a loopback address only (`New` rejects any
  non-loopback host).
- **stdout is the protocol channel (Art. 3.1):** only MCP bytes go to stdout; the
  approval URL and all diagnostics go to stderr.
- **Tamper-evident audit (Art. 2.3) and honest claims (Art. 2.4):** RFC 8785 +
  Ed25519, verifiable offline; the docs state exactly what the chain does and does
  not prove.
- **Bounded lifecycles (Art. 3.4):** the approval wait has a configurable timeout;
  no unbounded waits.

## 6. Known limitations / accepted risks (documented, not blockers)

These are honest, recorded, and acceptable for v0. They do not block GO but must
stay documented (Art. 2.5, 6.3).

- **Serial approvals (head-of-line blocking).** The request pump blocks on each
  approval, so one call is pending at a time. Fine for the v0 target (one local
  client, one server). See `ARCHITECTURE.md` §8.
- **Independent client-side timeout.** The MCP client has its own timeout; a very
  slow human approval can trip it. `DESIGN.md` §7.
- **No authentication on the approval page.** Loopback-only; anyone with local
  access to the port can approve/reject. `DESIGN.md` §7, `approval` package doc.
- **Audit log holds secrets.** Full args/results may contain tokens or PII; the
  file is `0600`, redaction is a later feature (Art. 2.5).
- **Tail truncation not detectable.** Removing entries from the end leaves a
  consistent shorter chain; external anchoring is a later feature (`ARCHITECTURE.md`
  §4).
- **`-race` runs on Linux only.** Windows has no C compiler; macOS cgo test binary
  hits an `LC_UUID` dyld issue, so CI runs the race detector on Linux.
- **`0600` is not enforced on Windows.** `run` creates the audit log and the signing
  key with mode `0600`; POSIX honors that and Windows does not. Checked with
  `icacls` during the F1-F5 smokes: both files carry only inherited ACLs (SYSTEM,
  Administrators and the owning user, all Full). On Windows the secrecy of the
  signing key therefore rests on the ACL of the directory holding it, not on the
  file mode. Windows is a shipped target, so this is said plainly rather than left
  implied (Art. 2.4).

## 7. Explicit non-goals for v0 (must stay out)

Multi-level identity, ML-based risk scoring, dashboards, blockchain anchoring,
pricing tiers, hosted SaaS, multi-server/HTTP transport, log redaction. All later,
only if real users ask (README, `USE_CASES.md`).

## 8. Blocking items (what flips NO-GO to GO)

1. ✅ **CI green on Linux/macOS/Windows** (G1). Confirmed green on `1bd3ce7`,
   the head of `main` and the commit to be tagged (CI #15, 2026-07-30).
2. ✅ **Run the manual smokes F1-F5** against a real MCP server and record the
   result. Done 2026-07-30: all five pass against
   `@modelcontextprotocol/server-filesystem`, including the three approval outcomes
   with a human at the page. Per-smoke evidence in §4; the two findings they
   surfaced are in §6, neither blocking.
3. ✅ **Choose a license.** Done 2026-07-30: **Apache-2.0**, `LICENSE` at the root,
   copyright 2026 Jegoba90, README section replaced. Chosen over MIT for the
   explicit patent grant and the trademark clause, both of which matter for a tool
   adopters embed in their own agent toolchain; chosen over AGPL because the
   network-copyleft trigger barely applies to a local binary, so it would cost
   enterprise adoption without buying protection. The zero-dependency rule (Art.
   1.1) means no third-party license has to be reconciled with it.
4. ✅ **Cut verifiable release artifacts** (cross-compiled binaries + checksums,
   Art. 5.2). **Done 2026-07-30: `v0.1.0` published from `c57ace8`, and the
   repository is public.** The automation landed the same day
   (`.github/workflows/release.yml`):
   pushing a `vX.Y.Z` tag re-runs the tests at that commit, cross-compiles six
   targets with the tag stamped into the binary, proves the stamp took by executing
   the linux/amd64 build, writes `SHA256SUMS`, and publishes the GitHub Release.
   **Rehearsed 2026-07-30 with `workflow_dispatch` (Release #2, green).** The first
   attempt failed and was worth every minute of it: the symbol guard reported a
   symbol missing that was present, because `go tool nm | grep -qF` under
   `pipefail` cannot succeed on a binary with more symbols than fit a pipe buffer.
   That bug was invisible to local verification on Windows, which has no SIGPIPE,
   and would have surfaced at tag time instead. Fixed in `f708cfb`. The two
   tag-gated steps a dry run cannot reach, the release notes and
   `gh release create`, then ran for the first time on the real tag and both
   worked.

All four items are satisfied and Sections 3-5 read all ✅. **This gate is closed:
v0 shipped on 2026-07-30.** It stays here as the record of what was checked before
the tag rather than claimed after it; anything beyond v0 needs a new gate, not an
edit to this one.

## 9. Sign-off

| Date | Verdict | Note |
|------|---------|------|
| 2026-07-29 | NO-GO (~70%) | v0 code-complete and pushed to `main` (M4 `a096fb8`+`128423f`); CI not yet confirmed green, manual smokes pending, license undefined. |
| 2026-07-30 | NO-GO (~73%) | Release pipeline added (blocking item 4's automation). Its build steps were reproduced and checked locally, but the workflow itself has not run on GitHub yet. Items 1-3 unchanged: CI confirmation, manual smokes F1-F5, and the license all still block. |
| 2026-07-30 | NO-GO (~78%) | License decided: Apache-2.0, `LICENSE` at the root, copyright 2026 Jegoba90. Blocking item 3 closes, and with it the last item that was a decision rather than a check. Remaining: confirm CI green on the three OSes, run the manual smokes, then tag. |
| 2026-07-30 | NO-GO (~83%) | G1 satisfied: CI confirmed green on all three OSes for `275335a` (the head of `main`, covering the release pipeline and the link-stamped vars). Blocking item 1 closes. The manual smokes F1-F5 are now the only substantive work left before a tag. |
| 2026-07-30 | NO-GO (~98%) | Manual smokes F1-F5 all pass against a real MCP server, the approval ones with a human at the page. Blocking item 2 closes, and with it the last substantive verification: every remaining step is an act, not a question. Two findings recorded in §6, neither blocking (Windows does not enforce `0600`; `scan` misses `edit_file`). Remaining: commit the pending license change, re-confirm CI on it, dry-run `release.yml`, then tag. |
| 2026-07-30 | **GO (~99%)** | `release.yml` rehearsed end to end on GitHub for the first time (Release #2, `workflow_dispatch`, green) on `1bd3ce7`, the commit CI #15 has green on all three OSes. The first rehearsal failed on the symbol guard, and the failure was a bug in the guard rather than in the stamping: `go tool nm` piped into `grep -q` under `pipefail` reports failure exactly when the symbol is found, and Windows has no SIGPIPE, so local verification could never have shown it (fixed in `f708cfb`). Blocking items 1-3 are closed and nothing is left to verify. Cleared to tag `v0.1.0`; the tag is the act, not a precondition for it. |
| 2026-07-30 | **GO, shipped (100%)** | `v0.1.0` tagged on `c57ace8` and published by the pipeline: six binaries plus `SHA256SUMS`, release notes rendered, `gh release create --verify-tag` accepted, Release marked Latest. The repository is now public, so the artifacts are reachable without a session and the CodeQL `upload: never` workaround is retired in the same change. Blocking item 4 closes and the gate with it. |
