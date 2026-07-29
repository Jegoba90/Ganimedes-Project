# Ganimedes v0 GO / NO-GO

> Release-readiness gate for the **v0 public release** (tagging v0 and making the
> repository public; the README license is deliberately "to be defined before the
> repository goes public"). This is a living checklist: mark an item WIP before
> touching it, flip it to a status only when the evidence exists. Honest by rule
> (Constitution Art. 2.4, 6.3): a criterion is GO only when it is enforced and
> checked, never because it is expected to pass.

**Current verdict (2026-07-29): NO-GO.** All four v0 milestones are code-complete
and the local gate is green, but the milestone-4 work is not yet committed or
CI-verified, the user-driven manual smokes have not been run, and the license is
undefined. See "Blocking items" at the bottom for exactly what flips this to GO.

## 1. Verdict summary

| Area | Criterion | Status |
|------|-----------|--------|
| Build order | M1 passthrough, M2 audit, M3 deny+scan+seal, M4 approval all code-complete | ✅ code-complete |
| CI gate | build, vet, gofmt, golangci-lint, go test (-race on Linux), govulncheck, Gitleaks, CodeQL green on Linux/macOS/Windows | ⏳ M4 not yet pushed / CI-run |
| Coverage ratchet | no package coverage decreases (Art. 4.2) | ✅ held/improved locally |
| Zero-dependency | standard library only, single static binary (Art. 1.1, 5.1) | ✅ verified |
| Docs-code sync | DESIGN / ARCHITECTURE / SEQUENCES / README describe actual behavior (Art. 6.2) | ✅ synced for M4 |
| Manual smokes | passthrough, audit+verify, deny, scan, approval (approve/reject/timeout) confirmed against a real MCP server | ⏳ pending (user) |
| Security posture | fail-closed, local-first, stdout-sacred, tamper-evident audit, loopback-only approval (Art. 2.x, 3.x) | ✅ by construction, ⏳ smoke-confirmed |
| Non-goals | out-of-scope items explicitly listed and not shipped (README, USE_CASES) | ✅ documented |
| License | a license chosen before the repo goes public | ⛔ undefined |

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
  (Art. 4.3). *Status: local gate green on Windows (cgo off). M4 is not yet
  committed/pushed, so CI has not run it. NOT satisfied until pushed and green.*
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
equivalents already pass in CI (Art. 4.1). Status: all ⏳ pending.

- **F1 - Transparent passthrough.** An agent wrapped by Ganimedes behaves exactly
  as if talking to the server directly (Art. 1.3, 6.1).
- **F2 - Audit + verify.** Every `tools/call` is logged; `ganimedes verify` reports
  the chain intact and signatures valid; a hand-edit makes `verify` fail with the
  tampered entry (Art. 2.3).
- **F3 - Deny.** A tool on the `deny` list returns a JSON-RPC error `code -32000`
  to the agent, never reaches the server, and is audited with `decision=deny`.
- **F4 - Scan.** `ganimedes scan` lists a server's tools and flags the risky ones,
  taking no enforcement action.
- **F5 - Approval (M4).** A tool on the `approve` list pauses; the local page at
  `--approval-addr` shows it; **Approve** forwards the call (audited
  `decision=approved`), **Reject** and a `--approval-timeout` expiry each return a
  JSON-RPC error to the agent (audited `decision=rejected` / `decision=timeout`,
  fail-closed).

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

## 7. Explicit non-goals for v0 (must stay out)

Multi-level identity, ML-based risk scoring, dashboards, blockchain anchoring,
pricing tiers, hosted SaaS, multi-server/HTTP transport, log redaction. All later,
only if real users ask (README, `USE_CASES.md`).

## 8. Blocking items (what flips NO-GO to GO)

1. **Commit and push M4; CI green on Linux/macOS/Windows** (G1). Currently local
   only. This is the single largest open item.
2. **Run the manual smokes F1-F5** against a real MCP server and record the result.
3. **Choose a license** and replace the README placeholder (⛔ hard blocker for
   going public).
4. **Cut verifiable release artifacts** (cross-compiled binaries + checksums,
   Art. 5.2) once 1-3 are done.

When items 1-4 are satisfied and Sections 3-5 read all ✅, this document is flipped
to **GO** with a dated sign-off here.

## 9. Sign-off

| Date | Verdict | Note |
|------|---------|------|
| 2026-07-29 | NO-GO | v0 code-complete; M4 not yet committed/CI-verified, manual smokes pending, license undefined. |
