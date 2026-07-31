# Ganimedes - Infrastructure

> Living document. Companion to [`DESIGN.md`](DESIGN.md). Scopes what
> infrastructure the project actually needs, and when, using the same
> discipline as the rest of the docs: don't build for a stage we're not at.

## 1. The core principle: v0 needs none

Ganimedes v0 is a self-hosted binary the developer runs on their own machine.
Nothing runs on infrastructure Ganimedes operates: no server, no database, no
cloud account. This is not an oversight, it's the point: a security gateway
that asked users to trust a third party's servers would undercut its own
pitch (see the trust/adoption reasoning in `DESIGN.md`).

So "infra" here does not mean "servers to run the product". It means: the
tooling to **build, test, and ship** the binary. That is a much smaller
problem, and it's the only one v0 has.

## 2. What we actually need, by timing

### A. Needed now / soon (to ship v0 as open source)

| Need | Why | Notes |
|------|-----|-------|
| CI (GitHub Actions) | Build + `go vet` + tests on every push/PR | **Done**, see `.github/workflows/ci.yml`. Cross-platform matrix (Linux/macOS/Windows) for build+test; single-OS for lint/security since those are text-content checks. Mirrors the rigor of CryptoCapi's `quality-gate.yml`: `golangci-lint` (lint), `gofmt` (format), `go test -race` (tests + concurrency safety), `govulncheck` + Gitleaks + Trivy (security), CodeQL (SAST). Circular imports and "type coverage" are not needed as separate checks: Go's compiler rejects the former and enforces full static typing by construction. CodeQL results land in the Security tab: while the repo was private that needed GitHub Advanced Security, so the workflow carried `upload: never` and shipped the SARIF as a downloadable artifact instead. The repo went public with v0.1.0, Code Scanning is free there, and the workaround was retired in `d29099d`. |
| Release automation | Cross-compile for target OS/arch, attach binaries to GitHub Releases | **Done and exercised**: two releases published (`v0.1.0` 2026-07-30, `v0.2.0` 2026-07-31) plus two `workflow_dispatch` dry runs. See `.github/workflows/release.yml`. Hand-rolled rather than `goreleaser` (decision recorded in §3). Triggered by pushing a `vX.Y.Z` tag; `workflow_dispatch` runs the same build as a dry run that publishes nothing. Six targets: linux, darwin and windows on amd64 and arm64. The version is stamped into the binary at link time (`-ldflags -X`), and the workflow re-runs `go vet` + `go test` at the tagged commit before building anything. What changed in a release is written by hand in `docs/release-notes/<tag>.md` and spliced into the notes at publish time; a tag with no such file still publishes, with a warning on the run. Hand-written and versioned with the code it describes, which keeps the release history in the repo without the generated changelog ruled out in §3. |
| Checksums for releases | Users of a *security* tool will want to verify what they downloaded | **Done**: each release ships a `SHA256SUMS` file covering the binaries themselves (not archives), so what a user verifies is byte-for-byte the file they execute. What that proves stops at integrity, which is why the provenance attestation below exists; binary signing remains a separate open question (§3). |
| Build provenance attestation | Checksums published beside the binaries prove integrity, not origin | **Done** (2026-07-31, decision in §3), see the `attest-build-provenance` step in `.github/workflows/release.yml`. Each of the six binaries gets a Sigstore-signed statement that it was built by that workflow, at that commit, in this repository; a user checks it with `gh attestation verify` against GitHub instead of against the release page. Keyless, so nothing has to be held or rotated. Effective from `v0.2.0`. |

That's the entire list. No servers, no database, no paid cloud account.

### B. Needed later, only if/when the hosted tier exists (explicitly out of v0)

This mirrors the "Later" section of [`USE_CASES.md`](USE_CASES.md) (compliance
evidence across a team, team-wide approval workflow). It is listed here only
so infra planning doesn't get ahead of product validation:

- A real backend (API + database) for centralized, multi-agent audit storage.
- Hosting for the web dashboard (the TS layer discussed separately from the
  Go core).
- Auth and billing infrastructure for a paid product.

None of this is designed yet. It only becomes relevant once v0 has real users
asking for it, per the "no rush, prove adoption first" approach the whole
project follows.

### C. Never required, by design

No infrastructure Ganimedes operates should ever be a **requirement** to run
the core gateway, even after a hosted tier exists. The hosted layer must stay
optional and additive, never a dependency of the free, local product. This is
a constraint on future design, not just a v0 scoping note.

## 3. Open decisions

| Decision | Options | Notes |
|----------|---------|-------|
| Binary signing | none (v0) vs `cosign`/similar | **Still open, and smaller than it was.** Deferred on key custody: a self-managed signing key has to be held, rotated and kept out of the repository, and losing it is worse than never having had it. The provenance attestation below now covers most of what signing was wanted for, without a key. What remains uncovered is distribution through channels that carry the binary away from GitHub (a package manager, a mirror), where an attestation tied to this repository's API is harder to check. Revisit if that day comes. |

### Resolved

**Build provenance attestation: yes, via GitHub's Sigstore-backed attestation**
(decided 2026-07-31, implemented the same day in `release.yml`). The reason is that
`SHA256SUMS` proves the download matches what was published and nothing more: the
checksums sit on the same page as the binaries, so anyone who can replace a release
can replace both. The attestation is a signed statement, held outside the release, that
a given binary was built by this workflow, from this commit, in this repository, and a
downloader verifies it without trusting the release page. It answers "why should a
developer run this binary?" with evidence rather than assurance, which is the argument
Ganimedes makes about agent actions in the first place. It cost far less than the
binary-signing decision it sits next to, because it is keyless (Sigstore issues a
short-lived certificate against the run's OIDC token) and free on public repositories,
so the "defer, key custody is a burden" reasoning that still holds for `cosign` never
applied here. It pairs with Art. 1.1: zero dependencies is what makes the attested
source small enough to actually audit. Scope kept honest (Art. 2.4): it proves origin,
not safety, and neither the release notes nor `SECURITY.md` may imply otherwise. The
step runs on dry runs too, because this pipeline has already demonstrated that a step
gated on tags is a step nobody has run.

**Release tooling: hand-rolled GitHub Actions, not `goreleaser`** (decided
2026-07-30, reversing the earlier "leaning `goreleaser`" note). `goreleaser` is
the community standard and would have worked, but the whole release path is one
`go build` loop over six targets, and keeping it that way means the pipeline that
produces a security binary is readable end to end in the same file that runs it,
with no external tool version to pin, trust, or keep current. That is the same
argument Art. 1.1 makes about runtime dependencies, applied to the build. The features
that justify `goreleaser` for most projects (Homebrew taps, archive formats,
generated changelogs, SBOMs, snapshot builds) are all v0 non-goals. Revisit if
packaging demands grow past what plain `go build` covers.

**Supported platforms at launch: six targets** (decided 2026-07-30):
`linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`,
`windows/arm64`. The earlier note proposed four; the two arm64 additions cost
nothing, because cgo is already off and cross-compiling is a pure matrix
expansion on a single runner, and they cover ARM servers and Windows on ARM.
