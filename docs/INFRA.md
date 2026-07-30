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
| CI (GitHub Actions) | Build + `go vet` + tests on every push/PR | **Done**, see `.github/workflows/ci.yml`. Cross-platform matrix (Linux/macOS/Windows) for build+test; single-OS for lint/security since those are text-content checks. Mirrors the rigor of CryptoCapi's `quality-gate.yml`: `golangci-lint` (lint), `gofmt` (format), `go test -race` (tests + concurrency safety), `govulncheck` + Gitleaks + Trivy (security), CodeQL (SAST). Circular imports and "type coverage" are not needed as separate checks: Go's compiler rejects the former and enforces full static typing by construction. **Known limitation:** the repo is private, and GitHub's Code Scanning (Security tab) requires GitHub Advanced Security, which is only free on public repos. CodeQL still runs and finds issues, but results upload as a downloadable artifact instead of the Security tab (`upload: never`), same workaround as CryptoCapi. Revisit once the repo goes public. |
| Release automation | Cross-compile for target OS/arch, attach binaries to GitHub Releases | **Written** (2026-07-30, not yet exercised on GitHub), see `.github/workflows/release.yml`. Hand-rolled rather than `goreleaser` (decision recorded in §3). Triggered by pushing a `vX.Y.Z` tag; `workflow_dispatch` runs the same build as a dry run that publishes nothing. Six targets: linux, darwin and windows on amd64 and arm64. The version is stamped into the binary at link time (`-ldflags -X`), and the workflow re-runs `go vet` + `go test` at the tagged commit before building anything. |
| Checksums for releases | Users of a *security* tool will want to verify what they downloaded | **Done**: each release ships a `SHA256SUMS` file covering the binaries themselves (not archives), so what a user verifies is byte-for-byte the file they execute. Code signing is a later hardening step. |

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
| Binary signing | none (v0) vs `cosign`/similar | **Still open.** Deferred; checksums are the v0 bar, signing is a later hardening step. Worth revisiting if the project ever distributes through a channel where a checksum on the same page as the download is not enough. |

### Resolved

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
