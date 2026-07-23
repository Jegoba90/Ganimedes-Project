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
| CI (GitHub Actions) | Build + `go vet` + tests on every push/PR | **Done**, see `.github/workflows/ci.yml`. Cross-platform matrix (Linux/macOS/Windows) for build+test; single-OS for lint/security since those are text-content checks. Mirrors the rigor of CryptoCapi's `quality-gate.yml`: `golangci-lint` (lint), `gofmt` (format), `go test -race` (tests + concurrency safety), `govulncheck` + Gitleaks + Trivy (security), CodeQL (SAST). Circular imports and "type coverage" are not needed as separate checks: Go's compiler rejects the former and enforces full static typing by construction. |
| Release automation | Cross-compile for target OS/arch, attach binaries to GitHub Releases | `goreleaser` is the Go community standard for this; avoids hand-rolled release scripts |
| Checksums for releases | Users of a *security* tool will want to verify what they downloaded | A `SHA256SUMS` file per release is the minimum bar; code signing is a later hardening step |

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
| Release tooling | `goreleaser` vs hand-rolled GitHub Actions | Leaning `goreleaser`: purpose-built for exactly this, widely used in the Go ecosystem |
| Supported platforms at launch | linux/amd64, darwin/amd64, darwin/arm64, windows/amd64 (the obvious four) vs a narrower first cut | Needs a decision once we're close to a shippable v0 |
| Binary signing | none (v0) vs `cosign`/similar | Deferred; checksums are the v0 bar, signing is a later hardening step |
