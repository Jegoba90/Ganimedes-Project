# 🏛️ Ganimedes Technical Constitution (CTG-2026)

**Version:** 1.0.1 | **Stack:** Go (stdlib only) | **Focus:** Transparency, Fail-Closed Security & Verifiable Audit

This document defines the immutable laws of the code. Every pull request must
comply with these articles.

**Governing purpose.** Ganimedes is built to be a *serious, stable seed*, not a
growth vehicle. Where a rule trades speed for correctness, correctness wins. The
success metric is craftsmanship, not velocity or scale. These laws exist to keep
that true as the project grows and as more hands (including future AI ones) touch
the code.

## 0. Normative Index and Linked Documents

This constitution is the single map of the code's laws. Areas with detailed
operational procedure live in sibling documents of mandatory consultation.

| Area | Document | Article(s) |
| :--- | :--- | :--- |
| Product scope, build order, decision log | [docs/DESIGN.md](docs/DESIGN.md) | 1.1, 2.x |
| Internal Go architecture and dev plan | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 3.x |
| Runtime behavior specs (wire protocol) | [docs/SEQUENCES.md](docs/SEQUENCES.md) | 3.3, 6.2 |
| Use cases and non-goals | [docs/USE_CASES.md](docs/USE_CASES.md) | 5.3, 6.3 |
| Build, release, and CI infrastructure | [docs/INFRA.md](docs/INFRA.md) | 4.x, 5.x |

> **Binding rule:** a procedure documented in a sibling doc is as binding as an
> article here. If a sibling doc and this constitution conflict, **the
> constitution prevails**, and the conflict must be resolved in the same PR.

## 1. The Iron Core (Global Rules)

### 1.1. Zero-Dependency Policy

- **Rule:** Ganimedes v0 uses the Go standard library only. Adding a third-party
  module is prohibited without a documented architectural justification.
- **Why it is a law, not a preference:** this is a security tool. Every
  dependency is code from someone else running inside the gateway that guards the
  user's agent. Fewer dependencies means a smaller attack surface, and that small
  surface *is* part of the product's value, not an incidental property.
- **Dependency-audit protocol:** each time a dependency is proposed, produce a
  report: (1) what stdlib-only alternative was tried and why it was insufficient;
  (2) the dependency's own transitive footprint and maintenance health; (3) the
  security blast radius if that dependency were compromised; (4) verdict, with the
  bar set deliberately high.
- **Corollary (config format):** because YAML has no stdlib parser, structured
  config uses **JSON** (`encoding/json`), never a YAML dependency. See DESIGN.md
  decision log.

### 1.2. Zero-Slop, Idiomatic Go

- **Rule:** all code is `gofmt`-clean, passes `go vet` and `golangci-lint` with no
  suppressions, and every exported symbol carries a godoc comment.
- **Errors are handled, never swallowed:** an ignored error requires an explicit
  `_ =` with a comment stating why it is safe. Wrap errors with `%w` to preserve
  the chain.
- **No panics in library code:** `internal/*` packages return errors; only
  `main`/`cli` may terminate the process. A proxy that panics mid-session is a
  denial of service against the user's agent.
- **Simplicity over cleverness:** if the standard, boring construct works, use it.
  Cleverness is a maintenance liability in a one-maintainer project.

### 1.3. Protocol Transparency (Never Corrupt the Wire)

- **Principle:** Ganimedes sits in the critical path of the user's agent. The bytes
  it forwards must be the **original** bytes.
- **Rule:** when a later milestone parses a message to inspect it, it forwards the
  original raw bytes, **never** a value it re-serialized. Re-marshaling can silently
  reorder keys or change encoding and break a working connection.
- **Acceptance bar:** an agent talking to a server *through* Ganimedes must behave
  identically to talking to it directly, except where a policy deliberately blocks
  or pauses a call.

## 2. Security Posture (The Reason the Product Exists)

### 2.1. Fail-Closed Enforcement

- **Principle:** the *policy model* is default-allow (a deny-list: only listed tools
  are blocked). The *enforcement mechanism* is the opposite: it **fails closed**.
- **Rule:** if the decision path cannot reach a definitive ALLOW — a policy engine
  error, an approval timeout, an internal fault — the call is **denied**. Ambiguity
  never resolves to "allow". The human-in-the-loop timeout defaults to deny.
- **Why:** a security gate that fails open is not a security gate. A false deny is
  an annoyance; a false allow can be irreversible.

### 2.2. Local-First, Zero Exfiltration

- **Rule:** Ganimedes runs on the user's machine and **never** transmits agent
  data, tool calls, arguments, results, or audit records to any server the project
  operates. No telemetry, no phone-home, no "anonymous usage stats".
- **Why:** the product asks a user to place it inline with their most sensitive
  actions. The moment it ships that data anywhere, it becomes the exact risk it was
  meant to remove. This invariant is permanent, even after a hosted tier exists
  (see 5.3).

### 2.3. Tamper-Evident Audit by Construction

- **Principle:** auditability must be *verifiable*, not decorative.
- **Rule:** each audit entry stores the full call (tool, arguments, result) and its
  `prev_hash`; the entry hash is `SHA-256` over the **canonical** JSON of the full
  entry. The chain property (`same inputs → same hash`, any edited past entry breaks
  the chain) is enforced by a `verify` command and covered by mandatory tests.
- **Canonical serialization is single-sourced:** one helper produces the digest
  (sorted keys, fixed separators). Reimplementing it inline is prohibited, so the
  bytes are identical between writer and verifier.
- **Shared DNA:** this is the same technique as CryptoCapi's multi-engine
  `protocol_hash` seal (its Constitution Art. 4.8). The two projects are siblings;
  this is the family trait.

### 2.4. Honest Audit and Capability Claims

- **Rule:** the audit log, the docs, and any future marketing must **never claim
  more than is enforced**. If a guarantee is not enforced in code and covered by a
  test, it is not advertised.
- **Why:** a security product's only real asset is trust. One overstated guarantee,
  discovered, is worse than a modest, true one.

### 2.5. The Audit Log Is Sensitive Data

- **Rule:** because entries store full arguments and results, the audit log may
  contain secrets (tokens, PII). It is treated as sensitive, and this fact is
  documented, never hidden. Redaction / field filtering is a planned feature; until
  it ships, the docs state plainly that the log is as sensitive as what flowed
  through it.

## 3. The Proxy Core (Go Concurrency and stdio)

### 3.1. stdout Is the Protocol Channel (Sacred)

- **Rule:** on the client-facing side, **nothing** but valid MCP protocol bytes is
  ever written to stdout. All logging, diagnostics, and human-facing output go to
  **stderr**. A stray `fmt.Println` to stdout corrupts the JSON-RPC stream and
  breaks the session.

### 3.2. Concurrency Safety

- **Rule:** all tests run under the race detector (`-race`) on every platform that
  supports it in CI. Zero tolerance for data races.
- **Ordered audit writes:** the hash chain requires strictly ordered appends, so
  audit writes are serialized through a single serialization point — a channel or
  a mutex. *(Clarified in 1.0.1:* milestone 3 appends from **both** proxy
  directions — the response side records allowed calls, the request side records
  a blocked call the instant it is denied — and the `audit.Logger` mutex is that
  serialization point, so no two appends ever run concurrently. The requirement
  is serialization, not a single writer goroutine; `-race` in CI proves no data
  race.*)*

### 3.3. Transparent Passthrough of Non-Inspected Traffic

- **Rule:** only the messages a milestone explicitly needs to inspect
  (`tools/call`) are examined. Everything else (`initialize`, `tools/list`,
  `resources/*`, `prompts/*`, notifications, and server errors) is forwarded
  verbatim. See SEQUENCES.md.

### 3.4. Bounded Lifecycles and Timeouts

- **Rule:** no wait is unbounded. Human-in-the-loop approval has a configurable
  timeout that fails closed (2.1). Subprocess and goroutine lifecycles are managed
  so a dead server or a closed client resolves cleanly.

## 4. Quality Gates (CI/CD)

### 4.1. Behavior Is Tested Without External Tools

- **Rule:** every behavior specified in SEQUENCES.md has an automated test. Tests
  must not depend on an external MCP server or network; stand-ins (e.g. the
  re-executed test binary) are used instead, so CI is hermetic.

### 4.2. Coverage Ratchet

- **Rule:** package test coverage **never decreases**. Lowering a threshold to make
  CI pass is prohibited (mirrors CryptoCapi Constitution Art. 5.3).

### 4.3. CI Is Sacred

- **Rule:** no `[skip ci]`, no bypasses. Every commit runs and passes the full gate:
  `go build`, `go vet`, `gofmt`, `golangci-lint`, `go test` (with `-race` where the
  runner supports cgo), `govulncheck`, Gitleaks, and CodeQL. A red gate blocks the
  merge; it is fixed, not worked around.

### 4.4. Cross-Platform by Default

- **Rule:** build and test run on Linux, macOS, and Windows, because Ganimedes ships
  as a binary for all three and `os/exec` behaves differently across them.

## 5. Distribution and Boundaries

### 5.1. Single Static Binary, No Runtime

- **Rule:** the product is one self-contained binary produced by `go build`. It must
  never require a runtime, interpreter, container, or install step to run. This is
  the promise that makes it adoptable and is not negotiable for the core gateway.

### 5.2. Verifiable Releases

- **Rule:** releases are cross-compiled for the supported platforms and ship with
  checksums, so a user of a *security* tool can verify what they downloaded. See
  INFRA.md.

### 5.3. The Open-Core Boundary

- **Rule:** the free, local gateway must **never** depend on any hosted service the
  project operates, even after a paid hosted tier exists. The hosted layer is always
  optional and additive. No infrastructure we run is ever a requirement to run the
  gateway (mirrors INFRA.md §C, reinforces 2.2).

## 6. Product Integrity

### 6.1. Do No Harm to the Host Setup

- **Principle:** installing Ganimedes must never leave a developer worse off than not
  using it.
- **Rule:** in passthrough, a working MCP connection stays working (3.1, 3.3). The
  gateway adds observation and control; it does not degrade the base experience.

### 6.2. Docs-Code Synchronization

- **Rule:** the sequence diagrams and design docs describe *actual* behavior. A change
  in behavior updates the corresponding diagram/spec in the **same PR**. Documentation
  drift is treated as a product defect, not tech debt (mirrors CryptoCapi Art. 6.2).

### 6.3. Honest Claims to the User

- **Rule:** the README and any user-facing copy never advertise a security guarantee
  that is not enforced and tested (extends 2.4 to the outside world). Non-goals stay
  explicitly listed in USE_CASES.md so the product is never oversold.

## 7. Amendment

- This constitution changes only by an explicit, reasoned edit to this file, made in
  the same PR as the code or doc change that motivates it. An article is never
  silently violated: either the code complies, or the article is amended on the
  record with its rationale.
- **Version** bumps: patch for clarifications, minor for a new article, major for a
  reversal of an existing law.
