# Ganimedes v0 - Design

> Living document. Rough now, polished as we go. Product vision lives in
> [`README.md`](../README.md); this file is the technical scoping for v0.

## 1. What v0 is

MCP works like this: a **client/host** (Claude Desktop, an agent) connects to
**MCP servers** that expose **tools**. They speak **JSON-RPC 2.0**, almost always
over **stdio** (the client spawns the server as a subprocess and talks over
stdin/stdout). The security-relevant message is `tools/call`: the agent invoking
a tool with arguments.

Ganimedes v0 is a **proxy that sits in the middle**. To the client it looks like
an MCP server; to the real server it acts like a client. The developer changes
zero lines of their agent: they just point their MCP client config at Ganimedes
instead of at the server directly. That is the adoption win.

## 2. Architecture

```
  MCP CLIENT                GANIMEDES                MCP SERVER(S)
  (the agent)  ──stdio──▶  (the proxy)  ──stdio──▶  (the real tools)
                            │
                            ├─ intercepts tools/call
                            ├─ applies policy (allow/deny/approve)
                            ├─ records to audit log
                            └─ forwards or blocks
```

## 3. Components

| # | Component | What it does | Difficulty |
|---|-----------|--------------|-----------|
| 1 | **Proxy core (the pipe)** | Reads JSON-RPC from the client, spawns the real server, forwards both directions, intercepts `tools/call`, correlates request/response by `id`, passes the `initialize` handshake through. | **High.** Foundation and biggest risk: if it corrupts the protocol, nothing works. |
| 2 | **Config loader** | JSON file: which server to wrap (command + args), deny rules, which tools require approval. | Low |
| 3 | **Policy engine** | Given a `tools/call` (name + args), decides ALLOW / DENY / REQUIRE_APPROVAL. v0: match by name, **default-allow** (anything not listed is allowed). Denied tools still appear in `tools/list` and are blocked on call. Deterministic, no ML. | Low |
| 4 | **Human-in-the-loop** | When a tool requires approval: pause, show it to a human, wait for approve/reject, with timeout (no answer = deny). | Medium-high (UX) |
| 5 | **Hash-chained, signed audit log** | Append-only log. Each entry stores the **full call** (tool, args, result) plus decision, timestamp, session, and `prev_hash`. `entry hash = SHA-256(RFC 8785 canonical JSON of the entry)`, and each entry is **Ed25519-signed** (decided 2026-07-24, see §7). Full content serves debugging; the chain + signature give tamper-evidence *and* authenticity. Plus a `verify` command. | Low-medium |
| 6 | **CLI / entrypoint** | `ganimedes run --config ...`, `ganimedes verify`, `ganimedes scan`, `ganimedes init`. | Low |
| 7 | **Packaging** | Single static binary via `go build`; install and run, no runtime. | Low |
| 8 | **Risk scanner (`scan`)** | Connects to the wrapped MCP server, calls `tools/list`, and flags tools whose name/description match risky keywords (`delete`, `drop`, `exec`, `shell`, `payment`, `transfer`, network access, ...). A pre-flight helper for writing the deny-list, not a runtime enforcement path — same relationship to the deny-list that `verify` has to the audit log. Deterministic keyword matching, no ML (decided 2026-07-24, see §7). | Low |

## 4. Risk map

- **Tractable, deterministic (low risk):** config, deny-list policy, audit
  hash-chain + verify. Small, closed pieces.
- **The real risk lives in two places:**
  1. **The proxy core.** Passing JSON-RPC through without corrupting the
     handshake, notifications, or id correlation. If this fails, there is no
     product.
  2. **The approval UX.** stdio is already busy speaking MCP, so the "approve
     this?" prompt cannot live on the same stdio. It has to move elsewhere.

## 5. Build order

Each step is a checkpoint that works on its own. **Status (2026-07-28): steps 1
and 2 are shipped and on `main`; step 3 (deny-list core) is implemented, and both
its companions are now built too, the `scan` command and the audit RFC 8785 +
Ed25519 upgrade; step 4 (human-in-the-loop) is the only one still pending.** See
[`ARCHITECTURE.md`](ARCHITECTURE.md) §3, §5, and §6 for the per-milestone task
lists.

1. ✅ **Transparent passthrough.** The proxy only forwards. Proves we can sit in
   the middle without breaking MCP. *Milestone: the agent works exactly as
   before, but through Ganimedes.*
2. ✅ **Audit log.** Record every `tools/call` + result, hash-chained, with
   `verify`. *Milestone: "what did my agent do?" answered, tamper-evident.*
   Highest value, lowest risk, so it goes second.
3. ✅ **Deny-list.** Block configured tools, return a clean MCP error to the
   client. *Milestone: dangerous tool blocked — done 2026-07-26.* A denied
   `tools/call` is blocked before it reaches the server, the client gets a
   JSON-RPC error (`code -32000`), and the attempt is audited with
   `decision=deny`. Config is a JSON file (`--config`, Art. 1.1). Two companions
   were scoped with this step, and both are now **done (2026-07-28)**: the
   **`scan` command** (§3, §7), which tells you what's risky in a wrapped server
   before you write the deny rules, and the **audit RFC 8785 + Ed25519 upgrade**
   (§7), which now covers every deny decision the moment it is recorded. See
   `TECH_DEBT.md` TD-2 for a
   real-world incident informing an optional rate/volume extension to this
   milestone (not implemented; see §6).
4. ⬜ **Human-in-the-loop.** Approval for flagged tools. *Milestone: the
   30-second demo.*

Rationale: prove the riskiest piece (the pipe) first; ship the most valuable and
cheapest piece (audit) second.

## 6. Open decisions

| Decision | Options | Current lean |
|----------|---------|--------------|
| Proxy implementation | Official MCP SDK vs raw JSON-RPC passthrough | **Raw passthrough.** The SDK is built to *implement* a server, not to proxy; fighting its abstraction is worse. |
| Transport | stdio / HTTP | **stdio only in v0.** HTTP later. |
| Approval UX | localhost page / separate TTY / webhook / desktop notification | **localhost page.** Most portable, best for the demo. |
| Audit storage | JSONL file / database | **JSONL file in v0.** DB later. |
| Servers wrapped | one / many | **One in v0.** Multi-server complicates id correlation without helping the demo. |
| Rate/volume limiting in the policy engine | Add now vs. evaluate when M3 design opens | **Defer to M3, judge on its own merits.** Prompted by a real incident (`TECH_DEBT.md` TD-2: an autonomous agent's escape was caught by anomalous *call volume*, not a single flagged action — a gap in a stateless per-call policy). The cheap, incident-informed items (a cited case study in USE_CASES.md, an explicit boundary-of-responsibility note) are worth doing regardless of this decision. The rate-limiting feature itself should not be adopted reflexively because a scary incident happened elsewhere — it earns its place in M3 only if it fits the deterministic, no-ML deny-list model and justifies its added complexity for a v0 aimed at a solo developer wrapping one local MCP server, not a frontier lab's threat model. |

## 7. Decision log

### Language: Go (decided for v0)

- **Decision:** Go for v0. Confirmed 2026-07-22.
- **Why:**
  - The chosen architecture is **raw JSON-RPC passthrough, not the MCP SDK**, so
    the main reason to prefer TypeScript (its mature SDK) does not apply. MCP's
    stdio transport is newline-delimited JSON, which Go handles natively with
    `os/exec`, `bufio`, `encoding/json`, and one goroutine per direction.
  - **Single static binary, no runtime.** For a security gateway that sits inline,
    a dependency-free install is part of the trust and adoption story. `go build`
    gives that; Node does not.
  - Native concurrency (goroutines) fits a bidirectional proxy.
  - De-facto standard for infrastructure and security CLIs (Vault, Consul, caddy,
    kubectl, gh), which signals "serious infra".
  - "No rush" neutralizes TypeScript's only real edge here (prototyping speed).
  - The sole maintainer wants to work in and learn Go. For a one-person project,
    long-term maintainability by that person matters most.
- **Accepted tradeoffs:** slightly higher distribution friction than `npx` for the
  Node-heavy MCP crowd (mitigated: an MCP client config can point at any
  executable, so a Go binary works fine as a server command), plus the
  maintainer's Go learning curve (accepted deliberately).

### Deny-list and tool discovery: appear-and-block (decided 2026-07-23)

- **Decision:** a denied tool still appears in `tools/list`; it is blocked at
  call time with a JSON-RPC error, not hidden from discovery.
- **Why:** hiding a tool means rewriting the `tools/list` response (more proxy
  complexity) and leaves the agent guessing why a tool vanished. Blocking on
  call is simpler, returns a clear error, and leaves an audit record that the
  agent tried.
- **v0 default:** default-allow. Everything not on the deny-list passes; the
  deny-list is the exception, not an allow-list.
- **Later option:** a "hide from discovery" mode for users who prefer denied
  tools to be invisible.

### Audit content: full entry plus hash chain (decided 2026-07-23)

- **Decision:** the audit log stores the **full** call (tool, arguments, result)
  in each JSONL entry, and the SHA-256 hash chain is computed over the canonical
  JSON of the full entry (including `prev_hash`).
- **Why:** storing only a hash of the result gives tamper-evidence but kills the
  debugging use case (you cannot see what actually happened). Storing the full
  entry serves both: debugging reads the content, `verify` walks the chain.
- **Accepted tradeoff:** full arguments and results may contain secrets (tokens,
  PII), so the audit log itself becomes sensitive data. v0 logs everything as-is
  and documents this; **redaction / field filtering is a planned later feature.**

### Audit log rigor: real canonical JSON (RFC 8785) + Ed25519 signing (decided 2026-07-24)

- **Decision:** upgrade the audit log's canonicalization from the milestone-2
  shipped approach (a fixed Go struct field order, no key sorting) to real
  **RFC 8785** (JSON Canonicalization Scheme — sorted keys, canonical number/
  string formatting), and add **Ed25519 cryptographic signing** of every
  entry, on top of the existing hash chain. This resolves `TECH_DEBT.md`
  TD-1 by upgrading the implementation to match what Constitution Art. 2.3
  always described, rather than by softening the article's wording to match
  the lighter milestone-2 implementation.
- **Why:** competitive research (`TECH_DEBT.md` TD-3, 2026-07-24) found that
  the closest open-source competitor with a tamper-evident audit log
  (MakerChecker) already ships exactly this — RFC 8785 + Ed25519, hash-chained,
  independently verifiable offline. Matching that rigor is the concrete
  technical spine of Ganimedes' chosen position: the zero-dependency,
  cryptographically strongest MCP gateway, aimed first at the underserved
  Spanish-speaking/LatAm developer community (see TD-3). A claim of "the most
  rigorous audit trail in the category" has to be literally true, not
  asserted, per Art. 2.4 (Honest Audit and Capability Claims) — so the
  implementation is upgraded rather than the claim being left aspirational.
- **Stays inside the Zero-Dependency Policy (Art. 1.1):** `crypto/ed25519` is
  Go standard library. RFC 8785 canonicalization has no official Go stdlib
  implementation, so it will need to be either hand-written (sorted map keys,
  spec-compliant number/string formatting) or, if any external code is used
  for it, run through the Art. 1.1 dependency-audit protocol first.
- **What changed concretely (done 2026-07-28):**
  - `internal/audit`'s `payload.hash()` now computes over real key-sorted
    RFC 8785 canonical JSON, via a hand-rolled canonicalizer (`canonical.go`)
    that sorts object keys by UTF-16 code unit, applies ECMAScript number
    formatting, and escapes strings per the spec. It is validated against the
    RFC 8785 §3.2.3 worked example. The verbatim wire bytes of args/result/error
    are still stored as-is; canonicalization is applied only to compute the seal.
  - Each `Entry` gained a `sig` field alongside `hash` and `prev_hash`; `Logger`
    holds an Ed25519 signing key; `Verify` gained a signature-check step
    alongside the hash and chain-link checks. Digest and signature are taken over
    the same canonical bytes, so a third party can reproduce them offline.
  - This changed the on-disk JSONL schema. Ganimedes has no external users yet,
    so it was a pre-1.0 schema change, no migration path needed.
- **Resolved sub-decisions (at implementation, 2026-07-28):**
  - **Where the signing key lives:** auto-generate on first `run` into a 0600
    PEM file (`ganimedes-signing.key`, PKCS#8), with the public half written
    beside it (`.pub`, PKIX) for verifiers; overridable via `--signing-key` or
    `GANIMEDES_SIGNING_KEY` for a key managed elsewhere (a secrets manager, a
    separate volume). `verify` reads the public key from `--pubkey`, the default
    `.pub`, or by deriving it from the private key. Rotation is not automated in
    v0. Honest framing (Art. 2.4): where an attacker controls both the log and
    the key, signing adds authenticity and defense-in-depth, not a new guarantee;
    its teeth are provenance and verification where the private key never goes.
  - **Hand-roll vs dependency:** hand-rolled, to stay inside the Zero-Dependency
    Policy (Art. 1.1); `crypto/ed25519` and `crypto/x509` are stdlib.
- **Status:** ✅ implemented 2026-07-28 (`internal/audit/canonical.go`,
  `keys.go`, and the updated `audit.go`/`verify.go`). This closes the gap between
  Art. 2.3's "canonical JSON" wording and the lighter milestone-2 byte-
  canonicalization.

### Risk scanner (`ganimedes scan`): a pre-flight helper for the deny-list (decided 2026-07-24)

- **Decision:** add a `scan` subcommand that connects to a wrapped MCP server,
  performs `initialize` + `tools/list`, and prints each discovered tool with a
  flag if its name or description matches a fixed list of risky keywords
  (`delete`, `drop`, `exec`, `shell`, `payment`, `transfer`, network-fetch
  verbs, etc.). It takes **no enforcement action** — it only reports. Writing
  a good M3 deny-list requires knowing what a wrapped server can actually do;
  `scan` answers that question before any config is written.
- **Why:** prompted by reviewing MakerChecker's `mc scan` (`TECH_DEBT.md`
  TD-3), which does the analogous thing at the agent-code level (static
  analysis of what an agent's code can do). Ganimedes cannot copy that
  mechanism — it has no visibility into agent code, only into the MCP
  protocol — but the underlying idea (surface the risk before you have to
  configure against it) transfers cleanly to the protocol layer, and reuses
  the `initialize`/`tools/list` handling the proxy core already implements.
- **Deliberately not copied from MakerChecker:** no code analysis, no
  `--fix`-style auto-generated config, no risk score — just a flagged list.
  Keeping it a reporting-only command, with a fixed keyword list, keeps it
  inside "Deterministic, no ML" (README's "Explicitly NOT in v0" boundary)
  and avoids turning a small helper into a second product.
- **Framing relative to the README's "three things, and nothing more":**
  `scan` is not a fourth pillar. It has the same status as `verify` — a
  diagnostic/support command for an existing pillar (deny-list), not a new
  enforcement capability. The v0 scope stays three things; `scan` and
  `verify` are helpers around two of them.
- **Status:** ✅ implemented 2026-07-28 as `internal/scan` + the `ganimedes scan`
  subcommand (§3, §5). Reporting-only, stdlib-only, deterministic; the server
  handshake (`initialize` + `notifications/initialized` + `tools/list`) reuses
  the same MCP framing the proxy core relies on, bounded by a scan-wide timeout
  (Art. 3.4).
- **Resolved at implementation (2026-07-28):** the keyword list is a **hardcoded
  default** for v0, curated so no keyword is a substring of another (so a tool is
  never double-flagged for the same match); matching is case-insensitive
  substring matching over name + description. An **editable per-project list**
  and word-boundary matching are noted as future refinements, not built.

### Human-in-the-loop timeout: configurable, default deny (decided 2026-07-23)

- **Decision:** the approval wait has a **configurable timeout**; on expiry the
  call is denied (fail-closed).
- **Known limitation:** while Ganimedes holds a `tools/call` open waiting for a
  human, the MCP **client has its own timeout** and may give up first. These are
  two independent timers. v0 does not solve the client-side timeout; it
  documents that very long human delays can hit it, and keeps the approval
  timeout configurable so it can be tuned below the client's.
