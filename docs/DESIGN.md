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

Each step is a checkpoint that works on its own. **Status (2026-07-30): all four
code steps are complete and on `main`.** Steps 1 and 2 are shipped; step 3
(deny-list) plus its two companions (the `scan` command and the audit RFC 8785 +
Ed25519 upgrade) are done; and step 4 (human-in-the-loop) is implemented too, the
last v0 code milestone. What remains is step 5, releasing it, which is not code:
it is verification the code cannot do for itself. See
[`ARCHITECTURE.md`](ARCHITECTURE.md) §3, §5, §6, and §8 for the per-milestone task
lists.

**Progress: v0 shipped on 2026-07-30. `v0.1.0` is tagged, its binaries are
published, and the repository is public.** The pipeline
(`.github/workflows/release.yml`), the license (Apache-2.0), the three-OS CI
confirmation, the manual smokes F1-F5 and a green dry run of the release pipeline
all landed the same day, ahead of the tag rather than after it. The gate that
graded all of it, with the per-smoke evidence, is closed at 100% in
[`GO_NO_GO.md`](GO_NO_GO.md); anything past v0 needs a new gate.

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
4. ✅ **Human-in-the-loop.** Approval for flagged tools, done 2026-07-29. A
   tools/call whose name is on the config's `approve` list is paused; the call is
   shown on a local approval page (`--approval-addr`, loopback only) and the human
   clicks Approve or Reject. Approve forwards the call and audits it with
   `decision=approved`; Reject and a `--approval-timeout` expiry both block it
   (the client gets a JSON-RPC error `code -32000`) and audit it with
   `decision=rejected` / `decision=timeout`. The timeout fails closed (Art. 2.1,
   3.4). *Milestone: the 30-second demo.* See `ARCHITECTURE.md` §8/§9 and the
   decision-log entry below.

5. ✅ **Release v0.** Done 2026-07-30. No new features: with the license settled,
   the work was only proving what was already built. In order, because each step
   could invalidate the next:
   1. ✅ **Confirm CI is green** on Linux, macOS and Windows. Done 2026-07-30 for
      `1bd3ce7`, the head of `main` and the commit to be tagged. That is `ci.yml`,
      the everyday gate; `release.yml` is a separate pipeline and was rehearsed on
      its own (step 4).
   2. ✅ **Run the manual smokes** against a real MCP server. These are the only
      checks no automated test replaces, because they exercise a server we did
      not write. Done 2026-07-30 against
      `@modelcontextprotocol/server-filesystem`: F1-F5 all pass, including the
      three approval outcomes with a human at the page. Two non-blocking findings
      came out of it, both recorded in `GO_NO_GO.md` §6.
   3. ✅ **Choose a license.** Done 2026-07-30, ahead of the two checks above
      because it was the only item here that was a decision rather than a
      verification, and a tag published under no license is not undone by deleting
      it. **Apache-2.0** (`LICENSE`, copyright 2026 Jegoba90): the explicit patent
      grant and trademark clause are worth the extra text for something adopters
      embed in their own toolchain, and the zero-dependency rule means no other
      license has to be reconciled with it. See the decision log below.
   4. ✅ **Push the tag.** Done 2026-07-30: `v0.1.0` on `c57ace8`, published with
      six binaries and `SHA256SUMS`, and the repository opened.
      `.github/workflows/release.yml` (2026-07-30) re-runs
      the tests at that commit, cross-compiles six targets with the version
      stamped in, and publishes the binaries with `SHA256SUMS` (Art. 5.2).
      Rehearsed 2026-07-30 with `workflow_dispatch`, which builds and verifies but
      publishes nothing. The rehearsal earned its keep on the first try: it failed
      on the symbol guard, and the bug was in the guard rather than the stamping
      (`go tool nm` piped into `grep -q` under `pipefail`, invisible on Windows,
      which has no SIGPIPE). Fixed in `f708cfb`, green on the second run, and the
      two steps no dry run can reach, the release notes and `gh release create`,
      then worked first time on the real tag.

   The checklist those steps are graded against, with per-item evidence and the
   current verdict, is [`GO_NO_GO.md`](GO_NO_GO.md); it is the single source of
   truth for readiness, and this list only says what order to attack it in.
   Packaging decisions (hand-rolled pipeline, six targets, no signing in v0) live
   in [`INFRA.md`](INFRA.md).

Rationale: prove the riskiest piece (the pipe) first; ship the most valuable and
cheapest piece (audit) second; release only what has been checked, last.

## 6. Open decisions

| Decision | Options | Current lean |
|----------|---------|--------------|
| Proxy implementation | Official MCP SDK vs raw JSON-RPC passthrough | **Raw passthrough.** The SDK is built to *implement* a server, not to proxy; fighting its abstraction is worse. |
| Transport | stdio / HTTP | **stdio only in v0.** HTTP later. |
| Approval UX | localhost page / separate TTY / webhook / desktop notification | **localhost page** (implemented, M4 2026-07-29). Most portable, best for the demo. |
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

### Human-in-the-loop implementation (milestone 4, done 2026-07-29)

- **What shipped:** a new leaf package `internal/approval` (an HTTP-plus-wait
  helper that knows nothing about JSON-RPC), a third policy verdict
  `RequireApproval`, a config `approve` list, and proxy wiring that pauses a
  flagged `tools/call`, consults the approver, and forwards or blocks on the
  result. `audit`'s `approved`/`rejected`/`timeout` decisions (reserved earlier)
  are now emitted.
- **Layering:** `approval` is a leaf like `policy`/`audit`. The `proxy` owns the
  only JSON-RPC knowledge and defines the `Approver` interface it depends on, so
  tests inject a fake approver and never bind a socket; `approval.Server` is the
  production implementation. No import cycle: `proxy → approval`, `approval →`
  stdlib only.
- **Resolved sub-decisions (at implementation):**
  - **Transport / page:** a `localhost` HTTP page rendered with `html/template`
    (auto-escapes hostile tool names/args), refreshed with a 2-second `meta`
    refresh so a paused call appears and a resolved one drops off with no
    JavaScript. Stdlib only (`net/http`, `html/template`), Art. 1.1.
    Buttons POST to `/decision`; `GET /` lists pending calls.
  - **Address:** `--approval-addr`, default `127.0.0.1:8765`, **validated to be a
    loopback host** (`New` rejects `0.0.0.0`, a bare `:port`, or any routable
    address). The page never leaves the machine (Art. 2.2). No authentication in
    v0: anyone with local access to the port can approve/reject; documented as an
    honest limitation (Art. 2.4), acceptable for a local developer tool.
  - **Timeout:** `--approval-timeout`, default `60s`, fail-closed to a denial on
    expiry (Art. 2.1, 3.4).
  - **Concurrency model:** approvals are handled **serially**. The proxy's
    request-direction pump blocks on the human decision, so at most one call is
    pending at a time and the page shows one item. This is head-of-line blocking
    for the (rare, single-client, local) v0 case and keeps the design simple
    ("simplicity over cleverness", Art. 1.2); combined with the known client-side
    timeout above, a very slow human can trip the client's own timer. A
    concurrent/queued model is a later option if it earns its complexity.
  - **Nil-approver safety:** if a tool somehow requires approval with no approver
    wired (unreachable from the CLI, which only omits the approver when the
    approval-list is empty), the call fails closed to a denial rather than passing
    through (Art. 2.1).
- **Status:** ✅ implemented 2026-07-29 (`internal/approval/approval.go`, the
  `RequireApproval` verdict in `internal/policy`, the `approve` field in
  `internal/config`, the approval wiring in `internal/proxy`, and the
  `--approval-addr`/`--approval-timeout` flags in `internal/cli`). Full gate green
  including `golangci-lint` and `govulncheck`; the manual smoke (§8 task list)
  runs in the user's environment.

### License: Apache-2.0 (decided 2026-07-30)

- **Decision:** the project ships under the **Apache License 2.0**, `LICENSE` at
  the repository root (verbatim upstream text, copyright 2026 Jegoba90). This was
  blocking item 3 of [`GO_NO_GO.md`](GO_NO_GO.md) and the last open decision on the
  path to a public v0.
- **Why not MIT** (what the closest competitor, Airlock, uses): MIT grants the same
  freedoms in a fifth of the words, but it says nothing about patents and nothing
  about trademarks. Ganimedes asks to be installed *between* an agent and its
  tools, inside someone else's toolchain, which is a decision their legal team
  reviews. Apache-2.0's explicit patent grant (§3) removes the ambiguity MIT leaves,
  and §6 makes clear the license conveys no rights to the project's name or marks.
  For a governance tool, those two clauses are worth the extra length.
- **Why not AGPL-3.0 plus a commercial exception** (what MakerChecker uses): AGPL's
  distinguishing power is §13, which triggers when software is *offered as a network
  service*. Ganimedes is a local binary that talks to a subprocess over stdio; it is
  not hosted, so that clause would rarely fire. The cost, however, is immediate and
  real: many companies ban AGPL outright by policy, which would exclude precisely the
  organizations that need agent governance. It buys protection this product's shape
  does not need, at a price it cannot afford. If a hosted tier ever exists
  (`INFRA.md` §2B), it can be licensed separately; Apache-2.0 on the local gateway
  does not block that.
- **What made this easy:** the zero-dependency rule (Art. 1.1). With no third-party
  code in the tree, there is no compatibility matrix to reconcile and no inherited
  attribution obligation. The three SVGs in `assets/` are original work by the same
  author, so one license covers the whole repository.
- **Not done, deliberately:** no per-file SPDX or copyright headers. Apache-2.0 does
  not require them, and they would push the teaching comments that open each file
  further down. Revisit only if a distributor asks. No `NOTICE` file either: it
  exists to force attribution to propagate into derivative works (§4(d)), an
  obligation not worth imposing at v0.
