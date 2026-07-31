# Ganimedes Product Specification (v0)

> The single, consolidated description of **what Ganimedes is and does**. It pulls
> together the product framing (`README.md`), the technical scoping (`DESIGN.md`),
> the internal architecture (`ARCHITECTURE.md`), and the wire-behavior specs
> (`SEQUENCES.md`) into one functional specification. Where those documents give
> the "why" and the "how", this one states the "what": capabilities, interfaces,
> formats, guarantees, and boundaries. Binding rule as everywhere else: it
> describes actual, tested behavior, never an aspiration (Constitution Art. 2.4,
> 6.2, 6.3).

## 1. Overview

Ganimedes is the governance and security layer for autonomous AI agents. It sits
between an agent and the tools the agent can call, and it controls and records
what the agent **does**, not just what it knows.

Concretely in v0, Ganimedes is a single Go binary that acts as a transparent
proxy in front of one MCP (Model Context Protocol) server. To the agent it looks
exactly like the real server; to the real server it looks like the agent. In the
middle it inspects `tools/call` messages and, on each one, can allow it, block it,
or pause it for a human, and it records every call to a tamper-evident audit log.

It answers four questions about every action an agent takes:

- **WHO** is the agent? (identity)
- What **CAN** it do? (capability)
- What **SHOULD** it do right now? (policy and risk)
- Can we **PROVE** what it did? (verifiable audit)

v0 delivers the last three at their simplest useful form. Identity is roadmap.

## 2. Positioning

Ganimedes is governance for agents, not a sandbox. It operates at the MCP
tool-call boundary. It does not isolate processes, patch vulnerabilities, or stop
an attacker who already controls the host. It makes what an agent does accountable
and controllable, and it never advertises a guarantee it does not enforce.

## 3. Scope of v0

v0 does three things, plus two diagnostic helpers:

**Pillars (enforcement):**

1. **Tamper-evident audit.** Every `tools/call` and its result are written to a
   hash-chained, Ed25519-signed JSONL log, verifiable offline.
2. **Deny-list policy.** JSON rules block named tools; everything else is allowed
   (default-allow). Deterministic, no ML.
3. **Human-in-the-loop approval.** Named tools pause and require explicit approval
   on a local page before they run. Deterministic, no ML.

**Helpers (diagnostic, no enforcement):**

4. **`verify`** walks the audit chain and checks signatures.
5. **`scan`** lists a wrapped server's tools and flags the risky ones, to help
   write the deny-list. It changes nothing.

## 4. Architecture (summary)

```
  MCP CLIENT                GANIMEDES                MCP SERVER
  (the agent)  ──stdio──▶  (the proxy)  ──stdio──▶  (the real tools)
                            ├─ intercepts tools/call
                            ├─ policy: allow / deny / require-approval
                            ├─ approval: localhost page (when required)
                            ├─ audit: append to hash-chained signed log
                            └─ forwards or blocks (never corrupts the wire)
```

Internally, `proxy` is the only package that knows JSON-RPC/MCP framing. `config`,
`policy`, `audit`, and `approval` are pure leaf packages the proxy wires together.
Full detail in [`ARCHITECTURE.md`](ARCHITECTURE.md).

## 5. Functional specification

### 5.1 Transparent proxy

- Reads newline-delimited JSON-RPC from the client, spawns the real server, and
  forwards messages in both directions.
- Forwards the **exact bytes** read, never a re-encoded copy, so inspection can
  never alter the wire (Art. 1.3).
- Only `tools/call` is inspected. `initialize`, `tools/list`, `resources/*`,
  `prompts/*`, notifications, and all server errors are pure passthrough (Art. 3.3).
- Acceptance: an agent behaves identically through Ganimedes as directly, except
  where a policy deliberately blocks or pauses a call.

### 5.2 Audit log

- Every observed `tools/call` becomes one JSONL entry holding the full call (tool,
  arguments, result or error), plus `decision`, `seq`, timestamp, `session`,
  `prev_hash`, `hash`, and `sig`.
- **Hash chain:** `hash = SHA-256(RFC 8785 canonical JSON of the entry minus its
  seal)`. Each entry links to the previous via `prev_hash`. Any edit, reorder,
  insert, or delete of a past entry breaks the chain.
- **Signature:** every entry is Ed25519-signed over the same canonical bytes, so a
  third party can verify authorship offline.
- **Decisions:** `allow`, `deny`, `approved`, `rejected`, `timeout`.
- **Failure mode:** auditing fails open. If an append fails, the proxy logs to
  stderr and keeps forwarding; losing a record is the lesser harm. Enforcement does
  not depend on auditing.

### 5.3 Deny-list policy

- Config field `deny: []string`. A `tools/call` whose name is listed never reaches
  the server: the client gets a JSON-RPC error `code -32000`, and the attempt is
  audited with `decision=deny`.
- Default-allow, exact name match, case-sensitive, deterministic, no ML.
- A denied tool still appears in `tools/list` (blocked at call time, not hidden).

### 5.4 Human-in-the-loop approval

- Config field `approve: []string`. A `tools/call` whose name is listed is paused.
- The proxy consults an approver; in production this is a local HTTP page bound to
  a loopback address (`--approval-addr`, default `127.0.0.1:8765`).
- The page lists pending calls (tool name and pretty-printed arguments, HTML-escaped)
  and offers **Approve** and **Reject**. It refreshes every 2 seconds.
- **Outcomes:**
  - **Approved:** the call is forwarded to the server; its response reaches the
    client; the entry is audited with `decision=approved`.
  - **Rejected:** the call is blocked; the client gets a JSON-RPC error; audited
    `decision=rejected`.
  - **Timeout:** if no human answers within `--approval-timeout` (default `60s`),
    the call is blocked (fail-closed, Art. 2.1); audited `decision=timeout`.
- **Precedence:** a tool on both `deny` and `approve` is denied (the stricter
  verdict).
- **v0 limitation:** approvals are handled serially (one pending at a time); the
  MCP client has an independent timeout. See `ARCHITECTURE.md` §8.

### 5.5 Risk scanner (`scan`)

- Spawns the wrapped server, runs `initialize` + `tools/list`, and prints each tool
  with a flag if its name or description matches a fixed risky-keyword list
  (`delete`, `drop`, `exec`, `shell`, `payment`, `transfer`, network verbs, ...).
- Reporting only: no enforcement, no audit log, no config written. It is the tool
  you run to decide the deny-list.

## 6. Interfaces

### 6.1 Commands

```
ganimedes run    [--config <path>] [--log <path>] [--signing-key <path>]
                 [--approval-addr <host:port>] [--approval-timeout <dur>]
                 -- <server-command> [args...]
ganimedes scan   [--config <path>] -- <server-command> [args...]
ganimedes verify [--pubkey <path>] [log-path]
ganimedes version
ganimedes help
```

- `--` separates Ganimedes' own flags from the wrapped command.
- The wrapped command may come from `--config` or the `--` tail; the explicit
  command line wins.
- Exit codes: `0` success, `1` runtime failure, `2` usage error. Invoking
  `ganimedes` with no command is a usage error: it has done nothing, and a
  script must be able to tell.
- `ganimedes init` (scaffold a config) is wired but not implemented, so it is
  not listed in `ganimedes help`. It answers "not implemented yet" and exits 1,
  which is a better reply than "unknown command" for anyone who found it here.
- Help that was asked for goes to stdout; help that accompanies a usage error
  goes to stderr with the error, keeping stdout clear (Art. 3.1).

### 6.2 Configuration file (JSON)

```json
{
  "command": "npx",
  "args": ["-y", "server-filesystem", "/data"],
  "deny": ["fs.delete", "db.dropTable"],
  "approve": ["email.send", "payment.execute"]
}
```

- JSON, not YAML (stdlib-only, Art. 1.1).
- Unknown fields are rejected, and trailing data after the object is rejected: a
  mistyped key fails loudly rather than silently disabling a rule.
- `command`/`args` are optional in the file (may be supplied on the CLI). `deny`
  and `approve` are both default-allow lists.

### 6.3 Audit log entry (JSONL, one object per line)

| Field | Meaning |
|-------|---------|
| `seq` | 1-based position in this file |
| `ts` | RFC3339 nanosecond UTC timestamp |
| `session` | groups entries from one proxy run |
| `tool` | the `tools/call` name |
| `args` | arguments, verbatim JSON from the wire |
| `result` / `error` | present on success / failure (mutually exclusive) |
| `decision` | `allow` \| `deny` \| `approved` \| `rejected` \| `timeout` |
| `prev_hash` | hash of the previous entry (chain link) |
| `hash` | hex SHA-256 of the RFC 8785 canonical payload |
| `sig` | base64 Ed25519 signature over the same bytes |

File permissions are `0600` (the log may contain secrets).

### 6.4 Approval page (HTTP, loopback only)

- `GET /` renders the pending-approval list.
- `POST /decision` with form fields `id` and `action` (`approve` / `reject`)
  resolves one pending call and redirects to `/`.
- No authentication in v0 (loopback-only; documented limitation, Art. 2.4).

### 6.5 Keys and environment

- The signing key auto-generates on first `run` at `--signing-key` (default
  `ganimedes-signing.key`, `0600`), with the public half written beside it as
  `.pub`. Overridable via `--signing-key` or the `GANIMEDES_SIGNING_KEY`
  environment variable.
- `verify` finds the public key via `--pubkey`, else the default `.pub`, else
  derives it from the private key.

## 7. Guarantees and their boundaries (honest, Art. 2.4)

- **What the audit log proves:** the recorded history was not altered after the
  fact, and the entries were signed by the holder of a specific key.
- **What it does not prove:** it does not stop someone who controls **both** the
  log and the signing key from rewriting the whole chain, and it does not detect
  entries truncated from the very end (external anchoring is a later feature).
- **Fail-closed:** any path that cannot reach a definite allow (policy error,
  approval timeout, missing approver) denies the call.
- **Local-first:** nothing is transmitted off the machine. No telemetry. The
  approval page is loopback-only.

## 8. Non-goals (v0)

Multi-level identity, ML-based risk scoring, dashboards, blockchain anchoring,
pricing tiers, hosted SaaS, multi-server or HTTP transport, and audit-log
redaction are explicitly out of v0. They come later, and only if real users ask
(see `USE_CASES.md`).

## 9. Non-functional requirements

- **Zero-dependency:** Go standard library only (Art. 1.1).
- **Single static binary:** `go build`, no runtime, no install step (Art. 5.1).
- **Cross-platform:** builds and tests on Linux, macOS, Windows (Art. 4.4).
- **Deterministic, no ML:** every decision is a readable, reproducible rule.
- **Tested behavior:** every `SEQUENCES.md` behavior has a hermetic automated test;
  package coverage never decreases (Art. 4.1, 4.2).
- **Verifiable releases:** cross-compiled binaries ship with checksums and a build
  provenance attestation (Art. 5.2). Six targets (linux/darwin/windows on amd64 and
  arm64), each with the version linked into the binary so `ganimedes version`
  identifies exactly what you have, and a `SHA256SUMS` over the binaries themselves.
  The checksums prove the download is intact; the attestation, held outside the
  release and checked with `gh attestation verify`, proves which workflow and commit
  produced it. Neither says anything about the code being correct (Art. 2.4). Built
  by `.github/workflows/release.yml`; see `INFRA.md` §2.

## 10. Roadmap beyond v0

The v0 gateway is the seed of a larger control plane, each pillar earned by real
adoption before it is built:

| Pillar | v0 | Later |
|--------|----|-------|
| Identity | (roadmap) | agent identity and ownership |
| Capability | deny-list | fine-grained capabilities |
| Policy | JSON rules (deny / approve) | policy engine + risk scoring |
| Proof | signed, verifiable log | external anchoring |

Distribution wedge under evaluation (not committed): the zero-dependency,
cryptographically rigorous MCP gateway, documented and supported in Spanish for the
LatAm developer community (`TECH_DEBT.md` TD-3).
