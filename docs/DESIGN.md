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
| 2 | **Config loader** | YAML file: which server to wrap (command + args), deny rules, which tools require approval. | Low |
| 3 | **Policy engine** | Given a `tools/call` (name + args), decides ALLOW / DENY / REQUIRE_APPROVAL. v0: match by name. Deterministic, no ML. | Low |
| 4 | **Human-in-the-loop** | When a tool requires approval: pause, show it to a human, wait for approve/reject, with timeout (no answer = deny). | Medium-high (UX) |
| 5 | **Hash-chained audit log** | Append-only log. Each entry: timestamp, session, tool, args, decision, result hash, and `prev_hash`. `hash = SHA-256(canonical JSON)`. Break a past entry, break the chain. Plus a `verify` command. | Low-medium |
| 6 | **CLI / entrypoint** | `ganimedes run --config ...`, `ganimedes verify`, `ganimedes init`. | Low |
| 7 | **Packaging** | Single static binary via `go build`; install and run, no runtime. | Low |

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

Each step is a checkpoint that works on its own:

1. **Transparent passthrough.** The proxy only forwards. Proves we can sit in the
   middle without breaking MCP. *Milestone: the agent works exactly as before,
   but through Ganimedes.*
2. **Audit log.** Record every `tools/call` + result, hash-chained, with
   `verify`. *Milestone: "what did my agent do?" answered, tamper-evident.*
   Highest value, lowest risk, so it goes second.
3. **Deny-list.** Block configured tools, return a clean MCP error to the client.
   *Milestone: dangerous tool blocked.*
4. **Human-in-the-loop.** Approval for flagged tools. *Milestone: the 30-second
   demo.*

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
