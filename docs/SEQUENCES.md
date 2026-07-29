# Ganimedes - Sequence Diagrams

> Living document. Each diagram below is the runtime behavior spec for one
> milestone in the build order from [`DESIGN.md`](DESIGN.md#5-build-order).
> They are written in [Mermaid](https://mermaid.js.org/) `sequenceDiagram`
> syntax, which GitHub renders natively in markdown, so the diagrams stay
> plain text and diffable in git instead of drifting screenshots.

**Scope of interception:** Ganimedes only inspects `tools/call`. Every other
message (`initialize`, `tools/list`, `resources/*`, `prompts/*`, notifications)
and every error returned by the real server is pure passthrough, forwarded
unchanged. Policy is **default-allow**: only tools on the deny-list or the
approval-list are treated specially.

## 1. Transparent passthrough ✅ *(implemented in v0)*

The proxy forwards every message unchanged in both directions, including the
`initialize` handshake. To the client, Ganimedes looks exactly like the real
MCP server.

```mermaid
sequenceDiagram
    participant C as MCP Client (agent)
    participant G as Ganimedes (proxy)
    participant S as MCP Server (real tools)

    C->>G: initialize (request)
    G->>S: initialize (forwarded)
    S-->>G: capabilities (response)
    G-->>C: capabilities (forwarded)
    C->>G: initialized (notification)
    G->>S: initialized (forwarded)

    C->>G: tools/list (request)
    G->>S: tools/list (forwarded)
    S-->>G: tool definitions (response)
    G-->>C: tool definitions (forwarded)

    C->>G: tools/call "search_files" (request, id=1)
    G->>S: tools/call "search_files" (forwarded, id=1)
    S-->>G: result (response, id=1)
    G-->>C: result (forwarded, id=1)
```

## 2. Audit log ✅ *(implemented in v0)*

Same passthrough, plus a side effect: every `tools/call` and its result are
appended to the hash-chained log. The client sees nothing different.

```mermaid
sequenceDiagram
    participant C as MCP Client (agent)
    participant G as Ganimedes (proxy)
    participant A as Audit Log (JSONL)
    participant S as MCP Server (real tools)

    C->>G: tools/call "search_files" (request, id=7)
    G->>S: tools/call "search_files" (forwarded)
    S-->>G: result
    G->>A: append full entry (tool, args, result) + prev_hash
    A-->>G: entry hash (SHA-256 of canonical entry)
    G-->>C: result (forwarded, id=7)
```

## 3. Deny-list ✅ *(implemented in v0)*

Policy is checked by tool name. An allowed call flows through like diagram 2;
a denied call never reaches the real server. Either way, Ganimedes records the
attempt. The denied call gets a JSON-RPC error (`code -32000`) synthesized by
Ganimedes; it is the one message on the client-facing stream that did not come
from the real server (the deliberate, documented policy exception to
Constitution Art. 1.3).

```mermaid
sequenceDiagram
    participant C as MCP Client (agent)
    participant G as Ganimedes (proxy)
    participant P as Policy Engine
    participant A as Audit Log
    participant S as MCP Server (real tools)

    C->>G: tools/call (request, id=12)
    G->>P: check policy (by tool name)
    P-->>G: decision

    alt ALLOW (default: tool not on deny-list)
        G->>S: tools/call (forwarded)
        S-->>G: result
        G->>A: append full entry (decision=ALLOW)
        G-->>C: result (forwarded)
    else DENY (tool on deny-list, e.g. "db.dropTable")
        G->>A: append full entry (decision=DENY)
        G-->>C: JSON-RPC error (denied by policy)
        Note over S: the real server never sees this call
    end
```

## 4. Human-in-the-loop ✅ *(implemented in v0)*

A flagged call pauses. A human reviews it on the local approval page. The
result branches on approve, reject, or timeout. The approval timeout is
configurable and fails closed (defaults to deny). A tool is flagged by putting
its name on the config's `approve` list; the page is served on a loopback address
(`--approval-addr`).

```mermaid
sequenceDiagram
    participant C as MCP Client (agent)
    participant G as Ganimedes (proxy)
    participant P as Policy Engine
    participant H as Approval Page (localhost)
    participant U as Human
    participant A as Audit Log
    participant S as MCP Server (real tools)

    C->>G: tools/call "email.send" (request, id=20)
    G->>P: check policy for "email.send"
    P-->>G: REQUIRE_APPROVAL
    Note over C,G: client's tools/call is held open while we wait (client has its own timeout, separate from ours)
    G->>H: open pending approval (tool, args)
    U->>H: reviews, clicks Approve/Reject

    alt Approved
        H-->>G: APPROVED
        G->>S: tools/call "email.send" (forwarded)
        S-->>G: result
        G->>A: append full entry (decision=APPROVED)
        G-->>C: result (forwarded)
    else Rejected or timeout
        H-->>G: REJECTED / TIMEOUT
        G->>A: append full entry (decision=REJECTED or TIMEOUT)
        G-->>C: JSON-RPC error (rejected by human / timeout)
    end
```
