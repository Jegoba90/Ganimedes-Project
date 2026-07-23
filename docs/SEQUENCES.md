# Ganimedes - Sequence Diagrams

> Living document. Each diagram below is the runtime behavior spec for one
> milestone in the build order from [`DESIGN.md`](DESIGN.md#5-build-order).
> They are written in [Mermaid](https://mermaid.js.org/) `sequenceDiagram`
> syntax, which GitHub renders natively in markdown, so the diagrams stay
> plain text and diffable in git instead of drifting screenshots.

## 1. Transparent passthrough

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

    C->>G: tools/call "search_files" (request, id=1)
    G->>S: tools/call "search_files" (forwarded, id=1)
    S-->>G: result (response, id=1)
    G-->>C: result (forwarded, id=1)
```

## 2. Audit log

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
    G->>A: append entry (tool, args, result hash, prev_hash)
    A-->>G: hash of new entry
    G-->>C: result (forwarded, id=7)
```

## 3. Deny-list

A denied call never reaches the real server. Ganimedes answers with a JSON-RPC
error directly and still records the attempt.

```mermaid
sequenceDiagram
    participant C as MCP Client (agent)
    participant G as Ganimedes (proxy)
    participant P as Policy Engine
    participant A as Audit Log
    participant S as MCP Server (real tools)

    C->>G: tools/call "db.dropTable" (request, id=12)
    G->>P: check policy for "db.dropTable"
    P-->>G: DENY
    G->>A: append entry (tool, args, decision=DENY)
    G-->>C: JSON-RPC error (denied by policy)
    Note over S: the real server never sees this call
```

## 4. Human-in-the-loop

A flagged call pauses. A human reviews it on the local approval page. The
result branches on approve, reject, or timeout (timeout defaults to deny).

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
    G->>H: open pending approval (tool, args)
    U->>H: reviews, clicks Approve/Reject

    alt Approved
        H-->>G: APPROVED
        G->>S: tools/call "email.send" (forwarded)
        S-->>G: result
        G->>A: append entry (decision=APPROVED, result hash)
        G-->>C: result (forwarded)
    else Rejected or timeout
        H-->>G: REJECTED / TIMEOUT
        G->>A: append entry (decision=REJECTED or TIMEOUT)
        G-->>C: JSON-RPC error (rejected by human / timeout)
    end
```
