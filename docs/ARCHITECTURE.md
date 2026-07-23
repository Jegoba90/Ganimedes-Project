# Ganimedes - Internal Architecture & Development Plan

> Living document. Companion to [`DESIGN.md`](DESIGN.md) (the what/why and the
> build order) and [`SEQUENCES.md`](SEQUENCES.md) (the wire-protocol view).
> This file is the internal, Go-level design: how the packages connect, what
> the core types look like, and the concrete task list to start coding
> milestone 1.

## 1. Package responsibilities and how they connect

```
cmd/ganimedes/main.go
        │  os.Exit(cli.Run(os.Args[1:]))
        ▼
internal/cli
        │  parses the subcommand, loads config, calls proxy.Run
        ▼
internal/proxy  ◀── internal/config (what to spawn, deny/approval lists)
        │       ◀── internal/policy (milestone 3+: ALLOW/DENY/REQUIRE_APPROVAL)
        │       ──▶ internal/audit  (milestone 2+: append-only hash-chained log)
        ▼
  the real MCP server (subprocess, spawned via os/exec)
```

`proxy` is the only package that talks to the outside world (stdio to the
client, a subprocess to the real server). `policy` and `audit` are pure
logic/IO packages with no knowledge of JSON-RPC framing; `proxy` calls into
them. This keeps each package testable on its own, without spawning a real
subprocess or a real MCP client.

## 2. Milestone 1 design: transparent passthrough

**Decision: raw line forwarding, no JSON parsing yet.** Milestone 1 only has
to prove the pipe works: spawn the real server, shuttle bytes both ways
without corrupting anything. Parsing JSON-RPC is not needed to prove that, and
skipping it keeps milestone 1 small. Parsing gets introduced in milestone 2,
when the audit log needs to read `tool`/`args`/`result` out of each message.
When it is introduced, the **original raw bytes are still what gets
forwarded** (never a re-marshaled copy), so nothing we do to inspect a message
can accidentally change it on the wire.

### Core types

`internal/config` owns the configuration type; `internal/proxy` consumes it:

```go
// package config
type Config struct {
    Command string   // executable of the real MCP server to wrap
    Args    []string // arguments passed to Command
}

// package proxy
//
// Run wires a client (reading from in, writing to out) to the MCP server
// described by cfg. in/out are plain io.Reader/io.Writer, not hardcoded to
// os.Stdin/Stdout, so tests can drive it with in-memory streams. It blocks
// until the server closes its output, then reaps the process.
func Run(cfg config.Config, in io.Reader, out io.Writer) error
```

### Concurrency model

MCP over stdio is two independent byte streams. `Run` spawns the real server
with `os/exec`, wires its `StdinPipe()`/`StdoutPipe()`, and starts **two
goroutines**, one per direction:

```
goroutine 1:  in (client)        --verbatim (io.Copy)-->  server's stdin
goroutine 2:  server's stdout    --verbatim (io.Copy)-->  out (client)
```

For milestone 1 each direction is a plain `io.Copy` (raw byte passthrough): no
line framing, no parsing, and no maximum-line-length limit to worry about.
`Run` waits on the server->client copy to finish (the server closing its stdout
is what ends the session), then calls `cmd.Wait()` to reap the process. Line
framing, needed to inspect individual messages, is introduced in milestone 2,
which forwards the original bytes regardless.

**Forward note, not designed yet:** once milestone 2 adds the audit log, the
hash chain requires writes to happen in a strict order (each entry's hash
depends on the previous one). That means audit writes cannot happen
concurrently from both goroutines without coordination — likely a single
writer goroutine fed by a channel, or a mutex around the log file. This is
milestone 2's problem to solve, noted here only so milestone 1's structure
does not accidentally make it harder later.

## 3. Milestone 1 task list

Status: **milestone 1 code complete** (2026-07-23). Steps reflect what was
actually built; where it diverged from the original plan, the note says why.

1. ✅ **`internal/config`**: `Config` struct defined. The YAML `Load` was
   **deferred to milestone 3**: milestone 1 needs only which server to spawn,
   which the CLI takes from its arguments, so no config file (and no file
   format) is needed yet. When the file arrives in milestone 3 it will be JSON
   (stdlib, keeps the zero-dependency promise), not YAML.
2. ✅ **`internal/proxy`**: `Run(cfg, in, out) error` implemented. Spawns the
   subprocess, wires its pipes, runs one goroutine per direction, waits on the
   server->client direction, then reaps the process. Uses `io.Copy` (raw byte
   passthrough) rather than line reading; line framing lands in milestone 2.
3. ✅ **`internal/cli`**: `run` wired to `runCommand`, which parses
   `ganimedes run -- <server-cmd> [args]` and calls
   `proxy.Run(cfg, os.Stdin, os.Stdout)`.
4. ⏳ **Manual test** (user-driven): point an MCP client at Ganimedes wrapping a
   real MCP server and confirm the agent behaves as if talking to the server
   directly. Pending; runs in the user's environment.
5. ✅ **Automated test**: `proxy_test.go` drives `Run` with an in-memory reader
   and the test binary re-executed as an echo "server" (the standard
   `TestHelperProcess` pattern), so CI needs no external MCP server. proxy
   package coverage: 72.2%. An additional manual smoke wrapping the real `sort`
   binary confirmed end-to-end passthrough.

Milestone 1's acceptance (the agent works transparently through the proxy) is
met for the automated path; the manual test against a real MCP server (step 4)
remains for the user to run.
