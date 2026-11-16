# Ganimedes

**Governance and verifiable audit for MCP tool calls.**

[![CI](https://img.shields.io/github/actions/workflow/status/Jegoba90/Ganimedes-Project/ci.yml?branch=main&event=push&style=flat-square&label=CI)](https://github.com/Jegoba90/Ganimedes-Project/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Jegoba90/Ganimedes-Project?style=flat-square&color=8b5cf6)](https://github.com/Jegoba90/Ganimedes-Project/releases/latest)
[![License](https://img.shields.io/github/license/Jegoba90/Ganimedes-Project?style=flat-square&color=8b5cf6)](https://github.com/Jegoba90/Ganimedes-Project/blob/main/LICENSE)

A local gateway between your AI agent and one stdio MCP server. Ganimedes
forwards allowed calls, blocks denied tools, pauses flagged calls for human
approval and records completed calls and blocked attempts in a signed,
hash-chained log.

| Control | What it gives you |
|---------|-------------------|
| Deny-list | Block selected tools with JSON rules |
| Human approval | Hold selected calls for an explicit decision on a local page |
| Verifiable audit | Check the log's hash chain and Ed25519 signatures offline |

## Install

With Go 1.26.10 or newer:

```sh
go install github.com/Jegoba90/Ganimedes-Project/cmd/ganimedes@latest
ganimedes help
```

The gateway uses the Go standard library only. Prebuilt binaries for Linux,
macOS and Windows are available in
[Releases](https://github.com/Jegoba90/Ganimedes-Project/releases/latest).

## Start with your server

Replace `your-mcp-server` with a stdio MCP server command installed on your
machine. Install its runtime separately if it needs one.

```sh
ganimedes scan -- your-mcp-server
ganimedes run -- your-mcp-server
```

`scan` lists the server's tools and flags risky keywords; it does not enforce
policy. `run` holds the MCP session open. Configure your MCP client to launch
that command; the [setup guide](https://github.com/Jegoba90/Ganimedes-Project#point-your-client-at-it)
shows the client configuration and absolute paths.

After stopping the gateway, verify the recorded log:

```sh
ganimedes verify --pubkey ganimedes-signing.pub ganimedes-audit.jsonl
```

## Know the boundary

Ganimedes governs calls crossing the server it wraps. It does not sandbox the
agent or control other connections. The audit log holds full arguments and
results, which may include secrets. Unanswered calls and failed appends can
leave gaps; verification does not detect removal of the log's tail. Keep the
signing key private and retain a trusted copy of the public key.

[Full guide](https://github.com/Jegoba90/Ganimedes-Project#quick-start) ·
[Policy and approval](https://github.com/Jegoba90/Ganimedes-Project#block-and-approve) ·
[Security and limitations](https://github.com/Jegoba90/Ganimedes-Project/blob/main/SECURITY.md)
