// Package proxy will hold the core of Ganimedes: a stdio MCP proxy that sits
// between an MCP client and the real MCP server, forwarding JSON-RPC messages
// in both directions and intercepting tools/call.
//
// No logic yet. This file only reserves the package so the layout from
// docs/DESIGN.md is visible. Implementation lands in build-order step 1
// (transparent passthrough).
package proxy
