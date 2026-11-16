// Ganimedes is a local security gateway for MCP servers over stdio.
// It blocks named tools, pauses selected calls for human approval, and records
// completed calls and blocked attempts in a hash-chained, Ed25519-signed log.
//
// # Install
//
// Building from source requires Go 1.26.10 or newer:
//
//	go install github.com/Jegoba90/Ganimedes-Project/cmd/ganimedes@latest
//
// # Wrap a server
//
// Replace your-mcp-server with an installed MCP server command and its arguments.
// Install that server and any runtime it needs separately. Configure your MCP
// client to launch the run command so calls pass through the gateway:
//
//	ganimedes run -- your-mcp-server
//	ganimedes scan -- your-mcp-server
//
// Scan lists the server's tools and flags potentially risky names or descriptions.
// It reports findings; enforcement happens during run, according to its policy.
//
// # Configure policy
//
// Save a JSON policy file, for example policy.json:
//
//	{"deny":["database.delete"],"approve":["payment.execute"]}
//
// Replace these example tool names with names reported by scan for your server.
//
// Apply it when wrapping the server:
//
//	ganimedes run --config policy.json -- your-mcp-server
//
// Tool names match exactly. Deny takes precedence over approval; unlisted names
// are allowed by policy. An approval timeout or an undecidable call is denied.
// Approval uses a local, loopback-only page whose address is printed on stderr.
//
// # Verify a log
//
// Verify the chain and signatures offline using the log and its public key:
//
//	ganimedes verify --pubkey ganimedes-signing.pub ganimedes-audit.jsonl
//
// The log stores full arguments and results and may contain secrets. Unanswered
// calls and failed log appends can leave gaps; verification does not prove that
// every attempted action was recorded. Ganimedes governs only calls through the
// wrapped MCP connection. It is not a process sandbox.
//
// # More information
//
//	ganimedes help
//	ganimedes version
//
// See the [README] for installation and worked examples and [SECURITY] for the
// security boundary, known limitations and release verification.
//
// [README]: https://github.com/Jegoba90/Ganimedes-Project/blob/main/README.md
// [SECURITY]: https://github.com/Jegoba90/Ganimedes-Project/blob/main/SECURITY.md
package main
