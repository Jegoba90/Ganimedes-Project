// Package config defines Ganimedes' configuration types (and, later, loading).
//
// In v0 milestone 1 the only configuration is which real MCP server to launch,
// which the CLI builds from its arguments. A config file (deny-list,
// approval-list) arrives in milestone 3; this package will grow a loader then.
package config

// Config describes how Ganimedes should run: which downstream MCP server to
// spawn and with what arguments. Ganimedes launches Command with Args and
// proxies the client's stdio to and from it.
type Config struct {
	// Command is the executable of the real MCP server to wrap.
	Command string
	// Args are the arguments passed to Command.
	Args []string
}
