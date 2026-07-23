// Package cli implements Ganimedes' command-line interface.
//
// Why `internal/`? Go gives special meaning to a directory named internal:
// packages under it can only be imported by code inside this module. It is
// the language's built-in "this is a private implementation detail" marker,
// which is exactly what a CLI's guts should be.
//
// v0 uses only the standard library (no CLI framework) so the fundamentals
// stay visible. A framework like cobra can come later if the surface grows.
package cli

import (
	"fmt"
	"os"

	"github.com/Jegoba90/Ganimedes-Project/internal/config"
	"github.com/Jegoba90/Ganimedes-Project/internal/proxy"
)

// version is stamped by hand for now. Later it can be injected at build time
// with -ldflags "-X ...". Keeping it inline keeps v0 dependency-free.
const version = "0.0.0-dev"

// Run is the real entrypoint. It receives the arguments (already stripped of
// the program name) and returns a process exit code (0 = success). Returning
// an int instead of calling os.Exit here keeps this function easy to test.
func Run(args []string) int {
	// No subcommand: show help and succeed.
	if len(args) == 0 {
		printUsage()
		return 0
	}

	// The first argument selects the subcommand. The rest (args[1:]) will be
	// handed to each command once it is implemented.
	switch args[0] {
	case "version", "-v", "--version":
		fmt.Println("ganimedes", version)
		return 0

	case "help", "-h", "--help":
		printUsage()
		return 0

	// `run` is milestone 1 (transparent passthrough). `verify` and `init`
	// stay wired but unbuilt until their milestones (see docs/DESIGN.md).
	case "run":
		return runCommand(args[1:])
	case "verify":
		return notImplemented("verify")
	case "init":
		return notImplemented("init")

	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		printUsage()
		return 2
	}
}

// runCommand implements `ganimedes run -- <server-command> [args...]`. It wraps
// the named MCP server, proxying the client's stdio (os.Stdin/os.Stdout) to and
// from it. A leading "--" is accepted and skipped so that `run` can grow its
// own flags later without colliding with the wrapped command's arguments.
func runCommand(args []string) int {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "run: usage: ganimedes run -- <server-command> [args...]")
		return 2
	}

	cfg := config.Config{Command: args[0], Args: args[1:]}
	if err := proxy.Run(cfg, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		return 1
	}
	return 0
}

// notImplemented is the placeholder for v0 commands that are wired but not
// built. It returns a non-zero code so scripts can tell they are not ready.
func notImplemented(name string) int {
	fmt.Fprintf(os.Stderr, "%s: not implemented yet (see docs/DESIGN.md)\n", name)
	return 1
}

// printUsage writes a short help text to stdout.
func printUsage() {
	fmt.Print(`ganimedes - the control and security layer for autonomous AI agents

Usage:
  ganimedes <command> [flags]

Commands:
  run       Wrap an MCP server: ganimedes run -- <server-cmd> [args]
  verify    Check the integrity of the audit log (not implemented yet)
  init      Scaffold a config file (not implemented yet)
  version   Print the version
  help      Show this help

This is a v0 skeleton. See docs/DESIGN.md for the plan.
`)
}
