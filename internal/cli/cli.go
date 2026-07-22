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

	// The three commands below are the v0 surface from docs/DESIGN.md. They
	// are wired up but deliberately not built yet: the logic lands in later
	// steps of the build order.
	case "run":
		return notImplemented("run")
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
  run       Start the MCP gateway (not implemented yet)
  verify    Check the integrity of the audit log (not implemented yet)
  init      Scaffold a config file (not implemented yet)
  version   Print the version
  help      Show this help

This is a v0 skeleton. See docs/DESIGN.md for the plan.
`)
}
