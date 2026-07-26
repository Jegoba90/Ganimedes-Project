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

	"github.com/Jegoba90/Ganimedes-Project/internal/audit"
	"github.com/Jegoba90/Ganimedes-Project/internal/config"
	"github.com/Jegoba90/Ganimedes-Project/internal/proxy"
)

// version is stamped by hand for now. Later it can be injected at build time
// with -ldflags "-X ...". Keeping it inline keeps v0 dependency-free.
const version = "0.0.0-dev"

// defaultLogPath is where the audit log lives when no --log is given. A path in
// the current directory keeps v0 transparent (you can see and cat the file);
// a config-driven location arrives with the config file in milestone 3.
const defaultLogPath = "ganimedes-audit.jsonl"

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

	// `run` (milestone 1 passthrough + milestone 2 audit) and `verify`
	// (milestone 2) are built. `init` stays wired but unbuilt until its
	// milestone (see docs/DESIGN.md).
	case "run":
		return runCommand(args[1:])
	case "verify":
		return verifyCommand(args[1:])
	case "init":
		return notImplemented("init")

	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		printUsage()
		return 2
	}
}

// usageRun is the one-line usage for the run subcommand.
const usageRun = "run: usage: ganimedes run [--config <path>] [--log <path>] -- <server-command> [args...]"

// runCommand implements
//
//	ganimedes run [--config <path>] [--log <path>] -- <server-command> [args...]
//
// It wraps an MCP server, proxying the client's stdio (os.Stdin/os.Stdout) to
// and from it, blocking any tools/call on the deny-list, and appending every
// tools/call to the audit log. A leading "--" separates Ganimedes' own flags
// from the wrapped command, so the server's arguments never collide with ours.
//
// The server command may come from --config or from the "--" tail; when both
// give one, the explicit command line wins. The deny-list comes from --config.
func runCommand(args []string) int {
	logPath := defaultLogPath
	configPath := ""

	// Hand-rolled flag parsing (no flag package) so the "--" boundary with the
	// wrapped command stays explicit. Only flags before "--" are ours.
	for len(args) > 0 {
		if args[0] == "--" {
			args = args[1:]
			break
		}
		if args[0] == "--log" {
			if len(args) < 2 {
				fmt.Fprintln(os.Stderr, "run: --log needs a path")
				return 2
			}
			logPath, args = args[1], args[2:]
			continue
		}
		if args[0] == "--config" {
			if len(args) < 2 {
				fmt.Fprintln(os.Stderr, "run: --config needs a path")
				return 2
			}
			configPath, args = args[1], args[2:]
			continue
		}
		// First non-flag token: the wrapped command starts here.
		break
	}

	// Start from the config file (if any) for the deny-list and any command it
	// specifies, then let an explicit command line override the command.
	var cfg config.Config
	if configPath != "" {
		c, err := config.Load(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "run: %v\n", err)
			return 1
		}
		cfg = c
	}
	if len(args) > 0 {
		cfg.Command, cfg.Args = args[0], args[1:]
	}
	if cfg.Command == "" {
		fmt.Fprintln(os.Stderr, usageRun)
		return 2
	}

	log, err := audit.Open(logPath, audit.NewSession())
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		return 1
	}
	defer log.Close()

	if err := proxy.Run(cfg, os.Stdin, os.Stdout, log); err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		return 1
	}
	return 0
}

// verifyCommand implements `ganimedes verify [path]`: it walks the audit log's
// hash chain and reports whether it is intact. The path defaults to the same
// file `run` writes. Exit codes: 0 = chain intact, 1 = broken or unreadable, so
// scripts and CI can gate on it.
func verifyCommand(args []string) int {
	path := defaultLogPath
	if len(args) > 0 {
		path = args[0]
	}

	res, err := audit.Verify(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify: %v\n", err)
		return 1
	}

	if res.OK {
		fmt.Printf("audit log OK: %d entries, chain intact (%s)\n", res.Entries, path)
		return 0
	}
	fmt.Fprintf(os.Stderr, "audit log TAMPERED: entry %d of %d: %s (%s)\n",
		res.BadEntry, res.Entries, res.Reason, path)
	return 1
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
  run       Wrap an MCP server: ganimedes run [--config <path>] [--log <path>] -- <server-cmd> [args]
  verify    Check the integrity of the audit log: ganimedes verify [path]
  init      Scaffold a config file (not implemented yet)
  version   Print the version
  help      Show this help

This is a v0 skeleton. See docs/DESIGN.md for the plan.
`)
}
