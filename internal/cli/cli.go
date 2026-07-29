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
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"time"

	"github.com/Jegoba90/Ganimedes-Project/internal/approval"
	"github.com/Jegoba90/Ganimedes-Project/internal/audit"
	"github.com/Jegoba90/Ganimedes-Project/internal/config"
	"github.com/Jegoba90/Ganimedes-Project/internal/proxy"
	"github.com/Jegoba90/Ganimedes-Project/internal/scan"
)

// version is stamped by hand for now. Later it can be injected at build time
// with -ldflags "-X ...". Keeping it inline keeps v0 dependency-free.
const version = "0.0.0-dev"

// defaultLogPath is where the audit log lives when no --log is given. A path in
// the current directory keeps v0 transparent (you can see and cat the file);
// a config-driven location arrives with the config file in milestone 3.
const defaultLogPath = "ganimedes-audit.jsonl"

// defaultSigningKeyPath is the Ed25519 signing key `run` uses when none is given.
// It is generated on first run next to the log, and its public half is written
// to the matching .pub path (audit.PublicKeyPath) so `verify` finds it with no
// flags. signingKeyEnv lets an operator point at a key they manage elsewhere
// (a secrets manager, a separate volume) without a flag on every invocation.
const (
	defaultSigningKeyPath = "ganimedes-signing.key"
	signingKeyEnv         = "GANIMEDES_SIGNING_KEY"
)

// Approval-page defaults (milestone 4). The address must be loopback (validated
// by internal/approval, Constitution Art. 2.2); the timeout fails closed to a
// denial when a human does not answer (Art. 2.1, 3.4). Both are configurable via
// --approval-addr and --approval-timeout.
const (
	defaultApprovalAddr    = "127.0.0.1:8765"
	defaultApprovalTimeout = 60 * time.Second
)

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

	// `run` (milestone 1 passthrough + milestone 2 audit + milestone 3 deny),
	// `scan` (the deny-list pre-flight helper), and `verify` (milestone 2) are
	// built. `init` stays wired but unbuilt until its milestone (see
	// docs/DESIGN.md).
	case "run":
		return runCommand(args[1:])
	case "scan":
		return scanCommand(args[1:])
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
const usageRun = "run: usage: ganimedes run [--config <path>] [--log <path>] [--signing-key <path>] [--approval-addr <host:port>] [--approval-timeout <dur>] -- <server-command> [args...]"

// runCommand implements
//
//	ganimedes run [--config <path>] [--log <path>] [--signing-key <path>] [--approval-addr <host:port>] [--approval-timeout <dur>] -- <server-command> [args...]
//
// It wraps an MCP server, proxying the client's stdio (os.Stdin/os.Stdout) to
// and from it, blocking any tools/call on the deny-list, pausing any tools/call
// on the approval-list for a human, and appending every tools/call to the audit
// log. A leading "--" separates Ganimedes' own flags from the wrapped command,
// so the server's arguments never collide with ours.
//
// The server command may come from --config or from the "--" tail; when both
// give one, the explicit command line wins. The deny-list and approval-list come
// from --config. When the approval-list is non-empty a local approval page is
// served at --approval-addr (loopback only) and each held call has --approval-timeout
// to be answered before it fails closed. Every audit entry is Ed25519-signed with
// the key at --signing-key (or the GANIMEDES_SIGNING_KEY env var, or the default
// path); the key is generated on first use if it does not exist.
func runCommand(args []string) int {
	logPath := defaultLogPath
	configPath := ""
	signingKeyPath := ""
	approvalAddr := defaultApprovalAddr
	approvalTimeout := defaultApprovalTimeout

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
		if args[0] == "--signing-key" {
			if len(args) < 2 {
				fmt.Fprintln(os.Stderr, "run: --signing-key needs a path")
				return 2
			}
			signingKeyPath, args = args[1], args[2:]
			continue
		}
		if args[0] == "--approval-addr" {
			if len(args) < 2 {
				fmt.Fprintln(os.Stderr, "run: --approval-addr needs an address")
				return 2
			}
			approvalAddr, args = args[1], args[2:]
			continue
		}
		if args[0] == "--approval-timeout" {
			if len(args) < 2 {
				fmt.Fprintln(os.Stderr, "run: --approval-timeout needs a duration (e.g. 60s)")
				return 2
			}
			d, err := time.ParseDuration(args[1])
			if err != nil {
				fmt.Fprintf(os.Stderr, "run: invalid --approval-timeout %q: %v\n", args[1], err)
				return 2
			}
			approvalTimeout, args = d, args[2:]
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

	keyPath := resolveSigningKeyPath(signingKeyPath)
	priv, created, err := audit.LoadOrCreateSigningKey(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		return 1
	}
	if created {
		fmt.Fprintf(os.Stderr, "run: generated a new signing key at %q (public key at %q)\n",
			keyPath, audit.PublicKeyPath(keyPath))
	}

	log, err := audit.Open(logPath, audit.NewSession(), priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		return 1
	}
	defer log.Close()

	// Human-in-the-loop: when the config lists tools that require approval, stand
	// up the local approval page and hand the proxy an approver. With no such
	// tools there is nothing to approve, so the page is not started and the proxy
	// runs exactly as in milestone 3.
	var appr proxy.Approver
	if len(cfg.Approve) > 0 {
		srv, err := approval.New(approvalAddr, approvalTimeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "run: %v\n", err)
			return 1
		}
		if err := srv.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "run: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "run: approval page at %s ; %d tool(s) require approval, %s timeout (fail-closed)\n",
			srv.URL(), len(cfg.Approve), approvalTimeout)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Close(ctx) // best-effort graceful shutdown on exit
		}()
		appr = srv
	}

	if err := proxy.Run(cfg, os.Stdin, os.Stdout, log, appr); err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		return 1
	}
	return 0
}

// usageScan is the one-line usage for the scan subcommand.
const usageScan = "scan: usage: ganimedes scan [--config <path>] -- <server-command> [args...]"

// scanCommand implements
//
//	ganimedes scan [--config <path>] -- <server-command> [args...]
//
// It spawns the wrapped MCP server, performs the initialize + tools/list
// handshake, and prints every discovered tool, flagging the ones whose name or
// description matches a risky keyword. scan is a pre-flight helper for writing
// the deny-list: it takes no enforcement action and writes no audit log, so it
// needs no --log. The server command may come from --config or the "--" tail;
// an explicit command line wins, and any deny-list in the config is ignored
// (scan is what you run to decide the deny-list). Exit codes: 0 = scanned
// (whether or not anything was flagged), 1 = could not scan, 2 = usage error.
func scanCommand(args []string) int {
	configPath := ""

	// Hand-rolled parsing mirrors runCommand: only flags before "--" are ours,
	// so the wrapped server's own arguments never collide with Ganimedes' flags.
	for len(args) > 0 {
		if args[0] == "--" {
			args = args[1:]
			break
		}
		if args[0] == "--config" {
			if len(args) < 2 {
				fmt.Fprintln(os.Stderr, "scan: --config needs a path")
				return 2
			}
			configPath, args = args[1], args[2:]
			continue
		}
		// First non-flag token: the wrapped command starts here.
		break
	}

	var cfg config.Config
	if configPath != "" {
		c, err := config.Load(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan: %v\n", err)
			return 1
		}
		cfg = c
	}
	if len(args) > 0 {
		cfg.Command, cfg.Args = args[0], args[1:]
	}
	if cfg.Command == "" {
		fmt.Fprintln(os.Stderr, usageScan)
		return 2
	}

	report, err := scan.Scan(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan: %v\n", err)
		return 1
	}
	scan.Render(os.Stdout, report, cfg.Command)
	return 0
}

// verifyCommand implements `ganimedes verify [--pubkey <path>] [log-path]`: it
// walks the audit log's hash chain and checks every entry's signature, reporting
// whether the log is intact. The log path defaults to the file `run` writes. The
// public key comes from --pubkey, else the default .pub next to the signing key,
// else it is derived from the signing key itself; an offline verifier passes
// --pubkey and needs only the public key and the log. Exit codes: 0 = intact,
// 1 = broken or unreadable, so scripts and CI can gate on it.
func verifyCommand(args []string) int {
	path := defaultLogPath
	pubkeyPath := ""

	for len(args) > 0 {
		if args[0] == "--pubkey" {
			if len(args) < 2 {
				fmt.Fprintln(os.Stderr, "verify: --pubkey needs a path")
				return 2
			}
			pubkeyPath, args = args[1], args[2:]
			continue
		}
		// First non-flag token is the log path.
		path, args = args[0], args[1:]
	}

	pub, err := resolvePublicKey(pubkeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify: %v\n", err)
		return 1
	}

	res, err := audit.Verify(path, pub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify: %v\n", err)
		return 1
	}

	if res.OK {
		fmt.Printf("audit log OK: %d entries, chain intact and signatures valid (%s)\n", res.Entries, path)
		return 0
	}
	fmt.Fprintf(os.Stderr, "audit log TAMPERED: entry %d of %d: %s (%s)\n",
		res.BadEntry, res.Entries, res.Reason, path)
	return 1
}

// resolveSigningKeyPath picks the signing key path from, in order: an explicit
// --signing-key, the GANIMEDES_SIGNING_KEY env var, or the default path.
func resolveSigningKeyPath(flag string) string {
	if flag != "" {
		return flag
	}
	if env := os.Getenv(signingKeyEnv); env != "" {
		return env
	}
	return defaultSigningKeyPath
}

// resolvePublicKey finds the public key verify should check against. An explicit
// --pubkey wins (this is the offline path: only the public key is needed). On the
// same host as run, the public key sits at the default .pub path; failing that,
// it is derived from the default signing key if that is present.
func resolvePublicKey(pubkeyFlag string) (ed25519.PublicKey, error) {
	if pubkeyFlag != "" {
		return audit.LoadPublicKey(pubkeyFlag)
	}
	pubPath := audit.PublicKeyPath(defaultSigningKeyPath)
	if _, err := os.Stat(pubPath); err == nil {
		return audit.LoadPublicKey(pubPath)
	}
	if priv, err := audit.LoadSigningKey(defaultSigningKeyPath); err == nil {
		pub, ok := priv.Public().(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("signing key %q did not yield an ed25519 public key", defaultSigningKeyPath)
		}
		return pub, nil
	}
	return nil, fmt.Errorf("no public key found (looked for %q); pass --pubkey <path>", pubPath)
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
  run       Wrap an MCP server: ganimedes run [--config <path>] [--log <path>] [--signing-key <path>] [--approval-addr <host:port>] [--approval-timeout <dur>] -- <server-cmd> [args]
  scan      List a server's tools and flag the risky ones: ganimedes scan [--config <path>] -- <server-cmd> [args]
  verify    Check the audit log's chain and signatures: ganimedes verify [--pubkey <path>] [log-path]
  init      Scaffold a config file (not implemented yet)
  version   Print the version
  help      Show this help

This is a v0 skeleton. See docs/DESIGN.md for the plan.
`)
}
