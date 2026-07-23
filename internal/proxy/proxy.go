// Package proxy is the core of Ganimedes: a stdio proxy that sits between an
// MCP client and the real MCP server, forwarding JSON-RPC messages in both
// directions.
//
// Milestone 1 is a transparent passthrough: bytes are shuttled unchanged, with
// no parsing. Message inspection (for the audit log and policy) arrives in
// later milestones; see docs/ARCHITECTURE.md.
package proxy

import (
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/Jegoba90/Ganimedes-Project/internal/config"
)

// Run wraps the MCP server described by cfg and proxies a single client
// session to it. Client bytes are read from in and forwarded to the server's
// stdin; the server's stdout is forwarded back to out. The real server's
// stderr is passed through to Ganimedes' own stderr so its logs stay visible.
//
// in and out are plain io.Reader/io.Writer (not hardcoded to os.Stdin/Stdout)
// so the proxy can be driven by in-memory streams in tests.
//
// Run blocks until the server closes its output (typically because it exited),
// then reaps the process. It returns the first error encountered, or nil on a
// clean shutdown.
func Run(cfg config.Config, in io.Reader, out io.Writer) error {
	cmd := exec.Command(cfg.Command, cfg.Args...)
	cmd.Stderr = os.Stderr // out-of-band: surface the real server's logs

	serverIn, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("wiring server stdin: %w", err)
	}
	serverOut, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("wiring server stdout: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting server %q: %w", cfg.Command, err)
	}

	// Direction 1 (client -> server): forward everything the client sends,
	// then close the server's stdin so it sees EOF and can shut down. This
	// runs in the background because a blocking read on the client must not
	// hold up the server's output. On a normal shutdown the client closes its
	// input, which unblocks this goroutine.
	go func() {
		_, _ = io.Copy(serverIn, in)
		_ = serverIn.Close()
	}()

	// Direction 2 (server -> client): the direction we wait on, since the
	// server closing its stdout is what signals the session is over.
	//
	// io.Copy (rather than line-by-line reads) keeps milestone 1 a pure byte
	// passthrough and sidesteps any max-line-length limit; line framing is
	// introduced only when a later milestone needs to inspect messages.
	if _, err := io.Copy(out, serverOut); err != nil {
		return fmt.Errorf("forwarding server output: %w", err)
	}

	// All output has been read, so it is now safe to reap the process. Wait
	// closes the stdout pipe, so it must come after the copy above.
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("server exited with error: %w", err)
	}
	return nil
}
