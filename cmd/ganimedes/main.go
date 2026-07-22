// Command ganimedes is the entrypoint for the Ganimedes CLI.
//
// In Go, an executable lives in `package main` and starts at func main().
// By convention we keep this file tiny: it wires the process together and
// hands off to internal/cli. All real logic lives in internal packages so it
// can be tested without spawning a process.
//
// Layout note: this file sits under cmd/ganimedes/. The `cmd/` directory is
// the Go community convention for "the main packages that produce binaries".
// The folder name (ganimedes) becomes the binary name when you run
// `go build ./cmd/ganimedes`.
package main

import (
	"os"

	"github.com/Jegoba90/Ganimedes-Project/internal/cli"
)

func main() {
	// os.Args[0] is the program name; the real arguments start at [1:].
	//
	// We keep os.Exit at the very top level and nowhere else, because the
	// moment you call os.Exit any deferred functions are skipped. cli.Run
	// returns the exit code so main can stay a single line.
	os.Exit(cli.Run(os.Args[1:]))
}
