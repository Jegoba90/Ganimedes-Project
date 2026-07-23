package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/Jegoba90/Ganimedes-Project/internal/config"
)

// TestRun_ForwardsBothDirections checks that Run transparently pipes the
// client's input to the server and the server's output back to the client.
// The "server" is this test binary re-executed as a helper (see
// TestHelperProcess) that echoes each line with a prefix, so the round trip
// is observable without depending on any external MCP server.
func TestRun_ForwardsBothDirections(t *testing.T) {
	// The helper only activates when this variable is set. exec.Command
	// inherits the parent environment, so the subprocess will see it.
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")

	in := strings.NewReader("hello\nworld\n")
	var out bytes.Buffer

	cfg := config.Config{
		Command: os.Args[0],
		Args:    []string{"-test.run=TestHelperProcess"},
	}

	if err := Run(cfg, in, &out); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	const want = "echo: hello\necho: world\n"
	if got := out.String(); got != want {
		t.Errorf("round trip mismatch:\n got: %q\nwant: %q", got, want)
	}
}

// TestHelperProcess is not a real test. Run's tests re-execute the test binary
// with GO_WANT_HELPER_PROCESS=1 to stand in for a real MCP server: it reads
// lines from stdin and writes each back to stdout with an "echo: " prefix,
// then exits at EOF.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		fmt.Printf("echo: %s\n", scanner.Text())
	}
	os.Exit(0)
}
