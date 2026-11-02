//go:build !(darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || windows)

package audit

import (
	"errors"
	"os"
)

// No kernel lock is wired up here. Appending without one could fork the chain
// with a concurrent writer, so the log refuses to open rather than pretend to
// be exclusive (Art. 2.1).
func lockFile(*os.File) error {
	return errors.New("exclusive audit log locking is not implemented on this platform")
}
