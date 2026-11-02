//go:build darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd

package audit

import (
	"errors"
	"os"
	"syscall"
)

// lockFile takes an exclusive flock on the log itself. flock belongs to the open
// file description, so the kernel drops it when the last descriptor closes,
// including when the process is killed: a client that terminates the gateway
// abruptly cannot leave a lock that blocks the next start. It also binds the
// inode rather than a pathname, so a hard-link alias contends for the same lock.
// Go opens files close-on-exec, so the wrapped server never inherits it.
//
// flock is advisory: a process that writes without asking for it, such as an
// older Ganimedes or an editor, is not stopped.
func lockFile(f *os.File) error {
	conn, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var lockErr error
	if err := conn.Control(func(fd uintptr) {
		lockErr = syscall.Flock(int(fd), syscall.LOCK_EX|syscall.LOCK_NB)
	}); err != nil {
		return err
	}
	if errors.Is(lockErr, syscall.EWOULDBLOCK) {
		return errLogLocked
	}
	return lockErr
}
