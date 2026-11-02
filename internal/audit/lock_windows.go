//go:build windows

package audit

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

// The standard library exposes no LockFileEx wrapper. kernel32.dll is a
// KnownDLL, always loaded from the system directory, so resolving it by name
// cannot pick up a planted copy beside the binary.
var procLockFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("LockFileEx")

const (
	lockfileFailImmediately = 0x1
	lockfileExclusiveLock   = 0x2

	errorLockViolation syscall.Errno = 33 // ERROR_LOCK_VIOLATION
)

// Windows byte-range locks are mandatory: a locked range refuses reads through
// every other handle. Locking the log's content would stop `ganimedes verify`
// from reading a log that is in use, so the lock covers one byte at an offset
// no log reaches. Locking beyond end of file is permitted, and appends at the
// real end never touch it.
const (
	lockOffsetLow  = 0xFFFFFFFF
	lockOffsetHigh = 0x7FFFFFFF
)

// lockFile takes an exclusive LockFileEx lock through the log's own handle.
// Windows releases it when the handle closes, including when the process is
// terminated, so an abrupt exit cannot leave a lock that blocks the next start.
// The lock belongs to the file rather than a pathname, so a hard-link alias
// contends for it too. Go opens handles non-inheritable, so the wrapped server
// never holds it.
func lockFile(f *os.File) error {
	conn, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var lockErr error
	if err := conn.Control(func(fd uintptr) {
		ol := syscall.Overlapped{Offset: lockOffsetLow, OffsetHigh: lockOffsetHigh}
		r, _, e := procLockFileEx.Call(fd, lockfileExclusiveLock|lockfileFailImmediately, 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
		if r == 0 {
			lockErr = e
		}
	}); err != nil {
		return err
	}
	if errors.Is(lockErr, errorLockViolation) {
		return errLogLocked
	}
	return lockErr
}
