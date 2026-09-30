//go:build !windows

package posix

import "syscall"

// rawUmask returns the process file mode creation mask. It is momentarily
// cleared while reading, which is only safe during backend construction,
// before any goroutine creates files.
func rawUmask() int {
	umask := syscall.Umask(0)
	syscall.Umask(umask)
	return umask
}
