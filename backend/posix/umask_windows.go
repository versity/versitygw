//go:build windows

package posix

// rawUmask reports a mask that strips every bit on Windows, where POSIX
// modes do not apply: the explicit chmod of the CreateTemp path is kept.
func rawUmask() int { return 0o777 }
