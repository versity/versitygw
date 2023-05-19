package posix

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

const procfddir = "/proc/self/fd"

func openTmpFile(dir string) (*os.File, error) {
	fd, err := unix.Open(dir, unix.O_RDWR|unix.O_TMPFILE|unix.O_CLOEXEC, 0666)
	if err != nil {
		return nil, err
	}

	return os.NewFile(uintptr(fd), filepath.Join(procfddir, strconv.Itoa(fd))), nil
}

func linkTmpFile(f *os.File, path string) error {
	err := os.Remove(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove stale part: %w", err)
	}

	procdir, err := os.Open(procfddir)
	if err != nil {
		return fmt.Errorf("open proc dir: %w", err)
	}
	defer procdir.Close()

	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open parent dir: %w", err)
	}
	defer dir.Close()

	err = unix.Linkat(int(procdir.Fd()), filepath.Base(f.Name()),
		int(dir.Fd()), filepath.Base(path), unix.AT_SYMLINK_FOLLOW)
	if err != nil {
		return fmt.Errorf("link tmpfile: %w", err)
	}

	return nil
}
