package posix

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

const procfddir = "/proc/self/fd"

type tmpfile struct {
	f       *os.File
	objname string
	isOTmp  bool
}

func openTmpFile(dir, obj string) (*tmpfile, error) {
	// O_TMPFILE allows for a file handle to an unnamed file in the filesystem.
	// This can help reduce contention within the namespace (parent directories),
	// etc. And will auto cleanup the inode on close if we never link this
	// file descriptor into the namespace.
	// Not all filesystems support this, so fallback to CreateTemp for when
	// this is not supported.
	fd, err := unix.Open(dir, unix.O_RDWR|unix.O_TMPFILE|unix.O_CLOEXEC, 0666)
	if err != nil {
		// O_TMPFILE not supported, try fallback
		f, err := os.CreateTemp(dir,
			fmt.Sprintf("%x\n", sha256.Sum256([]byte(obj))))
		if err != nil {
			return nil, err
		}
		return &tmpfile{f: f}, nil
	}

	f := os.NewFile(uintptr(fd), filepath.Join(procfddir, strconv.Itoa(fd)))
	return &tmpfile{f: f, isOTmp: true}, nil
}

func (tmp *tmpfile) link() error {
	// We use Linkat/Rename as the atomic operation for object puts. The
	// upload is written to a temp (or unnamed/O_TMPFILE) file to not conflict
	// with any other simultaneous uploads. The final operation is to move the
	// temp file into place for the object. This ensures the object semantics
	// of last upload completed wins and is not some combination of writes
	// from simultaneous uploads.
	err := os.Remove(tmp.objname)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove stale path: %w", err)
	}

	if tmp.isOTmp {
		procdir, err := os.Open(procfddir)
		if err != nil {
			return fmt.Errorf("open proc dir: %w", err)
		}
		defer procdir.Close()

		dir, err := os.Open(filepath.Dir(tmp.objname))
		if err != nil {
			return fmt.Errorf("open parent dir: %w", err)
		}
		defer dir.Close()

		err = unix.Linkat(int(procdir.Fd()), filepath.Base(tmp.f.Name()),
			int(dir.Fd()), filepath.Base(tmp.objname), unix.AT_SYMLINK_FOLLOW)
		if err != nil {
			return fmt.Errorf("link tmpfile: %w", err)
		}

		err = tmp.f.Close()
		if err != nil {
			return fmt.Errorf("close tmpfile: %w", err)
		}

		return nil
	}

	err = tmp.f.Close()
	if err != nil {
		return fmt.Errorf("close tmpfile: %w", err)
	}

	err = os.Rename(tmp.f.Name(), tmp.objname)
	if err != nil {
		return fmt.Errorf("rename tmpfile: %w", err)
	}

	return nil
}

func (tmp *tmpfile) Write(b []byte) (int, error) {
	return tmp.f.Write(b)
}

func (tmp *tmpfile) cleanup() {
	tmp.f.Close()
}
