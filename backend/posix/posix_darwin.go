package posix

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

type tmpfile struct {
	f       *os.File
	objname string
}

func openTmpFile(dir, obj string) (*tmpfile, error) {
	// Create a temp file for upload while in progress (see link comments below).
	f, err := os.CreateTemp(dir,
		fmt.Sprintf("%x\n", sha256.Sum256([]byte(obj))))
	if err != nil {
		return nil, err
	}
	return &tmpfile{f: f, objname: obj}, nil
}

func (tmp *tmpfile) link() error {
	// We use Rename as the atomic operation for object puts. The upload is
	// written to a temp file to not conflict with any other simultaneous
	// uploads. The final operation is to move the temp file into place for
	// the object. This ensures the object semantics of last upload completed
	// wins and is not some combination of writes from simultaneous uploads.
	err := os.Remove(tmp.objname)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove stale path: %w", err)
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
