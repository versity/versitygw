// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// Copyright 2024 Versity Software

// MkdirAll borrowed from stdlib to add ability to set ownership
// as directories are created

package backend

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/versity/versitygw/s3err"
)

// maxMkdirRaceRetries bounds how many times MkdirAll makes a directory
// again after a concurrent remove took it, or one of its parents, away.
const maxMkdirRaceRetries = 16

// MkdirAll is similar to os.MkdirAll but it will return
// ErrObjectParentIsFile when appropriate
// MkdirAll creates a directory named path,
// along with any necessary parents, and returns nil,
// or else returns an error.
// The permission bits perm (before umask) are used for all
// directories that MkdirAll creates.
// Any newly created directory is set to provided uid/gid ownership.
// If path is already a directory, MkdirAll does nothing
// and returns nil.
// Any directory created will be set to provided uid/gid ownership
// if doChown is true.
//
// Unlike os.MkdirAll it tolerates directories being removed while it runs:
// the implicit parent directories of objects are removed by deletes of other
// objects under them, without any coordination with the writers that make
// them.
func MkdirAll(path string, uid, gid int, doChown bool, dirPerm fs.FileMode) error {
	retries := maxMkdirRaceRetries
	return mkdirAll(path, uid, gid, doChown, dirPerm, &retries)
}

func mkdirAll(path string, uid, gid int, doChown bool, dirPerm fs.FileMode, retries *int) error {
	// Fast path: if we can tell whether path is a directory or file, stop with success or error.
	dir, err := os.Stat(path)
	if err == nil {
		if dir.IsDir() {
			return nil
		}
		return s3err.GetAPIError(s3err.ErrObjectParentIsFile)
	}

	// Slow path: make sure parent exists and then call Mkdir for path.
	i := len(path)
	for i > 0 && os.IsPathSeparator(path[i-1]) { // Skip trailing path separator.
		i--
	}

	j := i
	for j > 0 && !os.IsPathSeparator(path[j-1]) { // Scan backward over element.
		j--
	}

	for {
		if j > 1 {
			// Create parent.
			err = mkdirAll(path[:j-1], uid, gid, doChown, dirPerm, retries)
			if err != nil {
				return err
			}
		}

		// Parent now exists; invoke Mkdir and use its result.
		err = os.Mkdir(path, dirPerm)
		if err == nil {
			break
		}

		if errors.Is(err, fs.ErrNotExist) && *retries > 0 {
			// The parent was removed after it was made, make it again.
			*retries--
			continue
		}

		// Handle arguments like "foo/." by
		// double-checking that directory doesn't exist.
		dir, err1 := os.Lstat(path)
		if errors.Is(err, fs.ErrExist) && errors.Is(err1, fs.ErrNotExist) {
			// Mkdir saw a directory that Lstat doesn't: it was removed
			// right after another writer made it, or this client has a
			// stale lookup of it cached.
			dir, err1 = lstatRevalidated(path)
			if errors.Is(err1, fs.ErrNotExist) && *retries > 0 {
				*retries--
				continue
			}
		}
		if err1 == nil {
			if dir.IsDir() {
				return nil
			}
			if errors.Is(err, fs.ErrExist) {
				return s3err.GetAPIError(s3err.ErrObjectParentIsFile)
			}
		}
		return err
	}

	if doChown {
		err = os.Chown(path, uid, gid)
		if err != nil {
			return err
		}
	}
	return nil
}

// lstatRevalidated is os.Lstat for a path that a client caching lookups may
// have cached as missing. Opening the parent directory makes an NFS client
// revalidate the directory (close-to-open consistency), which drops the
// entries it cached as missing if another client has changed it since.
func lstatRevalidated(path string) (fs.FileInfo, error) {
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		d.Close()
	}
	return os.Lstat(path)
}
