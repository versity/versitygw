// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// Copyright 2024 Versity Software

// MkdirAll borrowed from stdlib to add ability to set ownership
// as directories are created

package backend

import (
	"io/fs"
	"os"

	"github.com/versity/versitygw/s3err"
)

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
func MkdirAll(path string, uid, gid int, doChown bool, dirPerm fs.FileMode) error {
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

	if j > 1 {
		// Create parent.
		err = MkdirAll(path[:j-1], uid, gid, doChown, dirPerm)
		if err != nil {
			return err
		}
	}

	// Parent now exists; invoke Mkdir and use its result.
	err = os.Mkdir(path, dirPerm)
	if err != nil {
		// Handle arguments like "foo/." by
		// double-checking that directory doesn't exist.
		dir, err1 := os.Lstat(path)
		if err1 == nil && dir.IsDir() {
			return nil
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
