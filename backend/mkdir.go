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
	"syscall"
	"time"

	"github.com/versity/versitygw/s3err"
)

const (
	// maxMkdirRaceRetries bounds how many times MkdirAll makes a directory
	// again after a concurrent remove took it, or one of its parents, away.
	maxMkdirRaceRetries = 16
	// mkdirRetryWait is the wait before the second retry, which doubles
	// with each further retry up to mkdirRetryMaxWait.
	mkdirRetryWait    = 100 * time.Microsecond
	mkdirRetryMaxWait = 128 * mkdirRetryWait
)

// osMkdir and osLstat are os.Mkdir and os.Lstat, replaced in tests to
// reproduce what shared filesystems report while another node removes a
// directory. Tests that replace them must not run in parallel.
var (
	osMkdir = os.Mkdir
	osLstat = os.Lstat
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
		err = osMkdir(path, dirPerm)
		if err == nil {
			break
		}

		// ENOENT: the parent was removed after it was made.
		// ENOTDIR or ESTALE, unless path ends in a separator: Mkdir itself
		// reports that a parent isn't a directory anymore, the same race the
		// Lstat branch below retries after an EEXIST. A trailing separator
		// stays with that branch: Mkdir("file/") for a regular file is not
		// a parent that vanished.
		if *retries > 0 && (errors.Is(err, fs.ErrNotExist) || (i == len(path) && isNotDirOrStale(err))) {
			takeMkdirRetry(retries)
			continue
		}

		// Handle arguments like "foo/." by
		// double-checking that directory doesn't exist.
		dir, err1 := osLstat(path)
		if errors.Is(err, fs.ErrExist) && errors.Is(err1, fs.ErrNotExist) {
			// Mkdir saw a directory that Lstat doesn't: it was removed
			// right after another writer made it, or this client has a
			// stale lookup of it cached.
			dir, err1 = lstatRevalidated(path)
		}
		// Mkdir found path, so unless path ends in a separator, its
		// parents were directories then, and a lookup that fails on one
		// of them now means it has been removed since: IBM Storage Scale
		// reports a directory that another node is removing as ENOTDIR,
		// and NFS a removed one as ESTALE. With a trailing separator
		// ("file/") the two calls give these answers for a file at path,
		// with nothing removed, so that isn't retried.
		parentGone := i == len(path) && isNotDirOrStale(err1)
		if errors.Is(err, fs.ErrExist) && (errors.Is(err1, fs.ErrNotExist) || parentGone) {
			if *retries == 0 {
				// Return the lookup error rather than the EEXIST, so
				// callers can tell a path that vanished from one that
				// exists.
				return err1
			}
			// Make the parents again. If a file has taken the place of
			// one, the stat of it on the next pass returns
			// ErrObjectParentIsFile.
			takeMkdirRetry(retries)
			continue
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

// takeMkdirRetry takes a retry from the budget of MkdirAll and waits before
// it, unless it is the first one. A directory that is being removed is still
// found by a lookup for a moment after the remove has made it unusable: on
// Linux, rmdir marks the directory dead before the path to it is gone, and a
// mkdir in it fails with ENOENT meanwhile. Retrying at once would only repeat
// that for as long as the remove takes to finish, which a remover that is
// preempted under load can stretch past the whole budget.
func takeMkdirRetry(retries *int) {
	used := maxMkdirRaceRetries - *retries
	*retries--
	if used == 0 {
		return
	}
	time.Sleep(min(mkdirRetryWait<<(used-1), mkdirRetryMaxWait))
}

// lstatRevalidated is os.Lstat for a path that a client caching lookups may
// have cached as missing. Opening the parent directory makes an NFS client
// revalidate the directory (close-to-open consistency), which drops the
// entries it cached as missing if another client has changed it since.
func lstatRevalidated(path string) (fs.FileInfo, error) {
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		d.Close()
	}
	return osLstat(path)
}

// isNotDirOrStale reports whether err is ENOTDIR or a stale handle (ESTALE):
// what a lookup of a path returns when a parent directory of it isn't a
// directory anymore. A parent that is missing (ENOENT) is not included.
func isNotDirOrStale(err error) bool {
	return errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ESTALE)
}
