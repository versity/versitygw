// Copyright 2025 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package meta

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/versity/versitygw/s3err"
)

// SideCar is a metadata storer that uses sidecar files to store metadata.
type SideCar struct {
	dir string
}

const (
	sidecarmeta = "meta"
)

// NewSideCar creates a new SideCar metadata storer.
func NewSideCar(dir string) (SideCar, error) {
	fi, err := os.Lstat(dir)
	if err != nil {
		return SideCar{}, fmt.Errorf("failed to stat directory: %v", err)
	}
	if !fi.IsDir() {
		return SideCar{}, fmt.Errorf("not a directory")
	}

	return SideCar{dir: dir}, nil
}

// RetrieveAttribute retrieves the value of a specific attribute for an object or a bucket.
func (s SideCar) RetrieveAttribute(_ *os.File, bucket, object, attribute string) ([]byte, error) {
	metadir := filepath.Join(s.dir, bucket, object, sidecarmeta)
	if object == "" {
		metadir = filepath.Join(s.dir, bucket, sidecarmeta)
	}
	attr := filepath.Join(metadir, attribute)

	value, err := os.ReadFile(attr)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoSuchKey
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read attribute: %v", err)
	}

	return value, nil
}

// tmpSidecarID returns a string that uniquely identifies an in-flight upload
// for the purpose of naming its temporary sidecar directory.
//
// On Unix it uses the file's inode number, which is stable for the lifetime
// of the upload's data file regardless of fd-number reuse.  This is critical
// on Linux where O_TMPFILE fds can be reused by other goroutines as soon as
// link() closes the fd.
// On platforms without POSIX inodes (e.g. Windows), fileIno returns 0 and
// the function falls back to the path-based identifier, which is always
// unique because CreateTemp generates uniquely-named files.
//
// IMPORTANT: the token format must stay in sync with tmpfile.SidecarToken() in
// backend/posix/otmpfile_common.go, which computes the same value from the
// captured inode after link().  Both functions must produce identical output for
// the staging and commit steps to find the same directory.
func tmpSidecarID(f *os.File) string {
	if ino := fileIno(f); ino != 0 {
		return fmt.Sprintf("%d.%d", os.Getpid(), ino)
	}
	return fmt.Sprintf("%d.%s", os.Getpid(), filepath.Base(f.Name()))
}

// StoreAttribute stores the value of a specific attribute for an object or a bucket.
//
// When f is non-nil and object is non-empty the attribute is written to a
// per-upload temporary sidecar directory instead of the final path.  This
// prevents a race where concurrent uploads of the same object could have their
// checksum metadata and data file committed by different goroutines.  Call
// CommitMetadata after the data file has been linked to atomically move the
// temp sidecar to the final location.
func (s SideCar) StoreAttribute(f *os.File, bucket, object, attribute string, value []byte) error {
	var metadir string
	if f != nil && object != "" {
		metadir = filepath.Join(s.dir, bucket, ".sgwtmp."+tmpSidecarID(f), sidecarmeta)
	} else {
		metadir = filepath.Join(s.dir, bucket, object, sidecarmeta)
		if object == "" {
			metadir = filepath.Join(s.dir, bucket, sidecarmeta)
		}
	}
	// mkdirAndCreateTemp atomically retries MkdirAll+CreateTemp when the
	// directory is removed between the two calls.  This can happen when a
	// concurrent CommitMetadata goroutine calls RemoveAll on the same
	// inode-named temp sidecar directory (possible via inode reuse after
	// a previous upload's data file was overwritten and its inode freed).
	const maxRetries = 5
	var (
		tempfile *os.File
		lastErr  error
	)
	for range maxRetries {
		if err := os.MkdirAll(metadir, 0777); err != nil {
			if errors.Is(err, syscall.ENOSPC) {
				return s3err.GetAPIError(s3err.ErrNoSpaceLeftOnDevice)
			}
			return fmt.Errorf("failed to create metadata directory: %v", err)
		}
		var err error
		tempfile, err = os.CreateTemp(metadir, attribute)
		if err == nil {
			break
		}
		if errors.Is(err, syscall.ENOSPC) {
			return s3err.GetAPIError(s3err.ErrNoSpaceLeftOnDevice)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("failed to create temporary file: %v", err)
		}
		// ENOENT: the directory was removed by a concurrent CommitMetadata
		// (inode reuse race); retry with a fresh MkdirAll.
		lastErr = err
	}
	if tempfile == nil {
		return fmt.Errorf("failed to create temporary file in %v after %v retries: %w", metadir, maxRetries, lastErr)
	}
	defer os.Remove(tempfile.Name())

	attr := filepath.Join(metadir, attribute)

	if _, err := tempfile.Write(value); err != nil {
		tempfile.Close()
		if errors.Is(err, syscall.ENOSPC) {
			return s3err.GetAPIError(s3err.ErrNoSpaceLeftOnDevice)
		}
		return fmt.Errorf("failed to write attribute: %v", err)
	}

	// Close explicitly before rename to prevent error on Windows:
	// The process cannot access the file because it is being used by another process.
	if err := tempfile.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file: %v", err)
	}

	if err := os.Rename(tempfile.Name(), attr); err != nil {
		return fmt.Errorf("failed to rename temporary file: %v", err)
	}
	return nil
}

// DeleteAttribute removes the value of a specific attribute for an object or a bucket.
func (s SideCar) DeleteAttribute(bucket, object, attribute string) error {
	metadir := filepath.Join(s.dir, bucket, object, sidecarmeta)
	if object == "" {
		metadir = filepath.Join(s.dir, bucket, sidecarmeta)
	}
	attr := filepath.Join(metadir, attribute)

	err := os.Remove(attr)
	if errors.Is(err, os.ErrNotExist) {
		return ErrNoSuchKey
	}
	if err != nil {
		return fmt.Errorf("failed to remove attribute: %v", err)
	}

	s.cleanupEmptyDirs(metadir, bucket, object)

	return nil
}

// ListAttributes lists all attributes for an object or a bucket.
func (s SideCar) ListAttributes(bucket, object string) ([]string, error) {
	metadir := filepath.Join(s.dir, bucket, object, sidecarmeta)
	if object == "" {
		metadir = filepath.Join(s.dir, bucket, sidecarmeta)
	}

	ents, err := os.ReadDir(metadir)
	if errors.Is(err, os.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to list attributes: %v", err)
	}

	var attrs []string
	for _, ent := range ents {
		attrs = append(attrs, ent.Name())
	}

	return attrs, nil
}

// DeleteAttributes removes all attributes for an object or a bucket.
// When object is empty the entire bucket sidecar directory is removed,
// cleaning up any orphaned object or multipart metadata within it.
func (s SideCar) DeleteAttributes(bucket, object string) error {
	if object == "" {
		// Remove the entire bucket sidecar directory so that orphaned
		// object/multipart metadata does not accumulate after DeleteBucket.
		bucketDir := filepath.Join(s.dir, bucket)
		err := os.RemoveAll(bucketDir)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("failed to remove bucket attributes: %w", err)
		}
		return nil
	}

	metadir := filepath.Join(s.dir, bucket, object, sidecarmeta)
	err := os.RemoveAll(metadir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to remove attributes: %w", err)
	}
	s.cleanupEmptyDirs(metadir, bucket, object)
	return nil
}

// inoFromToken extracts the inode encoded in a SidecarToken string.
// Token format on Unix: "<pid>.<ino>" where ino is a decimal uint64.
// Token format on Windows: "<pid>.<basename>" where basename is non-numeric.
// Returns 0 if the suffix cannot be parsed as a uint64 (Windows fallback).
func inoFromToken(token string) uint64 {
	dot := strings.Index(token, ".")
	if dot < 0 {
		return 0
	}
	ino, err := strconv.ParseUint(token[dot+1:], 10, 64)
	if err != nil {
		return 0
	}
	return ino
}

// CommitMetadata moves the per-upload temporary sidecar attributes written by
// StoreAttribute to the final location for (bucket, object).  It must be
// called after the data file has been linked into the namespace.
//
// token is the per-upload sidecar identifier returned by tmpfile.SidecarToken(),
// computed before link() closed the file descriptor.
//
// dataPath is the filesystem path of the committed data file (e.g.
// filepath.Join(bucket, object) from the POSIX backend).  It is used to
// re-verify the inode before each attribute rename so that a goroutine whose
// inode was subsequently displaced by a later link() aborts instead of
// overwriting the correct winner's metadata.
//
// Each attribute file is moved individually (atomic rename).  Before each
// rename the inode at dataPath is re-verified against the inode encoded in
// token.  If the inode no longer matches (a later concurrent link() has
// installed a different upload's data file), this goroutine is no longer the
// winner: it aborts, removes its staged temp directory, and returns without
// error.  The true winner's CommitMetadata will overwrite any partially
// committed attributes before it finishes, leaving only consistent metadata.
func (s SideCar) CommitMetadata(bucket, object, token, dataPath string) error {
	if token == "" || object == "" {
		return nil
	}

	myIno := inoFromToken(token)

	tempDir := filepath.Join(s.dir, bucket, ".sgwtmp."+token)
	tempMetaDir := filepath.Join(tempDir, sidecarmeta)
	finalMetaDir := filepath.Join(s.dir, bucket, object, sidecarmeta)

	entries, err := os.ReadDir(tempMetaDir)
	if errors.Is(err, os.ErrNotExist) {
		// No metadata was staged for this upload; nothing to commit.
		return nil
	}
	if err != nil {
		return fmt.Errorf("read staged metadata: %w", err)
	}

	if err := os.MkdirAll(finalMetaDir, 0777); err != nil {
		if errors.Is(err, syscall.ENOSPC) {
			return s3err.GetAPIError(s3err.ErrNoSpaceLeftOnDevice)
		}
		return fmt.Errorf("create final metadata dir: %w", err)
	}

	for _, ent := range entries {
		// Re-verify we are still the link() winner before each rename.
		// If a concurrent goroutine has since won link() (replacing our inode
		// at dataPath), abort now.  Any attributes we already renamed will be
		// overwritten by the true winner's CommitMetadata, which will run to
		// completion because no later link() can displace its inode.
		if myIno != 0 && pathIno(dataPath) != myIno {
			os.RemoveAll(tempDir)
			return nil
		}

		src := filepath.Join(tempMetaDir, ent.Name())
		dst := filepath.Join(finalMetaDir, ent.Name())
		if err := os.Rename(src, dst); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("commit attribute %s: %w", ent.Name(), err)
		}
	}

	os.RemoveAll(tempDir)
	return nil
}

// CleanupMetadata removes the per-upload temporary sidecar directory staged by
// StoreAttribute without promoting it to the final location.  It should be
// called when the upload lost the concurrent link() race or when link()
// returned EEXIST, to prevent orphaned .sgwtmp.* directories from accumulating.
func (s SideCar) CleanupMetadata(bucket, token string) error {
	if token == "" {
		return nil
	}
	tempDir := filepath.Join(s.dir, bucket, ".sgwtmp."+token)
	if err := os.RemoveAll(tempDir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cleanup staged metadata: %w", err)
	}
	return nil
}

// RenameObject renames the sidecar metadata directory from oldObject to
// newObject so that path-based lookups continue to work after the data
// directory has been renamed.
func (s SideCar) RenameObject(bucket, oldObject, newObject string) error {
	oldPath := filepath.Join(s.dir, bucket, oldObject)
	newPath := filepath.Join(s.dir, bucket, newObject)

	if err := os.MkdirAll(filepath.Dir(newPath), 0777); err != nil {
		if errors.Is(err, syscall.ENOSPC) {
			return s3err.GetAPIError(s3err.ErrNoSpaceLeftOnDevice)
		}
		return fmt.Errorf("create parent for renamed metadata: %w", err)
	}

	err := os.Rename(oldPath, newPath)
	if errors.Is(err, os.ErrNotExist) {
		// No metadata stored yet — nothing to rename.
		return nil
	}
	return err
}

func (s SideCar) cleanupEmptyDirs(metadir, bucket, object string) {
	removeIfEmpty(metadir)
	if bucket == "" {
		return
	}
	bucketDir := filepath.Join(s.dir, bucket)
	if object != "" {
		removeEmptyParents(filepath.Dir(metadir), bucketDir)
	}
	removeIfEmpty(bucketDir)
}

func removeIfEmpty(dir string) {
	empty, err := isDirEmpty(dir)
	if err != nil || !empty {
		return
	}
	_ = os.Remove(dir)
}

func removeEmptyParents(dir, stopDir string) {
	for {
		if dir == stopDir || dir == "." || dir == string(filepath.Separator) {
			return
		}
		empty, err := isDirEmpty(dir)
		if err != nil || !empty {
			return
		}
		err = os.Remove(dir)
		if err != nil {
			return
		}
		dir = filepath.Dir(dir)
	}
}

func isDirEmpty(dir string) (bool, error) {
	f, err := os.Open(dir)
	if err != nil {
		return false, err
	}
	defer f.Close()

	ents, err := f.Readdirnames(1)
	if err == io.EOF {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return len(ents) == 0, nil
}
