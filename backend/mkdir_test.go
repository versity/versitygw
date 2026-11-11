// Copyright 2026 Versity Software
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

package backend

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/versity/versitygw/s3err"
)

// stubMkdirAll replaces osMkdir and osLstat for the test. Each stub gets the
// number of the call for target, starting at 1, and returns stubbed with
// the error to answer with, or false to let the real call answer. Calls for
// other paths go to the real ones. osMkdir and osLstat are package
// variables, so tests that use this must not run in parallel.
func stubMkdirAll(t *testing.T, target string,
	mkdirStub func(n int) (stubbed bool, err error),
	lstatStub func(n int) (stubbed bool, err error)) (mkdirCalls, lstatCalls *int) {
	t.Helper()
	realMkdir, realLstat := osMkdir, osLstat
	t.Cleanup(func() { osMkdir, osLstat = realMkdir, realLstat })

	mkdirCalls, lstatCalls = new(int), new(int)
	osMkdir = func(name string, perm fs.FileMode) error {
		if name == target && mkdirStub != nil {
			*mkdirCalls++
			if stubbed, err := mkdirStub(*mkdirCalls); stubbed {
				return err
			}
		}
		return realMkdir(name, perm)
	}
	osLstat = func(name string) (fs.FileInfo, error) {
		if name == target && lstatStub != nil {
			*lstatCalls++
			if stubbed, err := lstatStub(*lstatCalls); stubbed {
				return nil, err
			}
		}
		return realLstat(name)
	}
	return mkdirCalls, lstatCalls
}

func pathErr(op, path string, errno syscall.Errno) error {
	return &fs.PathError{Op: op, Path: path, Err: errno}
}

// TestMkdirAllParentGoneAfterEEXIST is the sequence of #2645: Mkdir fails
// with EEXIST because another writer has just made the directory, and the
// Lstat after it fails because a node removing a parent directory reports
// it as ENOTDIR (IBM Storage Scale), or as a stale handle (NFS). MkdirAll
// has to make the directories again instead of returning the EEXIST.
func TestMkdirAllParentGoneAfterEEXIST(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.ENOTDIR, syscall.ESTALE} {
		t.Run(errno.Error(), func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "a", "b", "c")
			mkdirCalls, _ := stubMkdirAll(t, target,
				func(n int) (bool, error) {
					if n == 1 {
						return true, pathErr("mkdir", target, syscall.EEXIST)
					}
					return false, nil
				},
				func(n int) (bool, error) {
					if n == 1 {
						return true, pathErr("lstat", target, errno)
					}
					return false, nil
				})

			if err := MkdirAll(target, 0, 0, false, 0o755); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			if fi, err := os.Stat(target); err != nil || !fi.IsDir() {
				t.Fatalf("directory not made: %v", err)
			}
			if *mkdirCalls != 2 {
				t.Fatalf("mkdir calls = %d, want 2", *mkdirCalls)
			}
		})
	}
}

// TestMkdirAllParentGoneAfterRevalidation covers an Lstat that first finds
// the path missing, and then, after lstatRevalidated has opened the parent,
// fails with ENOTDIR because the parent is being removed meanwhile.
func TestMkdirAllParentGoneAfterRevalidation(t *testing.T) {
	target := filepath.Join(t.TempDir(), "a", "b")
	mkdirCalls, lstatCalls := stubMkdirAll(t, target,
		func(n int) (bool, error) {
			if n == 1 {
				return true, pathErr("mkdir", target, syscall.EEXIST)
			}
			return false, nil
		},
		func(n int) (bool, error) {
			switch n {
			case 1:
				return true, pathErr("lstat", target, syscall.ENOENT)
			case 2:
				return true, pathErr("lstat", target, syscall.ENOTDIR)
			}
			return false, nil
		})

	if err := MkdirAll(target, 0, 0, false, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if fi, err := os.Stat(target); err != nil || !fi.IsDir() {
		t.Fatalf("directory not made: %v", err)
	}
	if *mkdirCalls != 2 || *lstatCalls != 2 {
		t.Fatalf("mkdir calls = %d, lstat calls = %d, want 2 and 2", *mkdirCalls, *lstatCalls)
	}
}

// TestMkdirAllParentReplacedByFile replaces the parent directory with a file
// between Mkdir and Lstat, so the real Lstat fails with ENOTDIR. The retry
// finds the file and reports it, as for a parent that was a file from the
// start.
func TestMkdirAllParentReplacedByFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Lstat under a file fails with ERROR_PATH_NOT_FOUND on Windows, not ENOTDIR")
	}
	parent := filepath.Join(t.TempDir(), "a")
	target := filepath.Join(parent, "b")
	stubMkdirAll(t, target,
		func(n int) (bool, error) {
			if n > 1 {
				t.Errorf("mkdir of %s retried after its parent became a file", target)
				return false, nil
			}
			// Another writer made the directory, then a delete removed it
			// and its parent, and an upload put an object at the parent key.
			if err := os.Mkdir(target, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(target); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(parent); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(parent, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			return true, pathErr("mkdir", target, syscall.EEXIST)
		}, nil)

	err := MkdirAll(target, 0, 0, false, 0o755)
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrObjectParentIsFile)) {
		t.Fatalf("MkdirAll: %v, want ErrObjectParentIsFile", err)
	}
}

// TestMkdirAllEEXISTRetriesBounded checks that a filesystem that keeps
// answering EEXIST to Mkdir and that the path, or a parent of it, is gone to
// Lstat takes the retry budget and no more, and then gets the Lstat error
// rather than the EEXIST: the path doesn't exist.
func TestMkdirAllEEXISTRetriesBounded(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.ENOENT, syscall.ENOTDIR, syscall.ESTALE} {
		t.Run(errno.Error(), func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "a", "b")
			mkdirCalls, _ := stubMkdirAll(t, target,
				func(int) (bool, error) { return true, pathErr("mkdir", target, syscall.EEXIST) },
				func(int) (bool, error) { return true, pathErr("lstat", target, errno) })

			err := MkdirAll(target, 0, 0, false, 0o755)
			if !errors.Is(err, errno) {
				t.Fatalf("MkdirAll: %v, want %v", err, errno)
			}
			if *mkdirCalls != maxMkdirRaceRetries+1 {
				t.Fatalf("mkdir calls = %d, want %d", *mkdirCalls, maxMkdirRaceRetries+1)
			}
		})
	}
}

// TestMkdirAllTrailingSeparator checks that a file at a path that ends in a
// separator isn't taken for a removed parent. Linux answers EEXIST to the
// Mkdir of "file/" and ENOTDIR to the Lstat of it on every pass, with no
// directory changing in between, so there is nothing to retry. MkdirAll
// itself makes such a path for "a//b", whose parent it takes to be "a/".
func TestMkdirAllTrailingSeparator(t *testing.T) {
	sep := string(os.PathSeparator)
	for _, tc := range []struct {
		name string
		// path returns the argument of MkdirAll and the path ending in a
		// separator that it calls Mkdir with, for a regular file.
		path func(file string) (path, target string)
	}{
		{"trailing separator", func(file string) (string, string) { return file + sep, file + sep }},
		{"doubled separator", func(file string) (string, string) { return file + sep + sep + "dir", file + sep }},
	} {
		// The answers of Linux, which macOS, for one, doesn't give.
		t.Run(tc.name+", as on Linux", func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(file, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			path, target := tc.path(file)
			mkdirCalls, _ := stubMkdirAll(t, target,
				func(int) (bool, error) { return true, pathErr("mkdir", target, syscall.EEXIST) },
				func(int) (bool, error) { return true, pathErr("lstat", target, syscall.ENOTDIR) })

			err := MkdirAll(path, 0, 0, false, 0o755)
			if !errors.Is(err, syscall.EEXIST) {
				t.Fatalf("MkdirAll: %v, want EEXIST", err)
			}
			if *mkdirCalls != 1 {
				t.Fatalf("mkdir calls = %d, want 1", *mkdirCalls)
			}
		})

		// Whatever this system answers, it is not retried.
		t.Run(tc.name, func(t *testing.T) {
			if runtime.GOOS == "windows" {
				t.Skip("what Windows answers for a file followed by a separator is not covered")
			}
			file := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(file, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			path, target := tc.path(file)
			mkdirCalls, _ := stubMkdirAll(t, target,
				func(int) (bool, error) { return false, nil }, nil)

			if err := MkdirAll(path, 0, 0, false, 0o755); err == nil {
				t.Fatal("MkdirAll made a directory under a file")
			}
			if *mkdirCalls != 1 {
				t.Fatalf("mkdir calls = %d, want 1", *mkdirCalls)
			}
		})
	}
}

// TestMkdirAllEEXISTOtherLstatErrors checks the cases that were not retried
// before and still aren't: a file at the path itself, and an Lstat error
// that says nothing about the parents being gone.
func TestMkdirAllEEXISTOtherLstatErrors(t *testing.T) {
	t.Run("file at path", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "a")
		mkdirCalls, _ := stubMkdirAll(t, target,
			func(int) (bool, error) {
				if err := os.WriteFile(target, nil, 0o644); err != nil {
					t.Fatal(err)
				}
				return true, pathErr("mkdir", target, syscall.EEXIST)
			}, nil)

		err := MkdirAll(target, 0, 0, false, 0o755)
		if !errors.Is(err, s3err.GetAPIError(s3err.ErrObjectParentIsFile)) {
			t.Fatalf("MkdirAll: %v, want ErrObjectParentIsFile", err)
		}
		if *mkdirCalls != 1 {
			t.Fatalf("mkdir calls = %d, want 1", *mkdirCalls)
		}
	})

	t.Run("eacces", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "a")
		mkdirCalls, _ := stubMkdirAll(t, target,
			func(int) (bool, error) { return true, pathErr("mkdir", target, syscall.EEXIST) },
			func(int) (bool, error) { return true, pathErr("lstat", target, syscall.EACCES) })

		err := MkdirAll(target, 0, 0, false, 0o755)
		if !errors.Is(err, syscall.EEXIST) {
			t.Fatalf("MkdirAll: %v, want EEXIST", err)
		}
		if *mkdirCalls != 1 {
			t.Fatalf("mkdir calls = %d, want 1", *mkdirCalls)
		}
	})
}
