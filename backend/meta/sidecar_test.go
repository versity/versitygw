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

package meta

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"syscall"
	"testing"
)

func TestSideCarReplaceObject(t *testing.T) {
	s, err := NewSideCar(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	// no metadata stored for the object
	if err := s.ReplaceObject("bucket", "obj", []string{"etag"}); err != nil {
		t.Fatalf("replace object without metadata: %v", err)
	}

	for _, attr := range []string{"etag", "checksums", "X-Amz-Tagging", "legal-hold"} {
		if err := s.StoreAttribute(nil, "bucket", "obj", attr, []byte(attr)); err != nil {
			t.Fatal(err)
		}
	}
	// the metadata of "obj/meta/child" is stored under the metadata
	// directory of "obj"
	if err := s.StoreAttribute(nil, "bucket", "obj/meta/child", "etag", []byte("child")); err != nil {
		t.Fatal(err)
	}

	if err := s.ReplaceObject("bucket", "obj", []string{"etag", "checksums"}); err != nil {
		t.Fatalf("replace object: %v", err)
	}

	for _, attr := range []string{"etag", "checksums"} {
		val, err := s.RetrieveAttribute(nil, "bucket", "obj", attr)
		if err != nil {
			t.Fatalf("kept attribute %v: %v", attr, err)
		}
		if string(val) != attr {
			t.Errorf("kept attribute %v: expected %q, got %q", attr, attr, val)
		}
	}
	for _, attr := range []string{"X-Amz-Tagging", "legal-hold"} {
		_, err := s.RetrieveAttribute(nil, "bucket", "obj", attr)
		if !errors.Is(err, ErrNoSuchKey) {
			t.Errorf("removed attribute %v: expected ErrNoSuchKey, got %v", attr, err)
		}
	}

	val, err := s.RetrieveAttribute(nil, "bucket", "obj/meta/child", "etag")
	if err != nil {
		t.Fatalf("nested object attribute: %v", err)
	}
	if string(val) != "child" {
		t.Errorf("nested object attribute: expected %q, got %q", "child", val)
	}

	attrs, err := s.ListAttributes("bucket", "obj")
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(attrs)
	if want := []string{"checksums", "child", "etag"}; !slices.Equal(attrs, want) {
		t.Errorf("expected the metadata directory entries to be %v, got %v", want, attrs)
	}
}

func TestSideCarRemoveObject(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSideCar(dir)
	if err != nil {
		t.Fatal(err)
	}

	// no metadata stored for the object
	if err := s.RemoveObject("bucket", "dir/obj"); err != nil {
		t.Fatalf("remove object without metadata: %v", err)
	}

	for _, object := range []string{"", "dir/obj", "dir/obj/1", "dir/obj/1/2", "dir/other"} {
		if err := s.StoreAttribute(nil, "bucket", object, "etag", []byte(object)); err != nil {
			t.Fatal(err)
		}
	}

	if err := s.RemoveObject("bucket", "dir/obj"); err != nil {
		t.Fatalf("remove object: %v", err)
	}

	for _, object := range []string{"dir/obj", "dir/obj/1", "dir/obj/1/2"} {
		_, err := s.RetrieveAttribute(nil, "bucket", object, "etag")
		if !errors.Is(err, ErrNoSuchKey) {
			t.Errorf("removed object %v: expected ErrNoSuchKey, got %v", object, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "bucket", "dir", "obj")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("expected the object directory to be removed, got %v", err)
	}
	for _, object := range []string{"", "dir/other"} {
		val, err := s.RetrieveAttribute(nil, "bucket", object, "etag")
		if err != nil {
			t.Fatalf("kept object %q: %v", object, err)
		}
		if string(val) != object {
			t.Errorf("kept object %q: expected %q, got %q", object, object, val)
		}
	}

	// the parent directories left empty are removed up to the bucket
	if err := s.RemoveObject("bucket", "dir/other"); err != nil {
		t.Fatalf("remove object: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "bucket", "dir")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("expected the empty parent directory to be removed, got %v", err)
	}
	if _, err := s.RetrieveAttribute(nil, "bucket", "", "etag"); err != nil {
		t.Errorf("bucket attribute: %v", err)
	}
}

func TestSideCarConcurrentStoreAndDeleteAttributes(t *testing.T) {
	s, err := NewSideCar(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	const (
		rounds  = 30
		writers = 4
		attrs   = 4
	)

	t.Run("same key", func(t *testing.T) {
		for round := 0; round < rounds; round++ {
			key := fmt.Sprintf("a/b/c/same-%02d", round)
			start := make(chan struct{})
			var wg sync.WaitGroup
			var mu sync.Mutex
			var errs []error

			for w := 0; w < writers; w++ {
				writerID := w
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					for a := 0; a < attrs; a++ {
						attr := fmt.Sprintf("attr-%d", a)
						val := fmt.Appendf(nil, "val-%d-%d", writerID, a)
						if err := s.StoreAttribute(nil, "bucket", key, attr, val); err != nil {
							mu.Lock()
							errs = append(errs, fmt.Errorf("StoreAttribute(%s, %s): %w", key, attr, err))
							mu.Unlock()
							return
						}
					}
				}()
			}

			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				if err := s.DeleteAttributes("bucket", key); err != nil {
					mu.Lock()
					errs = append(errs, fmt.Errorf("DeleteAttributes(%s): %w", key, err))
					mu.Unlock()
				}
			}()
			go func() {
				defer wg.Done()
				<-start
				if err := s.RemoveObject("bucket", key); err != nil {
					mu.Lock()
					errs = append(errs, fmt.Errorf("RemoveObject(%s): %w", key, err))
					mu.Unlock()
				}
			}()

			close(start)
			wg.Wait()

			if len(errs) > 0 {
				t.Fatalf("round %d: got %d errors, first: %v", round, len(errs), errs[0])
			}
		}
	})

	t.Run("sibling keys under shared prefix", func(t *testing.T) {
		for round := 0; round < rounds; round++ {
			prefix := fmt.Sprintf("shared/prefix-%02d", round)
			start := make(chan struct{})
			var wg sync.WaitGroup
			var mu sync.Mutex
			var errs []error

			for w := 0; w < writers; w++ {
				key := fmt.Sprintf("%s/k%d", prefix, w)
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					for a := 0; a < attrs; a++ {
						attr := fmt.Sprintf("attr-%d", a)
						if err := s.StoreAttribute(nil, "bucket", key, attr, []byte("v")); err != nil {
							mu.Lock()
							errs = append(errs, fmt.Errorf("StoreAttribute(%s, %s): %w", key, attr, err))
							mu.Unlock()
							return
						}
					}
				}()
			}

			for d := 0; d < writers; d++ {
				key := fmt.Sprintf("%s/k%d", prefix, d)
				useRemove := d%2 == 1
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					var delErr error
					if useRemove {
						delErr = s.RemoveObject("bucket", key)
					} else {
						delErr = s.DeleteAttributes("bucket", key)
					}
					if delErr != nil {
						mu.Lock()
						errs = append(errs, fmt.Errorf("delete(%s): %w", key, delErr))
						mu.Unlock()
					}
				}()
			}

			close(start)
			wg.Wait()

			if len(errs) > 0 {
				t.Fatalf("round %d: got %d errors, first: %v", round, len(errs), errs[0])
			}
		}
	})
}

func TestSideCarRetryableMetaDirErrDoesNotMaskLiveDirEINVAL(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix EINVAL directory disappearance check")
	}

	root := t.TempDir()
	existingDir := filepath.Join(root, "live")
	if err := os.Mkdir(existingDir, 0755); err != nil {
		t.Fatal(err)
	}
	dirInfo, err := os.Lstat(existingDir)
	if err != nil {
		t.Fatal(err)
	}
	missingDir := filepath.Join(root, "gone")

	if isRetryableMetaDirErr(syscall.EINVAL, existingDir, dirInfo) {
		t.Fatalf("expected EINVAL on unchanged live dir %q not to be retryable", existingDir)
	}
	if !isRetryableMetaDirErr(syscall.EINVAL, missingDir, dirInfo) {
		t.Fatalf("expected EINVAL on missing dir %q to be retryable", missingDir)
	}

	if err := os.Remove(existingDir); err != nil {
		t.Fatal(err)
	}
	// Hold a dummy file so the filesystem allocates a distinct inode for the
	// recreated directory even on filesystems that aggressively reuse inodes.
	holder := filepath.Join(root, "inode-holder")
	if err := os.WriteFile(holder, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(existingDir, 0755); err != nil {
		t.Fatal(err)
	}
	recreatedInfo, err := os.Lstat(existingDir)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(dirInfo, recreatedInfo) {
		t.Skip("filesystem reused the exact same inode for recreated directory")
	}
	if !isRetryableMetaDirErr(syscall.EINVAL, existingDir, dirInfo) {
		t.Fatalf("expected EINVAL on removed-and-recreated dir %q to be retryable", existingDir)
	}
}

func TestRemoveAllIgnoreNotEmptyPreservesPermissionError(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires non-root unix permissions")
	}

	root := t.TempDir()
	target := filepath.Join(root, "target")
	okDir := filepath.Join(target, "a-normal")
	roDir := filepath.Join(target, "b-readonly")
	if err := os.MkdirAll(okDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(okDir, "file"), []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(roDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(roDir, "locked"), []byte("no"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(roDir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(roDir, 0700)
	})

	err := removeSidecarSubtree(root, "target")
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("removeSidecarSubtree(%q, %q) = %v, want permission error", root, "target", err)
	}
}

func TestRemoveSidecarSubtreeNeverFollowsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires unix symlink permissions")
	}

	t.Run("pre-existing symlink inside metadata directory", func(t *testing.T) {
		sidecarDir := t.TempDir()
		victimDir := t.TempDir()
		sentinel := filepath.Join(victimDir, "sentinel.txt")
		if err := os.WriteFile(sentinel, []byte("keep-me"), 0644); err != nil {
			t.Fatal(err)
		}

		s, err := NewSideCar(sidecarDir)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.StoreAttribute(nil, "bucket", "obj", "etag", []byte("123")); err != nil {
			t.Fatal(err)
		}

		linkPath := filepath.Join(sidecarDir, "bucket", "obj", sidecarmeta, "escape")
		if err := os.Symlink(victimDir, linkPath); err != nil {
			t.Fatal(err)
		}

		if err := s.DeleteAttributes("bucket", "obj"); err != nil {
			t.Fatalf("DeleteAttributes: %v", err)
		}
		if _, err := os.Lstat(linkPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected symlink %q to be removed, got %v", linkPath, err)
		}
		got, err := os.ReadFile(sentinel)
		if err != nil {
			t.Fatalf("victim sentinel was damaged: %v", err)
		}
		if string(got) != "keep-me" {
			t.Fatalf("victim sentinel content = %q, want %q", got, "keep-me")
		}
	})

	t.Run("concurrent directory-to-symlink replacement race", func(t *testing.T) {
		sidecarDir := t.TempDir()
		victimDir := t.TempDir()
		sentinel := filepath.Join(victimDir, "sentinel.txt")
		if err := os.WriteFile(sentinel, []byte("untouched"), 0644); err != nil {
			t.Fatal(err)
		}

		s, err := NewSideCar(sidecarDir)
		if err != nil {
			t.Fatal(err)
		}

		const rounds = 40
		for round := 0; round < rounds; round++ {
			key := fmt.Sprintf("obj-%02d", round)
			subDir := filepath.Join(sidecarDir, "bucket", key, sidecarmeta, "nested")
			if err := os.MkdirAll(subDir, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(subDir, "attr"), []byte("v"), 0644); err != nil {
				t.Fatal(err)
			}

			stop := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
						_ = os.RemoveAll(subDir)
						_ = os.Symlink(victimDir, subDir)
						_ = os.Remove(subDir)
						_ = os.MkdirAll(subDir, 0755)
						_ = os.WriteFile(filepath.Join(subDir, "attr"), []byte("v"), 0644)
					}
				}
			}()

			if round%2 == 0 {
				_ = s.DeleteAttributes("bucket", key)
			} else {
				_ = s.RemoveObject("bucket", key)
			}
			close(stop)
			wg.Wait()

			got, err := os.ReadFile(sentinel)
			if err != nil {
				t.Fatalf("round %d: victim sentinel missing or unreadable: %v", round, err)
			}
			if string(got) != "untouched" {
				t.Fatalf("round %d: victim sentinel content = %q, want %q", round, got, "untouched")
			}
		}
	})

	t.Run("in-root relative symlink as parent segment", func(t *testing.T) {
		sidecarDir := t.TempDir()
		s, err := NewSideCar(sidecarDir)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.StoreAttribute(nil, "bucket", "victim", "etag", []byte("keep-victim")); err != nil {
			t.Fatal(err)
		}

		aliasPath := filepath.Join(sidecarDir, "bucket", "alias")
		if err := os.Symlink("victim", aliasPath); err != nil {
			t.Fatal(err)
		}

		if err := s.DeleteAttributes("bucket", "alias"); err == nil {
			t.Fatal("expected DeleteAttributes through in-root relative symlink parent to fail")
		}
		got, err := s.RetrieveAttribute(nil, "bucket", "victim", "etag")
		if err != nil {
			t.Fatalf("victim attribute damaged: %v", err)
		}
		if string(got) != "keep-victim" {
			t.Fatalf("victim attribute = %q, want %q", got, "keep-victim")
		}
	})

	t.Run("in-root relative symlink inside meta", func(t *testing.T) {
		sidecarDir := t.TempDir()
		s, err := NewSideCar(sidecarDir)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.StoreAttribute(nil, "bucket", "victim", "etag", []byte("keep-victim")); err != nil {
			t.Fatal(err)
		}
		if err := s.StoreAttribute(nil, "bucket", "obj", "etag", []byte("obj-etag")); err != nil {
			t.Fatal(err)
		}

		linkPath := filepath.Join(sidecarDir, "bucket", "obj", sidecarmeta, "sub")
		if err := os.Symlink(filepath.Join("..", "..", "victim", sidecarmeta), linkPath); err != nil {
			t.Fatal(err)
		}

		if err := s.DeleteAttributes("bucket", "obj"); err != nil {
			t.Fatalf("DeleteAttributes: %v", err)
		}
		if _, err := os.Lstat(linkPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected relative symlink %q to be removed, got %v", linkPath, err)
		}
		got, err := s.RetrieveAttribute(nil, "bucket", "victim", "etag")
		if err != nil {
			t.Fatalf("victim attribute damaged: %v", err)
		}
		if string(got) != "keep-victim" {
			t.Fatalf("victim attribute = %q, want %q", got, "keep-victim")
		}
	})

	t.Run("concurrent directory-to-in-root-relative-symlink swap race", func(t *testing.T) {
		sidecarDir := t.TempDir()
		s, err := NewSideCar(sidecarDir)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.StoreAttribute(nil, "bucket", "victim", "etag", []byte("untouched-victim")); err != nil {
			t.Fatal(err)
		}

		relTarget := filepath.Join("..", "..", "victim", sidecarmeta)
		const rounds = 40
		for round := 0; round < rounds; round++ {
			key := fmt.Sprintf("rel-%02d", round)
			subDir := filepath.Join(sidecarDir, "bucket", key, sidecarmeta, "nested")
			if err := os.MkdirAll(subDir, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(subDir, "attr"), []byte("v"), 0644); err != nil {
				t.Fatal(err)
			}

			stop := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
						_ = os.RemoveAll(subDir)
						_ = os.Symlink(relTarget, subDir)
						_ = os.Remove(subDir)
						_ = os.MkdirAll(subDir, 0755)
						_ = os.WriteFile(filepath.Join(subDir, "attr"), []byte("v"), 0644)
					}
				}
			}()

			if round%2 == 0 {
				_ = s.DeleteAttributes("bucket", key)
			} else {
				_ = s.RemoveObject("bucket", key)
			}
			close(stop)
			wg.Wait()

			got, err := s.RetrieveAttribute(nil, "bucket", "victim", "etag")
			if err != nil {
				t.Fatalf("round %d: victim attribute missing or unreadable: %v", round, err)
			}
			if string(got) != "untouched-victim" {
				t.Fatalf("round %d: victim attribute = %q, want %q", round, got, "untouched-victim")
			}
		}
	})
}
