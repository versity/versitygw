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

package posix

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// recordSyncs replaces the sync hooks for one test and returns what they saw.
func recordSyncs(t *testing.T) (files *int, dirs *[]string) {
	t.Helper()
	origFile, origDir := syncFile, syncDir
	t.Cleanup(func() { syncFile, syncDir = origFile, origDir })
	files, dirs = new(int), new([]string)
	syncFile = func(f *os.File) error { *files++; return origFile(f) }
	syncDir = func(dir string, d *os.File) error { *dirs = append(*dirs, dir); return origDir(dir, d) }
	return files, dirs
}

func putTestObject(t *testing.T, p *Posix, bucket, key, body string) error {
	t.Helper()
	_, err := p.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket:        &bucket,
		Key:           &key,
		Body:          strings.NewReader(body),
		ContentLength: aws.Int64(int64(len(body))),
	})
	return err
}

// TestFsyncPutObject checks that with Fsync set a PUT flushes the object and
// every directory from the object's parent up to the bucket, and that
// without it nothing is flushed. Both O_TMPFILE and the rename fallback are
// covered.
func TestFsyncPutObject(t *testing.T) {
	for _, noTmp := range []bool{false, true} {
		for _, fsync := range []bool{false, true} {
			name := "otmpfile"
			if noTmp {
				name = "rename"
			}
			if fsync {
				name += "/fsync"
			}
			t.Run(name, func(t *testing.T) {
				root := t.TempDir()
				p, err := New(root, meta.XattrMeta{}, PosixOpts{
					AbsolutePaths:  true,
					ForceNoTmpFile: noTmp,
					Fsync:          fsync,
				})
				if err != nil {
					t.Fatalf("new posix: %v", err)
				}
				bucket := "bucket"
				createTestBucket(t, p, bucket)

				files, dirs := recordSyncs(t)
				if err := putTestObject(t, p, bucket, "a/b/object", "hello"); err != nil {
					t.Fatalf("put object: %v", err)
				}

				got, err := os.ReadFile(filepath.Join(root, bucket, "a", "b", "object"))
				if err != nil || string(got) != "hello" {
					t.Fatalf("read object = %q, %v", got, err)
				}

				if !fsync {
					if *files != 0 || len(*dirs) != 0 {
						t.Fatalf("synced %d files and %v without Fsync", *files, *dirs)
					}
					return
				}
				if *files != 1 {
					t.Fatalf("synced %d files, want 1", *files)
				}
				want := []string{
					filepath.Join(root, bucket, "a", "b"),
					filepath.Join(root, bucket, "a"),
					filepath.Join(root, bucket),
				}
				if !slices.Equal(*dirs, want) {
					t.Fatalf("synced directories %v, want %v", *dirs, want)
				}
			})
		}
	}
}

// TestFsyncFailureFailsThePut checks that a failed flush fails the PUT
// instead of acknowledging an object that may not be durable.
func TestFsyncFailureFailsThePut(t *testing.T) {
	root := t.TempDir()
	p, err := New(root, meta.XattrMeta{}, PosixOpts{AbsolutePaths: true, Fsync: true})
	if err != nil {
		t.Fatalf("new posix: %v", err)
	}
	bucket := "bucket"
	createTestBucket(t, p, bucket)

	origFile := syncFile
	t.Cleanup(func() { syncFile = origFile })
	errSync := errors.New("injected fsync failure")
	syncFile = func(*os.File) error { return errSync }

	// PutObject reports every link failure as a 409, so only check that
	// the PUT failed and that nothing was published.
	if err := putTestObject(t, p, bucket, "object", "hello"); err == nil {
		t.Fatal("put object succeeded after a failed fsync")
	}
	if _, err := os.Stat(filepath.Join(root, bucket, "object")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("object was published after a failed fsync: %v", err)
	}
}

// TestFsyncConcurrentDelete checks that removing the object and its empty
// parents after publication does not turn a successful PUT into an error
// when the directory handles are flushed.
func TestFsyncConcurrentDelete(t *testing.T) {
	for _, noTmp := range []bool{false, true} {
		name := "otmpfile"
		if noTmp {
			name = "rename"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			p, err := New(root, meta.XattrMeta{}, PosixOpts{AbsolutePaths: true, ForceNoTmpFile: noTmp, Fsync: true})
			if err != nil {
				t.Fatal(err)
			}
			createTestBucket(t, p, "bucket")
			orig := syncDir
			t.Cleanup(func() { syncDir = orig })
			var synced []string
			syncDir = func(dir string, d *os.File) error {
				synced = append(synced, dir)
				if len(synced) == 1 {
					// DeleteObject removes the object and its empty
					// parents through the real removeParents path.
					bucket, key := "bucket", "a/b/object"
					_, err := p.DeleteObject(context.Background(), &s3.DeleteObjectInput{Bucket: &bucket, Key: &key})
					if err != nil {
						t.Fatal(err)
					}
				}
				return orig(dir, d)
			}
			if err := putTestObject(t, p, "bucket", "a/b/object", "hello"); err != nil {
				t.Fatal(err)
			}
			want := []string{
				filepath.Join(root, "bucket", "a", "b"),
				filepath.Join(root, "bucket", "a"),
				filepath.Join(root, "bucket"),
			}
			if !slices.Equal(synced, want) {
				t.Fatalf("synced %v, want %v", synced, want)
			}
		})
	}
}

// TestFsyncUnreadableAncestor checks that a directory that cannot be opened
// for flushing fails the PUT with AccessDenied before the object is published.
func TestFsyncUnreadableAncestor(t *testing.T) {
	for _, noTmp := range []bool{false, true} {
		name := "otmpfile"
		if noTmp {
			name = "rename"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			p, err := New(root, meta.XattrMeta{}, PosixOpts{AbsolutePaths: true, ForceNoTmpFile: noTmp, Fsync: true})
			if err != nil {
				t.Fatal(err)
			}
			createTestBucket(t, p, "bucket")
			parent := filepath.Join(root, "bucket/a")
			if err := os.MkdirAll(filepath.Join(parent, "b"), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(parent, 0300); err != nil {
				t.Fatal(err)
			}
			defer os.Chmod(parent, 0755)
			if d, err := os.Open(parent); err == nil {
				d.Close()
				t.Skip("user can read directories without read permission")
			} else if !errors.Is(err, os.ErrPermission) {
				t.Fatal(err)
			}
			err = putTestObject(t, p, "bucket", "a/b/object", "hello")
			if !errors.Is(err, s3err.GetAPIError(s3err.ErrAccessDenied)) {
				t.Fatalf("put = %v, want AccessDenied", err)
			}
			if _, err := os.Stat(filepath.Join(parent, "b/object")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("object published: %v", err)
			}
		})
	}
}

// TestFsyncNamespaceFailureClosesHandles checks that every directory handle
// is closed when flushing the namespace fails.
func TestFsyncNamespaceFailureClosesHandles(t *testing.T) {
	bucket := t.TempDir()
	dir := filepath.Join(bucket, "a", "b")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	tmp := &tmpfile{bucket: bucket, fsync: true}
	dirs, err := tmp.openDirForSync(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(dirs) == 0 {
		t.Skip("directory fsync is disabled on this platform")
	}
	orig := syncDir
	t.Cleanup(func() { syncDir = orig })
	want := errors.New("directory sync failed")
	syncDir = func(string, *os.File) error { return want }
	if err := tmp.syncNamespace(dirs); !errors.Is(err, want) {
		t.Fatalf("sync error = %v, want %v", err, want)
	}
	for _, d := range dirs {
		if _, err := d.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Errorf("handle %q not closed: %v", d.Name(), err)
		}
	}
}

// TestFsyncMoveIntoUsesHandle checks that publishing renames relative to the
// retained parent handle: if the directory chain is removed and recreated
// after the handles were opened, the rename fails instead of placing the
// object in the new directories while the removed ones get synced.
func TestFsyncMoveIntoUsesHandle(t *testing.T) {
	bucket := t.TempDir()
	dir := filepath.Join(bucket, "a", "b")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	tmp := &tmpfile{bucket: bucket, fsync: true}
	dirs, err := tmp.openDirForSync(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer dirs.Close()
	if len(dirs) == 0 {
		t.Skip("directory fsync is disabled on this platform")
	}
	if ok, _ := renameInDir("", -1, ""); !ok {
		t.Skip("rename relative to a directory handle is unsupported here")
	}
	src := filepath.Join(bucket, "temp")
	if err := os.WriteFile(src, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(bucket, "a")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	obj := filepath.Join(dir, "object")
	if err := moveInto(src, obj, 0644, dirs); err == nil {
		t.Fatal("move into a removed directory succeeded")
	}
	if _, err := os.Stat(obj); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("object landed in the recreated directory: %v", err)
	}
}
