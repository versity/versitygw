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
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/s3response"
)

// recordSyncs replaces the sync hooks for one test and returns what they saw.
func recordSyncs(t *testing.T) (files *int, dirs *[]string) {
	t.Helper()
	origFile, origDir := syncFile, syncDir
	t.Cleanup(func() { syncFile, syncDir = origFile, origDir })
	files, dirs = new(int), new([]string)
	syncFile = func(f *os.File) error { *files++; return origFile(f) }
	syncDir = func(dir string) error { *dirs = append(*dirs, dir); return origDir(dir) }
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

// TestFsyncPutObjectMeta checks that with Fsync set the tags and Object Lock
// settings written after the object is published are flushed before the PUT
// returns, and that a PUT without them still costs a single flush.
func TestFsyncPutObjectMeta(t *testing.T) {
	cases := []struct {
		name  string
		input func(in *s3response.PutObjectInput)
		files int
	}{
		{"plain", func(*s3response.PutObjectInput) {}, 1},
		{"tagging", func(in *s3response.PutObjectInput) { in.Tagging = aws.String("k=v") }, 2},
		{"legal hold", func(in *s3response.PutObjectInput) {
			in.ObjectLockLegalHoldStatus = types.ObjectLockLegalHoldStatusOn
		}, 2},
	}
	for _, tc := range cases {
		for _, fsync := range []bool{false, true} {
			name := tc.name
			if fsync {
				name += "/fsync"
			}
			t.Run(name, func(t *testing.T) {
				root := t.TempDir()
				p, err := New(root, meta.XattrMeta{}, PosixOpts{
					AbsolutePaths: true,
					Fsync:         fsync,
					VersioningDir: t.TempDir(),
				})
				if err != nil {
					t.Fatalf("new posix: %v", err)
				}
				bucket := "bucket"
				err = p.CreateBucket(context.Background(), &s3.CreateBucketInput{
					Bucket:                     &bucket,
					ObjectLockEnabledForBucket: aws.Bool(true),
					CreateBucketConfiguration:  &types.CreateBucketConfiguration{},
				}, []byte{})
				if err != nil {
					t.Fatalf("create bucket: %v", err)
				}

				files, _ := recordSyncs(t)
				in := s3response.PutObjectInput{
					Bucket:        &bucket,
					Key:           aws.String("object"),
					Body:          strings.NewReader("hello"),
					ContentLength: aws.Int64(5),
				}
				tc.input(&in)
				if _, err := p.PutObject(context.Background(), in); err != nil {
					t.Fatalf("put object: %v", err)
				}

				want := 0
				if fsync {
					want = tc.files
				}
				if *files != want {
					t.Fatalf("synced %d files, want %d", *files, want)
				}
			})
		}
	}
}
