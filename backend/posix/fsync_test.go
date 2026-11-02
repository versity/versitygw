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
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

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

// newFsyncMetaPosix returns a gateway with an Object Lock bucket "bucket" and
// the given default retention rule, if any.
func newFsyncMetaPosix(t *testing.T, fsync bool, lockCfg string) (*Posix, string) {
	t.Helper()
	p, err := New(t.TempDir(), meta.XattrMeta{}, PosixOpts{
		AbsolutePaths:       true,
		Fsync:               fsync,
		VersioningDir:       t.TempDir(),
		CopyObjectThreshold: 1 << 20,
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
	if lockCfg != "" {
		err = p.PutObjectLockConfiguration(context.Background(), bucket, []byte(lockCfg))
		if err != nil {
			t.Fatalf("put object lock config: %v", err)
		}
	}
	return p, bucket
}

var metaAttrs = []string{tagHdr, objectLegalHoldKey, objectRetentionKey}

// recordAttrsAtSync replaces the sync hooks for one test. It returns the
// number of file syncs and, for the last file sync and the last sync of the
// directory object dirObject, which of the tag, legal hold and retention
// attributes were already stored then. A file is looked at through the handle
// being synced, as a staged file has no path yet.
func recordAttrsAtSync(t *testing.T, p *Posix, bucket, object, dirObject string) (files *int, atFile, atDir map[string]bool) {
	t.Helper()
	origFile, origDir := syncFile, syncDir
	t.Cleanup(func() { syncFile, syncDir = origFile, origDir })
	files, atFile, atDir = new(int), map[string]bool{}, map[string]bool{}
	syncFile = func(f *os.File) error {
		*files++
		for _, k := range metaAttrs {
			_, err := p.meta.RetrieveAttribute(f, bucket, object, k)
			atFile[k] = err == nil
		}
		return origFile(f)
	}
	syncDir = func(dir string) error {
		if dirObject != "" && dir == p.ObjectPath(bucket, dirObject) {
			for _, k := range metaAttrs {
				_, err := p.meta.RetrieveAttribute(nil, bucket, dirObject, k)
				atDir[k] = err == nil
			}
		}
		return origDir(dir)
	}
	return files, atFile, atDir
}

func wantAttrs(tag, hold, retention bool) map[string]bool {
	return map[string]bool{tagHdr: tag, objectLegalHoldKey: hold, objectRetentionKey: retention}
}

// TestFsyncPutObjectMeta checks that the tags and Object Lock settings of a
// PUT are on the file when it is flushed, which is before it is published,
// that they cost no flush of their own, and that nothing is flushed without
// Fsync.
func TestFsyncPutObjectMeta(t *testing.T) {
	const defaultRetention = `{"Enabled":true,"DefaultRetention":{"Mode":"GOVERNANCE","Days":1}}`
	cases := []struct {
		name    string
		input   func(in *s3response.PutObjectInput)
		lockCfg string
		want    map[string]bool
	}{
		{"plain", func(*s3response.PutObjectInput) {}, "", wantAttrs(false, false, false)},
		{"tagging", func(in *s3response.PutObjectInput) { in.Tagging = aws.String("k=v") }, "",
			wantAttrs(true, false, false)},
		{"legal hold", func(in *s3response.PutObjectInput) {
			in.ObjectLockLegalHoldStatus = types.ObjectLockLegalHoldStatusOn
		}, "", wantAttrs(false, true, false)},
		{"retention", func(in *s3response.PutObjectInput) {
			in.ObjectLockMode = types.ObjectLockModeGovernance
			in.ObjectLockRetainUntilDate = aws.Time(time.Now().Add(time.Hour))
		}, "", wantAttrs(false, false, true)},
		{"default retention", func(*s3response.PutObjectInput) {}, defaultRetention, wantAttrs(false, false, true)},
		{"all", func(in *s3response.PutObjectInput) {
			in.Tagging = aws.String("k=v")
			in.ObjectLockLegalHoldStatus = types.ObjectLockLegalHoldStatusOn
			in.ObjectLockMode = types.ObjectLockModeGovernance
			in.ObjectLockRetainUntilDate = aws.Time(time.Now().Add(time.Hour))
		}, "", wantAttrs(true, true, true)},
	}
	for _, tc := range cases {
		for _, fsync := range []bool{false, true} {
			name := tc.name
			if fsync {
				name += "/fsync"
			}
			t.Run(name, func(t *testing.T) {
				p, bucket := newFsyncMetaPosix(t, fsync, tc.lockCfg)
				files, atFile, _ := recordAttrsAtSync(t, p, bucket, "object", "")

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

				if !fsync {
					if *files != 0 {
						t.Fatalf("synced %d files without fsync", *files)
					}
					return
				}
				if *files != 1 {
					t.Fatalf("synced %d files, want 1", *files)
				}
				if !reflect.DeepEqual(atFile, tc.want) {
					t.Fatalf("attributes at the flush: got %v, want %v", atFile, tc.want)
				}
			})
		}
	}
}

// TestFsyncPutDirectoryObjectMeta checks the same for a directory object,
// which has no staged file: its attributes are flushed before the PUT returns.
func TestFsyncPutDirectoryObjectMeta(t *testing.T) {
	p, bucket := newFsyncMetaPosix(t, true, "")
	_, _, atDir := recordAttrsAtSync(t, p, bucket, "dir/", "dir")

	_, err := p.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket:                    &bucket,
		Key:                       aws.String("dir/"),
		Body:                      strings.NewReader(""),
		ContentLength:             aws.Int64(0),
		Tagging:                   aws.String("k=v"),
		ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatusOn,
	})
	if err != nil {
		t.Fatalf("put directory object: %v", err)
	}
	if want := wantAttrs(true, true, false); !reflect.DeepEqual(atDir, want) {
		t.Fatalf("attributes at the last directory flush: got %v, want %v", atDir, want)
	}
}

// TestFsyncCopyObjectMeta checks CopyObject: the source tags that the default
// directive copies are on the file when it is flushed, and a copy onto itself
// that only replaces the metadata is flushed too.
func TestFsyncCopyObjectMeta(t *testing.T) {
	p, bucket := newFsyncMetaPosix(t, true, "")
	_, err := p.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket:        &bucket,
		Key:           aws.String("src"),
		Body:          strings.NewReader("hello"),
		ContentLength: aws.Int64(5),
		Tagging:       aws.String("k=v"),
	})
	if err != nil {
		t.Fatalf("put source: %v", err)
	}

	t.Run("copy tagging", func(t *testing.T) {
		files, atFile, _ := recordAttrsAtSync(t, p, bucket, "dst", "")
		_, err := p.CopyObject(context.Background(), s3response.CopyObjectInput{
			Bucket:              &bucket,
			Key:                 aws.String("dst"),
			CopySource:          aws.String(bucket + "/src"),
			ExpectedBucketOwner: aws.String(""),
			MetadataDirective:   types.MetadataDirectiveCopy,
			TaggingDirective:    types.TaggingDirectiveCopy,
		})
		if err != nil {
			t.Fatalf("copy: %v", err)
		}
		if *files != 1 {
			t.Fatalf("synced %d files, want 1", *files)
		}
		if want := wantAttrs(true, false, false); !reflect.DeepEqual(atFile, want) {
			t.Fatalf("attributes at the flush: got %v, want %v", atFile, want)
		}
		tags, err := p.GetObjectTagging(context.Background(), bucket, "dst", "")
		if err != nil || tags["k"] != "v" {
			t.Fatalf("destination tags: got %v, %v", tags, err)
		}
	})

	t.Run("replace tagging", func(t *testing.T) {
		files, atFile, _ := recordAttrsAtSync(t, p, bucket, "dst2", "")
		_, err := p.CopyObject(context.Background(), s3response.CopyObjectInput{
			Bucket:              &bucket,
			Key:                 aws.String("dst2"),
			CopySource:          aws.String(bucket + "/src"),
			ExpectedBucketOwner: aws.String(""),
			MetadataDirective:   types.MetadataDirectiveCopy,
			TaggingDirective:    types.TaggingDirectiveReplace,
			Tagging:             aws.String("a=b"),
		})
		if err != nil {
			t.Fatalf("copy: %v", err)
		}
		if *files != 1 {
			t.Fatalf("synced %d files, want 1", *files)
		}
		if want := wantAttrs(true, false, false); !reflect.DeepEqual(atFile, want) {
			t.Fatalf("attributes at the flush: got %v, want %v", atFile, want)
		}
	})

	t.Run("self copy replacing metadata", func(t *testing.T) {
		files, _, _ := recordAttrsAtSync(t, p, bucket, "src", "")
		_, err := p.CopyObject(context.Background(), s3response.CopyObjectInput{
			Bucket:              &bucket,
			Key:                 aws.String("src"),
			CopySource:          aws.String(bucket + "/src"),
			ExpectedBucketOwner: aws.String(""),
			MetadataDirective:   types.MetadataDirectiveReplace,
			Metadata:            map[string]string{"m": "1"},
		})
		if err != nil {
			t.Fatalf("copy: %v", err)
		}
		if *files < 1 {
			t.Fatal("the in-place metadata rewrite was not flushed")
		}
	})
}

// TestFsyncPutDirectoryObjectNested checks that the parent directories created
// for a nested directory object are flushed up to the bucket.
func TestFsyncPutDirectoryObjectNested(t *testing.T) {
	p, bucket := newFsyncMetaPosix(t, true, "")
	_, dirs := recordSyncs(t)

	_, err := p.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket:        &bucket,
		Key:           aws.String("a/b/dir/"),
		Body:          strings.NewReader(""),
		ContentLength: aws.Int64(0),
		Tagging:       aws.String("k=v"),
	})
	if err != nil {
		t.Fatalf("put directory object: %v", err)
	}
	for _, d := range []string{"a/b/dir", "a/b", "a", ""} {
		want := filepath.Clean(filepath.Join(p.BucketPath(bucket), d))
		if !slices.Contains(*dirs, want) {
			t.Errorf("directory %q was not flushed; flushed: %v", want, *dirs)
		}
	}
}

// TestFsyncSelfCopyInPlace checks a copy onto itself that replaces the metadata
// and tags, in a gateway without a versioning directory and a bucket without
// Object Lock, which is rewritten in place. The replaced metadata is on the
// object at the last flush.
func TestFsyncSelfCopyInPlace(t *testing.T) {
	p, err := New(t.TempDir(), meta.XattrMeta{}, PosixOpts{
		AbsolutePaths:       true,
		Fsync:               true,
		CopyObjectThreshold: 1 << 20,
	})
	if err != nil {
		t.Fatalf("new posix: %v", err)
	}
	bucket := "plain"
	err = p.CreateBucket(context.Background(), &s3.CreateBucketInput{
		Bucket:                    &bucket,
		CreateBucketConfiguration: &types.CreateBucketConfiguration{},
	}, []byte{})
	if err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	_, err = p.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket:        &bucket,
		Key:           aws.String("src"),
		Body:          strings.NewReader("hello"),
		ContentLength: aws.Int64(5),
	})
	if err != nil {
		t.Fatalf("put source: %v", err)
	}

	origFile := syncFile
	t.Cleanup(func() { syncFile = origFile })
	var files int
	var tagAtSync, metaAtSync bool
	syncFile = func(f *os.File) error {
		files++
		_, err := p.meta.RetrieveAttribute(f, bucket, "src", tagHdr)
		tagAtSync = err == nil
		_, err = p.meta.RetrieveAttribute(f, bucket, "src", metadataHdr)
		metaAtSync = err == nil
		return origFile(f)
	}

	_, err = p.CopyObject(context.Background(), s3response.CopyObjectInput{
		Bucket:              &bucket,
		Key:                 aws.String("src"),
		CopySource:          aws.String(bucket + "/src"),
		ExpectedBucketOwner: aws.String(""),
		MetadataDirective:   types.MetadataDirectiveReplace,
		Metadata:            map[string]string{"m": "1"},
		TaggingDirective:    types.TaggingDirectiveReplace,
		Tagging:             aws.String("k=v"),
	})
	if err != nil {
		t.Fatalf("copy: %v", err)
	}
	if files < 1 {
		t.Fatal("the in-place rewrite was not flushed")
	}
	if !tagAtSync || !metaAtSync {
		t.Fatalf("at the last flush: tags stored %v, metadata stored %v", tagAtSync, metaAtSync)
	}
}
