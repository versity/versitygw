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
	"fmt"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/s3response"
)

// TestListObjectsV2ContinuationTokenEcho checks that ListObjectsV2 echoes
// the request continuation token, and only that: start-after must not be
// reported back as a continuation token.
func TestListObjectsV2ContinuationTokenEcho(t *testing.T) {
	p := newTestPosix(t, metaModes(t)["xattr"])
	bucket := "testbucket"
	createTestBucket(t, p, bucket)

	ctx := context.Background()
	for _, key := range []string{"a", "b", "c"} {
		_, err := p.PutObject(ctx, s3response.PutObjectInput{
			Bucket:        &bucket,
			Key:           aws.String(key),
			Body:          strings.NewReader("data"),
			ContentLength: aws.Int64(4),
		})
		if err != nil {
			t.Fatalf("put object %q: %v", key, err)
		}
	}

	tests := []struct {
		name       string
		cToken     string
		startAfter string
		wantToken  *string
		wantKeys   []string
	}{
		{"no token or start-after", "", "", nil, []string{"a", "b", "c"}},
		{"start-after only", "", "a", nil, []string{"b", "c"}},
		{"continuation token only", "a", "", aws.String("a"), []string{"b", "c"}},
		{"start-after past the continuation token", "a", "b", aws.String("a"), []string{"c"}},
		{"continuation token past start-after", "b", "a", aws.String("b"), []string{"c"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := p.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
				Bucket:            &bucket,
				ContinuationToken: &tt.cToken,
				StartAfter:        &tt.startAfter,
				MaxKeys:           aws.Int32(1000),
			})
			if err != nil {
				t.Fatalf("list objects v2: %v", err)
			}

			if !reflect.DeepEqual(out.ContinuationToken, tt.wantToken) {
				t.Fatalf("continuation token = %q, want %q",
					aws.ToString(out.ContinuationToken), aws.ToString(tt.wantToken))
			}

			var keys []string
			for _, obj := range out.Contents {
				keys = append(keys, aws.ToString(obj.Key))
			}
			if strings.Join(keys, ",") != strings.Join(tt.wantKeys, ",") {
				t.Fatalf("keys = %v, want %v", keys, tt.wantKeys)
			}
		})
	}
}

// entryGoneMeta stands in for a shared filesystem on which the directory of
// one listed entry is being removed by another node: reading that entry's
// etag fails with errno, as Storage Scale reports it.
type entryGoneMeta struct {
	meta.XattrMeta
	object string
	errno  syscall.Errno
}

func (m entryGoneMeta) WithRootDir(rootdir string) meta.MetadataStorer {
	m.XattrMeta = m.XattrMeta.WithRootDir(rootdir).(meta.XattrMeta)
	return m
}

func (m entryGoneMeta) RetrieveAttribute(f *os.File, bucket, object, attribute string) ([]byte, error) {
	if object == m.object && attribute == etagkey {
		return nil, fmt.Errorf("xattr.get %v user.etag: %w", object, m.errno)
	}
	return m.XattrMeta.RetrieveAttribute(f, bucket, object, attribute)
}

// TestListObjectsSkipsEntryWhoseDirIsGone checks that ListObjects and
// ListObjectsV2 skip an entry whose etag read reports that its directory
// is gone, as they skip an entry that no longer exists, instead of failing
// the listing.
func TestListObjectsSkipsEntryWhoseDirIsGone(t *testing.T) {
	for _, tc := range []struct {
		name, object, want string
	}{
		// the etag read of an object
		{"object", "dir/b", "a,dir/c"},
		// the etag read of a directory, to tell if it's a directory object
		{"directory", "dir/", "a,dir/b,dir/c"},
	} {
		for _, errno := range []syscall.Errno{syscall.ENOTDIR, syscall.ESTALE} {
			t.Run(tc.name+"/"+errno.Error(), func(t *testing.T) {
				p := newTestPosix(t, func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
					return entryGoneMeta{object: tc.object, errno: errno}, PosixOpts{NewDirPerm: 0755}
				})
				bucket := "testbucket"
				createTestBucket(t, p, bucket)

				ctx := context.Background()
				for _, key := range []string{"a", "dir/b", "dir/c"} {
					_, err := p.PutObject(ctx, s3response.PutObjectInput{
						Bucket:        &bucket,
						Key:           aws.String(key),
						Body:          strings.NewReader("data"),
						ContentLength: aws.Int64(4),
					})
					if err != nil {
						t.Fatalf("put object %q: %v", key, err)
					}
				}

				want := tc.want
				keys := func(objs []s3response.Object) string {
					var k []string
					for _, obj := range objs {
						k = append(k, aws.ToString(obj.Key))
					}
					return strings.Join(k, ",")
				}

				v1, err := p.ListObjects(ctx, &s3.ListObjectsInput{
					Bucket:  &bucket,
					MaxKeys: aws.Int32(1000),
				})
				if err != nil {
					t.Fatalf("list objects: %v", err)
				}
				if got := keys(v1.Contents); got != want {
					t.Fatalf("list objects keys = %v, want %v", got, want)
				}

				v2, err := p.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
					Bucket:     &bucket,
					StartAfter: aws.String(""),
					MaxKeys:    aws.Int32(1000),
				})
				if err != nil {
					t.Fatalf("list objects v2: %v", err)
				}
				if got := keys(v2.Contents); got != want {
					t.Fatalf("list objects v2 keys = %v, want %v", got, want)
				}
			})
		}
	}
}

// infoGoneEntry is a listed entry whose file info read reports that its
// directory is gone.
type infoGoneEntry struct {
	fs.DirEntry
	errno syscall.Errno
}

func (e infoGoneEntry) Info() (fs.FileInfo, error) {
	return nil, &fs.PathError{Op: "lstat", Path: e.Name(), Err: e.errno}
}

// TestFileToObjSkipsEntryWhoseInfoIsGone checks that FileToObj skips a
// directory object and an object whose file info read reports that their
// directory is gone.
func TestFileToObjSkipsEntryWhoseInfoIsGone(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.ENOTDIR, syscall.ESTALE} {
		t.Run(errno.Error(), func(t *testing.T) {
			p := newTestPosix(t, func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
				return meta.XattrMeta{}, PosixOpts{NewDirPerm: 0755}
			})
			bucket := "testbucket"
			createTestBucket(t, p, bucket)

			ctx := context.Background()
			for _, key := range []string{"dir/", "dir/b"} {
				_, err := p.PutObject(ctx, s3response.PutObjectInput{
					Bucket:        &bucket,
					Key:           aws.String(key),
					Body:          strings.NewReader(""),
					ContentLength: aws.Int64(0),
				})
				if err != nil {
					t.Fatalf("put object %q: %v", key, err)
				}

				fi, err := fs.Stat(p.bucketFS(bucket), strings.TrimSuffix(key, "/"))
				if err != nil {
					t.Fatalf("stat %q: %v", key, err)
				}
				_, err = p.FileToObj(bucket, false)(key, infoGoneEntry{fs.FileInfoToDirEntry(fi), errno})
				if !errors.Is(err, backend.ErrSkipObj) {
					t.Fatalf("file to object %q: expected the entry to be skipped, got %v", key, err)
				}
			}
		})
	}
}
