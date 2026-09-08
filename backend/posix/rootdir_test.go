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
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// TestDefaultModeChangesWorkingDirectory documents the default behavior: New
// changes the process working directory to the root and addresses buckets by
// relative paths.
func TestDefaultModeChangesWorkingDirectory(t *testing.T) {
	work := t.TempDir()
	t.Chdir(work)
	root := t.TempDir()

	p, err := New(root, meta.XattrMeta{}, PosixOpts{})
	if err != nil {
		t.Fatalf("new posix: %v", err)
	}
	// Compare by identity: on macOS the temp dir is reached through a
	// symlink, so Getwd returns a different spelling of the same directory.
	wdInfo, err := os.Stat(".")
	if err != nil {
		t.Fatalf("stat working directory: %v", err)
	}
	rootInfo, err := os.Stat(root)
	if err != nil {
		t.Fatalf("stat root: %v", err)
	}
	if !os.SameFile(wdInfo, rootInfo) {
		wd, _ := os.Getwd()
		t.Fatalf("working directory = %q; want root %q", wd, root)
	}
	if got := p.BucketPath("b"); got != "b" {
		t.Fatalf("BucketPath = %q, want %q", got, "b")
	}
	if got := p.ObjectPath("b", "d/o"); got != filepath.Join("b", "d", "o") {
		t.Fatalf("ObjectPath = %q, want %q", got, filepath.Join("b", "d", "o"))
	}
}

// TestRootDirIndependentOfWorkingDirectory checks that with AbsolutePaths the
// backend neither changes the process working directory nor depends on it:
// every operation resolves buckets and objects under the root directory it
// was given, so the gateway can be embedded in a process whose working
// directory is elsewhere.
func TestRootDirIndependentOfWorkingDirectory(t *testing.T) {
	for name, mkMeta := range metaModes(t) {
		t.Run(name, func(t *testing.T) {
			// Work from a directory that is neither the gateway root nor
			// anything under it, and hand New a relative path to the root so
			// that its resolution against the working directory is exercised.
			work := t.TempDir()
			t.Chdir(work)
			root := t.TempDir()
			relRoot, err := filepath.Rel(work, root)
			if err != nil {
				t.Fatalf("relative root: %v", err)
			}

			storer, opts := mkMeta(t)
			opts.AbsolutePaths = true
			opts.CopyObjectThreshold = 1 << 20
			p, err := New(relRoot, storer, opts)
			if err != nil {
				t.Fatalf("new posix: %v", err)
			}

			if wd, err := os.Getwd(); err != nil || wd != work {
				t.Fatalf("New changed the working directory to %q (want %q, err %v)", wd, work, err)
			}
			if got := p.BucketPath("b"); got != filepath.Join(root, "b") {
				t.Fatalf("BucketPath = %q, want %q", got, filepath.Join(root, "b"))
			}

			ctx := context.Background()
			bucket, object, body := "bucket", "dir/object", "hello"
			createTestBucket(t, p, bucket)

			_, err = p.PutObject(ctx, s3response.PutObjectInput{
				Bucket:        &bucket,
				Key:           &object,
				Body:          strings.NewReader(body),
				ContentLength: aws.Int64(int64(len(body))),
			})
			if err != nil {
				t.Fatalf("put object: %v", err)
			}

			// Everything landed under the root, nothing under the working
			// directory.
			if _, err := os.Stat(filepath.Join(root, bucket, object)); err != nil {
				t.Fatalf("object not under root: %v", err)
			}
			if _, err := os.Stat(filepath.Join(work, bucket)); err == nil {
				t.Fatalf("bucket directory created under the working directory")
			}

			out, err := p.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &object})
			if err != nil {
				t.Fatalf("get object: %v", err)
			}
			got, err := io.ReadAll(out.Body)
			out.Body.Close()
			if err != nil || string(got) != body {
				t.Fatalf("get object body = %q, %v; want %q", got, err, body)
			}

			list, err := p.ListObjects(ctx, &s3.ListObjectsInput{Bucket: &bucket, MaxKeys: aws.Int32(1000)})
			if err != nil {
				t.Fatalf("list objects: %v", err)
			}
			if len(list.Contents) != 1 || *list.Contents[0].Key != object {
				t.Fatalf("list objects = %+v, want just %q", list.Contents, object)
			}

			buckets, err := p.ListBuckets(ctx, s3response.ListBucketsInput{IsAdmin: true, MaxBuckets: 1000})
			if err != nil {
				t.Fatalf("list buckets: %v", err)
			}
			if len(buckets.Buckets.Bucket) != 1 || buckets.Buckets.Bucket[0].Name != bucket {
				t.Fatalf("list buckets = %+v, want just %q", buckets.Buckets.Bucket, bucket)
			}

			// A multipart upload stores its checksum algorithm in metadata
			// keyed by the upload's temporary directory; ListParts must find
			// it under the root, and the parts must land there too.
			mpKey := "mp/object"
			mp, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
				Bucket:            &bucket,
				Key:               &mpKey,
				ChecksumAlgorithm: types.ChecksumAlgorithmCrc32,
				ChecksumType:      types.ChecksumTypeComposite,
			})
			if err != nil {
				t.Fatalf("create multipart upload: %v", err)
			}
			uploadID := mp.UploadId
			crc := make([]byte, 4)
			binary.BigEndian.PutUint32(crc, crc32.ChecksumIEEE([]byte(body)))
			partCRC := base64.StdEncoding.EncodeToString(crc)
			part, err := p.UploadPart(ctx, &s3.UploadPartInput{
				Bucket:        &bucket,
				Key:           &mpKey,
				UploadId:      &uploadID,
				PartNumber:    aws.Int32(1),
				ContentLength: aws.Int64(int64(len(body))),
				Body:          strings.NewReader(body),
				ChecksumCRC32: &partCRC,
			})
			if err != nil {
				t.Fatalf("upload part: %v", err)
			}
			// The copy source's bucket goes through the same validation as
			// every other bucket name.
			for _, srcBucket := range []string{"..", "."} {
				_, err := p.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
					Bucket:     &bucket,
					Key:        &mpKey,
					UploadId:   &uploadID,
					PartNumber: aws.Int32(2),
					CopySource: aws.String(srcBucket + "/" + object),
				})
				if !errors.Is(err, s3err.GetBucketErr(s3err.ErrInvalidBucketName, srcBucket)) {
					t.Fatalf("upload part copy from bucket %q: got %v, want InvalidBucketName", srcBucket, err)
				}
			}
			// A valid copy source resolves under the root like any object.
			_, err = p.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
				Bucket:          &bucket,
				Key:             &mpKey,
				UploadId:        &uploadID,
				PartNumber:      aws.Int32(2),
				CopySource:      aws.String(bucket + "/" + object),
				CopySourceRange: aws.String(""),
			})
			if err != nil {
				t.Fatalf("upload part copy: %v", err)
			}
			if _, err := os.Stat(filepath.Join(root, bucket, MetaTmpMultipartDir)); err != nil {
				t.Fatalf("multipart directory not under root: %v", err)
			}
			lp, err := p.ListParts(ctx, &s3.ListPartsInput{Bucket: &bucket, Key: &mpKey, UploadId: &uploadID, MaxParts: aws.Int32(1000)})
			if err != nil {
				t.Fatalf("list parts: %v", err)
			}
			if lp.ChecksumAlgorithm != types.ChecksumAlgorithmCrc32 || len(lp.Parts) != 2 {
				t.Fatalf("list parts = algorithm %q, %d parts; want CRC32, 2 parts", lp.ChecksumAlgorithm, len(lp.Parts))
			}
			_, _, err = p.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
				Bucket:   &bucket,
				Key:      &mpKey,
				UploadId: &uploadID,
				MultipartUpload: &types.CompletedMultipartUpload{
					Parts: []types.CompletedPart{{ETag: part.ETag, PartNumber: aws.Int32(1), ChecksumCRC32: &partCRC}},
				},
			})
			if err != nil {
				t.Fatalf("complete multipart upload: %v", err)
			}
			if _, err := os.Stat(filepath.Join(root, bucket, mpKey)); err != nil {
				t.Fatalf("multipart object not under root: %v", err)
			}

			// CopyObject resolves both source and destination under the root.
			copyKey := "copy/object"
			_, err = p.CopyObject(ctx, s3response.CopyObjectInput{
				Bucket:              &bucket,
				Key:                 &copyKey,
				CopySource:          aws.String(bucket + "/" + object),
				ExpectedBucketOwner: aws.String(""),
			})
			if err != nil {
				t.Fatalf("copy object: %v", err)
			}
			if _, err := os.Stat(filepath.Join(root, bucket, copyKey)); err != nil {
				t.Fatalf("copied object not under root: %v", err)
			}
			if _, err := os.Stat(filepath.Join(work, bucket)); err == nil {
				t.Fatalf("bucket directory created under the working directory")
			}
			_, err = p.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &copyKey})
			if err != nil {
				t.Fatalf("delete copied object: %v", err)
			}

			// Deleting an explicitly created directory object that still has
			// children removes only its metadata; the lookup is by bucket and
			// object name.
			dirKey := "dir/"
			_, err = p.PutObject(ctx, s3response.PutObjectInput{
				Bucket:        &bucket,
				Key:           &dirKey,
				Body:          strings.NewReader(""),
				ContentLength: aws.Int64(0),
			})
			if err != nil {
				t.Fatalf("put directory object: %v", err)
			}
			if _, err := p.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &dirKey}); err != nil {
				t.Fatalf("head directory object: %v", err)
			}
			_, err = p.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &dirKey})
			if err != nil {
				t.Fatalf("delete non-empty directory object: %v", err)
			}
			if _, err := os.Stat(filepath.Join(root, bucket, object)); err != nil {
				t.Fatalf("child object removed with directory object: %v", err)
			}
			_, err = p.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &dirKey})
			if !errors.Is(err, s3err.GetAPIError(s3err.ErrDirectoryNotEmpty)) {
				t.Fatalf("second delete of directory object: got %v, want DirectoryNotEmpty", err)
			}

			_, err = p.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &object})
			if err != nil {
				t.Fatalf("delete object: %v", err)
			}
			if _, err := os.Stat(filepath.Join(root, bucket, "dir")); !os.IsNotExist(err) {
				t.Fatalf("empty parent directory not removed: %v", err)
			}
			_, err = p.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &mpKey})
			if err != nil {
				t.Fatalf("delete multipart object: %v", err)
			}

			// Bucket names that would resolve to the root directory, its
			// parent, or outside the root are rejected in every validation
			// mode (the test backend has posix-level validation off).
			for _, name := range []string{"", ".", "..", "a/b", root} {
				want := s3err.GetBucketErr(s3err.ErrInvalidBucketName, name)
				_, err = p.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &name})
				if !errors.Is(err, want) {
					t.Fatalf("head bucket %q: got %v, want InvalidBucketName", name, err)
				}
				if err := p.DeleteBucket(ctx, name); !errors.Is(err, want) {
					t.Fatalf("delete bucket %q: got %v, want InvalidBucketName", name, err)
				}
			}
			if _, err := os.Stat(root); err != nil {
				t.Fatalf("root directory gone: %v", err)
			}

			err = p.DeleteBucket(ctx, bucket)
			if err != nil {
				t.Fatalf("delete bucket: %v", err)
			}
			if _, err := os.Stat(filepath.Join(root, bucket)); !os.IsNotExist(err) {
				t.Fatalf("bucket directory not removed: %v", err)
			}

			if wd, err := os.Getwd(); err != nil || wd != work {
				t.Fatalf("working directory changed to %q (want %q, err %v)", wd, work, err)
			}
		})
	}
}

// TestVersioningDirIndependentOfWorkingDirectory checks the versioning
// directory substitution with AbsolutePaths: the versioning code passes the
// absolute path of a bucket's versioning directory where a bucket name is
// expected, and both the backend and the metadata storer must use it as
// given rather than resolving it under the root or the working directory.
func TestVersioningDirIndependentOfWorkingDirectory(t *testing.T) {
	for name, mkMeta := range metaModes(t) {
		t.Run(name, func(t *testing.T) {
			work := t.TempDir()
			t.Chdir(work)
			root := t.TempDir()
			vdir := t.TempDir()
			relRoot, err := filepath.Rel(work, root)
			if err != nil {
				t.Fatalf("relative root: %v", err)
			}
			relVdir, err := filepath.Rel(work, vdir)
			if err != nil {
				t.Fatalf("relative versioning dir: %v", err)
			}

			storer, opts := mkMeta(t)
			opts.VersioningDir = relVdir
			opts.AbsolutePaths = true
			p, err := New(relRoot, storer, opts)
			if err != nil {
				t.Fatalf("new posix: %v", err)
			}

			ctx := context.Background()
			bucket, object := "bucket", "object"
			createTestBucket(t, p, bucket)
			if err := p.PutBucketVersioning(ctx, bucket, types.BucketVersioningStatusEnabled); err != nil {
				t.Fatalf("put bucket versioning: %v", err)
			}

			put := func(body string) string {
				t.Helper()
				out, err := p.PutObject(ctx, s3response.PutObjectInput{
					Bucket:        &bucket,
					Key:           &object,
					Body:          strings.NewReader(body),
					ContentLength: aws.Int64(int64(len(body))),
				})
				if err != nil {
					t.Fatalf("put object %q: %v", body, err)
				}
				return out.VersionID
			}
			v1 := put("one")
			v2 := put("two")
			if v1 == "" || v2 == "" || v1 == v2 {
				t.Fatalf("version ids = %q, %q; want two distinct non-empty ids", v1, v2)
			}

			// The first version was copied into the versioning directory;
			// the root holds only the bucket (and the object lock directory)
			// and the working directory stays empty.
			if _, err := os.Stat(filepath.Join(vdir, bucket)); err != nil {
				t.Fatalf("bucket versioning directory missing: %v", err)
			}
			ents, err := os.ReadDir(root)
			if err != nil {
				t.Fatalf("read root directory: %v", err)
			}
			for _, e := range ents {
				if e.Name() != bucket && e.Name() != objLockDir {
					t.Fatalf("unexpected entry %q in root directory", e.Name())
				}
			}
			if ents, err := os.ReadDir(work); err != nil || len(ents) != 0 {
				t.Fatalf("working directory entries = %v, %v; want none", ents, err)
			}

			get := func(versionID string) string {
				t.Helper()
				in := &s3.GetObjectInput{Bucket: &bucket, Key: &object}
				if versionID != "" {
					in.VersionId = &versionID
				}
				out, err := p.GetObject(ctx, in)
				if err != nil {
					t.Fatalf("get object version %q: %v", versionID, err)
				}
				defer out.Body.Close()
				got, err := io.ReadAll(out.Body)
				if err != nil {
					t.Fatalf("read object version %q: %v", versionID, err)
				}
				return string(got)
			}
			if got := get(""); got != "two" {
				t.Fatalf("current version = %q, want %q", got, "two")
			}
			if got := get(v1); got != "one" {
				t.Fatalf("version %q = %q, want %q", v1, got, "one")
			}

			// Deleting a specific version removes it from the versioning
			// directory.
			_, err = p.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &object, VersionId: &v1})
			if err != nil {
				t.Fatalf("delete version: %v", err)
			}
			_, err = p.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &object, VersionId: &v1})
			if !errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchVersion)) {
				t.Fatalf("get deleted version: got %v, want NoSuchVersion", err)
			}

			if wd, err := os.Getwd(); err != nil || wd != work {
				t.Fatalf("working directory changed to %q (want %q, err %v)", wd, work, err)
			}
		})
	}
}
