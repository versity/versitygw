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

//go:build linux && amd64

package scoutfs

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/versity/scoutfs-go"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// TestHeadObjectDeleteMarker checks that HeadObject returns the delete
// marker output along with the error, so the response carries the
// x-amz-delete-marker, x-amz-version-id and Last-Modified headers.
func TestHeadObjectDeleteMarker(t *testing.T) {
	// New() chdirs into the gateway root; restore the original working
	// directory when the test completes.
	t.Chdir(t.TempDir())

	s, err := New(t.TempDir(), ScoutfsOpts{
		VersioningDir:       t.TempDir(),
		ValidateBucketNames: true,
	})
	if err != nil {
		t.Fatalf("init scoutfs backend: %v", err)
	}
	t.Cleanup(s.Shutdown)

	ctx := context.Background()
	bucket, key, body := "bucket", "object", "data"
	err = s.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket:                    &bucket,
		CreateBucketConfiguration: &types.CreateBucketConfiguration{},
	}, []byte{})
	if err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	err = s.PutBucketVersioning(ctx, bucket, types.BucketVersioningStatusEnabled)
	if err != nil {
		t.Fatalf("put bucket versioning: %v", err)
	}
	_, err = s.PutObject(ctx, s3response.PutObjectInput{
		Bucket:        &bucket,
		Key:           &key,
		Body:          strings.NewReader(body),
		ContentLength: aws.Int64(int64(len(body))),
	})
	if err != nil {
		t.Fatalf("put object: %v", err)
	}
	del, err := s.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		t.Fatalf("delete object: %v", err)
	}

	// the current version is the delete marker
	res, err := s.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &key})
	assert.ErrorIs(t, err, s3err.GetAPIError(s3err.ErrNoSuchKey))
	if assert.NotNil(t, res) {
		assert.Equal(t, aws.Bool(true), res.DeleteMarker)
		assert.Equal(t, del.VersionId, res.VersionId)
		assert.Nil(t, res.LastModified)
	}

	// the requested version is the delete marker
	res, err = s.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket:    &bucket,
		Key:       &key,
		VersionId: del.VersionId,
	})
	assert.ErrorIs(t, err, s3err.GetAPIError(s3err.ErrMethodNotAllowed))
	if assert.NotNil(t, res) {
		assert.Equal(t, aws.Bool(true), res.DeleteMarker)
		assert.Equal(t, del.VersionId, res.VersionId)
		assert.NotNil(t, res.LastModified)
	}
}

// TestDetectStaleEtag checks that DetectStaleEtag reaches the posix backend:
// an object rewritten in place outside the gateway gets an ETag made from its
// size and modification time, and a PUT through the gateway stores a current
// ETag again.
func TestDetectStaleEtag(t *testing.T) {
	// New() chdirs into the gateway root; restore the original working
	// directory when the test completes.
	t.Chdir(t.TempDir())

	root := t.TempDir()
	s, err := New(root, ScoutfsOpts{ValidateBucketNames: true, DetectStaleEtag: true})
	if err != nil {
		t.Fatalf("init scoutfs backend: %v", err)
	}
	t.Cleanup(s.Shutdown)

	ctx := context.Background()
	bucket, key := "bucket", "object"
	err = s.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket:                    &bucket,
		CreateBucketConfiguration: &types.CreateBucketConfiguration{},
	}, []byte{})
	if err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	put := func(body string) string {
		t.Helper()
		out, err := s.PutObject(ctx, s3response.PutObjectInput{
			Bucket:        &bucket,
			Key:           &key,
			Body:          strings.NewReader(body),
			ContentLength: aws.Int64(int64(len(body))),
		})
		if err != nil {
			t.Fatalf("put object: %v", err)
		}
		return strings.Trim(out.ETag, `"`)
	}
	head := func() string {
		t.Helper()
		res, err := s.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &key})
		if err != nil {
			t.Fatalf("head object: %v", err)
		}
		return strings.Trim(aws.ToString(res.ETag), `"`)
	}

	etag := put("data")
	assert.Equal(t, etag, head())

	// rewrite the file in place, keeping its inode and attributes
	err = os.WriteFile(filepath.Join(root, bucket, key), []byte("changed data"), 0o644)
	if err != nil {
		t.Fatalf("rewrite object: %v", err)
	}
	stale := head()
	assert.Contains(t, stale, "-s")
	assert.NotEqual(t, etag, stale)

	etag = put("new data")
	assert.Equal(t, etag, head())
	assert.NotContains(t, etag, "-s")
}

// TestGetObjectGlacierOffline checks a glacier mode GetObject of an offline
// object on a real ScoutFS filesystem. Like S3 for an archived object, it
// evaluates the preconditions, the range and the part number before it
// returns InvalidObjectState, and it checks the requested version. Set
// SCOUTFS_TEST_DIR to a directory on a ScoutFS mount to run it.
func TestGetObjectGlacierOffline(t *testing.T) {
	dir := os.Getenv("SCOUTFS_TEST_DIR")
	if dir == "" {
		t.Skip("SCOUTFS_TEST_DIR is not set")
	}

	// New() chdirs into the gateway root; restore the original working
	// directory when the test completes.
	t.Chdir(t.TempDir())

	versioningDir := mkdirTempIn(t, dir, "gw-versions-")
	s, err := New(mkdirTempIn(t, dir, "gw-root-"), ScoutfsOpts{
		GlacierMode:         true,
		VersioningDir:       versioningDir,
		ValidateBucketNames: true,
	})
	if err != nil {
		t.Fatalf("init scoutfs backend: %v", err)
	}
	t.Cleanup(s.Shutdown)

	ctx := context.Background()
	bucket, key, body := "bucket", "archived", "hello world"
	err = s.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket:                    &bucket,
		CreateBucketConfiguration: &types.CreateBucketConfiguration{},
	}, []byte{})
	if err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	err = s.PutBucketVersioning(ctx, bucket, types.BucketVersioningStatusEnabled)
	if err != nil {
		t.Fatalf("put bucket versioning: %v", err)
	}

	put := func(key, body string) *string {
		t.Helper()
		res, err := s.PutObject(ctx, s3response.PutObjectInput{
			Bucket:        &bucket,
			Key:           &key,
			Body:          strings.NewReader(body),
			ContentLength: aws.Int64(int64(len(body))),
		})
		if err != nil {
			t.Fatalf("put object %q: %v", key, err)
		}
		return aws.String(res.VersionID)
	}
	head := func(key string, versionId *string) *s3.HeadObjectOutput {
		t.Helper()
		res, err := s.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:    &bucket,
			Key:       &key,
			VersionId: versionId,
		})
		if err != nil {
			t.Fatalf("head object %q: %v", key, err)
		}
		return res
	}

	put(key, body)
	releaseFile(t, s.ObjectPath(bucket, key))
	obj := head(key, nil)
	assert.Equal(t, types.StorageClassGlacier, obj.StorageClass)
	etag := strings.Trim(aws.ToString(obj.ETag), `"`)
	before := aws.ToTime(obj.LastModified).Add(-time.Hour)

	// the older version is offline, the latest one isn't. The new PUT
	// copies the older version's data, so release it after that.
	versionedKey, oldBody, newBody := "versioned", "version-one", "version-two!"
	oldVersion := put(versionedKey, oldBody)
	put(versionedKey, newBody)
	releaseFile(t, versionFilePath(t, versioningDir, *oldVersion))
	oldETag := strings.Trim(aws.ToString(head(versionedKey, oldVersion).ETag), `"`)

	errArchived := s3err.GetAPIError(s3err.ErrInvalidObjectState)
	tests := []struct {
		name     string
		input    s3.GetObjectInput
		want     error
		wantBody string
	}{
		{name: "no conditions", input: s3.GetObjectInput{Key: &key}, want: errArchived},
		{name: "if-none-match matches", input: s3.GetObjectInput{Key: &key, IfNoneMatch: &etag}, want: s3err.GetAPIError(s3err.ErrNotModified)},
		{name: "if-none-match differs", input: s3.GetObjectInput{Key: &key, IfNoneMatch: aws.String("other")}, want: errArchived},
		{name: "if-match differs", input: s3.GetObjectInput{Key: &key, IfMatch: aws.String("other")}, want: s3err.GetPreconditionFailedErr(s3err.ConditionIfMatch)},
		{name: "if-unmodified-since fails", input: s3.GetObjectInput{Key: &key, IfUnmodifiedSince: &before}, want: s3err.GetPreconditionFailedErr(s3err.ConditionIfUnmodifiedSince)},
		{name: "unsatisfiable range", input: s3.GetObjectInput{Key: &key, Range: aws.String("bytes=100-200")}, want: s3err.GetInvalidRangeErr("bytes=100-200", int64(len(body)))},
		{name: "part number out of range", input: s3.GetObjectInput{Key: &key, PartNumber: aws.Int32(2)}, want: s3err.GetInvalidPartNumberRangeErr(1, 2)},
		{name: "latest version online", input: s3.GetObjectInput{Key: &versionedKey}, wantBody: newBody},
		{name: "older version offline", input: s3.GetObjectInput{Key: &versionedKey, VersionId: oldVersion}, want: errArchived},
		{name: "older version if-none-match matches", input: s3.GetObjectInput{Key: &versionedKey, VersionId: oldVersion, IfNoneMatch: &oldETag}, want: s3err.GetAPIError(s3err.ErrNotModified)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := tt.input
			input.Bucket = &bucket
			if input.Range == nil {
				input.Range = aws.String("")
			}
			res, err := s.GetObject(ctx, &input)
			if tt.want != nil {
				assert.ErrorIs(t, err, tt.want)
				return
			}
			if !assert.NoError(t, err) {
				return
			}
			defer res.Body.Close()
			got, err := io.ReadAll(res.Body)
			assert.NoError(t, err)
			assert.Equal(t, tt.wantBody, string(got))
		})
	}
}

// mkdirTempIn creates a directory in dir that is removed when the test
// completes.
func mkdirTempIn(t *testing.T, dir, pattern string) string {
	t.Helper()
	d, err := os.MkdirTemp(dir, pattern)
	if err != nil {
		t.Fatalf("create directory in %v: %v", dir, err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// versionFilePath returns the path of the file in the versioning directory
// that holds the given object version, which is named by its version id.
func versionFilePath(t *testing.T, versioningDir, versionId string) string {
	t.Helper()
	var found string
	err := filepath.WalkDir(versioningDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() && d.Name() == versionId {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %v: %v", versioningDir, err)
	}
	if found == "" {
		t.Fatalf("no file for version %v in %v", versionId, versioningDir)
	}
	return found
}

// releaseFile frees the data extents of a file, leaving them offline the
// way an archiver does once the file has an archive copy.
func releaseFile(t *testing.T, path string) {
	t.Helper()
	st, err := scoutfs.StatMore(path)
	if err != nil {
		t.Fatalf("stat more %v: %v", path, err)
	}
	err = scoutfs.ReleaseFile(path, st.Data_version)
	if err != nil {
		t.Fatalf("release %v: %v", path, err)
	}
	st, err = scoutfs.StatMore(path)
	if err != nil {
		t.Fatalf("stat more %v: %v", path, err)
	}
	if st.Offline_blocks == 0 {
		t.Fatalf("expected offline blocks after releasing %v", path)
	}
}
