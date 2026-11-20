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
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// TestMultipartUploadSidecarCleanup checks that the sidecar metadata of a
// multipart upload, its parts and its key is removed with the upload.
func TestMultipartUploadSidecarCleanup(t *testing.T) {
	ctx := context.Background()
	bucket := "testbucket"

	t.Run("complete", func(t *testing.T) {
		p, sidecar := newSidecarTestPosix(t)
		createTestBucket(t, p, bucket)
		key := "a/complete.bin"

		uploadID, parts := uploadTestParts(t, p, s3response.CreateMultipartUploadInput{
			Bucket:      &bucket,
			Key:         &key,
			ContentType: aws.String("application/zip"),
			Tagging:     aws.String("key=value"),
		})
		_, _, err := p.CompleteMultipartUpload(ctx, completeTestUploadInput(bucket, key, uploadID, parts))
		assert.NoError(t, err)

		assert.Empty(t, multipartLeftovers(t, p.ObjectPath(bucket, "")))
		assert.Empty(t, multipartLeftovers(t, filepath.Join(sidecar, bucket)))

		// the object has the metadata of the upload
		out, err := p.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &key})
		assert.NoError(t, err)
		assert.Equal(t, "application/zip", aws.ToString(out.ContentType))
		tags, err := p.GetObjectTagging(ctx, bucket, key, "")
		assert.NoError(t, err)
		assert.Equal(t, map[string]string{"key": "value"}, tags)
	})

	t.Run("abort", func(t *testing.T) {
		p, sidecar := newSidecarTestPosix(t)
		createTestBucket(t, p, bucket)
		key := "a/abort.bin"

		uploadID, _ := uploadTestParts(t, p, s3response.CreateMultipartUploadInput{
			Bucket:      &bucket,
			Key:         &key,
			ContentType: aws.String("application/zip"),
		})
		err := p.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &key,
			UploadId: &uploadID,
		})
		assert.NoError(t, err)

		assert.Empty(t, multipartLeftovers(t, p.ObjectPath(bucket, "")))
		assert.Empty(t, multipartLeftovers(t, filepath.Join(sidecar, bucket)))
	})

	t.Run("other upload of the key remains", func(t *testing.T) {
		p, sidecar := newSidecarTestPosix(t)
		createTestBucket(t, p, bucket)
		key := "object"

		completed, parts := uploadTestParts(t, p, s3response.CreateMultipartUploadInput{Bucket: &bucket, Key: &key})
		remaining, _ := uploadTestParts(t, p, s3response.CreateMultipartUploadInput{Bucket: &bucket, Key: &key})

		_, _, err := p.CompleteMultipartUpload(ctx, completeTestUploadInput(bucket, key, completed, parts))
		assert.NoError(t, err)

		res, err := p.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:     &bucket,
			MaxUploads: aws.Int32(1000),
		})
		assert.NoError(t, err)
		if assert.Len(t, res.Uploads, 1) {
			assert.Equal(t, key, res.Uploads[0].Key)
			assert.Equal(t, remaining, res.Uploads[0].UploadID)
		}

		err = p.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &key,
			UploadId: &remaining,
		})
		assert.NoError(t, err)

		assert.Empty(t, multipartLeftovers(t, p.ObjectPath(bucket, "")))
		assert.Empty(t, multipartLeftovers(t, filepath.Join(sidecar, bucket)))
	})

	t.Run("failed complete keeps the upload", func(t *testing.T) {
		p, sidecar := newSidecarTestPosix(t)
		createTestBucket(t, p, bucket)
		key := "object"

		uploadID, parts := uploadTestParts(t, p, s3response.CreateMultipartUploadInput{Bucket: &bucket, Key: &key})

		wrong := []types.CompletedPart{parts[0], {ETag: parts[0].ETag, PartNumber: parts[1].PartNumber}}
		_, _, err := p.CompleteMultipartUpload(ctx, completeTestUploadInput(bucket, key, uploadID, wrong))
		assert.ErrorIs(t, err, s3err.GetInvalidPartErr(uploadID, *parts[1].PartNumber, *parts[0].ETag))

		res, err := p.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			Key:      &key,
			UploadId: &uploadID,
			MaxParts: aws.Int32(1000),
		})
		assert.NoError(t, err)
		if assert.Len(t, res.Parts, len(parts)) {
			for i, part := range res.Parts {
				assert.Equal(t, aws.ToString(parts[i].ETag), part.ETag)
			}
		}

		_, _, err = p.CompleteMultipartUpload(ctx, completeTestUploadInput(bucket, key, uploadID, parts))
		assert.NoError(t, err)

		assert.Empty(t, multipartLeftovers(t, p.ObjectPath(bucket, "")))
		assert.Empty(t, multipartLeftovers(t, filepath.Join(sidecar, bucket)))
	})

	t.Run("failed complete after the parts are consumed", func(t *testing.T) {
		p, sidecar := newSidecarTestPosix(t)
		createTestBucket(t, p, bucket)
		key := "object"

		uploadID, parts := uploadTestParts(t, p, s3response.CreateMultipartUploadInput{Bucket: &bucket, Key: &key})

		// a copy that can't be retried, followed by a failure to publish
		moveParts := func(from, to *os.File) (bool, error) {
			_, err := io.Copy(to, from)
			if err != nil {
				return true, err
			}
			return false, os.MkdirAll(p.ObjectPath(bucket, key), 0o755)
		}
		_, _, err := p.CompleteMultipartUploadWithCopy(ctx, completeTestUploadInput(bucket, key, uploadID, parts), moveParts)
		assert.ErrorIs(t, err, s3err.GetAPIError(s3err.ErrExistingObjectIsDirectory))

		assert.Empty(t, multipartLeftovers(t, p.ObjectPath(bucket, "")))
		assert.Empty(t, multipartLeftovers(t, filepath.Join(sidecar, bucket)))
	})

	t.Run("failed create", func(t *testing.T) {
		p, sidecar := newSidecarTestPosix(t)
		createTestBucket(t, p, bucket)
		key := "object"

		_, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
			Bucket:                    &bucket,
			Key:                       &key,
			ContentType:               aws.String("application/zip"),
			ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatusOn,
		})
		assert.ErrorIs(t, err, s3err.GetAPIError(s3err.ErrMissingObjectLockConfigurationNoSpaces))

		assert.Empty(t, multipartLeftovers(t, p.ObjectPath(bucket, "")))
		assert.Empty(t, multipartLeftovers(t, filepath.Join(sidecar, bucket)))
	})
}

// newSidecarTestPosix returns a posix backend with sidecar metadata and the
// sidecar directory.
func newSidecarTestPosix(t *testing.T) (*Posix, string) {
	t.Helper()
	dir := t.TempDir()
	sc, err := meta.NewSideCar(dir)
	if err != nil {
		t.Fatalf("new sidecar: %v", err)
	}
	p, err := New(t.TempDir(), sc, PosixOpts{NewDirPerm: 0755, SideCarDir: dir})
	if err != nil {
		t.Fatalf("new posix: %v", err)
	}
	return p, dir
}

// uploadTestParts creates a multipart upload with two parts and returns its
// upload ID and parts.
func uploadTestParts(t *testing.T, p *Posix, input s3response.CreateMultipartUploadInput) (string, []types.CompletedPart) {
	t.Helper()
	ctx := context.Background()
	mp, err := p.CreateMultipartUpload(ctx, input)
	if err != nil {
		t.Fatalf("create multipart upload: %v", err)
	}

	var parts []types.CompletedPart
	for i, size := range []int{backend.MinPartSize, 1} {
		body := bytes.Repeat([]byte{'a' + byte(i)}, size)
		part, err := p.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:        input.Bucket,
			Key:           input.Key,
			UploadId:      &mp.UploadId,
			PartNumber:    aws.Int32(int32(i + 1)),
			ContentLength: aws.Int64(int64(size)),
			Body:          bytes.NewReader(body),
		})
		if err != nil {
			t.Fatalf("upload part %d: %v", i+1, err)
		}
		parts = append(parts, types.CompletedPart{ETag: part.ETag, PartNumber: aws.Int32(int32(i + 1))})
	}
	return mp.UploadId, parts
}

func completeTestUploadInput(bucket, key, uploadID string, parts []types.CompletedPart) *s3.CompleteMultipartUploadInput {
	return &s3.CompleteMultipartUploadInput{
		Bucket:          &bucket,
		Key:             &key,
		UploadId:        &uploadID,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: parts},
	}
}

// multipartLeftovers returns the paths under the multipart directory of the
// bucket directory dir.
func multipartLeftovers(t *testing.T, dir string) []string {
	t.Helper()
	root := filepath.Join(dir, MetaTmpMultipartDir)
	var paths []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if path != root {
			rel, _ := filepath.Rel(root, path)
			paths = append(paths, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk multipart dir: %v", err)
	}
	return paths
}
