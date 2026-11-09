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
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// TestGetObjectAttributesPartsCount checks that GetObjectAttributes reports
// the parts count of an object completed from a multipart upload when
// ObjectParts is requested, and no object parts for an object that wasn't.
func TestGetObjectAttributesPartsCount(t *testing.T) {
	for name, mkMeta := range metaModes(t) {
		t.Run(name, func(t *testing.T) {
			p := newTestPosix(t, mkMeta)
			bucket := "testbucket"
			createTestBucket(t, p, bucket)
			ctx := context.Background()

			mpKey := "mp-obj"
			mp, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
				Bucket: &bucket,
				Key:    &mpKey,
			})
			if err != nil {
				t.Fatalf("create multipart upload: %v", err)
			}

			partSizes := []int64{backend.MinPartSize, 10}
			var parts []types.CompletedPart
			var totalSize int64
			for i, size := range partSizes {
				partNumber := int32(i + 1)
				part, err := p.UploadPart(ctx, &s3.UploadPartInput{
					Bucket:        &bucket,
					Key:           &mpKey,
					UploadId:      &mp.UploadId,
					PartNumber:    &partNumber,
					ContentLength: &size,
					Body:          bytes.NewReader(make([]byte, size)),
				})
				if err != nil {
					t.Fatalf("upload part %d: %v", partNumber, err)
				}
				parts = append(parts, types.CompletedPart{
					ETag:       part.ETag,
					PartNumber: &partNumber,
				})
				totalSize += size
			}

			_, _, err = p.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
				Bucket:          &bucket,
				Key:             &mpKey,
				UploadId:        &mp.UploadId,
				MultipartUpload: &types.CompletedMultipartUpload{Parts: parts},
			})
			if err != nil {
				t.Fatalf("complete multipart upload: %v", err)
			}

			partsAttr := []types.ObjectAttributes{types.ObjectAttributesObjectParts}
			out, err := p.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
				Bucket:           &bucket,
				Key:              &mpKey,
				ObjectAttributes: partsAttr,
			})
			if err != nil {
				t.Fatalf("get multipart object attributes: %v", err)
			}
			if out.ObjectParts == nil || out.ObjectParts.PartsCount == nil {
				t.Fatalf("expected the parts count, got object parts %+v", out.ObjectParts)
			}
			if got := *out.ObjectParts.PartsCount; got != int32(len(partSizes)) {
				t.Errorf("expected parts count %d, got %d", len(partSizes), got)
			}
			if got := aws.ToInt64(out.ObjectSize); got != totalSize {
				t.Errorf("expected object size %d, got %d", totalSize, got)
			}

			// the parts count is only looked up when ObjectParts is requested
			out, err = p.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
				Bucket:           &bucket,
				Key:              &mpKey,
				ObjectAttributes: []types.ObjectAttributes{types.ObjectAttributesObjectSize},
			})
			if err != nil {
				t.Fatalf("get multipart object size: %v", err)
			}
			if out.ObjectParts != nil {
				t.Errorf("expected no object parts when not requested, got %+v", *out.ObjectParts)
			}

			key := "obj"
			_, err = p.PutObject(ctx, s3response.PutObjectInput{
				Bucket:        &bucket,
				Key:           &key,
				Body:          bytes.NewReader([]byte("data")),
				ContentLength: aws.Int64(4),
			})
			if err != nil {
				t.Fatalf("put object: %v", err)
			}

			out, err = p.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
				Bucket:           &bucket,
				Key:              &key,
				ObjectAttributes: partsAttr,
			})
			if err != nil {
				t.Fatalf("get object attributes: %v", err)
			}
			if out.ObjectParts != nil {
				t.Errorf("expected no object parts, got %+v", *out.ObjectParts)
			}
			if got := aws.ToInt64(out.ObjectSize); got != 4 {
				t.Errorf("expected object size 4, got %d", got)
			}
		})
	}
}

// removeAfterReadMeta runs remove, once it is set, after the next read of
// attribute of object, so that the object is removed between that read and
// what the caller does next.
type removeAfterReadMeta struct {
	meta.XattrMeta
	object    string
	attribute string
	remove    *func()
}

func (m removeAfterReadMeta) RetrieveAttribute(f *os.File, bucket, object, attribute string) ([]byte, error) {
	b, err := m.XattrMeta.RetrieveAttribute(f, bucket, object, attribute)
	if object == m.object && attribute == m.attribute && *m.remove != nil {
		remove := *m.remove
		*m.remove = nil
		remove()
	}
	return b, err
}

// TestGetObjectRemovedBeforeOpen checks that GetObject answers NoSuchKey
// when the object is deleted after its stat of the object and before its
// open of it, also when the delete removes the object's directory and an
// upload puts an object in its place, which fails the open with ENOTDIR.
// It answers NoSuchVersion only when the request names a version, not when
// it looked up the version of the live object.
func TestGetObjectRemovedBeforeOpen(t *testing.T) {
	for _, tc := range []struct {
		name           string
		replaceDir     bool
		requestVersion bool
		dirObject      bool
	}{
		{"object removed", false, false, false},
		{"directory replaced by object", true, false, false},
		{"requested version removed", false, true, false},
		{"requested version directory replaced by object", true, true, false},
		{"directory object removed", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// remove the object after the delete marker check, the last read
			// GetObject does before its open (the attributes are read after it)
			attribute := deleteMarkerKey
			key := "dir/obj"
			if tc.dirObject {
				key = "dir/"
			}
			var remove func()
			p := newTestPosix(t, func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
				opts := PosixOpts{NewDirPerm: 0755, VersioningDir: t.TempDir()}
				return removeAfterReadMeta{object: key, attribute: attribute, remove: &remove}, opts
			})
			bucket := "testbucket"
			createTestBucket(t, p, bucket)

			ctx := context.Background()
			err := p.PutBucketVersioning(ctx, bucket, types.BucketVersioningStatusEnabled)
			if err != nil {
				t.Fatalf("put bucket versioning: %v", err)
			}
			content := "data"
			if tc.dirObject {
				content = ""
			}
			put, err := p.PutObject(ctx, s3response.PutObjectInput{
				Bucket:        &bucket,
				Key:           aws.String(key),
				Body:          strings.NewReader(content),
				ContentLength: aws.Int64(int64(len(content))),
			})
			if err != nil {
				t.Fatalf("put object: %v", err)
			}

			remove = func() {
				if err := os.Remove(p.ObjectPath(bucket, key)); err != nil {
					t.Errorf("remove object: %v", err)
				}
				if !tc.replaceDir || tc.dirObject {
					return
				}
				if err := os.Remove(p.ObjectPath(bucket, "dir")); err != nil {
					t.Errorf("remove object directory: %v", err)
				}
				if err := os.WriteFile(p.ObjectPath(bucket, "dir"), []byte("data"), 0644); err != nil {
					t.Errorf("put object in place of the directory: %v", err)
				}
			}

			input := &s3.GetObjectInput{
				Bucket: &bucket,
				Key:    aws.String(key),
			}
			want := s3err.GetAPIError(s3err.ErrNoSuchKey)
			if tc.requestVersion {
				input.VersionId = &put.VersionID
				want = s3err.GetAPIError(s3err.ErrNoSuchVersion)
			}
			out, err := p.GetObject(ctx, input)
			if err == nil {
				out.Body.Close()
			}
			if remove != nil {
				t.Fatalf("get object did not read the object %v", attribute)
			}
			if !errors.Is(err, want) {
				t.Fatalf("get object: expected %v, got %v", want.Code, err)
			}
		})
	}
}
