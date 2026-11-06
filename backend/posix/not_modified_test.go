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
	"strings"
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

// TestNotModifiedOutput checks that GetObject and HeadObject return, with the
// NotModified error, the object's metadata that a 304 repeats from the 200:
// the ETag, dates, user metadata, tag count and version, but no content.
func TestNotModifiedOutput(t *testing.T) {
	for name, mkMeta := range metaModes(t) {
		t.Run(name, func(t *testing.T) {
			p := newTestPosix(t, func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
				storer, opts := mkMeta(t)
				opts.VersioningDir = t.TempDir()
				return storer, opts
			})
			bucket, key, body := "testbucket", "obj", "data"
			createTestBucket(t, p, bucket)
			ctx := context.Background()
			err := p.PutBucketVersioning(ctx, bucket, types.BucketVersioningStatusEnabled)
			if err != nil {
				t.Fatalf("put bucket versioning: %v", err)
			}

			put, err := p.PutObject(ctx, s3response.PutObjectInput{
				Bucket:                  &bucket,
				Key:                     &key,
				Body:                    strings.NewReader(body),
				ContentLength:           aws.Int64(int64(len(body))),
				ContentType:             aws.String("text/plain"),
				CacheControl:            aws.String("max-age=60"),
				Expires:                 aws.String("Thu, 01 Jan 2099 00:00:00 GMT"),
				WebsiteRedirectLocation: aws.String("/redirect"),
				Tagging:                 aws.String("k=v"),
				Metadata:                map[string]string{"foo": "bar"},
			})
			if err != nil {
				t.Fatalf("put object: %v", err)
			}
			// the controller passes If-None-Match without its quotes
			ifNoneMatch := strings.Trim(put.ETag, `"`)

			check := func(t *testing.T, etag, cacheControl, expires, redirect *string,
				metadata map[string]string, tagCount *int32, versionId *string) {
				t.Helper()
				assert.Equal(t, put.ETag, aws.ToString(etag))
				assert.Equal(t, "max-age=60", aws.ToString(cacheControl))
				assert.Equal(t, "Thu, 01 Jan 2099 00:00:00 GMT", aws.ToString(expires))
				assert.Equal(t, "/redirect", aws.ToString(redirect))
				assert.Equal(t, map[string]string{"foo": "bar"}, metadata)
				assert.Equal(t, int32(1), aws.ToInt32(tagCount))
				assert.Equal(t, put.VersionID, aws.ToString(versionId))
			}

			for _, versionId := range []*string{nil, &put.VersionID} {
				get, err := p.GetObject(ctx, &s3.GetObjectInput{
					Bucket:      &bucket,
					Key:         &key,
					VersionId:   versionId,
					IfNoneMatch: &ifNoneMatch,
					Range:       aws.String(""),
				})
				assert.ErrorIs(t, err, s3err.GetAPIError(s3err.ErrNotModified))
				if assert.NotNil(t, get) {
					check(t, get.ETag, get.CacheControl, get.ExpiresString, get.WebsiteRedirectLocation,
						get.Metadata, get.TagCount, get.VersionId)
					assert.NotNil(t, get.LastModified)
					assert.Nil(t, get.Body)
					assert.Nil(t, get.ContentType)
				}

				head, err := p.HeadObject(ctx, &s3.HeadObjectInput{
					Bucket:      &bucket,
					Key:         &key,
					VersionId:   versionId,
					IfNoneMatch: &ifNoneMatch,
				})
				assert.ErrorIs(t, err, s3err.GetAPIError(s3err.ErrNotModified))
				if assert.NotNil(t, head) {
					check(t, head.ETag, head.CacheControl, head.ExpiresString, head.WebsiteRedirectLocation,
						head.Metadata, head.TagCount, head.VersionId)
					assert.NotNil(t, head.LastModified)
					assert.Nil(t, head.ContentType)
				}
			}
		})
	}
}

// TestNotModifiedPartsCount checks that a 304 to a request with partNumber
// reports the parts count of a multipart object, as its 200 does.
func TestNotModifiedPartsCount(t *testing.T) {
	for name, mkMeta := range metaModes(t) {
		t.Run(name, func(t *testing.T) {
			p := newTestPosix(t, mkMeta)
			bucket, key := "testbucket", "mp-obj"
			createTestBucket(t, p, bucket)
			ctx := context.Background()

			mp, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
				Bucket: &bucket,
				Key:    &key,
			})
			if err != nil {
				t.Fatalf("create multipart upload: %v", err)
			}
			var parts []types.CompletedPart
			for i, size := range []int64{backend.MinPartSize, 10} {
				partNumber := int32(i + 1)
				part, err := p.UploadPart(ctx, &s3.UploadPartInput{
					Bucket:        &bucket,
					Key:           &key,
					UploadId:      &mp.UploadId,
					PartNumber:    &partNumber,
					ContentLength: &size,
					Body:          bytes.NewReader(make([]byte, size)),
				})
				if err != nil {
					t.Fatalf("upload part %d: %v", partNumber, err)
				}
				parts = append(parts, types.CompletedPart{ETag: part.ETag, PartNumber: &partNumber})
			}
			out, _, err := p.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
				Bucket:          &bucket,
				Key:             &key,
				UploadId:        &mp.UploadId,
				MultipartUpload: &types.CompletedMultipartUpload{Parts: parts},
			})
			if err != nil {
				t.Fatalf("complete multipart upload: %v", err)
			}
			// the controller passes If-None-Match without its quotes
			etag := strings.Trim(aws.ToString(out.ETag), `"`)

			get, err := p.GetObject(ctx, &s3.GetObjectInput{
				Bucket:      &bucket,
				Key:         &key,
				PartNumber:  aws.Int32(1),
				IfNoneMatch: &etag,
			})
			assert.ErrorIs(t, err, s3err.GetAPIError(s3err.ErrNotModified))
			if assert.NotNil(t, get) {
				assert.Equal(t, int32(2), aws.ToInt32(get.PartsCount))
			}

			head, err := p.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket:      &bucket,
				Key:         &key,
				PartNumber:  aws.Int32(1),
				IfNoneMatch: &etag,
			})
			assert.ErrorIs(t, err, s3err.GetAPIError(s3err.ErrNotModified))
			if assert.NotNil(t, head) {
				assert.Equal(t, int32(2), aws.ToInt32(head.PartsCount))
			}
		})
	}
}
