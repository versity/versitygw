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
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3response"
)

// TestGetObjectAttributesPartsCount checks that GetObjectAttributes reports
// the parts count of an object completed from a multipart upload, and no
// object parts for an object that wasn't.
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

			out, err := p.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
				Bucket: &bucket,
				Key:    &mpKey,
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
				Bucket: &bucket,
				Key:    &key,
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
