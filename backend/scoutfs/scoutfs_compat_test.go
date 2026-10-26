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
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
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
