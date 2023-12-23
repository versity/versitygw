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

package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/plugins"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// Backend is the exported plugin entry point.
var Backend plugins.BackendPlugin = &noopPlugin{}

type noopPlugin struct{}

func (p *noopPlugin) New(_ string) (backend.Backend, error) {
	return newNoOp()
}

var startupTime time.Time

func init() {
	startupTime = time.Now()
}

type noOp struct {
	backend.BackendUnsupported
	emptyETag string
}

func newNoOp() (*noOp, error) {
	sum := md5.Sum([]byte{})
	etag := hex.EncodeToString(sum[:])
	return &noOp{emptyETag: etag}, nil
}

func (n *noOp) ListBuckets(context.Context, s3response.ListBucketsInput) (s3response.ListAllMyBucketsResult, error) {
	return s3response.ListAllMyBucketsResult{
		Owner: s3response.CanonicalUser{
			ID: "fakeid",
		},
		Buckets: s3response.ListAllMyBucketsList{
			Bucket: []s3response.ListAllMyBucketsEntry{{
				Name:         "test",
				CreationDate: startupTime,
			}},
		},
	}, nil
}

func (n *noOp) HeadBucket(ctx context.Context, input *s3.HeadBucketInput) (*s3.HeadBucketOutput, error) {
	return &s3.HeadBucketOutput{}, nil
}

var fakeUploadID = "abcdefghijklmnopqrstuvwxyz"

func (n *noOp) CreateMultipartUpload(_ context.Context, input s3response.CreateMultipartUploadInput) (s3response.InitiateMultipartUploadResult, error) {
	return s3response.InitiateMultipartUploadResult{
		Bucket:   *input.Bucket,
		Key:      *input.Key,
		UploadId: fakeUploadID,
	}, nil
}

func (n *noOp) CompleteMultipartUpload(ctx context.Context, input *s3.CompleteMultipartUploadInput) (s3response.CompleteMultipartUploadResult, string, error) {
	return s3response.CompleteMultipartUploadResult{
		Bucket: input.Bucket,
		ETag:   &n.emptyETag,
		Key:    input.Key,
	}, "", nil
}

func (n *noOp) AbortMultipartUpload(ctx context.Context, input *s3.AbortMultipartUploadInput) error {
	return nil
}

func (n *noOp) ListMultipartUploads(ctx context.Context, input *s3.ListMultipartUploadsInput) (s3response.ListMultipartUploadsResult, error) {
	return s3response.ListMultipartUploadsResult{
		Bucket:         *input.Bucket,
		Delimiter:      *input.Delimiter,
		Prefix:         *input.Prefix,
		MaxUploads:     int(*input.MaxUploads),
		Uploads:        []s3response.Upload{},
		CommonPrefixes: []s3response.CommonPrefix{},
	}, nil
}

func (n *noOp) ListParts(ctx context.Context, input *s3.ListPartsInput) (s3response.ListPartsResult, error) {
	return s3response.ListPartsResult{
		Bucket:    *input.Bucket,
		Key:       *input.Key,
		UploadID:  *input.UploadId,
		Initiator: s3response.Initiator{},
		Owner:     s3response.Owner{},
		MaxParts:  int(*input.MaxParts),
		Parts:     []s3response.Part{},
	}, nil
}

func (n *noOp) UploadPart(_ context.Context, input *s3.UploadPartInput) (*s3.UploadPartOutput, error) {
	if _, err := io.Copy(io.Discard, input.Body); err != nil {
		return nil, err
	}
	return &s3.UploadPartOutput{ETag: &n.emptyETag}, nil
}

func (n *noOp) UploadPartCopy(context.Context, *s3.UploadPartCopyInput) (s3response.CopyPartResult, error) {
	return s3response.CopyPartResult{
		ETag: &n.emptyETag,
	}, nil
}

func (n *noOp) PutObject(_ context.Context, input s3response.PutObjectInput) (s3response.PutObjectOutput, error) {
	if _, err := io.Copy(io.Discard, input.Body); err != nil {
		return s3response.PutObjectOutput{}, err
	}
	return s3response.PutObjectOutput{ETag: n.emptyETag}, nil
}

func (n *noOp) HeadObject(ctx context.Context, input *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
	return &s3.HeadObjectOutput{
		ETag:         &n.emptyETag,
		LastModified: backend.GetTimePtr(startupTime),
		Metadata:     map[string]string{},
	}, nil
}

func (n *noOp) GetObject(context.Context, *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	return &s3.GetObjectOutput{
		ETag:         &n.emptyETag,
		LastModified: backend.GetTimePtr(startupTime),
		Metadata:     map[string]string{},
	}, nil
}

func (n *noOp) GetObjectAttributes(context.Context, *s3.GetObjectAttributesInput) (s3response.GetObjectAttributesResponse, error) {
	return s3response.GetObjectAttributesResponse{
		ETag:         &n.emptyETag,
		LastModified: backend.GetTimePtr(startupTime),
		ObjectSize:   new(int64),
	}, nil
}

func (n *noOp) CopyObject(context.Context, s3response.CopyObjectInput) (s3response.CopyObjectOutput, error) {
	return s3response.CopyObjectOutput{
		CopyObjectResult: &s3response.CopyObjectResult{
			ETag: &n.emptyETag,
		},
	}, nil
}

func (n *noOp) ListObjects(_ context.Context, input *s3.ListObjectsInput) (s3response.ListObjectsResult, error) {
	return s3response.ListObjectsResult{
		CommonPrefixes: []types.CommonPrefix{},
		Contents:       []s3response.Object{},
		Delimiter:      input.Delimiter,
		IsTruncated:    new(bool),
		Marker:         new(string),
		MaxKeys:        input.MaxKeys,
		Name:           input.Bucket,
		NextMarker:     new(string),
		Prefix:         input.Prefix,
	}, nil
}

func (n *noOp) ListObjectsV2(_ context.Context, input *s3.ListObjectsV2Input) (s3response.ListObjectsV2Result, error) {
	return s3response.ListObjectsV2Result{
		CommonPrefixes:        []types.CommonPrefix{},
		Contents:              []s3response.Object{},
		Delimiter:             input.Delimiter,
		IsTruncated:           new(bool),
		ContinuationToken:     new(string),
		MaxKeys:               input.MaxKeys,
		Name:                  input.Bucket,
		NextContinuationToken: new(string),
		Prefix:                input.Prefix,
	}, nil
}

func (n *noOp) DeleteObject(context.Context, *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error) {
	return &s3.DeleteObjectOutput{}, nil
}

func (n *noOp) DeleteObjects(ctx context.Context, input *s3.DeleteObjectsInput) (s3response.DeleteResult, error) {
	return s3response.DeleteResult{}, nil
}

func (n *noOp) GetBucketAcl(ctx context.Context, input *s3.GetBucketAclInput) ([]byte, error) {
	return []byte{}, nil
}

func (n *noOp) PutBucketAcl(ctx context.Context, bucket string, data []byte) error {
	return nil
}

func (n *noOp) GetBucketPolicy(_ context.Context, bucket string) ([]byte, error) {
	return []byte{}, nil
}

func (n *noOp) GetObjectLockConfiguration(_ context.Context, bucket string) ([]byte, error) {
	return nil, s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound)
}

func (n *noOp) PutObjectTagging(context.Context, string, string, string, map[string]string) error {
	return nil
}

func (n *noOp) GetObjectTagging(context.Context, string, string, string) (map[string]string, error) {
	tags := make(map[string]string)
	return tags, nil
}

func (n *noOp) DeleteObjectTagging(context.Context, string, string, string) error {
	return nil
}
