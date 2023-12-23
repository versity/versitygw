// Copyright 2023 Versity Software
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

package noop

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3response"
)

type NoOp struct {
	backend.BackendUnsupported
	emptyETag string
}

func New() (*NoOp, error) {
	sum := md5.Sum([]byte{})
	etag := hex.EncodeToString(sum[:])

	return &NoOp{emptyETag: etag}, nil
}

func (n *NoOp) ListBuckets(ctx context.Context, owner string, isAdmin bool) (s3response.ListAllMyBucketsResult, error) {
	return s3response.ListAllMyBucketsResult{
		Owner: s3response.CanonicalUser{
			ID: "fakeid",
		},
		Buckets: s3response.ListAllMyBucketsList{
			Bucket: []s3response.ListAllMyBucketsEntry{},
		},
	}, nil
}

func (n *NoOp) HeadBucket(ctx context.Context, input *s3.HeadBucketInput) (*s3.HeadBucketOutput, error) {
	return &s3.HeadBucketOutput{}, nil
}

var (
	fakeUploadID = "abcdefghijklmnopqrstuvwxyz"
)

func (n *NoOp) CreateMultipartUpload(ctx context.Context, input *s3.CreateMultipartUploadInput) (*s3.CreateMultipartUploadOutput, error) {
	return &s3.CreateMultipartUploadOutput{
		Bucket:   input.Bucket,
		Key:      input.Key,
		UploadId: &fakeUploadID,
	}, nil
}

var (
	fakeETag = ""
)

func (n *NoOp) CompleteMultipartUpload(ctx context.Context, input *s3.CompleteMultipartUploadInput) (*s3.CompleteMultipartUploadOutput, error) {
	return &s3.CompleteMultipartUploadOutput{
		Bucket: input.Bucket,
		ETag:   &n.emptyETag,
		Key:    input.Key,
	}, nil
}

func (n *NoOp) AbortMultipartUpload(ctx context.Context, input *s3.AbortMultipartUploadInput) error {
	return nil
}

func (n *NoOp) ListMultipartUploads(ctx context.Context, input *s3.ListMultipartUploadsInput) (s3response.ListMultipartUploadsResult, error) {
	return s3response.ListMultipartUploadsResult{
		Bucket:         *input.Bucket,
		Delimiter:      *input.Delimiter,
		Prefix:         *input.Prefix,
		MaxUploads:     int(*input.MaxUploads),
		Uploads:        []s3response.Upload{},
		CommonPrefixes: []s3response.CommonPrefix{},
	}, nil
}

func (n *NoOp) ListParts(ctx context.Context, input *s3.ListPartsInput) (s3response.ListPartsResult, error) {
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

func (n *NoOp) UploadPart(ctx context.Context, input *s3.UploadPartInput) (etag string, err error) {
	b := make([]byte, 1048576)
	for {
		_, err := input.Body.Read(b)
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}
	return n.emptyETag, nil
}

func (n *NoOp) UploadPartCopy(ctx context.Context, input *s3.UploadPartCopyInput) (s3response.CopyObjectResult, error) {
	return s3response.CopyObjectResult{
		ETag: n.emptyETag,
	}, nil
}

func (n *NoOp) PutObject(ctx context.Context, input *s3.PutObjectInput) (string, error) {
	b := make([]byte, 1048576)
	for {
		_, err := input.Body.Read(b)
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}
	return n.emptyETag, nil
}

func (n *NoOp) HeadObject(ctx context.Context, input *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
	return &s3.HeadObjectOutput{
		ETag:         &n.emptyETag,
		LastModified: backend.GetTimePtr(time.Now()),
		Metadata:     map[string]string{},
	}, nil
}

func (n *NoOp) GetObject(ctx context.Context, input *s3.GetObjectInput, w io.Writer) (*s3.GetObjectOutput, error) {
	return &s3.GetObjectOutput{
		ETag:         &n.emptyETag,
		LastModified: backend.GetTimePtr(time.Now()),
		Metadata:     map[string]string{},
	}, nil
}

func (n *NoOp) GetObjectAttributes(ctx context.Context, input *s3.GetObjectAttributesInput) (*s3.GetObjectAttributesOutput, error) {
	return &s3.GetObjectAttributesOutput{
		ETag:         &n.emptyETag,
		LastModified: backend.GetTimePtr(time.Now()),
		ObjectSize:   new(int64),
	}, nil
}

func (n *NoOp) CopyObject(ctx context.Context, input *s3.CopyObjectInput) (*s3.CopyObjectOutput, error) {
	return &s3.CopyObjectOutput{
		CopyObjectResult: &types.CopyObjectResult{
			ETag: &n.emptyETag,
		},
	}, nil
}

func (n *NoOp) ListObjects(ctx context.Context, input *s3.ListObjectsInput) (*s3.ListObjectsOutput, error) {
	return &s3.ListObjectsOutput{
		CommonPrefixes: []types.CommonPrefix{},
		Contents:       []types.Object{},
		Delimiter:      input.Delimiter,
		IsTruncated:    new(bool),
		Marker:         new(string),
		MaxKeys:        input.MaxKeys,
		Name:           input.Bucket,
		NextMarker:     new(string),
		Prefix:         input.Prefix,
	}, nil
}

func (n *NoOp) ListObjectsV2(ctx context.Context, input *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
	return &s3.ListObjectsV2Output{
		CommonPrefixes:        []types.CommonPrefix{},
		Contents:              []types.Object{},
		Delimiter:             input.Delimiter,
		IsTruncated:           new(bool),
		ContinuationToken:     new(string),
		MaxKeys:               input.MaxKeys,
		Name:                  input.Bucket,
		NextContinuationToken: new(string),
		Prefix:                input.Prefix,
	}, nil
}

func (n *NoOp) DeleteObject(ctx context.Context, input *s3.DeleteObjectInput) error {
	return nil
}

func (n *NoOp) DeleteObjects(ctx context.Context, input *s3.DeleteObjectsInput) (s3response.DeleteObjectsResult, error) {
	return s3response.DeleteObjectsResult{
		Deleted: []types.DeletedObject{},
		Error:   []types.Error{},
	}, nil
}

func (n *NoOp) GetBucketAcl(ctx context.Context, input *s3.GetBucketAclInput) ([]byte, error) {
	return []byte{}, nil
}

func (n *NoOp) PutBucketAcl(ctx context.Context, bucket string, data []byte) error {
	return nil
}

func (n *NoOp) PutObjectTagging(ctx context.Context, bucket, object string, tags map[string]string) error {
	return nil
}

func (n *NoOp) GetObjectTagging(ctx context.Context, bucket, object string) (map[string]string, error) {
	tags := make(map[string]string)
	return tags, nil
}

func (n *NoOp) DeleteObjectTagging(ctx context.Context, bucket, object string) error {
	return nil
}
