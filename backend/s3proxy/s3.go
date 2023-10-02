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

package s3proxy

import (
	"context"
	"fmt"
	"io"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3response"
)

type S3be struct {
	backend.BackendUnsupported

	endpoint        string
	awsRegion       string
	disableChecksum bool
	sslSkipVerify   bool
	debug           bool
}

func New(endpoint, region string, disableChecksum, sslSkipVerify, debug bool) *S3be {
	return &S3be{
		endpoint:        endpoint,
		awsRegion:       region,
		disableChecksum: disableChecksum,
		sslSkipVerify:   sslSkipVerify,
		debug:           debug,
	}
}

func (s *S3be) ListBuckets(ctx context.Context, owner string, isAdmin bool) (s3response.ListAllMyBucketsResult, error) {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return s3response.ListAllMyBucketsResult{}, err
	}

	output, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return s3response.ListAllMyBucketsResult{}, err
	}

	var buckets []s3response.ListAllMyBucketsEntry
	for _, b := range output.Buckets {
		buckets = append(buckets, s3response.ListAllMyBucketsEntry{
			Name:         *b.Name,
			CreationDate: *b.CreationDate,
		})
	}

	return s3response.ListAllMyBucketsResult{
		Owner: s3response.CanonicalUser{
			ID:          *output.Owner.ID,
			DisplayName: *output.Owner.DisplayName,
		},
		Buckets: s3response.ListAllMyBucketsList{
			Bucket: buckets,
		},
	}, nil
}

func (s *S3be) HeadBucket(ctx context.Context, input *s3.HeadBucketInput) (*s3.HeadBucketOutput, error) {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	return client.HeadBucket(ctx, input)
}

func (s *S3be) CreateBucket(ctx context.Context, input *s3.CreateBucketInput) error {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return err
	}

	_, err = client.CreateBucket(ctx, input)
	return err
}

func (s *S3be) DeleteBucket(ctx context.Context, input *s3.DeleteBucketInput) error {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return err
	}

	_, err = client.DeleteBucket(ctx, input)
	return err
}

func (s *S3be) CreateMultipartUpload(ctx context.Context, input *s3.CreateMultipartUploadInput) (*s3.CreateMultipartUploadOutput, error) {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	return client.CreateMultipartUpload(ctx, input)
}

func (s *S3be) CompleteMultipartUpload(ctx context.Context, input *s3.CompleteMultipartUploadInput) (*s3.CompleteMultipartUploadOutput, error) {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	return client.CompleteMultipartUpload(ctx, input)
}

func (s *S3be) AbortMultipartUpload(ctx context.Context, input *s3.AbortMultipartUploadInput) error {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return err
	}

	_, err = client.AbortMultipartUpload(ctx, input)
	return err
}

const (
	iso8601Format = "20060102T150405Z"
)

func (s *S3be) ListMultipartUploads(ctx context.Context, input *s3.ListMultipartUploadsInput) (s3response.ListMultipartUploadsResult, error) {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return s3response.ListMultipartUploadsResult{}, err
	}

	output, err := client.ListMultipartUploads(ctx, input)
	if err != nil {
		return s3response.ListMultipartUploadsResult{}, err
	}

	var uploads []s3response.Upload
	for _, u := range output.Uploads {
		uploads = append(uploads, s3response.Upload{
			Key:      *u.Key,
			UploadID: *u.UploadId,
			Initiator: s3response.Initiator{
				ID:          *u.Initiator.ID,
				DisplayName: *u.Initiator.DisplayName,
			},
			Owner: s3response.Owner{
				ID:          *u.Owner.ID,
				DisplayName: *u.Owner.DisplayName,
			},
			StorageClass: string(u.StorageClass),
			Initiated:    u.Initiated.Format(iso8601Format),
		})
	}

	var cps []s3response.CommonPrefix
	for _, c := range output.CommonPrefixes {
		cps = append(cps, s3response.CommonPrefix{
			Prefix: *c.Prefix,
		})
	}

	return s3response.ListMultipartUploadsResult{
		Bucket:             *output.Bucket,
		KeyMarker:          *output.KeyMarker,
		UploadIDMarker:     *output.UploadIdMarker,
		NextKeyMarker:      *output.NextKeyMarker,
		NextUploadIDMarker: *output.NextUploadIdMarker,
		Delimiter:          *output.Delimiter,
		Prefix:             *output.Prefix,
		EncodingType:       string(output.EncodingType),
		MaxUploads:         int(output.MaxUploads),
		IsTruncated:        output.IsTruncated,
		Uploads:            uploads,
		CommonPrefixes:     cps,
	}, nil
}

func (s *S3be) ListParts(ctx context.Context, input *s3.ListPartsInput) (s3response.ListPartsResult, error) {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return s3response.ListPartsResult{}, err
	}

	output, err := client.ListParts(ctx, input)
	if err != nil {
		return s3response.ListPartsResult{}, err
	}

	var parts []s3response.Part
	for _, p := range output.Parts {
		parts = append(parts, s3response.Part{
			PartNumber:   int(p.PartNumber),
			LastModified: p.LastModified.Format(iso8601Format),
			ETag:         *p.ETag,
			Size:         p.Size,
		})
	}
	pnm, err := strconv.Atoi(*output.PartNumberMarker)
	if err != nil {
		return s3response.ListPartsResult{},
			fmt.Errorf("parse part number marker: %w", err)
	}

	npmn, err := strconv.Atoi(*output.NextPartNumberMarker)
	if err != nil {
		return s3response.ListPartsResult{},
			fmt.Errorf("parse next part number marker: %w", err)
	}

	return s3response.ListPartsResult{
		Bucket:   *output.Bucket,
		Key:      *output.Key,
		UploadID: *output.UploadId,
		Initiator: s3response.Initiator{
			ID:          *output.Initiator.ID,
			DisplayName: *output.Initiator.DisplayName,
		},
		Owner: s3response.Owner{
			ID:          *output.Owner.ID,
			DisplayName: *output.Owner.DisplayName,
		},
		StorageClass:         string(output.StorageClass),
		PartNumberMarker:     pnm,
		NextPartNumberMarker: npmn,
		MaxParts:             int(output.MaxParts),
		IsTruncated:          output.IsTruncated,
		Parts:                parts,
	}, nil
}

func (s *S3be) UploadPart(ctx context.Context, input *s3.UploadPartInput) (etag string, err error) {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return "", err
	}

	output, err := client.UploadPart(ctx, input)
	if err != nil {
		return "", err
	}

	return *output.ETag, nil
}

func (s *S3be) UploadPartCopy(ctx context.Context, input *s3.UploadPartCopyInput) (s3response.CopyObjectResult, error) {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return s3response.CopyObjectResult{}, err
	}

	output, err := client.UploadPartCopy(ctx, input)
	if err != nil {
		return s3response.CopyObjectResult{}, err
	}

	return s3response.CopyObjectResult{
		LastModified: *output.CopyPartResult.LastModified,
		ETag:         *output.CopyPartResult.ETag,
	}, nil
}

func (s *S3be) PutObject(ctx context.Context, input *s3.PutObjectInput) (string, error) {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return "", err
	}

	output, err := client.PutObject(ctx, input)
	if err != nil {
		return "", err
	}

	return *output.ETag, nil
}

func (s *S3be) HeadObject(ctx context.Context, input *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	return client.HeadObject(ctx, input)
}

func (s *S3be) GetObject(ctx context.Context, input *s3.GetObjectInput, w io.Writer) (*s3.GetObjectOutput, error) {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	output, err := client.GetObject(ctx, input)
	if err != nil {
		return nil, err
	}
	defer output.Body.Close()

	_, err = io.Copy(w, output.Body)
	if err != nil {
		return nil, err
	}

	return output, nil
}

func (s *S3be) GetObjectAttributes(ctx context.Context, input *s3.GetObjectAttributesInput) (*s3.GetObjectAttributesOutput, error) {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	return client.GetObjectAttributes(ctx, input)
}

func (s *S3be) CopyObject(ctx context.Context, input *s3.CopyObjectInput) (*s3.CopyObjectOutput, error) {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	return client.CopyObject(ctx, input)
}

func (s *S3be) ListObjects(ctx context.Context, input *s3.ListObjectsInput) (*s3.ListObjectsOutput, error) {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	return client.ListObjects(ctx, input)
}

func (s *S3be) ListObjectsV2(ctx context.Context, input *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	return client.ListObjectsV2(ctx, input)
}

func (s *S3be) DeleteObject(ctx context.Context, input *s3.DeleteObjectInput) error {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return err
	}

	_, err = client.DeleteObject(ctx, input)
	return err
}

func (s *S3be) DeleteObjects(ctx context.Context, input *s3.DeleteObjectsInput) (s3response.DeleteObjectsResult, error) {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return s3response.DeleteObjectsResult{}, err
	}

	output, err := client.DeleteObjects(ctx, input)
	if err != nil {
		return s3response.DeleteObjectsResult{}, err
	}

	return s3response.DeleteObjectsResult{
		Deleted: output.Deleted,
		Error:   output.Errors,
	}, nil
}
