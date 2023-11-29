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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
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
	err = handleError(err)
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

	out, err := client.HeadBucket(ctx, input)
	err = handleError(err)

	return out, err
}

func (s *S3be) CreateBucket(ctx context.Context, input *s3.CreateBucketInput) error {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return err
	}

	_, err = client.CreateBucket(ctx, input)
	return handleError(err)
}

func (s *S3be) DeleteBucket(ctx context.Context, input *s3.DeleteBucketInput) error {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return err
	}

	_, err = client.DeleteBucket(ctx, input)
	return handleError(err)
}

func (s *S3be) CreateMultipartUpload(ctx context.Context, input *s3.CreateMultipartUploadInput) (*s3.CreateMultipartUploadOutput, error) {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	out, err := client.CreateMultipartUpload(ctx, input)
	err = handleError(err)
	return out, err
}

func (s *S3be) CompleteMultipartUpload(ctx context.Context, input *s3.CompleteMultipartUploadInput) (*s3.CompleteMultipartUploadOutput, error) {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	out, err := client.CompleteMultipartUpload(ctx, input)
	err = handleError(err)
	return out, err
}

func (s *S3be) AbortMultipartUpload(ctx context.Context, input *s3.AbortMultipartUploadInput) error {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return err
	}

	_, err = client.AbortMultipartUpload(ctx, input)
	err = handleError(err)
	return err
}

func (s *S3be) ListMultipartUploads(ctx context.Context, input *s3.ListMultipartUploadsInput) (s3response.ListMultipartUploadsResult, error) {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return s3response.ListMultipartUploadsResult{}, err
	}

	output, err := client.ListMultipartUploads(ctx, input)
	err = handleError(err)
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
			Initiated:    u.Initiated.Format(backend.RFC3339TimeFormat),
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
		MaxUploads:         int(*output.MaxUploads),
		IsTruncated:        *output.IsTruncated,
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
	err = handleError(err)
	if err != nil {
		return s3response.ListPartsResult{}, err
	}

	var parts []s3response.Part
	for _, p := range output.Parts {
		parts = append(parts, s3response.Part{
			PartNumber:   int(*p.PartNumber),
			LastModified: p.LastModified.Format(backend.RFC3339TimeFormat),
			ETag:         *p.ETag,
			Size:         *p.Size,
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
		MaxParts:             int(*output.MaxParts),
		IsTruncated:          *output.IsTruncated,
		Parts:                parts,
	}, nil
}

func (s *S3be) UploadPart(ctx context.Context, input *s3.UploadPartInput) (etag string, err error) {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return "", err
	}

	output, err := client.UploadPart(ctx, input)
	err = handleError(err)
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
	err = handleError(err)
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
	err = handleError(err)
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

	out, err := client.HeadObject(ctx, input)
	err = handleError(err)

	return out, err
}

func (s *S3be) GetObject(ctx context.Context, input *s3.GetObjectInput, w io.Writer) (*s3.GetObjectOutput, error) {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	output, err := client.GetObject(ctx, input)
	err = handleError(err)
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

	out, err := client.GetObjectAttributes(ctx, input)
	err = handleError(err)

	return out, err
}

func (s *S3be) CopyObject(ctx context.Context, input *s3.CopyObjectInput) (*s3.CopyObjectOutput, error) {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	out, err := client.CopyObject(ctx, input)
	err = handleError(err)

	return out, err
}

func (s *S3be) ListObjects(ctx context.Context, input *s3.ListObjectsInput) (*s3.ListObjectsOutput, error) {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	out, err := client.ListObjects(ctx, input)
	err = handleError(err)

	return out, err
}

func (s *S3be) ListObjectsV2(ctx context.Context, input *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	out, err := client.ListObjectsV2(ctx, input)
	err = handleError(err)

	return out, err
}

func (s *S3be) DeleteObject(ctx context.Context, input *s3.DeleteObjectInput) error {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return err
	}

	_, err = client.DeleteObject(ctx, input)
	return handleError(err)
}

func (s *S3be) DeleteObjects(ctx context.Context, input *s3.DeleteObjectsInput) (s3response.DeleteObjectsResult, error) {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return s3response.DeleteObjectsResult{}, err
	}

	output, err := client.DeleteObjects(ctx, input)
	err = handleError(err)
	if err != nil {
		return s3response.DeleteObjectsResult{}, err
	}

	return s3response.DeleteObjectsResult{
		Deleted: output.Deleted,
		Error:   output.Errors,
	}, nil
}

func (s *S3be) GetBucketAcl(ctx context.Context, input *s3.GetBucketAclInput) ([]byte, error) {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	output, err := client.GetBucketAcl(ctx, input)
	err = handleError(err)
	if err != nil {
		return nil, err
	}

	var acl auth.ACL

	acl.Owner = *output.Owner.ID
	for _, el := range output.Grants {
		acl.Grantees = append(acl.Grantees, auth.Grantee{
			Permission: el.Permission,
			Access:     *el.Grantee.ID,
		})
	}

	return json.Marshal(acl)
}

func (s S3be) PutBucketAcl(ctx context.Context, bucket string, data []byte) error {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return err
	}

	acl, err := auth.ParseACL(data)
	if err != nil {
		return err
	}

	input := &s3.PutBucketAclInput{
		Bucket: &bucket,
		ACL:    acl.ACL,
		AccessControlPolicy: &types.AccessControlPolicy{
			Owner: &types.Owner{
				ID: &acl.Owner,
			},
		},
	}

	for _, el := range acl.Grantees {
		input.AccessControlPolicy.Grants = append(input.AccessControlPolicy.Grants, types.Grant{
			Permission: el.Permission,
			Grantee: &types.Grantee{
				ID:   &el.Access,
				Type: types.TypeCanonicalUser,
			},
		})
	}

	_, err = client.PutBucketAcl(ctx, input)
	return handleError(err)
}

func (s *S3be) PutObjectTagging(ctx context.Context, bucket, object string, tags map[string]string) error {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return err
	}

	tagging := &types.Tagging{
		TagSet: []types.Tag{},
	}
	for key, val := range tags {
		tagging.TagSet = append(tagging.TagSet, types.Tag{
			Key:   &key,
			Value: &val,
		})
	}

	_, err = client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
		Bucket:  &bucket,
		Key:     &object,
		Tagging: tagging,
	})
	return handleError(err)
}

func (s *S3be) GetObjectTagging(ctx context.Context, bucket, object string) (map[string]string, error) {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	output, err := client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
		Bucket: &bucket,
		Key:    &object,
	})
	err = handleError(err)
	if err != nil {
		return nil, err
	}

	tags := make(map[string]string)
	for _, el := range output.TagSet {
		tags[*el.Key] = *el.Value
	}

	return tags, nil
}

func (s *S3be) DeleteObjectTagging(ctx context.Context, bucket, object string) error {
	client, err := s.getClientFromCtx(ctx)
	if err != nil {
		return err
	}

	_, err = client.DeleteObjectTagging(ctx, &s3.DeleteObjectTaggingInput{
		Bucket: &bucket,
		Key:    &object,
	})
	return handleError(err)
}

func handleError(err error) error {
	if err == nil {
		return nil
	}

	var ae smithy.APIError
	if errors.As(err, &ae) {
		apiErr := s3err.APIError{
			Code:        ae.ErrorCode(),
			Description: ae.ErrorMessage(),
		}
		var re *awshttp.ResponseError
		if errors.As(err, &re) {
			apiErr.HTTPStatusCode = re.Response.StatusCode
		}
		return apiErr
	}
	return err
}
