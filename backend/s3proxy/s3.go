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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

type S3Proxy struct {
	backend.BackendUnsupported

	client *s3.Client

	access          string
	secret          string
	endpoint        string
	awsRegion       string
	disableChecksum bool
	sslSkipVerify   bool
	debug           bool
}

func New(access, secret, endpoint, region string, disableChecksum, sslSkipVerify, debug bool) (*S3Proxy, error) {
	s := &S3Proxy{
		access:          access,
		secret:          secret,
		endpoint:        endpoint,
		awsRegion:       region,
		disableChecksum: disableChecksum,
		sslSkipVerify:   sslSkipVerify,
		debug:           debug,
	}
	client, err := s.getClientWithCtx(context.Background())
	if err != nil {
		return nil, err
	}
	s.client = client
	return s, nil
}

func (s *S3Proxy) ListBuckets(ctx context.Context, owner string, isAdmin bool) (s3response.ListAllMyBucketsResult, error) {
	output, err := s.client.ListBuckets(ctx, &s3.ListBucketsInput{})
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
			ID: *output.Owner.ID,
		},
		Buckets: s3response.ListAllMyBucketsList{
			Bucket: buckets,
		},
	}, nil
}

func (s *S3Proxy) HeadBucket(ctx context.Context, input *s3.HeadBucketInput) (*s3.HeadBucketOutput, error) {
	out, err := s.client.HeadBucket(ctx, input)
	err = handleError(err)

	return out, err
}

func (s *S3Proxy) CreateBucket(ctx context.Context, input *s3.CreateBucketInput) error {
	_, err := s.client.CreateBucket(ctx, input)
	return handleError(err)
}

func (s *S3Proxy) DeleteBucket(ctx context.Context, input *s3.DeleteBucketInput) error {
	_, err := s.client.DeleteBucket(ctx, input)
	return handleError(err)
}

func (s *S3Proxy) CreateMultipartUpload(ctx context.Context, input *s3.CreateMultipartUploadInput) (*s3.CreateMultipartUploadOutput, error) {
	out, err := s.client.CreateMultipartUpload(ctx, input)
	err = handleError(err)
	return out, err
}

func (s *S3Proxy) CompleteMultipartUpload(ctx context.Context, input *s3.CompleteMultipartUploadInput) (*s3.CompleteMultipartUploadOutput, error) {
	out, err := s.client.CompleteMultipartUpload(ctx, input)
	err = handleError(err)
	return out, err
}

func (s *S3Proxy) AbortMultipartUpload(ctx context.Context, input *s3.AbortMultipartUploadInput) error {
	_, err := s.client.AbortMultipartUpload(ctx, input)
	err = handleError(err)
	return err
}

func (s *S3Proxy) ListMultipartUploads(ctx context.Context, input *s3.ListMultipartUploadsInput) (s3response.ListMultipartUploadsResult, error) {
	output, err := s.client.ListMultipartUploads(ctx, input)
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

func (s *S3Proxy) ListParts(ctx context.Context, input *s3.ListPartsInput) (s3response.ListPartsResult, error) {
	output, err := s.client.ListParts(ctx, input)
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

func (s *S3Proxy) UploadPart(ctx context.Context, input *s3.UploadPartInput) (etag string, err error) {
	// streaming backend is not seekable,
	// use unsigned payload for streaming ops
	output, err := s.client.UploadPart(ctx, input, s3.WithAPIOptions(
		v4.SwapComputePayloadSHA256ForUnsignedPayloadMiddleware,
	))
	err = handleError(err)
	if err != nil {
		return "", err
	}

	return *output.ETag, nil
}

func (s *S3Proxy) UploadPartCopy(ctx context.Context, input *s3.UploadPartCopyInput) (s3response.CopyObjectResult, error) {
	output, err := s.client.UploadPartCopy(ctx, input)
	err = handleError(err)
	if err != nil {
		return s3response.CopyObjectResult{}, err
	}

	return s3response.CopyObjectResult{
		LastModified: *output.CopyPartResult.LastModified,
		ETag:         *output.CopyPartResult.ETag,
	}, nil
}

func (s *S3Proxy) PutObject(ctx context.Context, input *s3.PutObjectInput) (string, error) {
	// streaming backend is not seekable,
	// use unsigned payload for streaming ops
	output, err := s.client.PutObject(ctx, input, s3.WithAPIOptions(
		v4.SwapComputePayloadSHA256ForUnsignedPayloadMiddleware,
	))
	err = handleError(err)
	if err != nil {
		return "", err
	}

	return *output.ETag, nil
}

func (s *S3Proxy) HeadObject(ctx context.Context, input *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
	out, err := s.client.HeadObject(ctx, input)
	err = handleError(err)

	return out, err
}

func (s *S3Proxy) GetObject(ctx context.Context, input *s3.GetObjectInput, w io.Writer) (*s3.GetObjectOutput, error) {
	output, err := s.client.GetObject(ctx, input)
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

func (s *S3Proxy) GetObjectAttributes(ctx context.Context, input *s3.GetObjectAttributesInput) (*s3.GetObjectAttributesOutput, error) {
	out, err := s.client.GetObjectAttributes(ctx, input)
	err = handleError(err)

	return out, err
}

func (s *S3Proxy) CopyObject(ctx context.Context, input *s3.CopyObjectInput) (*s3.CopyObjectOutput, error) {
	out, err := s.client.CopyObject(ctx, input)
	err = handleError(err)

	return out, err
}

func (s *S3Proxy) ListObjects(ctx context.Context, input *s3.ListObjectsInput) (*s3.ListObjectsOutput, error) {
	out, err := s.client.ListObjects(ctx, input)
	err = handleError(err)

	return out, err
}

func (s *S3Proxy) ListObjectsV2(ctx context.Context, input *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
	out, err := s.client.ListObjectsV2(ctx, input)
	err = handleError(err)

	return out, err
}

func (s *S3Proxy) DeleteObject(ctx context.Context, input *s3.DeleteObjectInput) error {
	_, err := s.client.DeleteObject(ctx, input)
	return handleError(err)
}

func (s *S3Proxy) DeleteObjects(ctx context.Context, input *s3.DeleteObjectsInput) (s3response.DeleteObjectsResult, error) {
	if len(input.Delete.Objects) == 0 {
		input.Delete.Objects = []types.ObjectIdentifier{}
	}

	output, err := s.client.DeleteObjects(ctx, input)
	err = handleError(err)
	if err != nil {
		return s3response.DeleteObjectsResult{}, err
	}

	return s3response.DeleteObjectsResult{
		Deleted: output.Deleted,
		Error:   output.Errors,
	}, nil
}

func (s *S3Proxy) GetBucketAcl(ctx context.Context, input *s3.GetBucketAclInput) ([]byte, error) {
	output, err := s.client.GetBucketAcl(ctx, input)
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

func (s S3Proxy) PutBucketAcl(ctx context.Context, bucket string, data []byte) error {
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
		acc := el.Access
		input.AccessControlPolicy.Grants = append(input.AccessControlPolicy.Grants, types.Grant{
			Permission: el.Permission,
			Grantee: &types.Grantee{
				ID:   &acc,
				Type: types.TypeCanonicalUser,
			},
		})
	}

	_, err = s.client.PutBucketAcl(ctx, input)
	return handleError(err)
}

func (s *S3Proxy) PutObjectTagging(ctx context.Context, bucket, object string, tags map[string]string) error {
	tagging := &types.Tagging{
		TagSet: []types.Tag{},
	}
	for key, val := range tags {
		tagging.TagSet = append(tagging.TagSet, types.Tag{
			Key:   &key,
			Value: &val,
		})
	}

	_, err := s.client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
		Bucket:  &bucket,
		Key:     &object,
		Tagging: tagging,
	})
	return handleError(err)
}

func (s *S3Proxy) GetObjectTagging(ctx context.Context, bucket, object string) (map[string]string, error) {
	output, err := s.client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
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

func (s *S3Proxy) DeleteObjectTagging(ctx context.Context, bucket, object string) error {
	_, err := s.client.DeleteObjectTagging(ctx, &s3.DeleteObjectTaggingInput{
		Bucket: &bucket,
		Key:    &object,
	})
	return handleError(err)
}

func (s *S3Proxy) ChangeBucketOwner(ctx context.Context, bucket, newOwner string) error {
	req, err := http.NewRequest(http.MethodPatch, fmt.Sprintf("%v/change-bucket-owner/?bucket=%v&owner=%v", s.endpoint, bucket, newOwner), nil)
	if err != nil {
		return fmt.Errorf("failed to send the request: %w", err)
	}

	signer := v4.NewSigner()

	hashedPayload := sha256.Sum256([]byte{})
	hexPayload := hex.EncodeToString(hashedPayload[:])

	req.Header.Set("X-Amz-Content-Sha256", hexPayload)

	signErr := signer.SignHTTP(req.Context(), aws.Credentials{AccessKeyID: s.access, SecretAccessKey: s.secret}, req, hexPayload, "s3", s.awsRegion, time.Now())
	if signErr != nil {
		return fmt.Errorf("failed to sign the request: %w", err)
	}

	client := http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send the request: %w", err)
	}

	if resp.StatusCode > 300 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		return fmt.Errorf(string(body))
	}

	return nil
}

func (s *S3Proxy) ListBucketsAndOwners(ctx context.Context) ([]s3response.Bucket, error) {
	req, err := http.NewRequest(http.MethodPatch, fmt.Sprintf("%v/list-buckets", s.endpoint), nil)
	if err != nil {
		return []s3response.Bucket{}, fmt.Errorf("failed to send the request: %w", err)
	}

	signer := v4.NewSigner()

	hashedPayload := sha256.Sum256([]byte{})
	hexPayload := hex.EncodeToString(hashedPayload[:])

	req.Header.Set("X-Amz-Content-Sha256", hexPayload)

	signErr := signer.SignHTTP(req.Context(), aws.Credentials{AccessKeyID: s.access, SecretAccessKey: s.secret}, req, hexPayload, "s3", s.awsRegion, time.Now())
	if signErr != nil {
		return []s3response.Bucket{}, fmt.Errorf("failed to sign the request: %w", err)
	}

	client := http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return []s3response.Bucket{}, fmt.Errorf("failed to send the request: %w", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return []s3response.Bucket{}, err
	}
	defer resp.Body.Close()

	var buckets []s3response.Bucket
	if err := json.Unmarshal(body, &buckets); err != nil {
		return []s3response.Bucket{}, err
	}

	return buckets, nil
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
