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
	"encoding/base64"
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

const aclKey string = "versitygwAcl"

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

var _ backend.Backend = &S3Proxy{}

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
	if err != nil {
		return s3response.ListAllMyBucketsResult{}, handleError(err)
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
	return out, handleError(err)
}

func (s *S3Proxy) CreateBucket(ctx context.Context, input *s3.CreateBucketInput, acl []byte) error {
	_, err := s.client.CreateBucket(ctx, input)
	if err != nil {
		return handleError(err)
	}

	var tagSet []types.Tag
	tagSet = append(tagSet, types.Tag{
		Key:   backend.GetStringPtr(aclKey),
		Value: backend.GetStringPtr(base64Encode(acl)),
	})

	_, err = s.client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
		Bucket: input.Bucket,
		Tagging: &types.Tagging{
			TagSet: tagSet,
		},
	})
	return handleError(err)
}

func (s *S3Proxy) DeleteBucket(ctx context.Context, input *s3.DeleteBucketInput) error {
	_, err := s.client.DeleteBucket(ctx, input)
	return handleError(err)
}

func (s *S3Proxy) PutBucketOwnershipControls(ctx context.Context, bucket string, ownership types.ObjectOwnership) error {
	_, err := s.client.PutBucketOwnershipControls(ctx, &s3.PutBucketOwnershipControlsInput{
		Bucket: &bucket,
		OwnershipControls: &types.OwnershipControls{
			Rules: []types.OwnershipControlsRule{
				{
					ObjectOwnership: ownership,
				},
			},
		},
	})
	return handleError(err)
}

func (s *S3Proxy) GetBucketOwnershipControls(ctx context.Context, bucket string) (types.ObjectOwnership, error) {
	var ownship types.ObjectOwnership
	resp, err := s.client.GetBucketOwnershipControls(ctx, &s3.GetBucketOwnershipControlsInput{
		Bucket: &bucket,
	})
	if err != nil {
		return ownship, handleError(err)
	}
	return resp.OwnershipControls.Rules[0].ObjectOwnership, nil
}
func (s *S3Proxy) DeleteBucketOwnershipControls(ctx context.Context, bucket string) error {
	_, err := s.client.DeleteBucketOwnershipControls(ctx, &s3.DeleteBucketOwnershipControlsInput{
		Bucket: &bucket,
	})
	return handleError(err)
}

func (s *S3Proxy) CreateMultipartUpload(ctx context.Context, input *s3.CreateMultipartUploadInput) (*s3.CreateMultipartUploadOutput, error) {
	out, err := s.client.CreateMultipartUpload(ctx, input)
	return out, handleError(err)
}

func (s *S3Proxy) CompleteMultipartUpload(ctx context.Context, input *s3.CompleteMultipartUploadInput) (*s3.CompleteMultipartUploadOutput, error) {
	out, err := s.client.CompleteMultipartUpload(ctx, input)
	return out, handleError(err)
}

func (s *S3Proxy) AbortMultipartUpload(ctx context.Context, input *s3.AbortMultipartUploadInput) error {
	_, err := s.client.AbortMultipartUpload(ctx, input)
	return handleError(err)
}

func (s *S3Proxy) ListMultipartUploads(ctx context.Context, input *s3.ListMultipartUploadsInput) (s3response.ListMultipartUploadsResult, error) {
	output, err := s.client.ListMultipartUploads(ctx, input)
	if err != nil {
		return s3response.ListMultipartUploadsResult{}, handleError(err)
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
	if err != nil {
		return s3response.ListPartsResult{}, handleError(err)
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
	if err != nil {
		return "", handleError(err)
	}

	return *output.ETag, nil
}

func (s *S3Proxy) UploadPartCopy(ctx context.Context, input *s3.UploadPartCopyInput) (s3response.CopyObjectResult, error) {
	output, err := s.client.UploadPartCopy(ctx, input)
	if err != nil {
		return s3response.CopyObjectResult{}, handleError(err)
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
	if err != nil {
		return "", handleError(err)
	}

	return *output.ETag, nil
}

func (s *S3Proxy) HeadObject(ctx context.Context, input *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
	out, err := s.client.HeadObject(ctx, input)
	return out, handleError(err)
}

func (s *S3Proxy) GetObject(ctx context.Context, input *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	output, err := s.client.GetObject(ctx, input)
	if err != nil {
		return nil, handleError(err)
	}

	return output, nil
}

func (s *S3Proxy) GetObjectAttributes(ctx context.Context, input *s3.GetObjectAttributesInput) (s3response.GetObjectAttributesResult, error) {
	out, err := s.client.GetObjectAttributes(ctx, input)

	parts := s3response.ObjectParts{}
	objParts := out.ObjectParts
	if objParts != nil {
		if objParts.PartNumberMarker != nil {
			partNumberMarker, err := strconv.Atoi(*objParts.PartNumberMarker)
			if err != nil {
				parts.PartNumberMarker = partNumberMarker
			}
			if objParts.NextPartNumberMarker != nil {
				nextPartNumberMarker, err := strconv.Atoi(*objParts.NextPartNumberMarker)
				if err != nil {
					parts.NextPartNumberMarker = nextPartNumberMarker
				}
			}
			if objParts.IsTruncated != nil {
				parts.IsTruncated = *objParts.IsTruncated
			}
			if objParts.MaxParts != nil {
				parts.MaxParts = int(*objParts.MaxParts)
			}
			parts.Parts = objParts.Parts
		}
	}

	return s3response.GetObjectAttributesResult{
		ETag:         out.ETag,
		LastModified: out.LastModified,
		ObjectSize:   out.ObjectSize,
		StorageClass: &out.StorageClass,
		VersionId:    out.VersionId,
		ObjectParts:  &parts,
	}, handleError(err)
}

func (s *S3Proxy) CopyObject(ctx context.Context, input *s3.CopyObjectInput) (*s3.CopyObjectOutput, error) {
	out, err := s.client.CopyObject(ctx, input)
	return out, handleError(err)
}

func (s *S3Proxy) ListObjects(ctx context.Context, input *s3.ListObjectsInput) (*s3.ListObjectsOutput, error) {
	out, err := s.client.ListObjects(ctx, input)
	return out, handleError(err)
}

func (s *S3Proxy) ListObjectsV2(ctx context.Context, input *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
	out, err := s.client.ListObjectsV2(ctx, input)
	return out, handleError(err)
}

func (s *S3Proxy) DeleteObject(ctx context.Context, input *s3.DeleteObjectInput) error {
	_, err := s.client.DeleteObject(ctx, input)
	return handleError(err)
}

func (s *S3Proxy) DeleteObjects(ctx context.Context, input *s3.DeleteObjectsInput) (s3response.DeleteResult, error) {
	if len(input.Delete.Objects) == 0 {
		input.Delete.Objects = []types.ObjectIdentifier{}
	}

	output, err := s.client.DeleteObjects(ctx, input)
	if err != nil {
		return s3response.DeleteResult{}, handleError(err)
	}

	return s3response.DeleteResult{
		Deleted: output.Deleted,
		Error:   output.Errors,
	}, nil
}

func (s *S3Proxy) GetBucketAcl(ctx context.Context, input *s3.GetBucketAclInput) ([]byte, error) {
	tagout, err := s.client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
		Bucket: input.Bucket,
	})
	if err != nil {
		return nil, handleError(err)
	}

	for _, tag := range tagout.TagSet {
		if *tag.Key == aclKey {
			acl, err := base64Decode(*tag.Value)
			if err != nil {
				return nil, handleError(err)
			}
			return acl, nil
		}
	}

	return []byte{}, nil
}

func (s *S3Proxy) PutBucketAcl(ctx context.Context, bucket string, data []byte) error {
	tagout, err := s.client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
		Bucket: &bucket,
	})
	if err != nil {
		return handleError(err)
	}

	var found bool
	for i, tag := range tagout.TagSet {
		if *tag.Key == aclKey {
			tagout.TagSet[i] = types.Tag{
				Key:   backend.GetStringPtr(aclKey),
				Value: backend.GetStringPtr(base64Encode(data)),
			}
			found = true
			break
		}
	}
	if !found {
		tagout.TagSet = append(tagout.TagSet, types.Tag{
			Key:   backend.GetStringPtr(aclKey),
			Value: backend.GetStringPtr(base64Encode(data)),
		})
	}

	_, err = s.client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
		Bucket: &bucket,
		Tagging: &types.Tagging{
			TagSet: tagout.TagSet,
		},
	})
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
	if err != nil {
		return nil, handleError(err)
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

func (s *S3Proxy) PutBucketPolicy(ctx context.Context, bucket string, policy []byte) error {
	_, err := s.client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
		Bucket: &bucket,
		Policy: backend.GetStringPtr(string(policy)),
	})
	return handleError(err)
}

func (s *S3Proxy) GetBucketPolicy(ctx context.Context, bucket string) ([]byte, error) {
	policy, err := s.client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket: &bucket,
	})
	if err != nil {
		return nil, handleError(err)
	}

	result := []byte{}
	if policy.Policy != nil {
		result = []byte(*policy.Policy)
	}

	return result, nil
}

func (s *S3Proxy) DeleteBucketPolicy(ctx context.Context, bucket string) error {
	_, err := s.client.DeleteBucketPolicy(ctx, &s3.DeleteBucketPolicyInput{
		Bucket: &bucket,
	})
	return handleError(err)
}

func (s *S3Proxy) PutObjectLockConfiguration(ctx context.Context, bucket string, config []byte) error {
	cfg, err := auth.ParseBucketLockConfigurationOutput(config)
	if err != nil {
		return err
	}

	_, err = s.client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
		Bucket:                  &bucket,
		ObjectLockConfiguration: cfg,
	})

	return handleError(err)
}

func (s *S3Proxy) GetObjectLockConfiguration(ctx context.Context, bucket string) ([]byte, error) {
	resp, err := s.client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
		Bucket: &bucket,
	})
	if err != nil {
		return nil, handleError(err)
	}

	config := auth.BucketLockConfig{
		Enabled:          resp.ObjectLockConfiguration.ObjectLockEnabled == types.ObjectLockEnabledEnabled,
		DefaultRetention: resp.ObjectLockConfiguration.Rule.DefaultRetention,
	}

	return json.Marshal(config)
}

func (s *S3Proxy) PutObjectRetention(ctx context.Context, bucket, object, versionId string, bypass bool, retention []byte) error {
	ret, err := auth.ParseObjectLockRetentionOutput(retention)
	if err != nil {
		return err
	}

	_, err = s.client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
		Bucket:                    &bucket,
		Key:                       &object,
		VersionId:                 &versionId,
		Retention:                 ret,
		BypassGovernanceRetention: &bypass,
	})
	return handleError(err)
}

func (s *S3Proxy) GetObjectRetention(ctx context.Context, bucket, object, versionId string) ([]byte, error) {
	resp, err := s.client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
		Bucket:    &bucket,
		Key:       &object,
		VersionId: &versionId,
	})
	if err != nil {
		return nil, handleError(err)
	}

	return json.Marshal(resp.Retention)
}

func (s *S3Proxy) PutObjectLegalHold(ctx context.Context, bucket, object, versionId string, status bool) error {
	var st types.ObjectLockLegalHoldStatus
	if status {
		st = types.ObjectLockLegalHoldStatusOn
	} else {
		st = types.ObjectLockLegalHoldStatusOff
	}

	_, err := s.client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
		Bucket:    &bucket,
		Key:       &object,
		VersionId: &versionId,
		LegalHold: &types.ObjectLockLegalHold{
			Status: st,
		},
	})
	return handleError(err)
}

func (s *S3Proxy) GetObjectLegalHold(ctx context.Context, bucket, object, versionId string) (*bool, error) {
	resp, err := s.client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
		Bucket:    &bucket,
		Key:       &object,
		VersionId: &versionId,
	})
	if err != nil {
		return nil, handleError(err)
	}

	status := resp.LegalHold.Status == types.ObjectLockLegalHoldStatusOn
	return &status, nil
}

func (s *S3Proxy) ChangeBucketOwner(ctx context.Context, bucket string, acl []byte) error {
	var acll auth.ACL
	if err := json.Unmarshal(acl, &acll); err != nil {
		return fmt.Errorf("unmarshal acl: %w", err)
	}
	req, err := http.NewRequest(http.MethodPatch, fmt.Sprintf("%v/change-bucket-owner/?bucket=%v&owner=%v", s.endpoint, bucket, acll.Owner), nil)
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

func base64Encode(input []byte) string {
	return base64.StdEncoding.EncodeToString(input)
}

func base64Decode(encoded string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}
