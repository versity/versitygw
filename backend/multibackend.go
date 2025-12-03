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

package backend

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// MultiBackend wraps multiple backends and provides fallback on read operations
// when objects are not found. Write operations go to the first (primary) backend.
type MultiBackend struct {
	backends []Backend
	primary  Backend
}

var _ Backend = &MultiBackend{}

// NewMultiBackend creates a new multi-backend with fallback support.
// The first backend in the list is considered the primary backend for write operations.
func NewMultiBackend(backends ...Backend) (*MultiBackend, error) {
	if len(backends) == 0 {
		return nil, fmt.Errorf("at least one backend is required")
	}
	return &MultiBackend{
		backends: backends,
		primary:  backends[0],
	}, nil
}

func (m *MultiBackend) String() string {
	names := make([]string, len(m.backends))
	for i, be := range m.backends {
		names[i] = be.String()
	}
	return fmt.Sprintf("MultiBackend[%s]", strings.Join(names, ", "))
}

func (m *MultiBackend) Shutdown() {
	for _, be := range m.backends {
		be.Shutdown()
	}
}

// isNotFoundError checks if an error represents a "not found" condition
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}

	// Check for S3 API NoSuchKey error
	apiErr := s3err.GetAPIError(s3err.ErrNoSuchKey)
	if errors.Is(err, apiErr) {
		return true
	}

	// Check for AWS SDK NoSuchKey error
	var nsk *types.NoSuchKey
	if errors.As(err, &nsk) {
		return true
	}

	// Check for S3 API NoSuchBucket error (for bucket operations)
	apiBucketErr := s3err.GetAPIError(s3err.ErrNoSuchBucket)
	if errors.Is(err, apiBucketErr) {
		return true
	}

	// Check for AWS SDK NoSuchBucket error
	var nsb *types.NoSuchBucket
	if errors.As(err, &nsb) {
		return true
	}

	return false
}

// Read operations with fallback logic

func (m *MultiBackend) HeadObject(ctx context.Context, input *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
	var lastErr error
	for _, be := range m.backends {
		output, err := be.HeadObject(ctx, input)
		if err == nil {
			return output, nil
		}
		if !isNotFoundError(err) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

func (m *MultiBackend) GetObject(ctx context.Context, input *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	var lastErr error
	for _, be := range m.backends {
		output, err := be.GetObject(ctx, input)
		if err == nil {
			return output, nil
		}
		if !isNotFoundError(err) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

func (m *MultiBackend) GetObjectAcl(ctx context.Context, input *s3.GetObjectAclInput) (*s3.GetObjectAclOutput, error) {
	var lastErr error
	for _, be := range m.backends {
		output, err := be.GetObjectAcl(ctx, input)
		if err == nil {
			return output, nil
		}
		if !isNotFoundError(err) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

func (m *MultiBackend) GetObjectAttributes(ctx context.Context, input *s3.GetObjectAttributesInput) (s3response.GetObjectAttributesResponse, error) {
	var lastErr error
	for _, be := range m.backends {
		output, err := be.GetObjectAttributes(ctx, input)
		if err == nil {
			return output, nil
		}
		if !isNotFoundError(err) {
			return s3response.GetObjectAttributesResponse{}, err
		}
		lastErr = err
	}
	return s3response.GetObjectAttributesResponse{}, lastErr
}

func (m *MultiBackend) GetObjectTagging(ctx context.Context, bucket, object, versionId string) (map[string]string, error) {
	var lastErr error
	for _, be := range m.backends {
		tags, err := be.GetObjectTagging(ctx, bucket, object, versionId)
		if err == nil {
			return tags, nil
		}
		if !isNotFoundError(err) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

func (m *MultiBackend) GetObjectRetention(ctx context.Context, bucket, object, versionId string) ([]byte, error) {
	var lastErr error
	for _, be := range m.backends {
		retention, err := be.GetObjectRetention(ctx, bucket, object, versionId)
		if err == nil {
			return retention, nil
		}
		if !isNotFoundError(err) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

func (m *MultiBackend) GetObjectLegalHold(ctx context.Context, bucket, object, versionId string) (*bool, error) {
	var lastErr error
	for _, be := range m.backends {
		hold, err := be.GetObjectLegalHold(ctx, bucket, object, versionId)
		if err == nil {
			return hold, nil
		}
		if !isNotFoundError(err) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

func (m *MultiBackend) SelectObjectContent(ctx context.Context, input *s3.SelectObjectContentInput) func(w *bufio.Writer) {
	// Try each backend until one succeeds
	// This is a special case since it returns a function
	for i, be := range m.backends {
		if i == len(m.backends)-1 {
			// Last backend, return its result regardless
			return be.SelectObjectContent(ctx, input)
		}
		// For non-last backends, we'd need to check if object exists first
		// Using HeadObject as a preliminary check
		headInput := &s3.HeadObjectInput{
			Bucket: input.Bucket,
			Key:    input.Key,
		}
		_, err := be.HeadObject(ctx, headInput)
		if err == nil {
			return be.SelectObjectContent(ctx, input)
		}
		if !isNotFoundError(err) {
			// Non-404 error, return error handler
			return be.SelectObjectContent(ctx, input)
		}
	}
	// Shouldn't reach here, but return last backend as fallback
	return m.backends[len(m.backends)-1].SelectObjectContent(ctx, input)
}

// Bucket read operations with fallback

func (m *MultiBackend) HeadBucket(ctx context.Context, input *s3.HeadBucketInput) (*s3.HeadBucketOutput, error) {
	var lastErr error
	for _, be := range m.backends {
		output, err := be.HeadBucket(ctx, input)
		if err == nil {
			return output, nil
		}
		if !isNotFoundError(err) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

func (m *MultiBackend) GetBucketAcl(ctx context.Context, input *s3.GetBucketAclInput) ([]byte, error) {
	var lastErr error
	for _, be := range m.backends {
		acl, err := be.GetBucketAcl(ctx, input)
		if err == nil {
			return acl, nil
		}
		if !isNotFoundError(err) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

func (m *MultiBackend) GetBucketVersioning(ctx context.Context, bucket string) (s3response.GetBucketVersioningOutput, error) {
	var lastErr error
	for _, be := range m.backends {
		versioning, err := be.GetBucketVersioning(ctx, bucket)
		if err == nil {
			return versioning, nil
		}
		if !isNotFoundError(err) {
			return s3response.GetBucketVersioningOutput{}, err
		}
		lastErr = err
	}
	return s3response.GetBucketVersioningOutput{}, lastErr
}

func (m *MultiBackend) GetBucketPolicy(ctx context.Context, bucket string) ([]byte, error) {
	var lastErr error
	for _, be := range m.backends {
		policy, err := be.GetBucketPolicy(ctx, bucket)
		if err == nil {
			return policy, nil
		}
		if !isNotFoundError(err) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

func (m *MultiBackend) GetBucketOwnershipControls(ctx context.Context, bucket string) (types.ObjectOwnership, error) {
	var lastErr error
	for _, be := range m.backends {
		controls, err := be.GetBucketOwnershipControls(ctx, bucket)
		if err == nil {
			return controls, nil
		}
		if !isNotFoundError(err) {
			return types.ObjectOwnershipBucketOwnerEnforced, err
		}
		lastErr = err
	}
	return types.ObjectOwnershipBucketOwnerEnforced, lastErr
}

func (m *MultiBackend) GetBucketCors(ctx context.Context, bucket string) ([]byte, error) {
	var lastErr error
	for _, be := range m.backends {
		cors, err := be.GetBucketCors(ctx, bucket)
		if err == nil {
			return cors, nil
		}
		if !isNotFoundError(err) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

func (m *MultiBackend) GetBucketTagging(ctx context.Context, bucket string) (map[string]string, error) {
	var lastErr error
	for _, be := range m.backends {
		tags, err := be.GetBucketTagging(ctx, bucket)
		if err == nil {
			return tags, nil
		}
		if !isNotFoundError(err) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

func (m *MultiBackend) GetBucketLockConfiguration(ctx context.Context, bucket string) ([]byte, error) {
	var lastErr error
	for _, be := range m.backends {
		config, err := be.GetObjectLockConfiguration(ctx, bucket)
		if err == nil {
			return config, nil
		}
		if !isNotFoundError(err) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

// List operations - combine results from all backends for comprehensive view

func (m *MultiBackend) ListBuckets(ctx context.Context, input s3response.ListBucketsInput) (s3response.ListAllMyBucketsResult, error) {
	// For bucket listing, we query all backends and merge results
	bucketMap := make(map[string]s3response.ListAllMyBucketsEntry)

	for _, be := range m.backends {
		result, err := be.ListBuckets(ctx, input)
		if err != nil {
			// Continue even if one backend fails
			continue
		}
		for _, bucket := range result.Buckets.Bucket {
			// Keep the first occurrence of each bucket name
			if _, exists := bucketMap[bucket.Name]; !exists {
				bucketMap[bucket.Name] = bucket
			}
		}
	}

	buckets := make([]s3response.ListAllMyBucketsEntry, 0, len(bucketMap))
	for _, bucket := range bucketMap {
		buckets = append(buckets, bucket)
	}

	return s3response.ListAllMyBucketsResult{
		Buckets: s3response.ListAllMyBucketsList{
			Bucket: buckets,
		},
	}, nil
}

func (m *MultiBackend) ListObjects(ctx context.Context, input *s3.ListObjectsInput) (s3response.ListObjectsResult, error) {
	// Try each backend until one succeeds
	// Object listing is not merged to avoid confusion
	var lastErr error
	for _, be := range m.backends {
		result, err := be.ListObjects(ctx, input)
		if err == nil {
			return result, nil
		}
		if !isNotFoundError(err) {
			return s3response.ListObjectsResult{}, err
		}
		lastErr = err
	}
	return s3response.ListObjectsResult{}, lastErr
}

func (m *MultiBackend) ListObjectsV2(ctx context.Context, input *s3.ListObjectsV2Input) (s3response.ListObjectsV2Result, error) {
	var lastErr error
	for _, be := range m.backends {
		result, err := be.ListObjectsV2(ctx, input)
		if err == nil {
			return result, nil
		}
		if !isNotFoundError(err) {
			return s3response.ListObjectsV2Result{}, err
		}
		lastErr = err
	}
	return s3response.ListObjectsV2Result{}, lastErr
}

func (m *MultiBackend) ListObjectVersions(ctx context.Context, input *s3.ListObjectVersionsInput) (s3response.ListVersionsResult, error) {
	var lastErr error
	for _, be := range m.backends {
		result, err := be.ListObjectVersions(ctx, input)
		if err == nil {
			return result, nil
		}
		if !isNotFoundError(err) {
			return s3response.ListVersionsResult{}, err
		}
		lastErr = err
	}
	return s3response.ListVersionsResult{}, lastErr
}

func (m *MultiBackend) ListMultipartUploads(ctx context.Context, input *s3.ListMultipartUploadsInput) (s3response.ListMultipartUploadsResult, error) {
	var lastErr error
	for _, be := range m.backends {
		result, err := be.ListMultipartUploads(ctx, input)
		if err == nil {
			return result, nil
		}
		if !isNotFoundError(err) {
			return s3response.ListMultipartUploadsResult{}, err
		}
		lastErr = err
	}
	return s3response.ListMultipartUploadsResult{}, lastErr
}

func (m *MultiBackend) ListParts(ctx context.Context, input *s3.ListPartsInput) (s3response.ListPartsResult, error) {
	var lastErr error
	for _, be := range m.backends {
		result, err := be.ListParts(ctx, input)
		if err == nil {
			return result, nil
		}
		if !isNotFoundError(err) {
			return s3response.ListPartsResult{}, err
		}
		lastErr = err
	}
	return s3response.ListPartsResult{}, lastErr
}

func (m *MultiBackend) ListBucketsAndOwners(ctx context.Context) ([]s3response.Bucket, error) {
	// Merge results from all backends
	bucketMap := make(map[string]s3response.Bucket)

	for _, be := range m.backends {
		buckets, err := be.ListBucketsAndOwners(ctx)
		if err != nil {
			continue
		}
		for _, bucket := range buckets {
			// Use Name as key for deduplication
			if _, exists := bucketMap[bucket.Name]; !exists {
				bucketMap[bucket.Name] = bucket
			}
		}
	}

	buckets := make([]s3response.Bucket, 0, len(bucketMap))
	for _, bucket := range bucketMap {
		buckets = append(buckets, bucket)
	}

	return buckets, nil
}

// Write operations - all go to primary backend only

func (m *MultiBackend) PutObject(ctx context.Context, input s3response.PutObjectInput) (s3response.PutObjectOutput, error) {
	return m.primary.PutObject(ctx, input)
}

func (m *MultiBackend) CopyObject(ctx context.Context, input s3response.CopyObjectInput) (s3response.CopyObjectOutput, error) {
	return m.primary.CopyObject(ctx, input)
}

func (m *MultiBackend) DeleteObject(ctx context.Context, input *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error) {
	return m.primary.DeleteObject(ctx, input)
}

func (m *MultiBackend) DeleteObjects(ctx context.Context, input *s3.DeleteObjectsInput) (s3response.DeleteResult, error) {
	return m.primary.DeleteObjects(ctx, input)
}

func (m *MultiBackend) PutObjectAcl(ctx context.Context, input *s3.PutObjectAclInput) error {
	return m.primary.PutObjectAcl(ctx, input)
}

func (m *MultiBackend) PutObjectTagging(ctx context.Context, bucket, object, versionId string, tags map[string]string) error {
	return m.primary.PutObjectTagging(ctx, bucket, object, versionId, tags)
}

func (m *MultiBackend) DeleteObjectTagging(ctx context.Context, bucket, object, versionId string) error {
	return m.primary.DeleteObjectTagging(ctx, bucket, object, versionId)
}

func (m *MultiBackend) PutObjectRetention(ctx context.Context, bucket, object, versionId string, retention []byte) error {
	return m.primary.PutObjectRetention(ctx, bucket, object, versionId, retention)
}

func (m *MultiBackend) PutObjectLegalHold(ctx context.Context, bucket, object, versionId string, status bool) error {
	return m.primary.PutObjectLegalHold(ctx, bucket, object, versionId, status)
}

func (m *MultiBackend) RestoreObject(ctx context.Context, input *s3.RestoreObjectInput) error {
	return m.primary.RestoreObject(ctx, input)
}

// Bucket write operations - all go to primary backend

func (m *MultiBackend) CreateBucket(ctx context.Context, input *s3.CreateBucketInput, acl []byte) error {
	return m.primary.CreateBucket(ctx, input, acl)
}

func (m *MultiBackend) DeleteBucket(ctx context.Context, bucket string) error {
	return m.primary.DeleteBucket(ctx, bucket)
}

func (m *MultiBackend) PutBucketAcl(ctx context.Context, bucket string, data []byte) error {
	return m.primary.PutBucketAcl(ctx, bucket, data)
}

func (m *MultiBackend) PutBucketVersioning(ctx context.Context, bucket string, status types.BucketVersioningStatus) error {
	return m.primary.PutBucketVersioning(ctx, bucket, status)
}

func (m *MultiBackend) PutBucketPolicy(ctx context.Context, bucket string, policy []byte) error {
	return m.primary.PutBucketPolicy(ctx, bucket, policy)
}

func (m *MultiBackend) DeleteBucketPolicy(ctx context.Context, bucket string) error {
	return m.primary.DeleteBucketPolicy(ctx, bucket)
}

func (m *MultiBackend) PutBucketOwnershipControls(ctx context.Context, bucket string, ownership types.ObjectOwnership) error {
	return m.primary.PutBucketOwnershipControls(ctx, bucket, ownership)
}

func (m *MultiBackend) DeleteBucketOwnershipControls(ctx context.Context, bucket string) error {
	return m.primary.DeleteBucketOwnershipControls(ctx, bucket)
}

func (m *MultiBackend) PutBucketCors(ctx context.Context, bucket string, cors []byte) error {
	return m.primary.PutBucketCors(ctx, bucket, cors)
}

func (m *MultiBackend) DeleteBucketCors(ctx context.Context, bucket string) error {
	return m.primary.DeleteBucketCors(ctx, bucket)
}

func (m *MultiBackend) PutBucketTagging(ctx context.Context, bucket string, tags map[string]string) error {
	return m.primary.PutBucketTagging(ctx, bucket, tags)
}

func (m *MultiBackend) DeleteBucketTagging(ctx context.Context, bucket string) error {
	return m.primary.DeleteBucketTagging(ctx, bucket)
}

func (m *MultiBackend) PutObjectLockConfiguration(ctx context.Context, bucket string, config []byte) error {
	return m.primary.PutObjectLockConfiguration(ctx, bucket, config)
}

func (m *MultiBackend) GetObjectLockConfiguration(ctx context.Context, bucket string) ([]byte, error) {
	var lastErr error
	for _, be := range m.backends {
		config, err := be.GetObjectLockConfiguration(ctx, bucket)
		if err == nil {
			return config, nil
		}
		if !isNotFoundError(err) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

func (m *MultiBackend) ChangeBucketOwner(ctx context.Context, bucket, owner string) error {
	return m.primary.ChangeBucketOwner(ctx, bucket, owner)
}

// Multipart operations - all go to primary backend

func (m *MultiBackend) CreateMultipartUpload(ctx context.Context, input s3response.CreateMultipartUploadInput) (s3response.InitiateMultipartUploadResult, error) {
	return m.primary.CreateMultipartUpload(ctx, input)
}

func (m *MultiBackend) CompleteMultipartUpload(ctx context.Context, input *s3.CompleteMultipartUploadInput) (s3response.CompleteMultipartUploadResult, string, error) {
	return m.primary.CompleteMultipartUpload(ctx, input)
}

func (m *MultiBackend) AbortMultipartUpload(ctx context.Context, input *s3.AbortMultipartUploadInput) error {
	return m.primary.AbortMultipartUpload(ctx, input)
}

func (m *MultiBackend) UploadPart(ctx context.Context, input *s3.UploadPartInput) (*s3.UploadPartOutput, error) {
	return m.primary.UploadPart(ctx, input)
}

func (m *MultiBackend) UploadPartCopy(ctx context.Context, input *s3.UploadPartCopyInput) (s3response.CopyPartResult, error) {
	return m.primary.UploadPartCopy(ctx, input)
}
