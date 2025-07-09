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
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
	"github.com/versity/versitygw/s3select"
)

//go:generate moq -out ../s3api/controllers/backend_moq_test.go -pkg controllers . Backend
type Backend interface {
	fmt.Stringer
	Shutdown()

	// bucket operations
	ListBuckets(context.Context, s3response.ListBucketsInput) (s3response.ListAllMyBucketsResult, error)
	HeadBucket(context.Context, *s3.HeadBucketInput) (*s3.HeadBucketOutput, error)
	GetBucketAcl(context.Context, *s3.GetBucketAclInput) ([]byte, error)
	CreateBucket(_ context.Context, _ *s3.CreateBucketInput, defaultACL []byte) error
	PutBucketAcl(_ context.Context, bucket string, data []byte) error
	DeleteBucket(_ context.Context, bucket string) error
	PutBucketVersioning(_ context.Context, bucket string, status types.BucketVersioningStatus) error
	GetBucketVersioning(_ context.Context, bucket string) (s3response.GetBucketVersioningOutput, error)
	PutBucketPolicy(_ context.Context, bucket string, policy []byte) error
	GetBucketPolicy(_ context.Context, bucket string) ([]byte, error)
	DeleteBucketPolicy(_ context.Context, bucket string) error
	PutBucketOwnershipControls(_ context.Context, bucket string, ownership types.ObjectOwnership) error
	GetBucketOwnershipControls(_ context.Context, bucket string) (types.ObjectOwnership, error)
	DeleteBucketOwnershipControls(_ context.Context, bucket string) error
	PutBucketCors(context.Context, []byte) error
	GetBucketCors(_ context.Context, bucket string) ([]byte, error)
	DeleteBucketCors(_ context.Context, bucket string) error

	// multipart operations
	CreateMultipartUpload(context.Context, s3response.CreateMultipartUploadInput) (s3response.InitiateMultipartUploadResult, error)
	CompleteMultipartUpload(context.Context, *s3.CompleteMultipartUploadInput) (_ s3response.CompleteMultipartUploadResult, versionid string, _ error)
	AbortMultipartUpload(context.Context, *s3.AbortMultipartUploadInput) error
	ListMultipartUploads(context.Context, *s3.ListMultipartUploadsInput) (s3response.ListMultipartUploadsResult, error)
	ListParts(context.Context, *s3.ListPartsInput) (s3response.ListPartsResult, error)
	UploadPart(context.Context, *s3.UploadPartInput) (*s3.UploadPartOutput, error)
	UploadPartCopy(context.Context, *s3.UploadPartCopyInput) (s3response.CopyPartResult, error)

	// standard object operations
	PutObject(context.Context, s3response.PutObjectInput) (s3response.PutObjectOutput, error)
	HeadObject(context.Context, *s3.HeadObjectInput) (*s3.HeadObjectOutput, error)
	GetObject(context.Context, *s3.GetObjectInput) (*s3.GetObjectOutput, error)
	GetObjectAcl(context.Context, *s3.GetObjectAclInput) (*s3.GetObjectAclOutput, error)
	GetObjectAttributes(context.Context, *s3.GetObjectAttributesInput) (s3response.GetObjectAttributesResponse, error)
	CopyObject(context.Context, s3response.CopyObjectInput) (s3response.CopyObjectOutput, error)
	ListObjects(context.Context, *s3.ListObjectsInput) (s3response.ListObjectsResult, error)
	ListObjectsV2(context.Context, *s3.ListObjectsV2Input) (s3response.ListObjectsV2Result, error)
	DeleteObject(context.Context, *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error)
	DeleteObjects(context.Context, *s3.DeleteObjectsInput) (s3response.DeleteResult, error)
	PutObjectAcl(context.Context, *s3.PutObjectAclInput) error
	ListObjectVersions(context.Context, *s3.ListObjectVersionsInput) (s3response.ListVersionsResult, error)

	// special case object operations
	RestoreObject(context.Context, *s3.RestoreObjectInput) error
	SelectObjectContent(ctx context.Context, input *s3.SelectObjectContentInput) func(w *bufio.Writer)

	// bucket tagging operations
	GetBucketTagging(_ context.Context, bucket string) (map[string]string, error)
	PutBucketTagging(_ context.Context, bucket string, tags map[string]string) error
	DeleteBucketTagging(_ context.Context, bucket string) error

	// object tagging operations
	GetObjectTagging(_ context.Context, bucket, object string) (map[string]string, error)
	PutObjectTagging(_ context.Context, bucket, object string, tags map[string]string) error
	DeleteObjectTagging(_ context.Context, bucket, object string) error

	// object lock operations
	PutObjectLockConfiguration(_ context.Context, bucket string, config []byte) error
	GetObjectLockConfiguration(_ context.Context, bucket string) ([]byte, error)
	PutObjectRetention(_ context.Context, bucket, object, versionId string, bypass bool, retention []byte) error
	GetObjectRetention(_ context.Context, bucket, object, versionId string) ([]byte, error)
	PutObjectLegalHold(_ context.Context, bucket, object, versionId string, status bool) error
	GetObjectLegalHold(_ context.Context, bucket, object, versionId string) (*bool, error)

	// non AWS actions
	ChangeBucketOwner(_ context.Context, bucket, owner string) error
	ListBucketsAndOwners(context.Context) ([]s3response.Bucket, error)
}

type BackendUnsupported struct{}

var _ Backend = &BackendUnsupported{}

func New() Backend {
	return &BackendUnsupported{}
}
func (BackendUnsupported) Shutdown() {}
func (BackendUnsupported) String() string {
	return "Unsupported"
}
func (BackendUnsupported) ListBuckets(context.Context, s3response.ListBucketsInput) (s3response.ListAllMyBucketsResult, error) {
	return s3response.ListAllMyBucketsResult{}, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) HeadBucket(context.Context, *s3.HeadBucketInput) (*s3.HeadBucketOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) GetBucketAcl(context.Context, *s3.GetBucketAclInput) ([]byte, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) CreateBucket(context.Context, *s3.CreateBucketInput, []byte) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) PutBucketAcl(_ context.Context, bucket string, data []byte) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) DeleteBucket(_ context.Context, bucket string) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) PutBucketVersioning(_ context.Context, bucket string, status types.BucketVersioningStatus) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) GetBucketVersioning(_ context.Context, bucket string) (s3response.GetBucketVersioningOutput, error) {
	return s3response.GetBucketVersioningOutput{}, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) PutBucketPolicy(_ context.Context, bucket string, policy []byte) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) GetBucketPolicy(_ context.Context, bucket string) ([]byte, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) DeleteBucketPolicy(_ context.Context, bucket string) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) PutBucketOwnershipControls(_ context.Context, bucket string, ownership types.ObjectOwnership) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) GetBucketOwnershipControls(_ context.Context, bucket string) (types.ObjectOwnership, error) {
	return types.ObjectOwnershipBucketOwnerEnforced, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) DeleteBucketOwnershipControls(_ context.Context, bucket string) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) PutBucketCors(context.Context, []byte) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) GetBucketCors(_ context.Context, bucket string) ([]byte, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) DeleteBucketCors(_ context.Context, bucket string) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}

func (BackendUnsupported) CreateMultipartUpload(context.Context, s3response.CreateMultipartUploadInput) (s3response.InitiateMultipartUploadResult, error) {
	return s3response.InitiateMultipartUploadResult{}, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) CompleteMultipartUpload(context.Context, *s3.CompleteMultipartUploadInput) (s3response.CompleteMultipartUploadResult, string, error) {
	return s3response.CompleteMultipartUploadResult{}, "", s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) AbortMultipartUpload(context.Context, *s3.AbortMultipartUploadInput) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) ListMultipartUploads(context.Context, *s3.ListMultipartUploadsInput) (s3response.ListMultipartUploadsResult, error) {
	return s3response.ListMultipartUploadsResult{}, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) ListParts(context.Context, *s3.ListPartsInput) (s3response.ListPartsResult, error) {
	return s3response.ListPartsResult{}, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) UploadPart(context.Context, *s3.UploadPartInput) (*s3.UploadPartOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) UploadPartCopy(context.Context, *s3.UploadPartCopyInput) (s3response.CopyPartResult, error) {
	return s3response.CopyPartResult{}, s3err.GetAPIError(s3err.ErrNotImplemented)
}

func (BackendUnsupported) PutObject(context.Context, s3response.PutObjectInput) (s3response.PutObjectOutput, error) {
	return s3response.PutObjectOutput{}, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) HeadObject(context.Context, *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) GetObject(context.Context, *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) GetObjectAcl(context.Context, *s3.GetObjectAclInput) (*s3.GetObjectAclOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) GetObjectAttributes(context.Context, *s3.GetObjectAttributesInput) (s3response.GetObjectAttributesResponse, error) {
	return s3response.GetObjectAttributesResponse{}, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) CopyObject(context.Context, s3response.CopyObjectInput) (s3response.CopyObjectOutput, error) {
	return s3response.CopyObjectOutput{}, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) ListObjects(context.Context, *s3.ListObjectsInput) (s3response.ListObjectsResult, error) {
	return s3response.ListObjectsResult{}, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) ListObjectsV2(context.Context, *s3.ListObjectsV2Input) (s3response.ListObjectsV2Result, error) {
	return s3response.ListObjectsV2Result{}, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) DeleteObject(context.Context, *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) DeleteObjects(context.Context, *s3.DeleteObjectsInput) (s3response.DeleteResult, error) {
	return s3response.DeleteResult{}, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) PutObjectAcl(context.Context, *s3.PutObjectAclInput) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}

func (BackendUnsupported) RestoreObject(context.Context, *s3.RestoreObjectInput) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) SelectObjectContent(ctx context.Context, input *s3.SelectObjectContentInput) func(w *bufio.Writer) {
	return func(w *bufio.Writer) {
		var getProgress s3select.GetProgress
		progress := input.RequestProgress
		if progress != nil && *progress.Enabled {
			getProgress = func() (bytesScanned int64, bytesProcessed int64) {
				return -1, -1
			}
		}
		mh := s3select.NewMessageHandler(ctx, w, getProgress)
		apiErr := s3err.GetAPIError(s3err.ErrNotImplemented)
		mh.FinishWithError(apiErr.Code, apiErr.Description)
	}
}

func (BackendUnsupported) ListObjectVersions(context.Context, *s3.ListObjectVersionsInput) (s3response.ListVersionsResult, error) {
	return s3response.ListVersionsResult{}, s3err.GetAPIError(s3err.ErrNotImplemented)
}

func (BackendUnsupported) GetBucketTagging(_ context.Context, bucket string) (map[string]string, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) PutBucketTagging(_ context.Context, bucket string, tags map[string]string) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) DeleteBucketTagging(_ context.Context, bucket string) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}

func (BackendUnsupported) GetObjectTagging(_ context.Context, bucket, object string) (map[string]string, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) PutObjectTagging(_ context.Context, bucket, object string, tags map[string]string) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) DeleteObjectTagging(_ context.Context, bucket, object string) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}

func (BackendUnsupported) PutObjectLockConfiguration(_ context.Context, bucket string, config []byte) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) GetObjectLockConfiguration(_ context.Context, bucket string) ([]byte, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) PutObjectRetention(_ context.Context, bucket, object, versionId string, bypass bool, retention []byte) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) GetObjectRetention(_ context.Context, bucket, object, versionId string) ([]byte, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) PutObjectLegalHold(_ context.Context, bucket, object, versionId string, status bool) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) GetObjectLegalHold(_ context.Context, bucket, object, versionId string) (*bool, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}

func (BackendUnsupported) ChangeBucketOwner(_ context.Context, bucket, owner string) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) ListBucketsAndOwners(context.Context) ([]s3response.Bucket, error) {
	return []s3response.Bucket{}, s3err.GetAPIError(s3err.ErrNotImplemented)
}
