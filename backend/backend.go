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
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

//go:generate moq -out ../s3api/controllers/backend_moq_test.go -pkg controllers . Backend
type Backend interface {
	fmt.Stringer
	Shutdown()

	// bucket operations
	ListBuckets(_ context.Context, owner string, isRoot bool) (s3response.ListAllMyBucketsResult, error)
	HeadBucket(context.Context, *s3.HeadBucketInput) (*s3.HeadBucketOutput, error)
	GetBucketAcl(context.Context, *s3.GetBucketAclInput) ([]byte, error)
	CreateBucket(context.Context, *s3.CreateBucketInput) error
	PutBucketAcl(_ context.Context, bucket string, data []byte) error
	DeleteBucket(context.Context, *s3.DeleteBucketInput) error

	// multipart operations
	CreateMultipartUpload(context.Context, *s3.CreateMultipartUploadInput) (*s3.CreateMultipartUploadOutput, error)
	CompleteMultipartUpload(context.Context, *s3.CompleteMultipartUploadInput) (*s3.CompleteMultipartUploadOutput, error)
	AbortMultipartUpload(context.Context, *s3.AbortMultipartUploadInput) error
	ListMultipartUploads(context.Context, *s3.ListMultipartUploadsInput) (s3response.ListMultipartUploadsResult, error)
	ListParts(context.Context, *s3.ListPartsInput) (s3response.ListPartsResult, error)
	UploadPart(context.Context, *s3.UploadPartInput) (etag string, err error)
	UploadPartCopy(context.Context, *s3.UploadPartCopyInput) (s3response.CopyObjectResult, error)

	// standard object operations
	PutObject(context.Context, *s3.PutObjectInput) (string, error)
	HeadObject(context.Context, *s3.HeadObjectInput) (*s3.HeadObjectOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, io.Writer) (*s3.GetObjectOutput, error)
	GetObjectAcl(context.Context, *s3.GetObjectAclInput) (*s3.GetObjectAclOutput, error)
	GetObjectAttributes(context.Context, *s3.GetObjectAttributesInput) (*s3.GetObjectAttributesOutput, error)
	CopyObject(context.Context, *s3.CopyObjectInput) (*s3.CopyObjectOutput, error)
	ListObjects(context.Context, *s3.ListObjectsInput) (*s3.ListObjectsOutput, error)
	ListObjectsV2(context.Context, *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error)
	DeleteObject(context.Context, *s3.DeleteObjectInput) error
	DeleteObjects(context.Context, *s3.DeleteObjectsInput) (s3response.DeleteObjectsResult, error)
	PutObjectAcl(context.Context, *s3.PutObjectAclInput) error

	// special case object operations
	RestoreObject(context.Context, *s3.RestoreObjectInput) error
	SelectObjectContent(context.Context, *s3.SelectObjectContentInput) (s3response.SelectObjectContentResult, error)

	// object tags operations
	GetTags(_ context.Context, bucket, object string) (map[string]string, error)
	SetTags(_ context.Context, bucket, object string, tags map[string]string) error
	RemoveTags(_ context.Context, bucket, object string) error
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
func (BackendUnsupported) ListBuckets(context.Context, string, bool) (s3response.ListAllMyBucketsResult, error) {
	return s3response.ListAllMyBucketsResult{}, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) HeadBucket(context.Context, *s3.HeadBucketInput) (*s3.HeadBucketOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) GetBucketAcl(context.Context, *s3.GetBucketAclInput) ([]byte, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) CreateBucket(context.Context, *s3.CreateBucketInput) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) PutBucketAcl(_ context.Context, bucket string, data []byte) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) DeleteBucket(context.Context, *s3.DeleteBucketInput) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}

func (BackendUnsupported) CreateMultipartUpload(context.Context, *s3.CreateMultipartUploadInput) (*s3.CreateMultipartUploadOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) CompleteMultipartUpload(context.Context, *s3.CompleteMultipartUploadInput) (*s3.CompleteMultipartUploadOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
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
func (BackendUnsupported) UploadPart(context.Context, *s3.UploadPartInput) (etag string, err error) {
	return "", s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) UploadPartCopy(context.Context, *s3.UploadPartCopyInput) (s3response.CopyObjectResult, error) {
	return s3response.CopyObjectResult{}, s3err.GetAPIError(s3err.ErrNotImplemented)
}

func (BackendUnsupported) PutObject(context.Context, *s3.PutObjectInput) (string, error) {
	return "", s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) HeadObject(context.Context, *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) GetObject(context.Context, *s3.GetObjectInput, io.Writer) (*s3.GetObjectOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) GetObjectAcl(context.Context, *s3.GetObjectAclInput) (*s3.GetObjectAclOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) GetObjectAttributes(context.Context, *s3.GetObjectAttributesInput) (*s3.GetObjectAttributesOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) CopyObject(context.Context, *s3.CopyObjectInput) (*s3.CopyObjectOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) ListObjects(context.Context, *s3.ListObjectsInput) (*s3.ListObjectsOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) ListObjectsV2(context.Context, *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) DeleteObject(context.Context, *s3.DeleteObjectInput) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) DeleteObjects(context.Context, *s3.DeleteObjectsInput) (s3response.DeleteObjectsResult, error) {
	return s3response.DeleteObjectsResult{}, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) PutObjectAcl(context.Context, *s3.PutObjectAclInput) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}

func (BackendUnsupported) RestoreObject(context.Context, *s3.RestoreObjectInput) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) SelectObjectContent(context.Context, *s3.SelectObjectContentInput) (s3response.SelectObjectContentResult, error) {
	return s3response.SelectObjectContentResult{}, s3err.GetAPIError(s3err.ErrNotImplemented)
}

func (BackendUnsupported) GetTags(_ context.Context, bucket, object string) (map[string]string, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) SetTags(_ context.Context, bucket, object string, tags map[string]string) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) RemoveTags(_ context.Context, bucket, object string) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
