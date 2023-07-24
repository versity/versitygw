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

	ListBuckets(owner string, isRoot bool) (s3response.ListAllMyBucketsResult, error)
	HeadBucket(*s3.HeadBucketInput) (*s3.HeadBucketOutput, error)
	GetBucketAcl(*s3.GetBucketAclInput) ([]byte, error)
	CreateBucket(*s3.CreateBucketInput) error
	PutBucketAcl(bucket string, data []byte) error
	DeleteBucket(*s3.DeleteBucketInput) error

	CreateMultipartUpload(*s3.CreateMultipartUploadInput) (*s3.CreateMultipartUploadOutput, error)
	CompleteMultipartUpload(*s3.CompleteMultipartUploadInput) (*s3.CompleteMultipartUploadOutput, error)
	AbortMultipartUpload(*s3.AbortMultipartUploadInput) error
	ListMultipartUploads(*s3.ListMultipartUploadsInput) (s3response.ListMultipartUploadsResponse, error)
	ListParts(*s3.ListPartsInput) (s3response.ListPartsResponse, error)
	UploadPart(*s3.UploadPartInput) (etag string, err error)
	UploadPartCopy(*s3.UploadPartCopyInput) (s3response.CopyObjectResult, error)

	PutObject(*s3.PutObjectInput) (string, error)
	HeadObject(*s3.HeadObjectInput) (*s3.HeadObjectOutput, error)
	GetObject(*s3.GetObjectInput, io.Writer) (*s3.GetObjectOutput, error)
	GetObjectAcl(*s3.GetObjectAclInput) (*s3.GetObjectAclOutput, error)
	GetObjectAttributes(*s3.GetObjectAttributesInput) (*s3.GetObjectAttributesOutput, error)
	CopyObject(*s3.CopyObjectInput) (*s3.CopyObjectOutput, error)
	ListObjects(*s3.ListObjectsInput) (*s3.ListObjectsOutput, error)
	ListObjectsV2(*s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error)
	DeleteObject(*s3.DeleteObjectInput) error
	DeleteObjects(*s3.DeleteObjectsInput) error
	PutObjectAcl(*s3.PutObjectAclInput) error
	RestoreObject(*s3.RestoreObjectInput) error

	GetTags(bucket, object string) (map[string]string, error)
	SetTags(bucket, object string, tags map[string]string) error
	RemoveTags(bucket, object string) error
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
func (BackendUnsupported) ListBuckets(string, bool) (s3response.ListAllMyBucketsResult, error) {
	return s3response.ListAllMyBucketsResult{}, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) PutBucketAcl(bucket string, data []byte) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) PutObjectAcl(*s3.PutObjectAclInput) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) RestoreObject(*s3.RestoreObjectInput) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) UploadPartCopy(*s3.UploadPartCopyInput) (s3response.CopyObjectResult, error) {
	return s3response.CopyObjectResult{}, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) GetBucketAcl(*s3.GetBucketAclInput) ([]byte, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) HeadBucket(*s3.HeadBucketInput) (*s3.HeadBucketOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) CreateBucket(*s3.CreateBucketInput) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) DeleteBucket(*s3.DeleteBucketInput) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}

func (BackendUnsupported) CreateMultipartUpload(*s3.CreateMultipartUploadInput) (*s3.CreateMultipartUploadOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) CompleteMultipartUpload(*s3.CompleteMultipartUploadInput) (*s3.CompleteMultipartUploadOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) AbortMultipartUpload(*s3.AbortMultipartUploadInput) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) ListMultipartUploads(*s3.ListMultipartUploadsInput) (s3response.ListMultipartUploadsResponse, error) {
	return s3response.ListMultipartUploadsResponse{}, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) ListParts(*s3.ListPartsInput) (s3response.ListPartsResponse, error) {
	return s3response.ListPartsResponse{}, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) UploadPart(*s3.UploadPartInput) (etag string, err error) {
	return "", s3err.GetAPIError(s3err.ErrNotImplemented)
}

func (BackendUnsupported) PutObject(*s3.PutObjectInput) (string, error) {
	return "", s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) DeleteObject(*s3.DeleteObjectInput) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) DeleteObjects(*s3.DeleteObjectsInput) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) GetObject(*s3.GetObjectInput, io.Writer) (*s3.GetObjectOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) HeadObject(*s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) GetObjectAcl(*s3.GetObjectAclInput) (*s3.GetObjectAclOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) GetObjectAttributes(*s3.GetObjectAttributesInput) (*s3.GetObjectAttributesOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) CopyObject(*s3.CopyObjectInput) (*s3.CopyObjectOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) ListObjects(*s3.ListObjectsInput) (*s3.ListObjectsOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) ListObjectsV2(*s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}

func (BackendUnsupported) GetTags(bucket, object string) (map[string]string, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) SetTags(bucket, object string, tags map[string]string) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) RemoveTags(bucket, object string) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
