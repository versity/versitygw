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
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend/auth"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

//go:generate moq -out backend_moq_test.go . Backend
//go:generate moq -out ../s3api/controllers/backend_moq_test.go -pkg controllers . Backend
type Backend interface {
	fmt.Stringer
	Shutdown()

	ListBuckets() (*s3.ListBucketsOutput, error)
	HeadBucket(bucket string) (*s3.HeadBucketOutput, error)
	GetBucketAcl(bucket string) (*auth.GetBucketAclOutput, error)
	PutBucket(bucket, owner string) error
	PutBucketAcl(*s3.PutBucketAclInput) error
	DeleteBucket(bucket string) error

	CreateMultipartUpload(*s3.CreateMultipartUploadInput) (*s3.CreateMultipartUploadOutput, error)
	CompleteMultipartUpload(bucket, object, uploadID string, parts []types.Part) (*s3.CompleteMultipartUploadOutput, error)
	AbortMultipartUpload(*s3.AbortMultipartUploadInput) error
	ListMultipartUploads(output *s3.ListMultipartUploadsInput) (s3response.ListMultipartUploadsResponse, error)
	ListObjectParts(bucket, object, uploadID string, partNumberMarker int, maxParts int) (s3response.ListPartsResponse, error)
	CopyPart(srcBucket, srcObject, DstBucket, uploadID, rangeHeader string, part int) (*types.CopyPartResult, error)
	PutObjectPart(bucket, object, uploadID string, part int, length int64, r io.Reader) (etag string, err error)
	UploadPartCopy(*s3.UploadPartCopyInput) (*s3.UploadPartCopyOutput, error)

	PutObject(*s3.PutObjectInput) (string, error)
	HeadObject(bucket, object string) (*s3.HeadObjectOutput, error)
	GetObject(bucket, object, acceptRange string, writer io.Writer) (*s3.GetObjectOutput, error)
	GetObjectAcl(bucket, object string) (*s3.GetObjectAclOutput, error)
	GetObjectAttributes(bucket, object string, attributes []string) (*s3.GetObjectAttributesOutput, error)
	CopyObject(srcBucket, srcObject, DstBucket, dstObject string) (*s3.CopyObjectOutput, error)
	ListObjects(bucket, prefix, marker, delim string, maxkeys int) (*s3.ListObjectsOutput, error)
	ListObjectsV2(bucket, prefix, marker, delim string, maxkeys int) (*s3.ListObjectsV2Output, error)
	DeleteObject(bucket, object string) error
	DeleteObjects(bucket string, objects *s3.DeleteObjectsInput) error
	PutObjectAcl(*s3.PutObjectAclInput) error
	RestoreObject(bucket, object string, restoreRequest *s3.RestoreObjectInput) error

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
func (BackendUnsupported) ListBuckets() (*s3.ListBucketsOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) PutBucketAcl(*s3.PutBucketAclInput) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) PutObjectAcl(*s3.PutObjectAclInput) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) RestoreObject(bucket, object string, restoreRequest *s3.RestoreObjectInput) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) UploadPartCopy(*s3.UploadPartCopyInput) (*s3.UploadPartCopyOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) GetBucketAcl(bucket string) (*auth.GetBucketAclOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) HeadBucket(bucket string) (*s3.HeadBucketOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) PutBucket(bucket, owner string) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) DeleteBucket(bucket string) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}

func (BackendUnsupported) CreateMultipartUpload(input *s3.CreateMultipartUploadInput) (*s3.CreateMultipartUploadOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) CompleteMultipartUpload(bucket, object, uploadID string, parts []types.Part) (*s3.CompleteMultipartUploadOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) AbortMultipartUpload(input *s3.AbortMultipartUploadInput) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) ListMultipartUploads(output *s3.ListMultipartUploadsInput) (s3response.ListMultipartUploadsResponse, error) {
	return s3response.ListMultipartUploadsResponse{}, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) ListObjectParts(bucket, object, uploadID string, partNumberMarker int, maxParts int) (s3response.ListPartsResponse, error) {
	return s3response.ListPartsResponse{}, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) CopyPart(srcBucket, srcObject, DstBucket, uploadID, rangeHeader string, part int) (*types.CopyPartResult, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) PutObjectPart(bucket, object, uploadID string, part int, length int64, r io.Reader) (etag string, err error) {
	return "", s3err.GetAPIError(s3err.ErrNotImplemented)
}

func (BackendUnsupported) PutObject(*s3.PutObjectInput) (string, error) {
	return "", s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) DeleteObject(bucket, object string) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) DeleteObjects(bucket string, objects *s3.DeleteObjectsInput) error {
	return s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) GetObject(bucket, object, acceptRange string, writer io.Writer) (*s3.GetObjectOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) HeadObject(bucket, object string) (*s3.HeadObjectOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) GetObjectAcl(bucket, object string) (*s3.GetObjectAclOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) GetObjectAttributes(bucket, object string, attributes []string) (*s3.GetObjectAttributesOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) CopyObject(srcBucket, srcObject, DstBucket, dstObject string) (*s3.CopyObjectOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) ListObjects(bucket, prefix, marker, delim string, maxkeys int) (*s3.ListObjectsOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) ListObjectsV2(bucket, prefix, marker, delim string, maxkeys int) (*s3.ListObjectsV2Output, error) {
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
