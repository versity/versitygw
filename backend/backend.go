package backend

import (
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/scoutgw/s3err"
)

//go:generate moq -out backend_moq_test.go . Backend
//go:generate moq -out ../s3api/controllers/backend_moq_test.go -pkg controllers . Backend
type Backend interface {
	fmt.Stringer
	GetIAMConfig() ([]byte, error)
	Shutdown()

	ListBuckets() (*s3.ListBucketsOutput, error)
	HeadBucket(bucket string) (*s3.HeadBucketOutput, error)
	GetBucketAcl(bucket string) (*s3.GetBucketAclOutput, error)
	PutBucket(bucket string) error
	DeleteBucket(bucket string) error

	CreateMultipartUpload(*s3.CreateMultipartUploadInput) (*s3.CreateMultipartUploadOutput, error)
	CompleteMultipartUpload(bucket, object, uploadID string, parts []types.Part) (*s3.CompleteMultipartUploadOutput, error)
	AbortMultipartUpload(*s3.AbortMultipartUploadInput) error
	ListMultipartUploads(output *s3.ListMultipartUploadsInput) (*s3.ListMultipartUploadsOutput, error)
	ListObjectParts(bucket, object, uploadID string, partNumberMarker int, maxParts int) (*s3.ListPartsOutput, error)
	CopyPart(srcBucket, srcObject, DstBucket, uploadID, rangeHeader string, part int) (*types.CopyPartResult, error)
	PutObjectPart(bucket, object, uploadID string, part int, length int64, r io.Reader) (etag string, err error)

	PutObject(*s3.PutObjectInput) (string, error)
	HeadObject(bucket, object string, etag string) (*s3.HeadObjectOutput, error)
	GetObject(bucket, object string, startOffset, length int64, writer io.Writer) (*s3.GetObjectOutput, error)
	GetObjectAcl(bucket, object string) (*s3.GetObjectAclOutput, error)
	GetObjectAttributes(bucket, object string, attributes []string) (*s3.GetObjectAttributesOutput, error)
	CopyObject(srcBucket, srcObject, DstBucket, dstObject string) (*s3.CopyObjectOutput, error)
	ListObjects(bucket, prefix, marker, delim string, maxkeys int) (*s3.ListObjectsOutput, error)
	ListObjectsV2(bucket, prefix, marker, delim string, maxkeys int) (*s3.ListObjectsV2Output, error)
	DeleteObject(bucket, object string) error
	DeleteObjects(bucket string, objects *s3.DeleteObjectsInput) error
	PutBucketAcl(*s3.PutBucketAclInput) error
	PutObjectAcl(*s3.PutObjectAclInput) error
	RestoreObject(bucket, object string, restoreRequest *s3.RestoreObjectInput) error
	UploadPart(bucket, object, uploadId string, Body io.ReadSeeker) (*s3.UploadPartOutput, error)
	UploadPartCopy(*s3.UploadPartCopyInput) (*s3.UploadPartCopyOutput, error)

	IsTaggingSupported() bool
	GetTags(bucket, object string) (map[string]string, error)
	SetTags(bucket, object string, tags map[string]string) error
	RemoveTags(bucket, object string) error
}

type BackendUnsupported struct{}

var _ Backend = &BackendUnsupported{}

func New() Backend {
	return &BackendUnsupported{}
}

func (BackendUnsupported) GetIAMConfig() ([]byte, error) {
	return nil, fmt.Errorf("not supported")
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
func (BackendUnsupported) UploadPart(bucket, object, uploadId string, Body io.ReadSeeker) (*s3.UploadPartOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) GetBucketAcl(bucket string) (*s3.GetBucketAclOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) HeadBucket(bucket string) (*s3.HeadBucketOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) PutBucket(bucket string) error {
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
func (BackendUnsupported) ListMultipartUploads(output *s3.ListMultipartUploadsInput) (*s3.ListMultipartUploadsOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) ListObjectParts(bucket, object, uploadID string, partNumberMarker int, maxParts int) (*s3.ListPartsOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
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
func (BackendUnsupported) GetObject(bucket, object string, startOffset, length int64, writer io.Writer) (*s3.GetObjectOutput, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
func (BackendUnsupported) HeadObject(bucket, object string, etag string) (*s3.HeadObjectOutput, error) {
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

func (BackendUnsupported) IsTaggingSupported() bool { return false }
func (BackendUnsupported) GetTags(bucket, object string) (map[string]string, error) {
	return nil, fmt.Errorf("not supported")
}
func (BackendUnsupported) SetTags(bucket, object string, tags map[string]string) error {
	return fmt.Errorf("not supported")
}
func (BackendUnsupported) RemoveTags(bucket, object string) error {
	return fmt.Errorf("not supported")
}
