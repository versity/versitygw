package backend

import (
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/versity/scoutgw/s3err"
	"github.com/versity/scoutgw/s3response"
)

type Backend interface {
	fmt.Stringer
	GetIAMConfig() ([]byte, error)
	Shutdown()

	ListBuckets() (*s3response.ListAllMyBucketsList, s3err.ErrorCode)
	PutBucket(bucket string) s3err.ErrorCode
	DeleteBucket(bucket string) s3err.ErrorCode

	CreateMultipartUpload(*s3.CreateMultipartUploadInput) (*s3response.InitiateMultipartUploadResponse, s3err.ErrorCode)
	CompleteMultipartUpload(bucket, object, uploadID string, parts []s3response.Part) (*s3response.CompleteMultipartUploadResponse, s3err.ErrorCode)
	AbortMultipartUpload(*s3.AbortMultipartUploadInput) s3err.ErrorCode
	ListMultipartUploads(*s3.ListMultipartUploadsInput) (*s3response.ListMultipartUploadsResponse, s3err.ErrorCode)
	ListObjectParts(bucket, object, uploadID string, partNumberMarker int, maxParts int) (*s3response.ListPartsResponse, s3err.ErrorCode)
	CopyPart(srcBucket, srcObject, DstBucket, uploadID, rangeHeader string, part int) (*s3response.CopyObjectPartResponse, s3err.ErrorCode)
	PutObjectPart(bucket, object, uploadID string, part int, r io.Reader) (etag string, err s3err.ErrorCode)

	PutObject(bucket, object string, r io.Reader) (string, s3err.ErrorCode)
	GetObject(bucket, object string, startOffset, length int64, writer io.Writer, etag string) (*s3response.GetObjectResponse, s3err.ErrorCode)
	CopyObject(srcBucket, srcObject, DstBucket, dstObject string) (*s3response.CopyObjectResponse, s3err.ErrorCode)
	ListObjects(bucket, prefix, marker, delim string, maxkeys int) (*s3response.ListBucketResult, s3err.ErrorCode)
	ListObjectsV2(bucket, prefix, marker, delim string, maxkeys int) (*s3response.ListBucketResultV2, s3err.ErrorCode)
	DeleteObject(bucket, object string) s3err.ErrorCode
	DeleteObjects(bucket string, objects []string) s3err.ErrorCode

	IsTaggingSupported() bool
	GetTags(bucket, object string) (map[string]string, error)
	SetTags(bucket, object string, tags map[string]string) error
	RemoveTags(bucket, object string) error
}

type BackendUnsupported struct{}

func New() Backend {
	return &BackendUnsupported{}
}

func (BackendUnsupported) GetIAMConfig() ([]byte, error) {
	return nil, fmt.Errorf("not supported")
}
func (BackendUnsupported) SubscribeIAMEvents() {}
func (BackendUnsupported) Shutdown()           {}
func (BackendUnsupported) String() string {
	return "Unsupported"
}

func (BackendUnsupported) ListBuckets() (*s3response.ListAllMyBucketsList, s3err.ErrorCode) {
	return nil, s3err.ErrNotImplemented
}
func (BackendUnsupported) PutBucket(bucket string) s3err.ErrorCode {
	return s3err.ErrNotImplemented
}
func (BackendUnsupported) DeleteBucket(bucket string) s3err.ErrorCode {
	return s3err.ErrNotImplemented
}

func (BackendUnsupported) CreateMultipartUpload(*s3.CreateMultipartUploadInput) (*s3response.InitiateMultipartUploadResponse, s3err.ErrorCode) {
	return nil, s3err.ErrNotImplemented
}
func (BackendUnsupported) CompleteMultipartUpload(bucket, object, uploadID string, parts []s3response.Part) (*s3response.CompleteMultipartUploadResponse, s3err.ErrorCode) {
	return nil, s3err.ErrNotImplemented
}
func (BackendUnsupported) AbortMultipartUpload(*s3.AbortMultipartUploadInput) s3err.ErrorCode {
	return s3err.ErrNotImplemented
}
func (BackendUnsupported) ListMultipartUploads(*s3.ListMultipartUploadsInput) (*s3response.ListMultipartUploadsResponse, s3err.ErrorCode) {
	return nil, s3err.ErrNotImplemented
}
func (BackendUnsupported) ListObjectParts(bucket, object, uploadID string, partNumberMarker int, maxParts int) (*s3response.ListPartsResponse, s3err.ErrorCode) {
	return nil, s3err.ErrNotImplemented
}
func (BackendUnsupported) CopyPart(srcBucket, srcObject, DstBucket, uploadID, rangeHeader string, part int) (*s3response.CopyObjectPartResponse, s3err.ErrorCode) {
	return nil, s3err.ErrNotImplemented
}
func (BackendUnsupported) PutObjectPart(buket, object, uploadID string, part int, r io.Reader) (string, s3err.ErrorCode) {
	return "", s3err.ErrNotImplemented
}

func (BackendUnsupported) PutObject(buket, object string, r io.Reader) (string, s3err.ErrorCode) {
	return "", s3err.ErrNotImplemented
}
func (BackendUnsupported) DeleteObject(bucket, object string) s3err.ErrorCode {
	return s3err.ErrNotImplemented
}
func (BackendUnsupported) DeleteObjects(bucket string, object []string) s3err.ErrorCode {
	return s3err.ErrNotImplemented
}
func (BackendUnsupported) GetObject(bucket, object string, startOffset, length int64, writer io.Writer, etag string) (*s3response.GetObjectResponse, s3err.ErrorCode) {
	return nil, s3err.ErrNotImplemented
}
func (BackendUnsupported) CopyObject(srcBucket, srcObject, DstBucket, dstObject string) (*s3response.CopyObjectResponse, s3err.ErrorCode) {
	return nil, s3err.ErrNotImplemented
}
func (BackendUnsupported) ListObjects(bucket, prefix, marker, delim string, maxkeys int) (*s3response.ListBucketResult, s3err.ErrorCode) {
	return nil, s3err.ErrNotImplemented
}
func (BackendUnsupported) ListObjectsV2(bucket, prefix, marker, delim string, maxkeys int) (*s3response.ListBucketResultV2, s3err.ErrorCode) {
	return nil, s3err.ErrNotImplemented
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
