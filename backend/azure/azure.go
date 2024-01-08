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

package azure

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/streaming"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

const aclKey string = "Acl"

type Azure struct {
	backend.BackendUnsupported

	client     *azblob.Client
	creds      *azblob.SharedKeyCredential
	serviceURL string
}

var _ backend.Backend = &Azure{}

func New(accountName, accountKey, serviceURL string) (*Azure, error) {
	cred, err := azblob.NewSharedKeyCredential(accountName, accountKey)
	if err != nil {
		return nil, fmt.Errorf("init credentials: %w", err)
	}

	client, err := azblob.NewClientWithSharedKeyCredential(serviceURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("init client: %w", err)
	}

	return &Azure{client: client, serviceURL: serviceURL, creds: cred}, nil
}

func (az *Azure) Shutdown() {}

func (az *Azure) String() string {
	return "Azure Blob Gateway"
}

func (az *Azure) CreateBucket(ctx context.Context, input *s3.CreateBucketInput) error {
	owner := string(input.ObjectOwnership)
	acl := auth.ACL{ACL: "private", Owner: owner, Grantees: []auth.Grantee{}}
	jsonACL, err := json.Marshal(acl)
	if err != nil {
		return fmt.Errorf("marshal acl: %w", err)
	}
	meta := map[string]*string{
		aclKey: getStringPtr(string(jsonACL)),
	}
	_, err = az.client.CreateContainer(ctx, *input.Bucket, &container.CreateOptions{Metadata: meta})
	return azureErrToS3Err(err)
}

func (az *Azure) ListBuckets(ctx context.Context, owner string, isAdmin bool) (s3response.ListAllMyBucketsResult, error) {
	pager := az.client.NewListContainersPager(nil)

	var buckets []s3response.ListAllMyBucketsEntry
	var result s3response.ListAllMyBucketsResult

	for pager.More() {
		resp, err := pager.NextPage(ctx)
		if err != nil {
			return result, azureErrToS3Err(err)
		}
		for _, v := range resp.ContainerItems {
			buckets = append(buckets, s3response.ListAllMyBucketsEntry{
				Name: *v.Name,
				// TODO: using modification date here instead of creation, is that ok?
				CreationDate: *v.Properties.LastModified,
			})
		}
	}

	result.Buckets.Bucket = buckets

	return result, nil
}

func (az *Azure) HeadBucket(ctx context.Context, input *s3.HeadBucketInput) (*s3.HeadBucketOutput, error) {
	client, err := az.getContainerClient(*input.Bucket)
	if err != nil {
		return nil, err
	}

	_, err = client.GetProperties(ctx, nil)
	if err != nil {
		return nil, azureErrToS3Err(err)
	}

	return &s3.HeadBucketOutput{}, nil
}

func (az *Azure) DeleteBucket(ctx context.Context, input *s3.DeleteBucketInput) error {
	_, err := az.client.DeleteContainer(ctx, *input.Bucket, nil)
	return azureErrToS3Err(err)
}

func (az *Azure) PutObject(ctx context.Context, po *s3.PutObjectInput) (string, error) {
	tags, err := parseTags(po.Tagging)
	if err != nil {
		return "", err
	}

	uploadResp, err := az.client.UploadStream(ctx, *po.Bucket, *po.Key, po.Body, &blockblob.UploadStreamOptions{
		Metadata: parseMetadata(po.Metadata),
		Tags:     tags,
	})
	if err != nil {
		return "", azureErrToS3Err(err)
	}

	return string(*uploadResp.ETag), nil
}

func (az *Azure) GetObject(ctx context.Context, input *s3.GetObjectInput, writer io.Writer) (*s3.GetObjectOutput, error) {
	var opts *azblob.DownloadStreamOptions
	if input.Range != nil {
		offset, count, err := parseRange(*input.Range)
		if err != nil {
			return nil, err
		}
		opts = &azblob.DownloadStreamOptions{
			Range: blob.HTTPRange{
				Count:  count,
				Offset: offset,
			},
		}
	}
	blobDownloadResponse, err := az.client.DownloadStream(ctx, *input.Bucket, *input.Key, opts)
	if err != nil {
		return nil, azureErrToS3Err(err)
	}
	defer blobDownloadResponse.Body.Close()

	_, err = io.Copy(writer, blobDownloadResponse.Body)
	if err != nil {
		return nil, fmt.Errorf("copy data: %w", err)
	}

	var tagcount int32
	if blobDownloadResponse.TagCount != nil {
		tagcount = int32(*blobDownloadResponse.TagCount)
	}

	return &s3.GetObjectOutput{
		AcceptRanges:    blobDownloadResponse.AcceptRanges,
		ContentLength:   blobDownloadResponse.ContentLength,
		ContentEncoding: blobDownloadResponse.ContentEncoding,
		ContentType:     blobDownloadResponse.ContentType,
		ETag:            (*string)(blobDownloadResponse.ETag),
		LastModified:    blobDownloadResponse.LastModified,
		Metadata:        parseAzMetadata(blobDownloadResponse.Metadata),
		TagCount:        &tagcount,
		ContentRange:    blobDownloadResponse.ContentRange,
	}, nil
}

func (az *Azure) HeadObject(ctx context.Context, input *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
	client, err := az.getBlobClient(*input.Bucket, *input.Key)
	if err != nil {
		return nil, err
	}

	resp, err := client.GetProperties(ctx, nil)
	if err != nil {
		return nil, azureErrToS3Err(err)
	}

	return &s3.HeadObjectOutput{
		AcceptRanges:       resp.AcceptRanges,
		ContentLength:      resp.ContentLength,
		ContentType:        resp.ContentType,
		ContentEncoding:    resp.ContentEncoding,
		ContentLanguage:    resp.ContentLanguage,
		ContentDisposition: resp.ContentDisposition,
		ETag:               (*string)(resp.ETag),
		LastModified:       resp.LastModified,
		Metadata:           parseAzMetadata(resp.Metadata),
		Expires:            resp.ExpiresOn,
	}, nil
}

func (az *Azure) ListObjects(ctx context.Context, input *s3.ListObjectsInput) (*s3.ListObjectsOutput, error) {
	pager := az.client.NewListBlobsFlatPager(*input.Bucket, &azblob.ListBlobsFlatOptions{
		Marker:     input.Marker,
		MaxResults: input.MaxKeys,
		Prefix:     input.Prefix,
	})

	var objects []types.Object
	var nextMarker *string

	for pager.More() {
		resp, err := pager.NextPage(ctx)
		if err != nil {
			return nil, azureErrToS3Err(err)
		}
		for _, v := range resp.Segment.BlobItems {
			nextMarker = resp.NextMarker
			objects = append(objects, types.Object{
				ETag:         (*string)(v.Properties.ETag),
				Key:          v.Name,
				LastModified: v.Properties.LastModified,
				Size:         v.Properties.ContentLength,
				StorageClass: types.ObjectStorageClass(*v.Properties.AccessTier),
			})
		}
	}

	// TODO: generate common prefixes when appropriate
	// TODO: set truncated response status

	return &s3.ListObjectsOutput{
		Contents:   objects,
		Marker:     input.Marker,
		MaxKeys:    input.MaxKeys,
		Name:       input.Bucket,
		NextMarker: nextMarker,
		Prefix:     input.Prefix,
	}, nil
}

func (az *Azure) ListObjectsV2(ctx context.Context, input *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
	pager := az.client.NewListBlobsFlatPager(*input.Bucket, &azblob.ListBlobsFlatOptions{
		Marker:     input.ContinuationToken,
		MaxResults: input.MaxKeys,
		Prefix:     input.Prefix,
	})

	var objects []types.Object
	var nextMarker *string

	for pager.More() {
		resp, err := pager.NextPage(ctx)
		if err != nil {
			return nil, azureErrToS3Err(err)
		}
		for _, v := range resp.Segment.BlobItems {
			nextMarker = resp.NextMarker
			objects = append(objects, types.Object{
				ETag:         (*string)(v.Properties.ETag),
				Key:          v.Name,
				LastModified: v.Properties.LastModified,
				Size:         v.Properties.ContentLength,
				StorageClass: types.ObjectStorageClass(*v.Properties.AccessTier),
			})
		}
	}

	// TODO: generate common prefixes when appropriate
	// TODO: set truncated response status

	return &s3.ListObjectsV2Output{
		Contents:              objects,
		ContinuationToken:     input.ContinuationToken,
		MaxKeys:               input.MaxKeys,
		Name:                  input.Bucket,
		NextContinuationToken: nextMarker,
		Prefix:                input.Prefix,
	}, nil
}

func (az *Azure) DeleteObject(ctx context.Context, input *s3.DeleteObjectInput) error {
	_, err := az.client.DeleteBlob(ctx, *input.Bucket, *input.Key, nil)
	return azureErrToS3Err(err)
}

func (az *Azure) DeleteObjects(ctx context.Context, input *s3.DeleteObjectsInput) (s3response.DeleteObjectsResult, error) {
	delResult, errs := []types.DeletedObject{}, []types.Error{}
	for _, obj := range input.Delete.Objects {
		err := az.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: input.Bucket,
			Key:    obj.Key,
		})
		if err == nil {
			delResult = append(delResult, types.DeletedObject{Key: obj.Key})
		} else {
			serr, ok := err.(s3err.APIError)
			if ok {
				errs = append(errs, types.Error{
					Key:     obj.Key,
					Code:    &serr.Code,
					Message: &serr.Description,
				})
			} else {
				errs = append(errs, types.Error{
					Key:     obj.Key,
					Code:    getStringPtr("InternalError"),
					Message: getStringPtr(err.Error()),
				})
			}
		}
	}

	return s3response.DeleteObjectsResult{
		Deleted: delResult,
		Error:   errs,
	}, nil
}

func (az *Azure) CopyObject(ctx context.Context, input *s3.CopyObjectInput) (*s3.CopyObjectOutput, error) {
	client, err := az.getBlobClient(*input.Bucket, *input.Key)
	if err != nil {
		return nil, err
	}

	tags, err := parseTags(input.Tagging)
	if err != nil {
		return nil, err
	}

	resp, err := client.CopyFromURL(ctx, az.serviceURL+"/"+*input.CopySource, &blob.CopyFromURLOptions{
		BlobTags: tags,
		Metadata: parseMetadata(input.Metadata),
	})
	if err != nil {
		return nil, azureErrToS3Err(err)
	}

	return &s3.CopyObjectOutput{
		CopyObjectResult: &types.CopyObjectResult{
			ETag:         (*string)(resp.ETag),
			LastModified: resp.LastModified,
		},
	}, nil
}

func (az *Azure) PutObjectTagging(ctx context.Context, bucket, object string, tags map[string]string) error {
	client, err := az.getBlobClient(bucket, object)
	if err != nil {
		return err
	}

	_, err = client.SetTags(ctx, tags, nil)
	if err != nil {
		return azureErrToS3Err(err)
	}

	return nil
}

func (az *Azure) GetObjectTagging(ctx context.Context, bucket, object string) (map[string]string, error) {
	client, err := az.getBlobClient(bucket, object)
	if err != nil {
		return nil, err
	}

	tags, err := client.GetTags(ctx, nil)
	if err != nil {
		return nil, azureErrToS3Err(err)
	}

	return parseAzTags(tags.BlobTagSet), nil
}

func (az *Azure) DeleteObjectTagging(ctx context.Context, bucket, object string) error {
	client, err := az.getBlobClient(bucket, object)
	if err != nil {
		return err
	}

	_, err = client.SetTags(ctx, map[string]string{}, nil)
	if err != nil {
		return azureErrToS3Err(err)
	}

	return nil
}

// Multipart upload starts with UploadPart action.
// Each part is translated into an uncommitted block in a newly created blob in staging area
func (az *Azure) UploadPart(ctx context.Context, input *s3.UploadPartInput) (etag string, err error) {
	client, err := az.getBlockBlobClient(*input.Bucket, *input.Key)
	if err != nil {
		return "", err
	}

	rdr, err := getReadSeekCloser(input.Body)
	if err != nil {
		return "", err
	}

	// block id serves as etag here
	etag = blockIDInt32ToBase64(*input.PartNumber)
	_, err = client.StageBlock(ctx, etag, rdr, nil)
	if err != nil {
		return "", azureErrToS3Err(err)
	}

	return etag, nil
}

func (az *Azure) UploadPartCopy(ctx context.Context, input *s3.UploadPartCopyInput) (s3response.CopyObjectResult, error) {
	client, err := az.getBlockBlobClient(*input.Bucket, *input.Key)
	if err != nil {
		return s3response.CopyObjectResult{}, nil
	}

	//TODO: handle block copy by range
	//TODO: the action returns not implemented on azurite, maybe in production this will work?
	// UploadId here is the source block id
	_, err = client.StageBlockFromURL(ctx, *input.UploadId, *input.CopySource, nil)
	if err != nil {
		return s3response.CopyObjectResult{}, azureErrToS3Err(err)
	}

	return s3response.CopyObjectResult{}, nil
}

// Lists all uncommitted parts from the blob
func (az *Azure) ListParts(ctx context.Context, input *s3.ListPartsInput) (s3response.ListPartsResult, error) {
	client, err := az.getBlockBlobClient(*input.Bucket, *input.Key)
	if err != nil {
		return s3response.ListPartsResult{}, nil
	}

	resp, err := client.GetBlockList(ctx, blockblob.BlockListTypeUncommitted, nil)
	if err != nil {
		return s3response.ListPartsResult{}, azureErrToS3Err(err)
	}
	var partNumberMarker int
	var nextPartNumberMarker int
	var maxParts int32 = math.MaxInt32
	var isTruncated bool

	if *input.PartNumberMarker != "" {
		partNumberMarker, err = strconv.Atoi(*input.PartNumberMarker)
		if err != nil {
			return s3response.ListPartsResult{}, s3err.GetAPIError(s3err.ErrInvalidPartNumberMarker)
		}
	}
	if input.MaxParts != nil {
		maxParts = *input.MaxParts
	}

	parts := []s3response.Part{}
	for _, el := range resp.BlockList.UncommittedBlocks {
		partNumber, err := decodeBlockId(*el.Name)
		if err != nil {
			return s3response.ListPartsResult{}, err
		}
		if partNumberMarker != 0 && partNumberMarker < partNumber {
			continue
		}
		if len(parts) >= int(maxParts) {
			nextPartNumberMarker = partNumber
			isTruncated = true
			break
		}
		parts = append(parts, s3response.Part{
			Size:       *el.Size,
			ETag:       *el.Name,
			PartNumber: partNumber,
		})
	}
	return s3response.ListPartsResult{
		Bucket:               *input.Bucket,
		Key:                  *input.Key,
		Parts:                parts,
		NextPartNumberMarker: nextPartNumberMarker,
		PartNumberMarker:     partNumberMarker,
		IsTruncated:          isTruncated,
		MaxParts:             int(maxParts),
	}, nil
}

// Lists all block blobs, which has uncommitted blocks
func (az *Azure) ListMultipartUploads(ctx context.Context, input *s3.ListMultipartUploadsInput) (s3response.ListMultipartUploadsResult, error) {
	client, err := az.getContainerClient(*input.Bucket)
	if err != nil {
		return s3response.ListMultipartUploadsResult{}, nil
	}
	pager := client.NewListBlobsFlatPager(&container.ListBlobsFlatOptions{
		Include: container.ListBlobsInclude{UncommittedBlobs: true},
		Marker:  input.KeyMarker,
		Prefix:  input.Prefix,
	})

	var maxUploads int32
	if input.MaxUploads != nil {
		maxUploads = *input.MaxUploads
	}
	isTruncated := false
	nextKeyMarker := ""
	uploads := []s3response.Upload{}
	breakFlag := false

	for pager.More() {
		resp, err := pager.NextPage(ctx)
		if err != nil {
			return s3response.ListMultipartUploadsResult{}, azureErrToS3Err(err)
		}
		for _, el := range resp.Segment.BlobItems {
			if el.Properties.AccessTier == nil {
				if len(uploads) >= int(*input.MaxUploads) && maxUploads != 0 {
					breakFlag = true
					nextKeyMarker = *el.Name
					isTruncated = true
					break
				}
				uploads = append(uploads, s3response.Upload{
					Key:       *el.Name,
					Initiated: el.Properties.CreationTime.Format(backend.RFC3339TimeFormat),
				})
			}
		}
		if breakFlag {
			break
		}
	}
	return s3response.ListMultipartUploadsResult{
		Uploads:       uploads,
		Bucket:        *input.Bucket,
		KeyMarker:     *input.KeyMarker,
		NextKeyMarker: nextKeyMarker,
		MaxUploads:    int(maxUploads),
		Prefix:        *input.Prefix,
		IsTruncated:   isTruncated,
		Delimiter:     *input.Delimiter,
	}, nil
}

// Deletes the block blob with committed/uncommitted blocks
func (az *Azure) AbortMultipartUpload(ctx context.Context, input *s3.AbortMultipartUploadInput) error {
	_, err := az.client.DeleteBlob(ctx, *input.Bucket, *input.Key, nil)
	if err != nil {
		return azureErrToS3Err(err)
	}
	return nil
}

// Commits all the uncommitted blocks inside the block blob
// And moves the block blob from staging area into the blobs list
// It indicates the end of the multipart upload
func (az *Azure) CompleteMultipartUpload(ctx context.Context, input *s3.CompleteMultipartUploadInput) (*s3.CompleteMultipartUploadOutput, error) {
	client, err := az.getBlockBlobClient(*input.Bucket, *input.Key)
	if err != nil {
		return nil, err
	}
	blockIds := []string{}
	for _, el := range input.MultipartUpload.Parts {
		blockIds = append(blockIds, *el.ETag)
	}
	resp, err := client.CommitBlockList(ctx, blockIds, nil)
	if err != nil {
		return nil, azureErrToS3Err(err)
	}

	return &s3.CompleteMultipartUploadOutput{
		Bucket: input.Bucket,
		Key:    input.Key,
		ETag:   (*string)(resp.ETag),
	}, nil
}

func (az *Azure) PutBucketAcl(ctx context.Context, bucket string, data []byte) error {
	client, err := az.getContainerClient(bucket)
	if err != nil {
		return err
	}
	meta := map[string]*string{
		aclKey: getStringPtr(string(data)),
	}
	_, err = client.SetMetadata(ctx, &container.SetMetadataOptions{
		Metadata: meta,
	})
	if err != nil {
		return azureErrToS3Err(err)
	}
	return nil
}

func (az *Azure) GetBucketAcl(ctx context.Context, input *s3.GetBucketAclInput) ([]byte, error) {
	client, err := az.getContainerClient(*input.Bucket)
	if err != nil {
		return nil, err
	}
	props, err := client.GetProperties(ctx, nil)
	if err != nil {
		return nil, azureErrToS3Err(err)
	}

	aclPtr, ok := props.Metadata[aclKey]
	if !ok {
		return nil, s3err.GetAPIError(s3err.ErrInternalError)
	}

	return []byte(*aclPtr), nil
}

func (az *Azure) getBlobClient(container, blb string) (*blob.Client, error) {
	return blob.NewClientWithSharedKeyCredential(fmt.Sprintf("%v/%v/%v", az.serviceURL, container, blb), az.creds, nil)
}

func (az *Azure) getContainerClient(ctr string) (*container.Client, error) {
	return container.NewClientWithSharedKeyCredential(fmt.Sprintf("%v/%v", az.serviceURL, ctr), az.creds, nil)
}

func (az *Azure) getBlockBlobClient(container, blob string) (*blockblob.Client, error) {
	return blockblob.NewClientWithSharedKeyCredential(fmt.Sprintf("%v/%v/%v", az.serviceURL, container, blob), az.creds, nil)
}

func parseMetadata(m map[string]string) map[string]*string {
	if m == nil {
		return nil
	}

	meta := make(map[string]*string)

	for k, v := range m {
		meta[k] = &v
	}
	return meta
}

func parseAzMetadata(m map[string]*string) map[string]string {
	if m == nil {
		return nil
	}

	meta := make(map[string]string)

	for k, v := range m {
		meta[k] = *v
	}
	return meta
}

func parseTags(tagstr *string) (map[string]string, error) {
	tagsStr := getString(tagstr)
	tags := make(map[string]string)

	if tagsStr != "" {
		tagParts := strings.Split(tagsStr, "&")
		for _, prt := range tagParts {
			p := strings.Split(prt, "=")
			if len(p) != 2 {
				return nil, s3err.GetAPIError(s3err.ErrInvalidTag)
			}
			tags[p[0]] = p[1]
		}
	}

	return tags, nil
}

func parseAzTags(tagSet []*blob.Tags) map[string]string {
	tags := map[string]string{}
	for _, tag := range tagSet {
		tags[*tag.Key] = *tag.Value
	}

	return tags
}

func getString(str *string) string {
	if str == nil {
		return ""
	}
	return *str
}

func getStringPtr(str string) *string {
	return &str
}

// Parses azure ResponseError into AWS APIError
func azureErrToS3Err(apiErr error) error {
	var azErr *azcore.ResponseError
	if !errors.As(apiErr, &azErr) {
		return apiErr
	}

	resp := s3err.APIError{
		Code:           azErr.ErrorCode,
		Description:    azErr.RawResponse.Status,
		HTTPStatusCode: azErr.StatusCode,
	}
	fmt.Println(resp)
	return resp
}

// Converts io.Reader into io.ReadSeekCloser
func getReadSeekCloser(input io.Reader) (io.ReadSeekCloser, error) {
	var buffer bytes.Buffer
	_, err := io.Copy(&buffer, input)
	if err != nil {
		return nil, err
	}

	return streaming.NopCloser(bytes.NewReader(buffer.Bytes())), nil
}

// Creates a new Base64 encoded block id from a 32 bit integer
func blockIDInt32ToBase64(blockID int32) string {
	binaryBlockID := &[4]byte{} // All block IDs are 4 bytes long
	binary.LittleEndian.PutUint32(binaryBlockID[:], uint32(blockID))
	return base64.StdEncoding.EncodeToString(binaryBlockID[:])
}

// Decodes Base64 encoded string to integer
func decodeBlockId(blockID string) (int, error) {
	slice, err := base64.StdEncoding.DecodeString(blockID)
	if err != nil {
		return 0, nil
	}

	return int(binary.LittleEndian.Uint32(slice)), nil
}

func parseRange(rg string) (offset, count int64, err error) {
	rangeKv := strings.Split(rg, "=")

	if len(rangeKv) < 2 {
		return 0, 0, s3err.GetAPIError(s3err.ErrInvalidRange)
	}

	bRange := strings.Split(rangeKv[1], "-")
	if len(bRange) < 1 || len(bRange) > 2 {
		return 0, 0, s3err.GetAPIError(s3err.ErrInvalidRange)
	}

	offset, err = strconv.ParseInt(bRange[0], 10, 64)
	if err != nil {
		return 0, 0, s3err.GetAPIError(s3err.ErrInvalidRange)
	}

	if len(bRange) == 1 || bRange[1] == "" {
		return offset, count, nil
	}

	count, err = strconv.ParseInt(bRange[1], 10, 64)
	if err != nil {
		return 0, 0, s3err.GetAPIError(s3err.ErrInvalidRange)
	}

	if count < offset {
		return 0, 0, s3err.GetAPIError(s3err.ErrInvalidRange)
	}

	return offset, count - offset + 1, nil
}
