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
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/streaming"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/service"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// When getting container metadata with GetProperties method the sdk returns
// the first letter capital, when accessing the metadata after listing the containers
// it returns the first letter lower
type key string

const (
	keyAclCapital          key = "Acl"
	keyAclLower            key = "acl"
	keyOwnership           key = "Ownership"
	keyTags                key = "Tags"
	keyPolicy              key = "Policy"
	keyBucketLock          key = "Bucketlock"
	keyObjRetention        key = "Objectretention"
	keyObjLegalHold        key = "Objectlegalhold"
	keyExpires             key = "Vgwexpires"
	onameAttr              key = "Objname"
	onameAttrLower         key = "objname"
	metaTmpMultipartPrefix key = ".sgwtmp" + "/multipart"
)

func (key) Table() map[string]struct{} {
	return map[string]struct{}{
		"acl":               {},
		"ownership":         {},
		"tags":              {},
		"policy":            {},
		"bucketlock":        {},
		"objectretention":   {},
		"vgwexpires":        {},
		"objectlegalhold":   {},
		"objname":           {},
		".sgwtmp/multipart": {},
	}
}

type Azure struct {
	backend.BackendUnsupported

	client         *azblob.Client
	sharedkeyCreds *azblob.SharedKeyCredential
	defaultCreds   *azidentity.DefaultAzureCredential
	serviceURL     string
	sasToken       string
}

var _ backend.Backend = &Azure{}

func New(accountName, accountKey, serviceURL, sasToken string) (*Azure, error) {
	url := serviceURL
	if serviceURL == "" && accountName != "" {
		// if not otherwise specified, use the typical form:
		// http(s)://<account>.blob.core.windows.net/
		url = fmt.Sprintf("https://%s.blob.core.windows.net/", accountName)
	}

	if sasToken != "" {
		client, err := azblob.NewClientWithNoCredential(url+"?"+sasToken, nil)
		if err != nil {
			return nil, fmt.Errorf("init client: %w", err)
		}
		return &Azure{client: client, serviceURL: serviceURL, sasToken: sasToken}, nil
	}

	if accountName == "" {
		// if account name not provided, try to get from env var
		accountName = os.Getenv("AZURE_CLIENT_ID")
	}

	if accountName == "" || accountKey == "" {
		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("init default credentials: %w", err)
		}
		client, err := azblob.NewClient(url, cred, nil)
		if err != nil {
			return nil, fmt.Errorf("init client: %w", err)
		}
		return &Azure{client: client, serviceURL: url, defaultCreds: cred}, nil
	}

	cred, err := azblob.NewSharedKeyCredential(accountName, accountKey)
	if err != nil {
		return nil, fmt.Errorf("init credentials: %w", err)
	}

	client, err := azblob.NewClientWithSharedKeyCredential(url, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("init client: %w", err)
	}

	return &Azure{client: client, serviceURL: url, sharedkeyCreds: cred}, nil
}

func (az *Azure) Shutdown() {}

func (az *Azure) String() string {
	return "Azure Blob Gateway"
}

func (az *Azure) CreateBucket(ctx context.Context, input *s3.CreateBucketInput, acl []byte) error {
	meta := map[string]*string{
		string(keyAclCapital): backend.GetPtrFromString(encodeBytes(acl)),
		string(keyOwnership):  backend.GetPtrFromString(encodeBytes([]byte(input.ObjectOwnership))),
	}

	acct, ok := ctx.Value("account").(auth.Account)
	if !ok {
		acct = auth.Account{}
	}

	if input.ObjectLockEnabledForBucket != nil && *input.ObjectLockEnabledForBucket {
		now := time.Now()
		defaultLock := auth.BucketLockConfig{
			Enabled:   true,
			CreatedAt: &now,
		}

		defaultLockParsed, err := json.Marshal(defaultLock)
		if err != nil {
			return fmt.Errorf("parse default bucket lock state: %w", err)
		}

		meta[string(keyBucketLock)] = backend.GetPtrFromString(encodeBytes(defaultLockParsed))
	}

	_, err := az.client.CreateContainer(ctx, *input.Bucket, &container.CreateOptions{Metadata: meta})
	if errors.Is(s3err.GetAPIError(s3err.ErrBucketAlreadyExists), azureErrToS3Err(err)) {
		aclBytes, err := az.getContainerMetaData(ctx, *input.Bucket, string(keyAclCapital))
		if err != nil {
			return err
		}

		acl, err := auth.ParseACL(aclBytes)
		if err != nil {
			return err
		}

		if acl.Owner == acct.Access {
			return s3err.GetAPIError(s3err.ErrBucketAlreadyOwnedByYou)
		}
		return s3err.GetAPIError(s3err.ErrBucketAlreadyExists)
	}
	return azureErrToS3Err(err)
}

func (az *Azure) ListBuckets(ctx context.Context, input s3response.ListBucketsInput) (s3response.ListAllMyBucketsResult, error) {
	pager := az.client.NewListContainersPager(
		&service.ListContainersOptions{
			Include: service.ListContainersInclude{
				Metadata: true,
			},
			Marker:     &input.ContinuationToken,
			MaxResults: &input.MaxBuckets,
			Prefix:     &input.Prefix,
		})

	var buckets []s3response.ListAllMyBucketsEntry
	result := s3response.ListAllMyBucketsResult{
		Prefix: input.Prefix,
	}

	resp, err := pager.NextPage(ctx)
	if err != nil {
		return result, azureErrToS3Err(err)
	}
	for _, v := range resp.ContainerItems {
		if input.IsAdmin {
			buckets = append(buckets, s3response.ListAllMyBucketsEntry{
				Name: *v.Name,
				// TODO: using modification date here instead of creation, is that ok?
				CreationDate: *v.Properties.LastModified,
			})
		} else {
			acl, err := getAclFromMetadata(v.Metadata, keyAclLower)
			if err != nil {
				return result, err
			}

			if acl.Owner == input.Owner {
				buckets = append(buckets, s3response.ListAllMyBucketsEntry{
					Name: *v.Name,
					// TODO: using modification date here instead of creation, is that ok?
					CreationDate: *v.Properties.LastModified,
				})
			}
		}
	}

	if resp.NextMarker != nil {
		result.ContinuationToken = *resp.NextMarker
	}

	result.Buckets.Bucket = buckets
	result.Owner.ID = input.Owner

	return result, nil
}

func (az *Azure) HeadBucket(ctx context.Context, input *s3.HeadBucketInput) (*s3.HeadBucketOutput, error) {
	_, err := az.getContainerMetaData(ctx, *input.Bucket, "any")
	if err != nil {
		return nil, azureErrToS3Err(err)
	}

	return &s3.HeadBucketOutput{}, nil
}

func (az *Azure) DeleteBucket(ctx context.Context, bucket string) error {
	pager := az.client.NewListBlobsFlatPager(bucket, nil)

	pg, err := pager.NextPage(ctx)
	if err != nil {
		return azureErrToS3Err(err)
	}

	if len(pg.Segment.BlobItems) > 0 {
		return s3err.GetAPIError(s3err.ErrBucketNotEmpty)
	}
	_, err = az.client.DeleteContainer(ctx, bucket, nil)
	return azureErrToS3Err(err)
}

func (az *Azure) PutBucketOwnershipControls(ctx context.Context, bucket string, ownership types.ObjectOwnership) error {
	return az.setContainerMetaData(ctx, bucket, string(keyOwnership), []byte(ownership))
}

func (az *Azure) GetBucketOwnershipControls(ctx context.Context, bucket string) (types.ObjectOwnership, error) {
	var ownship types.ObjectOwnership
	ownership, err := az.getContainerMetaData(ctx, bucket, string(keyOwnership))
	if err != nil {
		return ownship, err
	}
	if len(ownership) == 0 {
		return ownship, s3err.GetAPIError(s3err.ErrOwnershipControlsNotFound)
	}

	return types.ObjectOwnership(ownership), nil
}

func (az *Azure) DeleteBucketOwnershipControls(ctx context.Context, bucket string) error {
	return az.deleteContainerMetaData(ctx, bucket, string(keyOwnership))
}

func (az *Azure) PutObject(ctx context.Context, po s3response.PutObjectInput) (s3response.PutObjectOutput, error) {
	tags, err := backend.ParseObjectTags(getString(po.Tagging))
	if err != nil {
		return s3response.PutObjectOutput{}, err
	}

	metadata := parseMetadata(po.Metadata)

	// Store the "Expires" property in the object metadata
	if getString(po.Expires) != "" {
		if metadata == nil {
			metadata = map[string]*string{
				string(keyExpires): po.Expires,
			}
		} else {
			metadata[string(keyExpires)] = po.Expires
		}
	}

	opts := &blockblob.UploadStreamOptions{
		Metadata: metadata,
		Tags:     tags,
	}

	opts.HTTPHeaders = &blob.HTTPHeaders{}
	opts.HTTPHeaders.BlobContentEncoding = po.ContentEncoding
	opts.HTTPHeaders.BlobContentLanguage = po.ContentLanguage
	opts.HTTPHeaders.BlobContentDisposition = po.ContentDisposition
	opts.HTTPHeaders.BlobContentLanguage = po.ContentLanguage
	opts.HTTPHeaders.BlobCacheControl = po.CacheControl
	if strings.HasSuffix(*po.Key, "/") {
		// Hardcode "application/x-directory" for direcoty objects
		opts.HTTPHeaders.BlobContentType = backend.GetPtrFromString(backend.DirContentType)
	} else {
		opts.HTTPHeaders.BlobContentType = po.ContentType
	}

	if opts.HTTPHeaders.BlobContentType == nil {
		opts.HTTPHeaders.BlobContentType = backend.GetPtrFromString(backend.DefaultContentType)
	}

	uploadResp, err := az.client.UploadStream(ctx, *po.Bucket, *po.Key, po.Body, opts)
	if err != nil {
		return s3response.PutObjectOutput{}, azureErrToS3Err(err)
	}

	// Set object legal hold
	if po.ObjectLockLegalHoldStatus == types.ObjectLockLegalHoldStatusOn {
		err := az.PutObjectLegalHold(ctx, *po.Bucket, *po.Key, "", true)
		if err != nil {
			return s3response.PutObjectOutput{}, err
		}
	}

	// Set object retention
	if po.ObjectLockMode != "" {
		retention := types.ObjectLockRetention{
			Mode:            types.ObjectLockRetentionMode(po.ObjectLockMode),
			RetainUntilDate: po.ObjectLockRetainUntilDate,
		}
		retParsed, err := json.Marshal(retention)
		if err != nil {
			return s3response.PutObjectOutput{}, fmt.Errorf("parse object lock retention: %w", err)
		}
		err = az.PutObjectRetention(ctx, *po.Bucket, *po.Key, "", true, retParsed)
		if err != nil {
			return s3response.PutObjectOutput{}, err
		}
	}

	return s3response.PutObjectOutput{
		ETag: string(*uploadResp.ETag),
	}, nil
}

func (az *Azure) PutBucketTagging(ctx context.Context, bucket string, tags map[string]string) error {
	if tags == nil {
		return az.deleteContainerMetaData(ctx, bucket, string(keyTags))
	}

	tagsJson, err := json.Marshal(tags)
	if err != nil {
		return err
	}

	return az.setContainerMetaData(ctx, bucket, string(keyTags), tagsJson)
}

func (az *Azure) GetBucketTagging(ctx context.Context, bucket string) (map[string]string, error) {
	tagsJson, err := az.getContainerMetaData(ctx, bucket, string(keyTags))
	if err != nil {
		return nil, err
	}

	if len(tagsJson) == 0 {
		return nil, s3err.GetAPIError(s3err.ErrBucketTaggingNotFound)
	}

	var tags map[string]string
	err = json.Unmarshal(tagsJson, &tags)
	if err != nil {
		return nil, err
	}

	return tags, nil
}

func (az *Azure) DeleteBucketTagging(ctx context.Context, bucket string) error {
	return az.PutBucketTagging(ctx, bucket, nil)
}

func (az *Azure) GetObject(ctx context.Context, input *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	client, err := az.getBlobClient(*input.Bucket, *input.Key)
	if err != nil {
		return nil, err
	}

	resp, err := client.GetProperties(ctx, nil)
	if err != nil {
		return nil, azureErrToS3Err(err)
	}

	var opts *azblob.DownloadStreamOptions
	if *input.Range != "" {
		offset, count, isValid, err := backend.ParseObjectRange(*resp.ContentLength, *input.Range)
		if err != nil {
			return nil, err
		}
		if isValid {
			opts = &azblob.DownloadStreamOptions{
				Range: blob.HTTPRange{
					Count:  count,
					Offset: offset,
				},
			}
		}
	}
	blobDownloadResponse, err := az.client.DownloadStream(ctx, *input.Bucket, *input.Key, opts)
	if err != nil {
		return nil, azureErrToS3Err(err)
	}

	var tagcount int32
	if blobDownloadResponse.TagCount != nil {
		tagcount = int32(*blobDownloadResponse.TagCount)
	}

	contentType := blobDownloadResponse.ContentType
	if contentType == nil {
		contentType = backend.GetPtrFromString(backend.DefaultContentType)
	}

	return &s3.GetObjectOutput{
		AcceptRanges:       backend.GetPtrFromString("bytes"),
		ContentLength:      blobDownloadResponse.ContentLength,
		ContentEncoding:    blobDownloadResponse.ContentEncoding,
		ContentType:        contentType,
		ContentDisposition: blobDownloadResponse.ContentDisposition,
		ContentLanguage:    blobDownloadResponse.ContentLanguage,
		CacheControl:       blobDownloadResponse.CacheControl,
		ExpiresString:      blobDownloadResponse.Metadata[string(keyExpires)],
		ETag:               (*string)(blobDownloadResponse.ETag),
		LastModified:       blobDownloadResponse.LastModified,
		Metadata:           parseAndFilterAzMetadata(blobDownloadResponse.Metadata),
		TagCount:           &tagcount,
		ContentRange:       blobDownloadResponse.ContentRange,
		Body:               blobDownloadResponse.Body,
		StorageClass:       types.StorageClassStandard,
	}, nil
}

func (az *Azure) HeadObject(ctx context.Context, input *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
	if input.PartNumber != nil {
		client, err := az.getBlockBlobClient(*input.Bucket, *input.Key)
		if err != nil {
			return nil, err
		}

		res, err := client.GetBlockList(ctx, blockblob.BlockListTypeUncommitted, nil)
		if err != nil {
			return nil, azureErrToS3Err(err)
		}

		partsCount := int32(len(res.UncommittedBlocks))

		for _, block := range res.UncommittedBlocks {
			partNumber, err := decodeBlockId(*block.Name)
			if err != nil {
				return nil, err
			}

			if partNumber == int(*input.PartNumber) {
				return &s3.HeadObjectOutput{
					ContentLength: block.Size,
					ETag:          block.Name,
					PartsCount:    &partsCount,
					StorageClass:  types.StorageClassStandard,
				}, nil
			}
		}

		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}

	client, err := az.getBlobClient(*input.Bucket, *input.Key)
	if err != nil {
		return nil, err
	}

	resp, err := client.GetProperties(ctx, nil)
	if err != nil {
		return nil, azureErrToS3Err(err)
	}
	var size int64
	if resp.ContentLength != nil {
		size = *resp.ContentLength
	}

	startOffset, length, isValid, err := backend.ParseObjectRange(size, getString(input.Range))
	if err != nil {
		return nil, err
	}

	var contentRange string
	if isValid {
		contentRange = fmt.Sprintf("bytes %v-%v/%v",
			startOffset, startOffset+length-1, size)
	}

	result := &s3.HeadObjectOutput{
		ContentRange:       &contentRange,
		AcceptRanges:       backend.GetPtrFromString("bytes"),
		ContentLength:      &length,
		ContentType:        resp.ContentType,
		ContentEncoding:    resp.ContentEncoding,
		ContentLanguage:    resp.ContentLanguage,
		ContentDisposition: resp.ContentDisposition,
		CacheControl:       resp.CacheControl,
		ExpiresString:      resp.Metadata[string(keyExpires)],
		ETag:               (*string)(resp.ETag),
		LastModified:       resp.LastModified,
		Metadata:           parseAndFilterAzMetadata(resp.Metadata),
		StorageClass:       types.StorageClassStandard,
	}

	status, ok := resp.Metadata[string(keyObjLegalHold)]
	if ok {
		if *status == "1" {
			result.ObjectLockLegalHoldStatus = types.ObjectLockLegalHoldStatusOn
		} else {
			result.ObjectLockLegalHoldStatus = types.ObjectLockLegalHoldStatusOff
		}
	}

	retention, ok := resp.Metadata[string(keyObjRetention)]
	if ok {
		var config types.ObjectLockRetention
		if err := json.Unmarshal([]byte(*retention), &config); err == nil {
			result.ObjectLockMode = types.ObjectLockMode(config.Mode)
			result.ObjectLockRetainUntilDate = config.RetainUntilDate
		}
	}

	return result, nil
}

func (az *Azure) GetObjectAttributes(ctx context.Context, input *s3.GetObjectAttributesInput) (s3response.GetObjectAttributesResponse, error) {
	data, err := az.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: input.Bucket,
		Key:    input.Key,
	})
	if err != nil {
		return s3response.GetObjectAttributesResponse{}, err
	}

	return s3response.GetObjectAttributesResponse{
		ETag:         backend.TrimEtag(data.ETag),
		ObjectSize:   data.ContentLength,
		StorageClass: data.StorageClass,
		LastModified: data.LastModified,
		VersionId:    data.VersionId,
		DeleteMarker: data.DeleteMarker,
	}, nil
}

func (az *Azure) ListObjects(ctx context.Context, input *s3.ListObjectsInput) (s3response.ListObjectsResult, error) {
	client, err := az.getContainerClient(*input.Bucket)
	if err != nil {
		return s3response.ListObjectsResult{}, nil
	}
	pager := client.NewListBlobsHierarchyPager(*input.Delimiter, &container.ListBlobsHierarchyOptions{
		Marker:     input.Marker,
		MaxResults: input.MaxKeys,
		Prefix:     input.Prefix,
	})

	var objects []s3response.Object
	var cPrefixes []types.CommonPrefix
	var nextMarker *string
	var isTruncated bool
	var maxKeys int32 = math.MaxInt32

	if input.MaxKeys != nil {
		maxKeys = *input.MaxKeys
	}

	// Retrieve the bucket acl to get the bucket owner
	// All the objects in the bucket are owner by the bucket owner
	aclBytes, err := az.getContainerMetaData(ctx, *input.Bucket, string(keyAclCapital))
	if err != nil {
		return s3response.ListObjectsResult{}, azureErrToS3Err(err)
	}

	acl, err := auth.ParseACL(aclBytes)
	if err != nil {
		return s3response.ListObjectsResult{}, err
	}

Pager:
	for pager.More() {
		resp, err := pager.NextPage(ctx)
		if err != nil {
			return s3response.ListObjectsResult{}, azureErrToS3Err(err)
		}
		for _, v := range resp.Segment.BlobItems {
			if len(objects)+len(cPrefixes) >= int(maxKeys) {
				nextMarker = objects[len(objects)-1].Key
				isTruncated = true
				break Pager
			}
			objects = append(objects, s3response.Object{
				ETag:         backend.GetPtrFromString(fmt.Sprintf("%q", *v.Properties.ETag)),
				Key:          v.Name,
				LastModified: v.Properties.LastModified,
				Size:         v.Properties.ContentLength,
				StorageClass: types.ObjectStorageClassStandard,
				Owner: &types.Owner{
					ID: &acl.Owner,
				},
			})
		}
		for _, v := range resp.Segment.BlobPrefixes {
			if *v.Name <= *input.Marker {
				continue
			}
			if len(objects)+len(cPrefixes) >= int(maxKeys) {
				nextMarker = cPrefixes[len(cPrefixes)-1].Prefix
				isTruncated = true
				break Pager
			}

			marker := getString(input.Marker)
			pfx := strings.TrimSuffix(*v.Name, getString(input.Delimiter))
			if marker != "" && strings.HasPrefix(marker, pfx) {
				continue
			}

			cPrefixes = append(cPrefixes, types.CommonPrefix{
				Prefix: v.Name,
			})
		}
	}

	return s3response.ListObjectsResult{
		Contents:       objects,
		Marker:         backend.GetPtrFromString(*input.Marker),
		MaxKeys:        input.MaxKeys,
		Name:           input.Bucket,
		NextMarker:     nextMarker,
		Prefix:         backend.GetPtrFromString(*input.Prefix),
		IsTruncated:    &isTruncated,
		Delimiter:      backend.GetPtrFromString(*input.Delimiter),
		CommonPrefixes: cPrefixes,
	}, nil
}

func (az *Azure) ListObjectsV2(ctx context.Context, input *s3.ListObjectsV2Input) (s3response.ListObjectsV2Result, error) {
	marker := ""
	if *input.ContinuationToken > *input.StartAfter {
		marker = *input.ContinuationToken
	} else {
		marker = *input.StartAfter
	}
	client, err := az.getContainerClient(*input.Bucket)
	if err != nil {
		return s3response.ListObjectsV2Result{}, nil
	}
	pager := client.NewListBlobsHierarchyPager(*input.Delimiter, &container.ListBlobsHierarchyOptions{
		Marker:     &marker,
		MaxResults: input.MaxKeys,
		Prefix:     input.Prefix,
	})

	var objects []s3response.Object
	var cPrefixes []types.CommonPrefix
	var nextMarker *string
	var isTruncated bool
	var maxKeys int32 = math.MaxInt32
	var fetchOwner bool

	if input.MaxKeys != nil {
		maxKeys = *input.MaxKeys
	}
	if input.FetchOwner != nil {
		fetchOwner = *input.FetchOwner
	}

	// Retrieve the bucket acl to get the bucket owner, if "fetchOwner" is true
	// All the objects in the bucket are owner by the bucket owner
	var acl auth.ACL
	if fetchOwner {
		aclBytes, err := az.getContainerMetaData(ctx, *input.Bucket, string(keyAclCapital))
		if err != nil {
			return s3response.ListObjectsV2Result{}, azureErrToS3Err(err)
		}

		acl, err = auth.ParseACL(aclBytes)
		if err != nil {
			return s3response.ListObjectsV2Result{}, err
		}
	}

Pager:
	for pager.More() {
		resp, err := pager.NextPage(ctx)
		if err != nil {
			return s3response.ListObjectsV2Result{}, azureErrToS3Err(err)
		}
		for _, v := range resp.Segment.BlobItems {
			if len(objects)+len(cPrefixes) >= int(maxKeys) {
				nextMarker = objects[len(objects)-1].Key
				isTruncated = true
				break Pager
			}

			obj := s3response.Object{
				ETag:         backend.GetPtrFromString(fmt.Sprintf("%q", *v.Properties.ETag)),
				Key:          v.Name,
				LastModified: v.Properties.LastModified,
				Size:         v.Properties.ContentLength,
				StorageClass: types.ObjectStorageClassStandard,
			}
			if fetchOwner {
				obj.Owner = &types.Owner{
					ID: &acl.Owner,
				}
			}
			objects = append(objects, obj)
		}
		for _, v := range resp.Segment.BlobPrefixes {
			if *v.Name <= marker {
				continue
			}
			if len(objects)+len(cPrefixes) >= int(maxKeys) {
				nextMarker = cPrefixes[len(cPrefixes)-1].Prefix
				isTruncated = true
				break Pager
			}

			marker := getString(input.ContinuationToken)
			pfx := strings.TrimSuffix(*v.Name, getString(input.Delimiter))
			if marker != "" && strings.HasPrefix(marker, pfx) {
				continue
			}

			cPrefixes = append(cPrefixes, types.CommonPrefix{
				Prefix: v.Name,
			})
		}
	}

	return s3response.ListObjectsV2Result{
		Contents:              objects,
		ContinuationToken:     backend.GetPtrFromString(*input.ContinuationToken),
		MaxKeys:               input.MaxKeys,
		Name:                  input.Bucket,
		NextContinuationToken: nextMarker,
		Prefix:                backend.GetPtrFromString(*input.Prefix),
		IsTruncated:           &isTruncated,
		Delimiter:             backend.GetPtrFromString(*input.Delimiter),
		CommonPrefixes:        cPrefixes,
		StartAfter:            backend.GetPtrFromString(*input.StartAfter),
	}, nil
}

func (az *Azure) DeleteObject(ctx context.Context, input *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error) {
	_, err := az.client.DeleteBlob(ctx, *input.Bucket, *input.Key, nil)
	if err != nil {
		azerr, ok := err.(*azcore.ResponseError)
		if ok && azerr.StatusCode == 404 {
			// if the object does not exist, S3 returns success
			return &s3.DeleteObjectOutput{}, nil
		}
	}
	return &s3.DeleteObjectOutput{}, azureErrToS3Err(err)
}

func (az *Azure) DeleteObjects(ctx context.Context, input *s3.DeleteObjectsInput) (s3response.DeleteResult, error) {
	delResult, errs := []types.DeletedObject{}, []types.Error{}
	for _, obj := range input.Delete.Objects {
		_, err := az.DeleteObject(ctx, &s3.DeleteObjectInput{
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
					Code:    backend.GetPtrFromString("InternalError"),
					Message: backend.GetPtrFromString(err.Error()),
				})
			}
		}
	}

	return s3response.DeleteResult{
		Deleted: delResult,
		Error:   errs,
	}, nil
}

func (az *Azure) CopyObject(ctx context.Context, input s3response.CopyObjectInput) (s3response.CopyObjectOutput, error) {
	dstClient, err := az.getBlobClient(*input.Bucket, *input.Key)
	if err != nil {
		return s3response.CopyObjectOutput{}, err
	}
	if strings.Join([]string{*input.Bucket, *input.Key}, "/") == *input.CopySource {
		if input.MetadataDirective != types.MetadataDirectiveReplace {
			return s3response.CopyObjectOutput{}, s3err.GetAPIError(s3err.ErrInvalidCopyDest)
		}

		// Set object meta http headers
		res, err := dstClient.SetHTTPHeaders(ctx, blob.HTTPHeaders{
			BlobCacheControl:       input.CacheControl,
			BlobContentDisposition: input.ContentDisposition,
			BlobContentEncoding:    input.ContentEncoding,
			BlobContentLanguage:    input.ContentLanguage,
			BlobContentType:        input.ContentType,
		}, nil)
		if err != nil {
			return s3response.CopyObjectOutput{}, azureErrToS3Err(err)
		}

		meta := input.Metadata
		if meta == nil {
			meta = make(map[string]string)
		}

		// Embed "Expires" in object metadata
		if getString(input.Expires) != "" {
			meta[string(keyExpires)] = *input.Expires
		}
		// Set object metadata
		_, err = dstClient.SetMetadata(ctx, parseMetadata(meta), nil)
		if err != nil {
			return s3response.CopyObjectOutput{}, azureErrToS3Err(err)
		}

		// Set object legal hold
		if input.ObjectLockLegalHoldStatus != "" {
			err = az.PutObjectLegalHold(ctx, *input.Bucket, *input.Key, "", input.ObjectLockLegalHoldStatus == types.ObjectLockLegalHoldStatusOn)
			if err != nil {
				return s3response.CopyObjectOutput{}, azureErrToS3Err(err)
			}
		}
		// Set object retention
		if input.ObjectLockMode != "" && input.ObjectLockRetainUntilDate != nil {
			retention := s3response.PutObjectRetentionInput{
				Mode: types.ObjectLockRetentionMode(input.ObjectLockMode),
				RetainUntilDate: s3response.AmzDate{
					Time: *input.ObjectLockRetainUntilDate,
				},
			}

			retParsed, err := json.Marshal(retention)
			if err != nil {
				return s3response.CopyObjectOutput{}, fmt.Errorf("parse object retention: %w", err)
			}
			err = az.PutObjectRetention(ctx, *input.Bucket, *input.Key, "", true, retParsed)
			if err != nil {
				return s3response.CopyObjectOutput{}, azureErrToS3Err(err)
			}
		}

		// Set object Tagging, if tagging directive is "REPLACE"
		if input.TaggingDirective == types.TaggingDirectiveReplace {
			tags, err := backend.ParseObjectTags(getString(input.Tagging))
			if err != nil {
				return s3response.CopyObjectOutput{}, err
			}
			_, err = dstClient.SetTags(ctx, tags, nil)
			if err != nil {
				return s3response.CopyObjectOutput{}, azureErrToS3Err(err)
			}
		}

		return s3response.CopyObjectOutput{
			CopyObjectResult: &s3response.CopyObjectResult{
				LastModified: res.LastModified,
				ETag:         (*string)(res.ETag),
			},
		}, nil
	}

	srcBucket, srcObj, _, err := backend.ParseCopySource(*input.CopySource)
	if err != nil {
		return s3response.CopyObjectOutput{}, err
	}

	// Get the source object
	downloadResp, err := az.client.DownloadStream(ctx, srcBucket, srcObj, nil)
	if err != nil {
		return s3response.CopyObjectOutput{}, azureErrToS3Err(err)
	}

	pInput := s3response.PutObjectInput{
		Body:                      downloadResp.Body,
		Bucket:                    input.Bucket,
		Key:                       input.Key,
		ContentLength:             downloadResp.ContentLength,
		ContentType:               input.ContentType,
		ContentEncoding:           input.ContentEncoding,
		ContentDisposition:        input.ContentDisposition,
		ContentLanguage:           input.ContentLanguage,
		CacheControl:              input.CacheControl,
		Expires:                   input.Expires,
		Metadata:                  input.Metadata,
		ObjectLockRetainUntilDate: input.ObjectLockRetainUntilDate,
		ObjectLockMode:            input.ObjectLockMode,
		ObjectLockLegalHoldStatus: input.ObjectLockLegalHoldStatus,
	}

	if input.MetadataDirective == types.MetadataDirectiveCopy {
		// Expires is in downloadResp.Metadata
		pInput.Expires = nil
		pInput.CacheControl = downloadResp.CacheControl
		pInput.ContentDisposition = downloadResp.ContentDisposition
		pInput.ContentEncoding = downloadResp.ContentEncoding
		pInput.ContentLanguage = downloadResp.ContentLanguage
		pInput.ContentType = downloadResp.ContentType
		pInput.Metadata = parseAzMetadata(downloadResp.Metadata)
	}

	if input.TaggingDirective == types.TaggingDirectiveReplace {
		pInput.Tagging = input.Tagging
	}

	// Create the destination object
	resp, err := az.PutObject(ctx, pInput)
	if err != nil {
		return s3response.CopyObjectOutput{}, err
	}

	// Copy the object tagging, if tagging directive is "COPY"
	if input.TaggingDirective == types.TaggingDirectiveCopy {
		srcClient, err := az.getBlobClient(srcBucket, srcObj)
		if err != nil {
			return s3response.CopyObjectOutput{}, err
		}
		res, err := srcClient.GetTags(ctx, nil)
		if err != nil {
			return s3response.CopyObjectOutput{}, azureErrToS3Err(err)
		}

		_, err = dstClient.SetTags(ctx, parseAzTags(res.BlobTagSet), nil)
		if err != nil {
			return s3response.CopyObjectOutput{}, azureErrToS3Err(err)
		}
	}

	return s3response.CopyObjectOutput{
		CopyObjectResult: &s3response.CopyObjectResult{
			ETag: &resp.ETag,
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

func (az *Azure) CreateMultipartUpload(ctx context.Context, input s3response.CreateMultipartUploadInput) (s3response.InitiateMultipartUploadResult, error) {
	if input.ObjectLockLegalHoldStatus != "" || input.ObjectLockMode != "" {
		bucketLock, err := az.getContainerMetaData(ctx, *input.Bucket, string(keyBucketLock))
		if err != nil {
			return s3response.InitiateMultipartUploadResult{}, azureErrToS3Err(err)
		}

		if len(bucketLock) == 0 {
			return s3response.InitiateMultipartUploadResult{}, s3err.GetAPIError(s3err.ErrInvalidBucketObjectLockConfiguration)
		}

		var bucketLockConfig auth.BucketLockConfig
		if err := json.Unmarshal(bucketLock, &bucketLockConfig); err != nil {
			return s3response.InitiateMultipartUploadResult{}, fmt.Errorf("parse bucket lock config: %w", err)
		}

		if !bucketLockConfig.Enabled {
			return s3response.InitiateMultipartUploadResult{}, s3err.GetAPIError(s3err.ErrInvalidBucketObjectLockConfiguration)
		}
	}

	meta := parseMetadata(input.Metadata)
	meta[string(onameAttr)] = input.Key

	if getString(input.Expires) != "" {
		meta[string(keyExpires)] = input.Expires
	}

	// parse object tags
	tags, err := backend.ParseObjectTags(getString(input.Tagging))
	if err != nil {
		return s3response.InitiateMultipartUploadResult{}, err
	}

	// set blob legal hold status in metadata
	if input.ObjectLockLegalHoldStatus == types.ObjectLockLegalHoldStatusOn {
		meta[string(keyObjLegalHold)] = backend.GetPtrFromString("1")
	}

	// set blob retention date
	if input.ObjectLockMode != "" {
		retention := types.ObjectLockRetention{
			Mode:            types.ObjectLockRetentionMode(input.ObjectLockMode),
			RetainUntilDate: input.ObjectLockRetainUntilDate,
		}
		retParsed, err := json.Marshal(retention)
		if err != nil {
			return s3response.InitiateMultipartUploadResult{}, azureErrToS3Err(err)
		}
		meta[string(keyObjRetention)] = backend.GetPtrFromString(string(retParsed))
	}

	uploadId := uuid.New().String()

	tmpPath := createMetaTmpPath(*input.Key, uploadId)

	opts := &blockblob.UploadBufferOptions{
		Metadata: meta,
		Tags:     tags,
		HTTPHeaders: &blob.HTTPHeaders{
			BlobContentType:        input.ContentType,
			BlobContentEncoding:    input.ContentEncoding,
			BlobCacheControl:       input.CacheControl,
			BlobContentDisposition: input.ContentDisposition,
			BlobContentLanguage:    input.ContentLanguage,
		},
	}

	// Create and empty blob in .sgwtmp/multipart/<uploadId>/<object hash>
	// The blob indicates multipart upload initialization and holds the mp metadata
	// e.g tagging, content-type, metadata, object lock status ...
	_, err = az.client.UploadBuffer(ctx, *input.Bucket, tmpPath, []byte{}, opts)
	if err != nil {
		return s3response.InitiateMultipartUploadResult{}, azureErrToS3Err(err)
	}

	return s3response.InitiateMultipartUploadResult{
		Bucket:   *input.Bucket,
		Key:      *input.Key,
		UploadId: uploadId,
	}, nil
}

// Each part is translated into an uncommitted block in a newly created blob in staging area
func (az *Azure) UploadPart(ctx context.Context, input *s3.UploadPartInput) (*s3.UploadPartOutput, error) {
	if err := az.checkIfMpExists(ctx, *input.Bucket, *input.Key, *input.UploadId); err != nil {
		return nil, err
	}

	// TODO: request streamable version of StageBlock()
	// (*blockblob.Client).StageBlock does not have a streamable
	// version of this function at this time, so we need to cache
	// the body in memory to create an io.ReadSeekCloser
	rdr, err := getReadSeekCloser(input.Body)
	if err != nil {
		return nil, err
	}

	client, err := az.getBlockBlobClient(*input.Bucket, *input.Key)
	if err != nil {
		return nil, err
	}

	// block id serves as etag here
	etag := blockIDInt32ToBase64(*input.PartNumber)
	_, err = client.StageBlock(ctx, etag, rdr, nil)
	if err != nil {
		return nil, parseMpError(err)
	}

	return &s3.UploadPartOutput{
		ETag: &etag,
	}, nil
}

func (az *Azure) UploadPartCopy(ctx context.Context, input *s3.UploadPartCopyInput) (s3response.CopyPartResult, error) {
	client, err := az.getBlockBlobClient(*input.Bucket, *input.Key)
	if err != nil {
		return s3response.CopyPartResult{}, nil
	}

	if err := az.checkIfMpExists(ctx, *input.Bucket, *input.Key, *input.UploadId); err != nil {
		return s3response.CopyPartResult{}, err
	}

	eTag := blockIDInt32ToBase64(*input.PartNumber)
	//TODO: handle block copy by range
	//TODO: the action returns not implemented on azurite, maybe in production this will work?
	_, err = client.StageBlockFromURL(ctx, eTag, *input.CopySource, nil)
	if err != nil {
		return s3response.CopyPartResult{}, parseMpError(err)
	}

	return s3response.CopyPartResult{}, nil
}

// Lists all uncommitted parts from the blob
func (az *Azure) ListParts(ctx context.Context, input *s3.ListPartsInput) (s3response.ListPartsResult, error) {
	if err := az.checkIfMpExists(ctx, *input.Bucket, *input.Key, *input.UploadId); err != nil {
		return s3response.ListPartsResult{}, err
	}
	client, err := az.getBlockBlobClient(*input.Bucket, *input.Key)
	if err != nil {
		return s3response.ListPartsResult{}, nil
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

	resp, err := client.GetBlockList(ctx, blockblob.BlockListTypeUncommitted, nil)
	if err != nil {
		// If the mp exists but the client returns 'NoSuchKey' error, return empty result
		if errors.Is(azureErrToS3Err(err), s3err.GetAPIError(s3err.ErrNoSuchKey)) {
			return s3response.ListPartsResult{
				Bucket:           *input.Bucket,
				Key:              *input.Key,
				PartNumberMarker: partNumberMarker,
				IsTruncated:      isTruncated,
				MaxParts:         int(maxParts),
				StorageClass:     types.StorageClassStandard,
			}, nil
		}
	}

	parts := []s3response.Part{}
	for _, el := range resp.UncommittedBlocks {
		partNumber, err := decodeBlockId(*el.Name)
		if err != nil {
			return s3response.ListPartsResult{}, err
		}
		if partNumberMarker >= partNumber {
			continue
		}
		parts = append(parts, s3response.Part{
			Size:         *el.Size,
			ETag:         *el.Name,
			PartNumber:   partNumber,
			LastModified: time.Now(),
		})
		if len(parts) >= int(maxParts) {
			nextPartNumberMarker = partNumber
			isTruncated = true
			break
		}
	}
	return s3response.ListPartsResult{
		Bucket:               *input.Bucket,
		Key:                  *input.Key,
		Parts:                parts,
		NextPartNumberMarker: nextPartNumberMarker,
		PartNumberMarker:     partNumberMarker,
		IsTruncated:          isTruncated,
		MaxParts:             int(maxParts),
		StorageClass:         types.StorageClassStandard,
	}, nil
}

// Lists all the multipart uploads initiated with .sgwtmp/multipart prefix
func (az *Azure) ListMultipartUploads(ctx context.Context, input *s3.ListMultipartUploadsInput) (s3response.ListMultipartUploadsResult, error) {
	client, err := az.getContainerClient(*input.Bucket)
	if err != nil {
		return s3response.ListMultipartUploadsResult{}, err
	}

	uploads := []s3response.Upload{}

	var uploadIDMarker string
	if input.UploadIdMarker != nil {
		uploadIDMarker = *input.UploadIdMarker
	}
	uploadIdMarkerFound := false
	prefix := string(metaTmpMultipartPrefix)

	pager := client.NewListBlobsFlatPager(&container.ListBlobsFlatOptions{
		Include: container.ListBlobsInclude{Metadata: true},
		Prefix:  &prefix,
	})

	for pager.More() {
		resp, err := pager.NextPage(ctx)
		if err != nil {
			return s3response.ListMultipartUploadsResult{}, azureErrToS3Err(err)
		}
		for _, el := range resp.Segment.BlobItems {
			key, ok := el.Metadata[string(onameAttrLower)]
			if !ok {
				continue
			}
			if *key <= *input.KeyMarker {
				continue
			}
			if input.Prefix != nil && !strings.HasPrefix(*key, *input.Prefix) {
				continue
			}

			path := filepath.Clean(*el.Name)
			parts := strings.Split(path, "/")
			uploadId := parts[2]

			uploads = append(uploads, s3response.Upload{
				Key:          *key,
				Initiated:    *el.Properties.CreationTime,
				UploadID:     uploadId,
				StorageClass: types.StorageClassStandard,
			})
		}
	}
	maxUploads := 1000
	if input.MaxUploads != nil {
		maxUploads = int(*input.MaxUploads)
	}
	if *input.KeyMarker != "" && uploadIDMarker != "" && !uploadIdMarkerFound {
		return s3response.ListMultipartUploadsResult{
			Bucket:         *input.Bucket,
			Delimiter:      *input.Delimiter,
			KeyMarker:      *input.KeyMarker,
			MaxUploads:     maxUploads,
			Prefix:         *input.Prefix,
			UploadIDMarker: *input.UploadIdMarker,
			Uploads:        []s3response.Upload{},
		}, nil
	}

	sort.SliceStable(uploads, func(i, j int) bool {
		return uploads[i].Key < uploads[j].Key
	})

	if *input.KeyMarker != "" && *input.UploadIdMarker != "" {
		// the uploads are already filtered by keymarker
		// filter the uploads by uploadIdMarker
		for i, upl := range uploads {
			if upl.UploadID == uploadIDMarker {
				uploads = uploads[i+1:]
				break
			}
		}
	}

	if len(uploads) <= maxUploads {
		return s3response.ListMultipartUploadsResult{
			Bucket:         *input.Bucket,
			Delimiter:      *input.Delimiter,
			KeyMarker:      *input.KeyMarker,
			MaxUploads:     maxUploads,
			Prefix:         *input.Prefix,
			UploadIDMarker: *input.UploadIdMarker,
			Uploads:        uploads,
		}, nil
	} else {
		resUploads := uploads[:maxUploads]
		return s3response.ListMultipartUploadsResult{
			Bucket:             *input.Bucket,
			Delimiter:          *input.Delimiter,
			KeyMarker:          *input.KeyMarker,
			NextKeyMarker:      resUploads[len(resUploads)-1].Key,
			MaxUploads:         maxUploads,
			Prefix:             *input.Prefix,
			UploadIDMarker:     *input.UploadIdMarker,
			NextUploadIDMarker: resUploads[len(resUploads)-1].UploadID,
			IsTruncated:        true,
			Uploads:            resUploads,
		}, nil
	}
}

// Deletes the block blob with committed/uncommitted blocks
// Cleans up the initiated multipart upload in .sgwtmp namespace
func (az *Azure) AbortMultipartUpload(ctx context.Context, input *s3.AbortMultipartUploadInput) error {
	tmpPath := createMetaTmpPath(*input.Key, *input.UploadId)
	_, err := az.client.DeleteBlob(ctx, *input.Bucket, tmpPath, nil)
	if err != nil {
		return parseMpError(err)
	}

	// Cleanup the uploaded parts
	_, err = az.client.DeleteBlob(ctx, *input.Bucket, *input.Key, nil)
	if err != nil {
		err = azureErrToS3Err(err)
		if errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchKey)) {
			return nil
		}

		return err
	}

	return nil
}

// Commits all the uncommitted blocks inside the block blob
// And moves the block blob from staging area into the blobs list.
// Copeies the multipart metadata from .sgwtmp namespace into the newly created blob
// Deletes the multipart upload 'blob' from .sgwtmp namespace
// It indicates the end of the multipart upload
func (az *Azure) CompleteMultipartUpload(ctx context.Context, input *s3.CompleteMultipartUploadInput) (s3response.CompleteMultipartUploadResult, string, error) {
	var res s3response.CompleteMultipartUploadResult

	tmpPath := createMetaTmpPath(*input.Key, *input.UploadId)
	blobClient, err := az.getBlobClient(*input.Bucket, tmpPath)
	if err != nil {
		return res, "", err
	}

	props, err := blobClient.GetProperties(ctx, nil)
	if err != nil {
		return res, "", parseMpError(err)
	}
	tags, err := blobClient.GetTags(ctx, nil)
	if err != nil {
		return res, "", parseMpError(err)
	}

	client, err := az.getBlockBlobClient(*input.Bucket, *input.Key)
	if err != nil {
		return res, "", err
	}
	blockIds := []string{}

	blockList, err := client.GetBlockList(ctx, blockblob.BlockListTypeUncommitted, nil)
	if err != nil {
		return res, "", azureErrToS3Err(err)
	}

	if len(blockList.UncommittedBlocks) != len(input.MultipartUpload.Parts) {
		return res, "", s3err.GetAPIError(s3err.ErrInvalidPart)
	}

	uncommittedBlocks := map[int32]*blockblob.Block{}
	for _, el := range blockList.UncommittedBlocks {
		ptNumber, err := decodeBlockId(backend.GetStringFromPtr(el.Name))
		if err != nil {
			return res, "", fmt.Errorf("invalid block name: %w", err)
		}

		uncommittedBlocks[int32(ptNumber)] = el
	}

	// The initialie values is the lower limit of partNumber: 0
	var totalSize int64
	var partNumber int32
	last := len(blockList.UncommittedBlocks) - 1
	for i, part := range input.MultipartUpload.Parts {
		if part.PartNumber == nil {
			return res, "", s3err.GetAPIError(s3err.ErrInvalidPart)
		}
		if *part.PartNumber < 1 {
			return res, "", s3err.GetAPIError(s3err.ErrInvalidCompleteMpPartNumber)
		}
		if *part.PartNumber <= partNumber {
			return res, "", s3err.GetAPIError(s3err.ErrInvalidPartOrder)
		}
		partNumber = *part.PartNumber

		block, ok := uncommittedBlocks[*part.PartNumber]
		if !ok {
			return res, "", s3err.GetAPIError(s3err.ErrInvalidPart)
		}

		if *part.ETag != *block.Name {
			return res, "", s3err.GetAPIError(s3err.ErrInvalidPart)
		}
		// all parts except the last need to be greater, than
		// the minimum allowed size (5 Mib)
		if i < last && *block.Size < backend.MinPartSize {
			return res, "", s3err.GetAPIError(s3err.ErrEntityTooSmall)
		}
		totalSize += *block.Size
		blockIds = append(blockIds, *block.Name)
	}

	if input.MpuObjectSize != nil && totalSize != *input.MpuObjectSize {
		return res, "", s3err.GetIncorrectMpObjectSizeErr(totalSize, *input.MpuObjectSize)
	}

	opts := &blockblob.CommitBlockListOptions{
		Metadata: props.Metadata,
		Tags:     parseAzTags(tags.BlobTagSet),
	}
	opts.HTTPHeaders = &blob.HTTPHeaders{
		BlobContentType:        props.ContentType,
		BlobContentEncoding:    props.ContentEncoding,
		BlobContentDisposition: props.ContentDisposition,
		BlobContentLanguage:    props.ContentLanguage,
		BlobCacheControl:       props.CacheControl,
	}

	resp, err := client.CommitBlockList(ctx, blockIds, opts)
	if err != nil {
		return res, "", parseMpError(err)
	}

	// cleanup the multipart upload
	_, err = blobClient.Delete(ctx, nil)
	if err != nil {
		return res, "", parseMpError(err)
	}

	return s3response.CompleteMultipartUploadResult{
		Bucket: input.Bucket,
		Key:    input.Key,
		ETag:   (*string)(resp.ETag),
	}, "", nil
}

func (az *Azure) PutBucketAcl(ctx context.Context, bucket string, data []byte) error {
	return az.setContainerMetaData(ctx, bucket, string(keyAclCapital), data)
}

func (az *Azure) GetBucketAcl(ctx context.Context, input *s3.GetBucketAclInput) ([]byte, error) {
	return az.getContainerMetaData(ctx, *input.Bucket, string(keyAclCapital))
}

func (az *Azure) PutBucketPolicy(ctx context.Context, bucket string, policy []byte) error {
	if policy == nil {
		return az.deleteContainerMetaData(ctx, bucket, string(keyPolicy))
	}

	return az.setContainerMetaData(ctx, bucket, string(keyPolicy), policy)
}

func (az *Azure) GetBucketPolicy(ctx context.Context, bucket string) ([]byte, error) {
	p, err := az.getContainerMetaData(ctx, bucket, string(keyPolicy))
	if err != nil {
		return nil, err
	}
	if len(p) == 0 {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucketPolicy)
	}
	return p, nil
}

func (az *Azure) DeleteBucketPolicy(ctx context.Context, bucket string) error {
	return az.PutBucketPolicy(ctx, bucket, nil)
}

func (az *Azure) PutObjectLockConfiguration(ctx context.Context, bucket string, config []byte) error {
	cfg, err := az.getContainerMetaData(ctx, bucket, string(keyBucketLock))
	if err != nil {
		return err
	}

	if len(cfg) == 0 {
		return s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotAllowed)
	}

	var bucketLockCfg auth.BucketLockConfig
	if err := json.Unmarshal(cfg, &bucketLockCfg); err != nil {
		return fmt.Errorf("unmarshal object lock config: %w", err)
	}

	if !bucketLockCfg.Enabled {
		return s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotAllowed)
	}

	return az.setContainerMetaData(ctx, bucket, string(keyBucketLock), config)
}

func (az *Azure) GetObjectLockConfiguration(ctx context.Context, bucket string) ([]byte, error) {
	cfg, err := az.getContainerMetaData(ctx, bucket, string(keyBucketLock))
	if err != nil {
		return nil, err
	}

	if len(cfg) == 0 {
		return nil, s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound)
	}

	return cfg, nil
}

func (az *Azure) PutObjectRetention(ctx context.Context, bucket, object, versionId string, bypass bool, retention []byte) error {
	err := az.isBucketObjectLockEnabled(ctx, bucket)
	if err != nil {
		return err
	}

	blobClient, err := az.getBlobClient(bucket, object)
	if err != nil {
		return err
	}

	blobProps, err := blobClient.GetProperties(ctx, nil)
	if err != nil {
		return azureErrToS3Err(err)
	}

	meta := blobProps.Metadata
	if meta == nil {
		meta = map[string]*string{
			string(keyObjRetention): backend.GetPtrFromString(string(retention)),
		}
	} else {
		objLockCfg, ok := meta[string(keyObjRetention)]
		if !ok {
			meta[string(keyObjRetention)] = backend.GetPtrFromString(string(retention))
		} else {
			var lockCfg types.ObjectLockRetention
			if err := json.Unmarshal([]byte(*objLockCfg), &lockCfg); err != nil {
				return fmt.Errorf("unmarshal object lock config: %w", err)
			}

			switch lockCfg.Mode {
			// Compliance mode can't be overridden
			case types.ObjectLockRetentionModeCompliance:
				return s3err.GetAPIError(s3err.ErrMethodNotAllowed)
			// To override governance mode user should have "s3:BypassGovernanceRetention" permission
			case types.ObjectLockRetentionModeGovernance:
				if !bypass {
					return s3err.GetAPIError(s3err.ErrMethodNotAllowed)
				}
			}

			meta[string(keyObjRetention)] = backend.GetPtrFromString(string(retention))
		}
	}

	_, err = blobClient.SetMetadata(ctx, meta, nil)
	if err != nil {
		return azureErrToS3Err(err)
	}

	return nil
}

func (az *Azure) GetObjectRetention(ctx context.Context, bucket, object, versionId string) ([]byte, error) {
	client, err := az.getBlobClient(bucket, object)
	if err != nil {
		return nil, err
	}
	props, err := client.GetProperties(ctx, nil)
	if err != nil {
		return nil, azureErrToS3Err(err)
	}

	err = az.isBucketObjectLockEnabled(ctx, bucket)
	if err != nil {
		return nil, err
	}

	retentionPtr, ok := props.Metadata[string(keyObjRetention)]
	if !ok {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchObjectLockConfiguration)
	}

	return []byte(*retentionPtr), nil
}

func (az *Azure) PutObjectLegalHold(ctx context.Context, bucket, object, versionId string, status bool) error {
	err := az.isBucketObjectLockEnabled(ctx, bucket)
	if err != nil {
		return err
	}

	blobClient, err := az.getBlobClient(bucket, object)
	if err != nil {
		return err
	}

	blobProps, err := blobClient.GetProperties(ctx, nil)
	if err != nil {
		return azureErrToS3Err(err)
	}

	var statusData string
	if status {
		statusData = "1"
	} else {
		statusData = "0"
	}

	meta := blobProps.Metadata
	if meta == nil {
		meta = map[string]*string{
			string(keyObjLegalHold): &statusData,
		}
	} else {
		meta[string(keyObjLegalHold)] = &statusData
	}

	_, err = blobClient.SetMetadata(ctx, meta, nil)
	if err != nil {
		return azureErrToS3Err(err)
	}

	return nil
}

func (az *Azure) GetObjectLegalHold(ctx context.Context, bucket, object, versionId string) (*bool, error) {
	client, err := az.getBlobClient(bucket, object)
	if err != nil {
		return nil, err
	}
	props, err := client.GetProperties(ctx, nil)
	if err != nil {
		return nil, azureErrToS3Err(err)
	}

	err = az.isBucketObjectLockEnabled(ctx, bucket)
	if err != nil {
		return nil, err
	}

	retentionPtr, ok := props.Metadata[string(keyObjLegalHold)]
	if !ok {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchObjectLockConfiguration)
	}

	status := *retentionPtr == "1"

	return &status, nil
}

func (az *Azure) ChangeBucketOwner(ctx context.Context, bucket, owner string) error {
	return auth.UpdateBucketACLOwner(ctx, az, bucket, owner)
}

// The action actually returns the containers owned by the user, who initialized the gateway
// TODO: Not sure if there's a way to list all the containers and owners?
func (az *Azure) ListBucketsAndOwners(ctx context.Context) (buckets []s3response.Bucket, err error) {
	opts := &service.ListContainersOptions{
		Include: service.ListContainersInclude{Metadata: true},
	}
	pager := az.client.NewListContainersPager(opts)

	for pager.More() {
		resp, err := pager.NextPage(ctx)
		if err != nil {
			return buckets, azureErrToS3Err(err)
		}
		for _, v := range resp.ContainerItems {
			acl, err := getAclFromMetadata(v.Metadata, keyAclLower)
			if err != nil {
				return buckets, err
			}

			buckets = append(buckets, s3response.Bucket{
				Name:  *v.Name,
				Owner: acl.Owner,
			})
		}
	}
	return buckets, nil
}

func (az *Azure) isBucketObjectLockEnabled(ctx context.Context, bucket string) error {
	cfg, err := az.getContainerMetaData(ctx, bucket, string(keyBucketLock))
	if err != nil {
		return azureErrToS3Err(err)
	}

	if len(cfg) == 0 {
		return s3err.GetAPIError(s3err.ErrInvalidBucketObjectLockConfiguration)
	}

	var bucketLockConfig auth.BucketLockConfig
	if err := json.Unmarshal(cfg, &bucketLockConfig); err != nil {
		return fmt.Errorf("parse bucket lock config: %w", err)
	}

	if !bucketLockConfig.Enabled {
		return s3err.GetAPIError(s3err.ErrInvalidBucketObjectLockConfiguration)
	}

	return nil
}

func (az *Azure) getContainerURL(cntr string) string {
	return fmt.Sprintf("%v/%v", strings.TrimRight(az.serviceURL, "/"), cntr)
}

func (az *Azure) getBlobURL(cntr, blb string) string {
	return fmt.Sprintf("%v/%v", az.getContainerURL(cntr), blb)
}

func (az *Azure) getBlobClient(cntr, blb string) (*blob.Client, error) {
	blobURL := az.getBlobURL(cntr, blb)
	if az.defaultCreds != nil {
		return blob.NewClient(blobURL, az.defaultCreds, nil)
	}
	if az.sasToken != "" {
		return blob.NewClientWithNoCredential(blobURL+"?"+az.sasToken, nil)
	}
	return blob.NewClientWithSharedKeyCredential(blobURL, az.sharedkeyCreds, nil)
}

func (az *Azure) getContainerClient(cntr string) (*container.Client, error) {
	containerURL := az.getContainerURL(cntr)
	if az.defaultCreds != nil {
		return container.NewClient(containerURL, az.defaultCreds, nil)
	}
	if az.sasToken != "" {
		return container.NewClientWithNoCredential(containerURL+"?"+az.sasToken, nil)
	}
	return container.NewClientWithSharedKeyCredential(containerURL, az.sharedkeyCreds, nil)
}

func (az *Azure) getBlockBlobClient(cntr, blb string) (*blockblob.Client, error) {
	blobURL := az.getBlobURL(cntr, blb)
	if az.defaultCreds != nil {
		return blockblob.NewClient(blobURL, az.defaultCreds, nil)
	}
	if az.sasToken != "" {
		return blockblob.NewClientWithNoCredential(blobURL+"?"+az.sasToken, nil)
	}
	return blockblob.NewClientWithSharedKeyCredential(blobURL, az.sharedkeyCreds, nil)
}

func parseMetadata(m map[string]string) map[string]*string {
	if m == nil {
		return nil
	}

	meta := make(map[string]*string)

	for k, v := range m {
		val := v
		meta[k] = &val
	}
	return meta
}

func parseAndFilterAzMetadata(m map[string]*string) map[string]string {
	if m == nil {
		return nil
	}

	keywords := keyTags.Table()

	meta := make(map[string]string)

	for k, v := range m {
		_, ok := keywords[strings.ToLower(k)]
		if ok {
			continue
		}
		meta[k] = *v
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

func encodeBytes(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func decodeString(str string) ([]byte, error) {
	if str == "" {
		return []byte{}, nil
	}

	decoded, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func (az *Azure) getContainerMetaData(ctx context.Context, bucket, key string) ([]byte, error) {
	client, err := az.getContainerClient(bucket)
	if err != nil {
		return nil, err
	}

	props, err := client.GetProperties(ctx, nil)
	if err != nil {
		return nil, azureErrToS3Err(err)
	}

	if props.Metadata == nil {
		return []byte{}, nil
	}

	data, ok := props.Metadata[key]
	if !ok {
		return []byte{}, nil
	}

	value, err := decodeString(*data)
	if err != nil {
		return nil, err
	}

	return value, nil
}

func (az *Azure) setContainerMetaData(ctx context.Context, bucket, key string, value []byte) error {
	client, err := az.getContainerClient(bucket)
	if err != nil {
		return err
	}

	props, err := client.GetProperties(ctx, nil)
	if err != nil {
		return azureErrToS3Err(err)
	}

	mdmap := props.Metadata
	if mdmap == nil {
		mdmap = make(map[string]*string)
	}

	str := encodeBytes(value)
	mdmap[key] = backend.GetPtrFromString(str)

	_, err = client.SetMetadata(ctx, &container.SetMetadataOptions{Metadata: mdmap})
	if err != nil {
		return err
	}
	return nil
}

func (az *Azure) deleteContainerMetaData(ctx context.Context, bucket, key string) error {
	client, err := az.getContainerClient(bucket)
	if err != nil {
		return err
	}

	props, err := client.GetProperties(ctx, nil)
	if err != nil {
		return azureErrToS3Err(err)
	}

	mdmap := props.Metadata
	if mdmap == nil {
		mdmap = make(map[string]*string)
	}

	delete(mdmap, key)

	_, err = client.SetMetadata(ctx, &container.SetMetadataOptions{Metadata: mdmap})
	if err != nil {
		return err
	}
	return nil
}

func getAclFromMetadata(meta map[string]*string, key key) (*auth.ACL, error) {
	data, ok := meta[string(key)]
	if !ok {
		return &auth.ACL{}, nil
	}

	value, err := decodeString(*data)
	if err != nil {
		return nil, err
	}

	acl, err := auth.ParseACL(value)
	if err != nil {
		return nil, err
	}

	return &acl, nil
}

func createMetaTmpPath(obj, uploadId string) string {
	objNameSum := sha256.Sum256([]byte(obj))
	return filepath.Join(string(metaTmpMultipartPrefix), uploadId, fmt.Sprintf("%x", objNameSum))
}

// Checks if the multipart upload existis with the given bucket, key and uploadId
func (az *Azure) checkIfMpExists(ctx context.Context, bucket, obj, uploadId string) error {
	tmpPath := createMetaTmpPath(obj, uploadId)
	blobClient, err := az.getBlobClient(bucket, tmpPath)
	if err != nil {
		return err
	}

	_, err = blobClient.GetProperties(ctx, nil)
	if err != nil {
		return s3err.GetAPIError(s3err.ErrNoSuchUpload)
	}

	return nil
}
