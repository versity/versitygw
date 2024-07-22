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
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/streaming"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/service"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
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
	keyAclCapital   key = "Acl"
	keyAclLower     key = "acl"
	keyOwnership    key = "Ownership"
	keyTags         key = "Tags"
	keyPolicy       key = "Policy"
	keyBucketLock   key = "Bucket-Lock"
	keyObjRetention key = "Object_retention"
	keyObjLegalHold key = "Object_legal_hold"
)

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
		string(keyAclCapital): backend.GetStringPtr(string(acl)),
		string(keyOwnership):  backend.GetStringPtr(string(input.ObjectOwnership)),
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

		meta[string(keyBucketLock)] = backend.GetStringPtr(string(defaultLockParsed))
	}
	_, err := az.client.CreateContainer(ctx, *input.Bucket, &container.CreateOptions{Metadata: meta})
	if errors.Is(s3err.GetAPIError(s3err.ErrBucketAlreadyExists), azureErrToS3Err(err)) {
		client, err := az.getContainerClient(*input.Bucket)
		if err != nil {
			return err
		}

		props, err := client.GetProperties(ctx, nil)
		if err != nil {
			return azureErrToS3Err(err)
		}

		aclPtr, ok := props.Metadata[string(keyAclCapital)]
		if !ok {
			return fmt.Errorf("missing acl in the bucket")
		}

		var acl auth.ACL
		if err := json.Unmarshal([]byte(*aclPtr), &acl); err != nil {
			return fmt.Errorf("unmarshal bucket acl: %w", err)
		}
		if acl.Owner == acct.Access {
			return s3err.GetAPIError(s3err.ErrBucketAlreadyOwnedByYou)
		}
	}
	return azureErrToS3Err(err)
}

func (az *Azure) ListBuckets(ctx context.Context, owner string, isAdmin bool) (s3response.ListAllMyBucketsResult, error) {
	pager := az.client.NewListContainersPager(
		&service.ListContainersOptions{
			Include: service.ListContainersInclude{
				Metadata: true,
			},
		})

	var buckets []s3response.ListAllMyBucketsEntry
	var result s3response.ListAllMyBucketsResult

	for pager.More() {
		resp, err := pager.NextPage(ctx)
		if err != nil {
			return result, azureErrToS3Err(err)
		}
		for _, v := range resp.ContainerItems {
			if isAdmin {
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

				if acl.Owner == owner {
					buckets = append(buckets, s3response.ListAllMyBucketsEntry{
						Name: *v.Name,
						// TODO: using modification date here instead of creation, is that ok?
						CreationDate: *v.Properties.LastModified,
					})
				}
			}
		}
	}

	result.Buckets.Bucket = buckets
	result.Owner.ID = owner

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
	pager := az.client.NewListBlobsFlatPager(*input.Bucket, nil)

	pg, err := pager.NextPage(ctx)
	if err != nil {
		return azureErrToS3Err(err)
	}

	if len(pg.Segment.BlobItems) > 0 {
		return s3err.GetAPIError(s3err.ErrBucketNotEmpty)
	}
	_, err = az.client.DeleteContainer(ctx, *input.Bucket, nil)
	return azureErrToS3Err(err)
}

func (az *Azure) PutBucketOwnershipControls(ctx context.Context, bucket string, ownership types.ObjectOwnership) error {
	client, err := az.getContainerClient(bucket)
	if err != nil {
		return err
	}

	resp, err := client.GetProperties(ctx, &container.GetPropertiesOptions{})
	if err != nil {
		return azureErrToS3Err(err)
	}
	resp.Metadata[string(keyOwnership)] = backend.GetStringPtr(string(ownership))

	_, err = client.SetMetadata(ctx, &container.SetMetadataOptions{Metadata: resp.Metadata})
	if err != nil {
		return azureErrToS3Err(err)
	}

	return nil
}

func (az *Azure) GetBucketOwnershipControls(ctx context.Context, bucket string) (types.ObjectOwnership, error) {
	var ownship types.ObjectOwnership
	client, err := az.getContainerClient(bucket)
	if err != nil {
		return ownship, err
	}

	resp, err := client.GetProperties(ctx, &container.GetPropertiesOptions{})
	if err != nil {
		return ownship, azureErrToS3Err(err)
	}

	ownership, ok := resp.Metadata[string(keyOwnership)]
	if !ok {
		return ownship, s3err.GetAPIError(s3err.ErrOwnershipControlsNotFound)
	}

	return types.ObjectOwnership(*ownership), nil
}

func (az *Azure) DeleteBucketOwnershipControls(ctx context.Context, bucket string) error {
	client, err := az.getContainerClient(bucket)
	if err != nil {
		return err
	}

	resp, err := client.GetProperties(ctx, &container.GetPropertiesOptions{})
	if err != nil {
		return azureErrToS3Err(err)
	}

	delete(resp.Metadata, string(keyOwnership))

	_, err = client.SetMetadata(ctx, &container.SetMetadataOptions{Metadata: resp.Metadata})
	if err != nil {
		return azureErrToS3Err(err)
	}

	return nil
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

	// Set object legal hold
	if po.ObjectLockLegalHoldStatus == types.ObjectLockLegalHoldStatusOn {
		if err := az.PutObjectLegalHold(ctx, *po.Bucket, *po.Key, "", true); err != nil {
			return "", err
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
			return "", fmt.Errorf("parse object lock retention: %w", err)
		}
		if err := az.PutObjectRetention(ctx, *po.Bucket, *po.Key, "", true, retParsed); err != nil {
			return "", err
		}
	}

	return string(*uploadResp.ETag), nil
}

func (az *Azure) PutBucketTagging(ctx context.Context, bucket string, tags map[string]string) error {
	client, err := az.getContainerClient(bucket)
	if err != nil {
		return err
	}

	resp, err := client.GetProperties(ctx, &container.GetPropertiesOptions{})
	if err != nil {
		return azureErrToS3Err(err)
	}

	if tags == nil {
		delete(resp.Metadata, string(keyTags))
	} else {
		tagsJson, err := json.Marshal(tags)
		if err != nil {
			return err
		}

		resp.Metadata[string(keyTags)] = backend.GetStringPtr(string(tagsJson))
	}

	_, err = client.SetMetadata(ctx, &container.SetMetadataOptions{Metadata: resp.Metadata})
	if err != nil {
		return azureErrToS3Err(err)
	}

	return nil
}

func (az *Azure) GetBucketTagging(ctx context.Context, bucket string) (map[string]string, error) {
	client, err := az.getContainerClient(bucket)
	if err != nil {
		return nil, err
	}

	resp, err := client.GetProperties(ctx, &container.GetPropertiesOptions{})
	if err != nil {
		return nil, azureErrToS3Err(err)
	}

	tagsJson, ok := resp.Metadata[string(keyTags)]
	if !ok {
		return nil, s3err.GetAPIError(s3err.ErrBucketTaggingNotFound)
	}

	var tags map[string]string
	if json.Unmarshal([]byte(*tagsJson), &tags); err != nil {
		return nil, err
	}

	return tags, nil
}

func (az *Azure) DeleteBucketTagging(ctx context.Context, bucket string) error {
	return az.PutBucketTagging(ctx, bucket, nil)
}

func (az *Azure) GetObject(ctx context.Context, input *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	var opts *azblob.DownloadStreamOptions
	if *input.Range != "" {
		offset, count, err := backend.ParseRange(0, *input.Range)
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

	var tagcount int32
	if blobDownloadResponse.TagCount != nil {
		tagcount = int32(*blobDownloadResponse.TagCount)
	}

	return &s3.GetObjectOutput{
		AcceptRanges:    input.Range,
		ContentLength:   blobDownloadResponse.ContentLength,
		ContentEncoding: blobDownloadResponse.ContentEncoding,
		ContentType:     blobDownloadResponse.ContentType,
		ETag:            (*string)(blobDownloadResponse.ETag),
		LastModified:    blobDownloadResponse.LastModified,
		Metadata:        parseAzMetadata(blobDownloadResponse.Metadata),
		TagCount:        &tagcount,
		ContentRange:    blobDownloadResponse.ContentRange,
		Body:            blobDownloadResponse.Body,
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

	result := &s3.HeadObjectOutput{
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

func (az *Azure) GetObjectAttributes(ctx context.Context, input *s3.GetObjectAttributesInput) (s3response.GetObjectAttributesResult, error) {
	data, err := az.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: input.Bucket,
		Key:    input.Key,
	})
	if err == nil {
		return s3response.GetObjectAttributesResult{
			ETag:         data.ETag,
			LastModified: data.LastModified,
			ObjectSize:   data.ContentLength,
			StorageClass: &data.StorageClass,
			VersionId:    data.VersionId,
		}, nil
	}
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchKey)) {
		return s3response.GetObjectAttributesResult{}, err
	}

	resp, err := az.ListParts(ctx, &s3.ListPartsInput{
		Bucket:           input.Bucket,
		Key:              input.Key,
		PartNumberMarker: input.PartNumberMarker,
		MaxParts:         input.MaxParts,
	})
	if errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchUpload)) {
		return s3response.GetObjectAttributesResult{}, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if err != nil {
		return s3response.GetObjectAttributesResult{}, err
	}

	parts := []types.ObjectPart{}

	for _, p := range resp.Parts {
		partNumber := int32(p.PartNumber)
		size := p.Size

		parts = append(parts, types.ObjectPart{
			Size:       &size,
			PartNumber: &partNumber,
		})
	}

	//TODO: handle PartsCount prop
	return s3response.GetObjectAttributesResult{
		ObjectParts: &s3response.ObjectParts{
			IsTruncated:          resp.IsTruncated,
			MaxParts:             resp.MaxParts,
			PartNumberMarker:     resp.PartNumberMarker,
			NextPartNumberMarker: resp.NextPartNumberMarker,
			Parts:                parts,
		},
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
	var isTruncated bool
	var maxKeys int32 = math.MaxInt32

	if input.MaxKeys != nil {
		maxKeys = *input.MaxKeys
	}

Pager:
	for pager.More() {
		resp, err := pager.NextPage(ctx)
		if err != nil {
			return nil, azureErrToS3Err(err)
		}

		for _, v := range resp.Segment.BlobItems {
			if nextMarker == nil && *resp.NextMarker != "" {
				nextMarker = resp.NextMarker
				isTruncated = true
			}
			if len(objects) >= int(maxKeys) {
				break Pager
			}
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

	return &s3.ListObjectsOutput{
		Contents:    objects,
		Marker:      input.Marker,
		MaxKeys:     input.MaxKeys,
		Name:        input.Bucket,
		NextMarker:  nextMarker,
		Prefix:      input.Prefix,
		IsTruncated: &isTruncated,
	}, nil
}

func (az *Azure) ListObjectsV2(ctx context.Context, input *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
	marker := ""
	if *input.ContinuationToken > *input.StartAfter {
		marker = *input.ContinuationToken
	} else {
		marker = *input.StartAfter
	}
	pager := az.client.NewListBlobsFlatPager(*input.Bucket, &azblob.ListBlobsFlatOptions{
		Marker:     &marker,
		MaxResults: input.MaxKeys,
		Prefix:     input.Prefix,
	})

	var objects []types.Object
	var nextMarker *string
	var isTruncated bool
	var maxKeys int32 = math.MaxInt32

	if input.MaxKeys != nil {
		maxKeys = *input.MaxKeys
	}

Pager:
	for pager.More() {
		resp, err := pager.NextPage(ctx)
		if err != nil {
			return nil, azureErrToS3Err(err)
		}
		for _, v := range resp.Segment.BlobItems {
			if nextMarker == nil && *resp.NextMarker != "" {
				nextMarker = resp.NextMarker
				isTruncated = true
			}
			if len(objects) >= int(maxKeys) {
				break Pager
			}
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

	return &s3.ListObjectsV2Output{
		Contents:              objects,
		ContinuationToken:     input.ContinuationToken,
		MaxKeys:               input.MaxKeys,
		Name:                  input.Bucket,
		NextContinuationToken: nextMarker,
		Prefix:                input.Prefix,
		IsTruncated:           &isTruncated,
		Delimiter:             input.Delimiter,
	}, nil
}

func (az *Azure) DeleteObject(ctx context.Context, input *s3.DeleteObjectInput) error {
	_, err := az.client.DeleteBlob(ctx, *input.Bucket, *input.Key, nil)
	return azureErrToS3Err(err)
}

func (az *Azure) DeleteObjects(ctx context.Context, input *s3.DeleteObjectsInput) (s3response.DeleteResult, error) {
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
					Code:    backend.GetStringPtr("InternalError"),
					Message: backend.GetStringPtr(err.Error()),
				})
			}
		}
	}

	return s3response.DeleteResult{
		Deleted: delResult,
		Error:   errs,
	}, nil
}

func (az *Azure) CopyObject(ctx context.Context, input *s3.CopyObjectInput) (*s3.CopyObjectOutput, error) {
	containerClient, err := az.getContainerClient(*input.Bucket)
	if err != nil {
		return nil, err
	}

	res, err := containerClient.GetProperties(ctx, &container.GetPropertiesOptions{})
	if err != nil {
		return nil, azureErrToS3Err(err)
	}

	cpSrc := *input.CopySource
	if cpSrc[0] == '/' {
		cpSrc = cpSrc[1:]
	}

	if strings.Join([]string{*input.Bucket, *input.Key}, "/") == cpSrc && isMetaSame(res.Metadata, input.Metadata) {
		return nil, s3err.GetAPIError(s3err.ErrInvalidCopyDest)
	}

	tags, err := parseTags(input.Tagging)
	if err != nil {
		return nil, err
	}

	client, err := az.getBlobClient(*input.Bucket, *input.Key)
	if err != nil {
		return nil, err
	}

	resp, err := client.CopyFromURL(ctx, az.serviceURL+"/"+cpSrc, &blob.CopyFromURLOptions{
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

func (az *Azure) CreateMultipartUpload(ctx context.Context, input *s3.CreateMultipartUploadInput) (*s3.CreateMultipartUploadOutput, error) {
	// Multipart upload starts with UploadPart action so there is no
	// correlating function for creating mutlipart uploads.
	// TODO: since azure only allows for a single multipart upload
	// for an object name at a time, we need to send an error back to
	// the client if there is already an outstanding upload in progress
	// for this object.
	// Alternatively, is there something we can do with upload ids to
	// keep concurrent uploads unique still? I haven't found an efficient
	// way to rename final objects.
	return &s3.CreateMultipartUploadOutput{
		Bucket:   input.Bucket,
		Key:      input.Key,
		UploadId: input.Key,
	}, nil
}

// Each part is translated into an uncommitted block in a newly created blob in staging area
func (az *Azure) UploadPart(ctx context.Context, input *s3.UploadPartInput) (etag string, err error) {
	client, err := az.getBlockBlobClient(*input.Bucket, *input.Key)
	if err != nil {
		return "", err
	}

	// TODO: request streamable version of StageBlock()
	// (*blockblob.Client).StageBlock does not have a streamable
	// version of this function at this time, so we need to cache
	// the body in memory to create an io.ReadSeekCloser
	rdr, err := getReadSeekCloser(input.Body)
	if err != nil {
		return "", err
	}

	// block id serves as etag here
	etag = blockIDInt32ToBase64(*input.PartNumber)
	_, err = client.StageBlock(ctx, etag, rdr, nil)
	if err != nil {
		return "", parseMpError(err)
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
		return s3response.CopyObjectResult{}, parseMpError(err)
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
		return s3response.ListPartsResult{}, parseMpError(err)
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
	for _, el := range resp.UncommittedBlocks {
		partNumber, err := decodeBlockId(*el.Name)
		if err != nil {
			return s3response.ListPartsResult{}, err
		}
		if partNumberMarker != 0 && partNumberMarker >= partNumber {
			continue
		}
		parts = append(parts, s3response.Part{
			Size:         *el.Size,
			ETag:         *el.Name,
			PartNumber:   partNumber,
			LastModified: time.Now().Format(backend.RFC3339TimeFormat),
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
	}, nil
}

// Lists all block blobs, which has uncommitted blocks
func (az *Azure) ListMultipartUploads(ctx context.Context, input *s3.ListMultipartUploadsInput) (s3response.ListMultipartUploadsResult, error) {
	client, err := az.getContainerClient(*input.Bucket)
	if err != nil {
		return s3response.ListMultipartUploadsResult{}, err
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
	// TODO: need to verify this blob has uncommitted blocks?
	_, err := az.client.DeleteBlob(ctx, *input.Bucket, *input.Key, nil)
	if err != nil {
		return parseMpError(err)
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

	blockList, err := client.GetBlockList(ctx, blockblob.BlockListTypeUncommitted, nil)
	if err != nil {
		return nil, azureErrToS3Err(err)
	}

	if len(blockList.UncommittedBlocks) != len(input.MultipartUpload.Parts) {
		return nil, s3err.GetAPIError(s3err.ErrInvalidPart)
	}

	slices.SortFunc(blockList.UncommittedBlocks, func(a *blockblob.Block, b *blockblob.Block) int {
		ptNumber, _ := decodeBlockId(*a.Name)
		nextPtNumber, _ := decodeBlockId(*b.Name)
		return ptNumber - nextPtNumber
	})

	for i, block := range blockList.UncommittedBlocks {
		ptNumber, err := decodeBlockId(*block.Name)
		if err != nil {
			return nil, s3err.GetAPIError(s3err.ErrInvalidPart)
		}

		if *input.MultipartUpload.Parts[i].ETag != *block.Name {
			return nil, s3err.GetAPIError(s3err.ErrInvalidPart)
		}
		if *input.MultipartUpload.Parts[i].PartNumber != int32(ptNumber) {
			return nil, s3err.GetAPIError(s3err.ErrInvalidPart)
		}
		blockIds = append(blockIds, *block.Name)
	}

	resp, err := client.CommitBlockList(ctx, blockIds, nil)
	if err != nil {
		return nil, parseMpError(err)
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
	props, err := client.GetProperties(ctx, nil)
	if err != nil {
		return azureErrToS3Err(err)
	}

	props.Metadata[string(keyAclCapital)] = backend.GetStringPtr(string(data))
	_, err = client.SetMetadata(ctx, &container.SetMetadataOptions{
		Metadata: props.Metadata,
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

	aclPtr, ok := props.Metadata[string(keyAclCapital)]
	if !ok {
		return nil, s3err.GetAPIError(s3err.ErrInternalError)
	}

	return []byte(*aclPtr), nil
}

func (az *Azure) PutBucketPolicy(ctx context.Context, bucket string, policy []byte) error {
	client, err := az.getContainerClient(bucket)
	if err != nil {
		return err
	}

	props, err := client.GetProperties(ctx, nil)
	if err != nil {
		return azureErrToS3Err(err)
	}

	if policy == nil {
		delete(props.Metadata, string(keyPolicy))
	} else {
		// Store policy as base64 encoded, because storing raw json causes an SDK error
		policyEncoded := base64.StdEncoding.EncodeToString(policy)
		props.Metadata[string(keyPolicy)] = &policyEncoded
	}

	_, err = client.SetMetadata(ctx, &container.SetMetadataOptions{
		Metadata: props.Metadata,
	})
	if err != nil {
		return azureErrToS3Err(err)
	}
	return nil
}

func (az *Azure) GetBucketPolicy(ctx context.Context, bucket string) ([]byte, error) {
	client, err := az.getContainerClient(bucket)
	if err != nil {
		return nil, err
	}
	props, err := client.GetProperties(ctx, nil)
	if err != nil {
		return nil, azureErrToS3Err(err)
	}

	policyPtr, ok := props.Metadata[string(keyPolicy)]
	if !ok {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucketPolicy)
	}

	policy, err := base64.StdEncoding.DecodeString(*policyPtr)
	if err != nil {
		return nil, err
	}

	return policy, nil
}

func (az *Azure) DeleteBucketPolicy(ctx context.Context, bucket string) error {
	return az.PutBucketPolicy(ctx, bucket, nil)
}

func (az *Azure) PutObjectLockConfiguration(ctx context.Context, bucket string, config []byte) error {
	client, err := az.getContainerClient(bucket)
	if err != nil {
		return err
	}

	props, err := client.GetProperties(ctx, nil)
	if err != nil {
		return azureErrToS3Err(err)
	}

	cfg, exists := props.Metadata[string(keyBucketLock)]
	if !exists {
		return s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotAllowed)
	}

	var bucketLockCfg auth.BucketLockConfig
	if err := json.Unmarshal([]byte(*cfg), &bucketLockCfg); err != nil {
		return fmt.Errorf("unmarshal object lock config: %w", err)
	}

	if !bucketLockCfg.Enabled {
		return s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotAllowed)
	}

	props.Metadata[string(keyBucketLock)] = backend.GetStringPtr(string(config))

	_, err = client.SetMetadata(ctx, &container.SetMetadataOptions{
		Metadata: props.Metadata,
	})
	if err != nil {
		return azureErrToS3Err(err)
	}

	return nil
}

func (az *Azure) GetObjectLockConfiguration(ctx context.Context, bucket string) ([]byte, error) {
	client, err := az.getContainerClient(bucket)
	if err != nil {
		return nil, err
	}
	props, err := client.GetProperties(ctx, nil)
	if err != nil {
		return nil, azureErrToS3Err(err)
	}

	config, ok := props.Metadata[string(keyBucketLock)]
	if !ok {
		return nil, s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound)
	}

	return []byte(*config), nil
}

func (az *Azure) PutObjectRetention(ctx context.Context, bucket, object, versionId string, bypass bool, retention []byte) error {
	contClient, err := az.getContainerClient(bucket)
	if err != nil {
		return err
	}
	contProps, err := contClient.GetProperties(ctx, nil)
	if err != nil {
		return azureErrToS3Err(err)
	}

	contCfg, ok := contProps.Metadata[string(keyBucketLock)]
	if !ok {
		return s3err.GetAPIError(s3err.ErrInvalidBucketObjectLockConfiguration)
	}

	var bucketLockConfig auth.BucketLockConfig
	if err := json.Unmarshal([]byte(*contCfg), &bucketLockConfig); err != nil {
		return fmt.Errorf("parse bucket lock config: %w", err)
	}

	if !bucketLockConfig.Enabled {
		return s3err.GetAPIError(s3err.ErrInvalidBucketObjectLockConfiguration)
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
			string(keyObjRetention): backend.GetStringPtr(string(retention)),
		}
	} else {
		objLockCfg, ok := meta[string(keyObjRetention)]
		if !ok {
			meta[string(keyObjRetention)] = backend.GetStringPtr(string(retention))
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

			meta[string(keyObjRetention)] = backend.GetStringPtr(string(retention))
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

	retentionPtr, ok := props.Metadata[string(keyObjRetention)]
	if !ok {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchObjectLockConfiguration)
	}

	return []byte(*retentionPtr), nil
}

func (az *Azure) PutObjectLegalHold(ctx context.Context, bucket, object, versionId string, status bool) error {
	contClient, err := az.getContainerClient(bucket)
	if err != nil {
		return err
	}
	contProps, err := contClient.GetProperties(ctx, nil)
	if err != nil {
		return azureErrToS3Err(err)
	}

	contCfg, ok := contProps.Metadata[string(keyBucketLock)]
	if !ok {
		return s3err.GetAPIError(s3err.ErrInvalidBucketObjectLockConfiguration)
	}

	var bucketLockConfig auth.BucketLockConfig
	if err := json.Unmarshal([]byte(*contCfg), &bucketLockConfig); err != nil {
		return fmt.Errorf("parse bucket lock config: %w", err)
	}

	if !bucketLockConfig.Enabled {
		return s3err.GetAPIError(s3err.ErrInvalidBucketObjectLockConfiguration)
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

	retentionPtr, ok := props.Metadata[string(keyObjLegalHold)]
	if !ok {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchObjectLockConfiguration)
	}

	status := *retentionPtr == "1"

	return &status, nil
}

func (az *Azure) ChangeBucketOwner(ctx context.Context, bucket string, acl []byte) error {
	return az.PutBucketAcl(ctx, bucket, acl)
}

// The action actually returns the containers owned by the user, who initialized the gateway
// TODO: Not sure if there's a way to list all the containers and owners?
func (az *Azure) ListBucketsAndOwners(ctx context.Context) (buckets []s3response.Bucket, err error) {
	pager := az.client.NewListContainersPager(nil)

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

func (az *Azure) getContainerURL(cntr string) string {
	return fmt.Sprintf("%v/%v", az.serviceURL, cntr)
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

func getAclFromMetadata(meta map[string]*string, key key) (*auth.ACL, error) {
	aclPtr, ok := meta[string(key)]
	if !ok {
		return nil, s3err.GetAPIError(s3err.ErrInternalError)
	}

	var acl auth.ACL
	err := json.Unmarshal([]byte(*aclPtr), &acl)
	if err != nil {
		return nil, fmt.Errorf("unmarshal acl: %w", err)
	}

	return &acl, nil
}

func isMetaSame(azMeta map[string]*string, awsMeta map[string]string) bool {
	if len(azMeta) != len(awsMeta)+1 {
		return false
	}

	for key, val := range azMeta {
		if key == string(keyAclCapital) || key == string(keyAclLower) {
			continue
		}
		awsVal, ok := awsMeta[key]
		if !ok || awsVal != *val {
			return false
		}
	}

	return true
}
