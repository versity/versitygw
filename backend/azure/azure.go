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
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

type Azure struct {
	backend.BackendUnsupported

	client *azblob.Client
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

	return &Azure{client: client}, nil
}

func (az *Azure) Shutdown() {}

func (az *Azure) String() string {
	return "Azure Blob Gateway"
}

func (az *Azure) CreateBucket(ctx context.Context, input *s3.CreateBucketInput) error {
	// TODO: handle ownership/ACLs
	_, err := az.client.CreateContainer(ctx, *input.Bucket, nil)
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

//func (az *Azure) HeadBucket(ctx context.Context, input *s3.HeadBucketInput) (*s3.HeadBucketOutput, error) {
//}

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
	// TODO: handle range request
	blobDownloadResponse, err := az.client.DownloadStream(ctx, *input.Bucket, *input.Key, nil)
	if err != nil {
		return nil, azureErrToS3Err(err)
	}
	defer blobDownloadResponse.Body.Close()

	_, err = io.Copy(writer, blobDownloadResponse.Body)
	if err != nil {
		return nil, fmt.Errorf("copy data: %w", err)
	}

	tagcount := int32(*blobDownloadResponse.TagCount)

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

func getString(str *string) string {
	if str == nil {
		return ""
	}
	return *str
}

func getStringPtr(str string) *string {
	return &str
}

func azureErrToS3Err(err error) error {
	// TODO: map azure errors to s3 errors
	return err
}
