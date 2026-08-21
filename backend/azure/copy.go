// Copyright 2026 Versity Software
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
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/sas"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/service"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

const copyPollInterval = 500 * time.Millisecond

// errServerSideCopyFallback signals that server-side copy could not be started
// and the caller should fall back to download+reupload. Failures before the
// copy is started are wrapped in this sentinel; once StartCopyFromURL has
// succeeded the destination blob has been written, so later failures are
// returned as-is rather than silently re-copying through the gateway.
var errServerSideCopyFallback = errors.New("server-side copy unavailable")

func (az *Azure) copySourceURL(ctx context.Context, srcBucket, srcObj string) (string, error) {
	if az.sharedkeyCreds != nil {
		now := time.Now().UTC()
		sasQueryParams, err := sas.BlobSignatureValues{
			Protocol:      sas.ProtocolHTTPS,
			Version:       az.copySASVersion,
			StartTime:     now.Add(-10 * time.Second),
			ExpiryTime:    now.Add(15 * time.Minute),
			Permissions:   (&sas.BlobPermissions{Read: true}).String(),
			ContainerName: srcBucket,
			BlobName:      srcObj,
		}.SignWithSharedKey(az.sharedkeyCreds)
		if err != nil {
			return "", err
		}

		return az.getBlobURL(srcBucket, srcObj) + "?" + sasQueryParams.Encode(), nil
	}

	if az.sasToken != "" {
		return az.getBlobURL(srcBucket, srcObj) + "?" + az.sasToken, nil
	}

	if az.defaultCreds != nil {
		svcClient, err := service.NewClient(az.serviceURL, az.defaultCreds, nil)
		if err != nil {
			return "", fmt.Errorf("init service client: %w", err)
		}

		now := time.Now().UTC()
		info := service.KeyInfo{
			Start:  backend.GetPtrFromString(now.Add(-10 * time.Second).Format(sas.TimeFormat)),
			Expiry: backend.GetPtrFromString(now.Add(48 * time.Hour).Format(sas.TimeFormat)),
		}

		udc, err := svcClient.GetUserDelegationCredential(ctx, info, nil)
		if err != nil {
			return "", fmt.Errorf("get user delegation credential: %w", err)
		}

		perms := &sas.BlobPermissions{Read: true}
		sasQueryParams, err := sas.BlobSignatureValues{
			Protocol:      sas.ProtocolHTTPS,
			Version:       az.copySASVersion,
			StartTime:     now.Add(-10 * time.Second),
			ExpiryTime:    now.Add(15 * time.Minute),
			Permissions:   perms.String(),
			ContainerName: srcBucket,
			BlobName:      srcObj,
		}.SignWithUserDelegation(udc)
		if err != nil {
			return "", fmt.Errorf("sign user delegation sas: %w", err)
		}

		return az.getBlobURL(srcBucket, srcObj) + "?" + sasQueryParams.Encode(), nil
	}

	return "", errors.New("no credentials available")
}

func (az *Azure) serverSideCopyObject(
	ctx context.Context,
	input s3response.CopyObjectInput,
	srcBucket, srcObj string,
	dstClient, srcClient *blob.Client,
	srcProps *blob.GetPropertiesResponse,
) (s3response.CopyObjectOutput, error) {
	srcURL, err := az.copySourceURL(ctx, srcBucket, srcObj)
	if err != nil {
		// Any failure to build a signed source URL means server-side copy can't
		// be started at all, so fall back instead of failing the request. This
		// notably covers GetUserDelegationCredential, which fails if the gateway
		// identity lacks the Storage Blob Delegator role or the endpoint doesn't
		// implement the delegation key API.
		return s3response.CopyObjectOutput{}, fmt.Errorf("%w: %v", errServerSideCopyFallback, err)
	}

	opts := &blob.StartCopyFromURLOptions{}

	// Copy Blob reads absent x-ms-meta-* headers as "inherit the source
	// metadata", so an empty opts.Metadata cannot express "no metadata". When
	// filtering empties the set, the destination metadata has to be cleared
	// after the copy instead.
	clearMetadata := false

	if input.MetadataDirective == types.MetadataDirectiveReplace {
		meta := input.Metadata
		if meta == nil {
			meta = make(map[string]string)
		}
		if getString(input.Expires) != "" {
			meta[string(keyExpires)] = *input.Expires
		}
		if getString(input.WebsiteRedirectLocation) != "" {
			meta[string(keyWebsiteRedirect)] = *input.WebsiteRedirectLocation
		}
		opts.Metadata = parseMetadata(meta)
	} else {
		// MetadataDirective COPY: StartCopyFromURL would otherwise copy the
		// source blob's metadata verbatim, including the internal website-redirect
		// key. Set the metadata explicitly so that key is dropped from the
		// destination, matching the download+reupload fallback.
		if srcProps == nil {
			return s3response.CopyObjectOutput{}, fmt.Errorf(
				"%w: source properties required to filter metadata", errServerSideCopyFallback)
		}
		if meta := parseAzMetadata(srcProps.Metadata); meta != nil {
			delete(meta, string(keyWebsiteRedirect))
			opts.Metadata = parseMetadata(meta)
			clearMetadata = len(meta) == 0
		}
	}

	if input.TaggingDirective == types.TaggingDirectiveReplace {
		tags, err := backend.ParseObjectTags(getString(input.Tagging))
		if err != nil {
			return s3response.CopyObjectOutput{}, err
		}
		opts.BlobTags = tags
	}

	startResp, err := dstClient.StartCopyFromURL(ctx, srcURL, opts)
	if err != nil {
		return s3response.CopyObjectOutput{}, fmt.Errorf("%w: %v", errServerSideCopyFallback, err)
	}

	finalProps, err := az.waitForCopy(ctx, dstClient, startResp.CopyStatus)
	if err != nil {
		return s3response.CopyObjectOutput{}, err
	}

	if clearMetadata {
		res, err := dstClient.SetMetadata(ctx, nil, nil)
		if err != nil {
			return s3response.CopyObjectOutput{}, azureErrToS3Err(err)
		}
		if res.LastModified != nil {
			finalProps.LastModified = res.LastModified
		}
		if res.ETag != nil {
			finalProps.ETag = res.ETag
		}
	}

	if input.MetadataDirective == types.MetadataDirectiveReplace {
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
		if res.LastModified != nil {
			finalProps.LastModified = res.LastModified
		}
		if res.ETag != nil {
			finalProps.ETag = res.ETag
		}
	}

	if input.TaggingDirective == types.TaggingDirectiveCopy {
		res, err := srcClient.GetTags(ctx, nil)
		if err != nil {
			return s3response.CopyObjectOutput{}, azureErrToS3Err(err)
		}
		_, err = dstClient.SetTags(ctx, parseAzTags(res.BlobTagSet), nil)
		if err != nil {
			return s3response.CopyObjectOutput{}, azureErrToS3Err(err)
		}
	}

	if err := az.applyCopyObjectLock(ctx, *input.Bucket, *input.Key, input); err != nil {
		return s3response.CopyObjectOutput{}, err
	}

	var etag string
	if finalProps.ETag != nil {
		etag = convertAzureEtag(finalProps.ETag)
	} else if startResp.ETag != nil {
		etag = convertAzureEtag(startResp.ETag)
	}

	lastModified := finalProps.LastModified
	if lastModified == nil {
		lastModified = startResp.LastModified
	}

	return s3response.CopyObjectOutput{
		CopyObjectResult: &s3response.CopyObjectResult{
			LastModified: lastModified,
			ETag:         backend.GetPtrFromString(etag),
		},
	}, nil
}

func (az *Azure) waitForCopy(ctx context.Context, dstClient *blob.Client, initialStatus *blob.CopyStatusType) (*blob.GetPropertiesResponse, error) {
	status := initialStatus
	for status != nil && *status == blob.CopyStatusTypePending {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(copyPollInterval):
		}

		props, err := dstClient.GetProperties(ctx, nil)
		if err != nil {
			return nil, azureErrToS3Err(err)
		}
		status = props.CopyStatus
	}

	props, err := dstClient.GetProperties(ctx, nil)
	if err != nil {
		return nil, azureErrToS3Err(err)
	}

	if props.CopyStatus != nil {
		switch *props.CopyStatus {
		case blob.CopyStatusTypeFailed, blob.CopyStatusTypeAborted:
			return nil, fmt.Errorf("blob copy failed with status %s", *props.CopyStatus)
		}
	}

	return &props, nil
}

func (az *Azure) applyCopyObjectLock(ctx context.Context, bucket, key string, input s3response.CopyObjectInput) error {
	if input.ObjectLockLegalHoldStatus != "" {
		err := az.PutObjectLegalHold(ctx, bucket, key, "", input.ObjectLockLegalHoldStatus == types.ObjectLockLegalHoldStatusOn)
		if err != nil {
			if errors.Is(err, s3err.GetAPIError(s3err.ErrMissingObjectLockConfiguration)) {
				err = s3err.GetAPIError(s3err.ErrMissingObjectLockConfigurationNoSpaces)
			}
			return azureErrToS3Err(err)
		}
	}

	if input.ObjectLockMode != "" && input.ObjectLockRetainUntilDate != nil {
		retention := s3response.PutObjectRetentionInput{
			Mode: types.ObjectLockRetentionMode(input.ObjectLockMode),
			RetainUntilDate: s3response.AmzDate{
				Time: *input.ObjectLockRetainUntilDate,
			},
		}

		retParsed, err := json.Marshal(retention)
		if err != nil {
			return fmt.Errorf("parse object retention: %w", err)
		}
		err = az.PutObjectRetention(ctx, bucket, key, "", retParsed)
		if err != nil {
			if errors.Is(err, s3err.GetAPIError(s3err.ErrMissingObjectLockConfiguration)) {
				err = s3err.GetAPIError(s3err.ErrMissingObjectLockConfigurationNoSpaces)
			}
			return azureErrToS3Err(err)
		}
	}

	return nil
}
