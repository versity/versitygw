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

package controllers

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3event"
	"github.com/versity/versitygw/s3response"
)

func (c S3ApiController) PutObjectTagging(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	key := strings.TrimPrefix(ctx.Path(), fmt.Sprintf("/%s/", bucket))
	versionId := ctx.Query("versionId")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	IsBucketPublic := utils.ContextKeyPublicBucket.IsSet(ctx)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	action := auth.PutObjectTaggingAction
	if versionId != "" {
		action = auth.PutObjectVersionTaggingAction
	}

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:        c.readonly,
		Acl:             parsedAcl,
		AclPermission:   auth.PermissionWrite,
		IsRoot:          isRoot,
		Acc:             acct,
		Bucket:          bucket,
		Object:          key,
		Action:          action,
		IsPublicRequest: IsBucketPublic,
	})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	err = utils.ValidateVersionId(versionId)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	tagging, err := utils.ParseTagging(ctx.Body(), utils.TagLimitObject)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	err = c.be.PutObjectTagging(ctx.Context(), bucket, key, versionId, tagging)
	return &Response{
		Headers: map[string]*string{
			"x-amz-version-id": &versionId,
		},
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
			EventName:   s3event.EventObjectTaggingPut,
		},
	}, err
}

func (c S3ApiController) PutObjectRetention(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	key := strings.TrimPrefix(ctx.Path(), fmt.Sprintf("/%s/", bucket))
	versionId := ctx.Query("versionId")
	bypass := strings.EqualFold(ctx.Get("X-Amz-Bypass-Governance-Retention"), "true")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	IsBucketPublic := utils.ContextKeyPublicBucket.IsSet(ctx)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:        c.readonly,
		Acl:             parsedAcl,
		AclPermission:   auth.PermissionWrite,
		IsRoot:          isRoot,
		Acc:             acct,
		Bucket:          bucket,
		Object:          key,
		Action:          auth.PutObjectRetentionAction,
		IsPublicRequest: IsBucketPublic,
	})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	err = utils.ValidateVersionId(versionId)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	// parse the request body bytes into a go struct and validate
	retention, err := auth.ParseObjectLockRetentionInput(ctx.Body())
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	// check if the operation is allowed
	err = auth.IsObjectLockRetentionPutAllowed(ctx.Context(), c.be, bucket, key, versionId, acct.Access, retention, bypass)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	// parse the retention to JSON
	data, err := auth.ParseObjectLockRetentionInputToJSON(retention)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	err = c.be.PutObjectRetention(ctx.Context(), bucket, key, versionId, data)
	return &Response{
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
		},
	}, err
}

func (c S3ApiController) PutObjectLegalHold(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	key := strings.TrimPrefix(ctx.Path(), fmt.Sprintf("/%s/", bucket))
	versionId := ctx.Query("versionId")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	IsBucketPublic := utils.ContextKeyPublicBucket.IsSet(ctx)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:        c.readonly,
		Acl:             parsedAcl,
		AclPermission:   auth.PermissionWrite,
		IsRoot:          isRoot,
		Acc:             acct,
		Bucket:          bucket,
		Object:          key,
		Action:          auth.PutObjectLegalHoldAction,
		IsPublicRequest: IsBucketPublic,
	})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	err = utils.ValidateVersionId(versionId)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	var legalHold types.ObjectLockLegalHold
	if err := xml.Unmarshal(ctx.Body(), &legalHold); err != nil {
		debuglogger.Logf("failed to parse request body: %v", err)
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrMalformedXML)
	}

	if legalHold.Status != types.ObjectLockLegalHoldStatusOff && legalHold.Status != types.ObjectLockLegalHoldStatusOn {
		debuglogger.Logf("invalid legal hold status: %v", legalHold.Status)
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrMalformedXML)
	}

	err = c.be.PutObjectLegalHold(ctx.Context(), bucket, key, versionId, legalHold.Status == types.ObjectLockLegalHoldStatusOn)
	return &Response{
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
		},
	}, err
}

func (c S3ApiController) UploadPart(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	key := strings.TrimPrefix(ctx.Path(), fmt.Sprintf("/%s/", bucket))
	partNumber := int32(ctx.QueryInt("partNumber", -1))
	uploadId := ctx.Query("uploadId")
	// context locals
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	IsBucketPublic := utils.ContextKeyPublicBucket.IsSet(ctx)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	contentLengthStr := ctx.Get("Content-Length")
	if contentLengthStr == "" {
		contentLengthStr = "0"
	}
	// Use decoded content length if available because the
	// middleware will decode the chunked transfer encoding
	decodedLength := ctx.Get("X-Amz-Decoded-Content-Length")
	if decodedLength != "" {
		contentLengthStr = decodedLength
	}

	err := auth.VerifyAccess(ctx.Context(), c.be,
		auth.AccessOptions{
			Readonly:        c.readonly,
			Acl:             parsedAcl,
			AclPermission:   auth.PermissionWrite,
			IsRoot:          isRoot,
			Acc:             acct,
			Bucket:          bucket,
			Object:          key,
			Action:          auth.PutObjectAction,
			IsPublicRequest: IsBucketPublic,
		})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	if partNumber < minPartNumber || partNumber > maxPartNumber {
		debuglogger.Logf("invalid part number: %d", partNumber)
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrInvalidPartNumber)
	}

	contentLength, err := strconv.ParseInt(contentLengthStr, 10, 64)
	if err != nil {
		debuglogger.Logf("error parsing content length %q: %v", contentLengthStr, err)
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrInvalidRequest)
	}

	algorithm, checksums, err := utils.ParseChecksumHeadersAndSdkAlgo(ctx)
	if err != nil {
		debuglogger.Logf("err parsing checksum headers: %v", err)
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	var body io.Reader
	bodyi := utils.ContextKeyBodyReader.Get(ctx)
	if bodyi != nil {
		body = bodyi.(io.Reader)
	} else {
		body = bytes.NewReader([]byte{})
	}

	res, err := c.be.UploadPart(ctx.Context(),
		&s3.UploadPartInput{
			Bucket:            &bucket,
			Key:               &key,
			UploadId:          &uploadId,
			PartNumber:        &partNumber,
			ContentLength:     &contentLength,
			Body:              body,
			ChecksumAlgorithm: algorithm,
			ChecksumCRC32:     utils.GetStringPtr(checksums[types.ChecksumAlgorithmCrc32]),
			ChecksumCRC32C:    utils.GetStringPtr(checksums[types.ChecksumAlgorithmCrc32c]),
			ChecksumSHA1:      utils.GetStringPtr(checksums[types.ChecksumAlgorithmSha1]),
			ChecksumSHA256:    utils.GetStringPtr(checksums[types.ChecksumAlgorithmSha256]),
			ChecksumCRC64NVME: utils.GetStringPtr(checksums[types.ChecksumAlgorithmCrc64nvme]),
		})
	var headers map[string]*string
	if err == nil {
		headers = map[string]*string{
			"ETag":                     res.ETag,
			"x-amz-checksum-crc32":     res.ChecksumCRC32,
			"x-amz-checksum-crc32c":    res.ChecksumCRC32C,
			"x-amz-checksum-crc64nvme": res.ChecksumCRC64NVME,
			"x-amz-checksum-sha1":      res.ChecksumSHA1,
			"x-amz-checksum-sha256":    res.ChecksumSHA256,
		}
	}
	return &Response{
		Headers: headers,
		MetaOpts: &MetaOptions{
			ContentLength: contentLength,
			BucketOwner:   parsedAcl.Owner,
		},
	}, err

}

func (c S3ApiController) UploadPartCopy(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	key := strings.TrimPrefix(ctx.Path(), fmt.Sprintf("/%s/", bucket))
	copySource := strings.TrimPrefix(ctx.Get("X-Amz-Copy-Source"), "/")
	copySrcRange := ctx.Get("X-Amz-Copy-Source-Range")
	partNumber := int32(ctx.QueryInt("partNumber", -1))
	uploadId := ctx.Query("uploadId")
	// context locals
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	IsBucketPublic := utils.ContextKeyPublicBucket.IsSet(ctx)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	err := utils.ValidateCopySource(copySource)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	err = auth.VerifyObjectCopyAccess(ctx.Context(), c.be, copySource,
		auth.AccessOptions{
			Acl:             parsedAcl,
			AclPermission:   auth.PermissionWrite,
			IsRoot:          isRoot,
			Acc:             acct,
			Bucket:          bucket,
			Object:          key,
			Action:          auth.PutObjectAction,
			IsPublicRequest: IsBucketPublic,
		})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	if len(ctx.Request().Body()) != 0 {
		debuglogger.Logf("expected empty request body")
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrNonEmptyRequestBody)
	}

	if partNumber < minPartNumber || partNumber > maxPartNumber {
		debuglogger.Logf("invalid part number: %d", partNumber)
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrInvalidPartNumber)
	}

	preconditionHdrs := utils.ParsePreconditionHeaders(ctx, utils.WithCopySource())

	resp, err := c.be.UploadPartCopy(ctx.Context(),
		&s3.UploadPartCopyInput{
			Bucket:                      &bucket,
			Key:                         &key,
			CopySource:                  &copySource,
			PartNumber:                  &partNumber,
			UploadId:                    &uploadId,
			CopySourceRange:             &copySrcRange,
			CopySourceIfMatch:           preconditionHdrs.IfMatch,
			CopySourceIfNoneMatch:       preconditionHdrs.IfNoneMatch,
			CopySourceIfModifiedSince:   preconditionHdrs.IfModSince,
			CopySourceIfUnmodifiedSince: preconditionHdrs.IfUnmodeSince,
		})
	var headers map[string]*string
	if err == nil && resp.CopySourceVersionId != "" {
		headers = map[string]*string{
			"x-amz-copy-source-version-id": &resp.CopySourceVersionId,
		}
	}
	return &Response{
		Headers: headers,
		Data:    resp,
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
		},
	}, err
}

func (c S3ApiController) PutObjectAcl(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	key := strings.TrimPrefix(ctx.Path(), fmt.Sprintf("/%s/", bucket))
	acl := ctx.Get("X-Amz-Acl")
	grantFullControl := ctx.Get("X-Amz-Grant-Full-Control")
	grantRead := ctx.Get("X-Amz-Grant-Read")
	grantReadACP := ctx.Get("X-Amz-Grant-Read-Acp")
	grantWrite := ctx.Get("X-Amz-Grant-Write")
	grantWriteACP := ctx.Get("X-Amz-Grant-Write-Acp")
	// context locals
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	err := auth.VerifyAccess(ctx.Context(), c.be,
		auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: auth.PermissionWrite,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Object:        key,
			Action:        auth.PutObjectAclAction,
		})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	err = c.be.PutObjectAcl(ctx.Context(), &s3.PutObjectAclInput{
		Bucket:           &bucket,
		Key:              &key,
		GrantFullControl: &grantFullControl,
		GrantRead:        &grantRead,
		GrantWrite:       &grantWrite,
		ACL:              types.ObjectCannedACL(acl),
		GrantReadACP:     &grantReadACP,
		GrantWriteACP:    &grantWriteACP,
	})
	return &Response{
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
			EventName:   s3event.EventObjectAclPut,
		},
	}, err
}

func (c S3ApiController) CopyObject(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	key := strings.TrimPrefix(ctx.Path(), fmt.Sprintf("/%s/", bucket))
	copySource := strings.TrimPrefix(ctx.Get("X-Amz-Copy-Source"), "/")
	metaDirective := types.MetadataDirective(ctx.Get("X-Amz-Metadata-Directive", string(types.MetadataDirectiveCopy)))
	taggingDirective := types.TaggingDirective(ctx.Get("X-Amz-Tagging-Directive", string(types.TaggingDirectiveCopy)))
	contentType := ctx.Get("Content-Type")
	contentEncoding := ctx.Get("Content-Encoding")
	contentDisposition := ctx.Get("Content-Disposition")
	contentLanguage := ctx.Get("Content-Language")
	cacheControl := ctx.Get("Cache-Control")
	expires := ctx.Get("Expires")
	tagging := ctx.Get("x-amz-tagging")
	storageClass := ctx.Get("X-Amz-Storage-Class")
	// context locals
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	err := utils.ValidateCopySource(copySource)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	err = auth.VerifyObjectCopyAccess(ctx.Context(), c.be, copySource,
		auth.AccessOptions{
			Acl:           parsedAcl,
			AclPermission: auth.PermissionWrite,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Object:        key,
			Action:        auth.PutObjectAction,
		})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	if len(ctx.Request().Body()) != 0 {
		debuglogger.Logf("expected empty request body")
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrNonEmptyRequestBody)
	}

	metadata := utils.GetUserMetaData(&ctx.Request().Header)

	if metaDirective != "" && metaDirective != types.MetadataDirectiveCopy && metaDirective != types.MetadataDirectiveReplace {
		debuglogger.Logf("invalid metadata directive: %v", metaDirective)
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrInvalidMetadataDirective)
	}

	if taggingDirective != "" && taggingDirective != types.TaggingDirectiveCopy && taggingDirective != types.TaggingDirectiveReplace {
		debuglogger.Logf("invalid tagging directive: %v", taggingDirective)
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrInvalidTaggingDirective)
	}

	checksumAlgorithm := types.ChecksumAlgorithm(ctx.Get("x-amz-checksum-algorithm"))
	err = utils.IsChecksumAlgorithmValid(checksumAlgorithm)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	objLock, err := utils.ParsObjectLockHdrs(ctx)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	preconditionHdrs := utils.ParsePreconditionHeaders(ctx, utils.WithCopySource())

	err = auth.CheckObjectAccess(ctx.Context(), bucket, acct.Access, []types.ObjectIdentifier{{Key: &key}}, true, false, c.be, true)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	res, err := c.be.CopyObject(ctx.Context(),
		s3response.CopyObjectInput{
			Bucket:                      &bucket,
			Key:                         &key,
			ContentType:                 &contentType,
			ContentDisposition:          &contentDisposition,
			ContentEncoding:             &contentEncoding,
			ContentLanguage:             &contentLanguage,
			CacheControl:                &cacheControl,
			Expires:                     &expires,
			Tagging:                     &tagging,
			TaggingDirective:            taggingDirective,
			CopySource:                  &copySource,
			CopySourceIfMatch:           preconditionHdrs.IfMatch,
			CopySourceIfNoneMatch:       preconditionHdrs.IfNoneMatch,
			CopySourceIfModifiedSince:   preconditionHdrs.IfModSince,
			CopySourceIfUnmodifiedSince: preconditionHdrs.IfUnmodeSince,
			ExpectedBucketOwner:         &acct.Access,
			Metadata:                    metadata,
			MetadataDirective:           metaDirective,
			StorageClass:                types.StorageClass(storageClass),
			ChecksumAlgorithm:           checksumAlgorithm,
			ObjectLockRetainUntilDate:   &objLock.RetainUntilDate,
			ObjectLockLegalHoldStatus:   objLock.LegalHoldStatus,
			ObjectLockMode:              objLock.ObjectLockMode,
		})

	var etag *string
	if err == nil {
		etag = res.CopyObjectResult.ETag
	}

	return &Response{
		Headers: map[string]*string{
			"x-amz-version-id":             res.VersionId,
			"x-amz-copy-source-version-id": res.CopySourceVersionId,
		},
		Data: res.CopyObjectResult,
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
			ObjectETag:  etag,
			VersionId:   res.VersionId,
			EventName:   s3event.EventObjectCreatedCopy,
		},
	}, err
}

func (c S3ApiController) PutObject(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	key := strings.TrimPrefix(ctx.Path(), fmt.Sprintf("/%s/", bucket))
	contentType := ctx.Get("Content-Type")
	contentEncoding := ctx.Get("Content-Encoding")
	contentDisposition := ctx.Get("Content-Disposition")
	contentLanguage := ctx.Get("Content-Language")
	cacheControl := ctx.Get("Cache-Control")
	expires := ctx.Get("Expires")
	tagging := ctx.Get("x-amz-tagging")
	// context locals
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	IsBucketPublic := utils.ContextKeyPublicBucket.IsSet(ctx)

	// Content Length
	contentLengthStr := ctx.Get("Content-Length")
	if contentLengthStr == "" {
		contentLengthStr = "0"
	}
	// Use decoded content length if available because the
	// middleware will decode the chunked transfer encoding
	decodedLength := ctx.Get("X-Amz-Decoded-Content-Length")
	if decodedLength != "" {
		contentLengthStr = decodedLength
	}

	// load the meta headers
	metadata := utils.GetUserMetaData(&ctx.Request().Header)

	err := auth.VerifyAccess(ctx.Context(), c.be,
		auth.AccessOptions{
			Readonly:        c.readonly,
			Acl:             parsedAcl,
			AclPermission:   auth.PermissionWrite,
			IsRoot:          isRoot,
			Acc:             acct,
			Bucket:          bucket,
			Object:          key,
			Action:          auth.PutObjectAction,
			IsPublicRequest: IsBucketPublic,
		})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	err = auth.CheckObjectAccess(ctx.Context(), bucket, acct.Access, []types.ObjectIdentifier{{Key: &key}}, true, IsBucketPublic, c.be, true)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	contentLength, err := strconv.ParseInt(contentLengthStr, 10, 64)
	if err != nil {
		debuglogger.Logf("error parsing content length %q: %v", contentLengthStr, err)
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrInvalidRequest)
	}

	objLock, err := utils.ParsObjectLockHdrs(ctx)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	algorithm, checksums, err := utils.ParseChecksumHeadersAndSdkAlgo(ctx)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	var body io.Reader
	bodyi := utils.ContextKeyBodyReader.Get(ctx)
	if bodyi != nil {
		body = bodyi.(io.Reader)
	} else {
		body = bytes.NewReader([]byte{})
	}

	ifMatch, ifNoneMatch := utils.ParsePreconditionMatchHeaders(ctx)

	res, err := c.be.PutObject(ctx.Context(),
		s3response.PutObjectInput{
			Bucket:                    &bucket,
			Key:                       &key,
			ContentLength:             &contentLength,
			ContentType:               &contentType,
			ContentEncoding:           &contentEncoding,
			ContentDisposition:        &contentDisposition,
			ContentLanguage:           &contentLanguage,
			CacheControl:              &cacheControl,
			Expires:                   &expires,
			Metadata:                  metadata,
			Body:                      body,
			Tagging:                   &tagging,
			ObjectLockRetainUntilDate: &objLock.RetainUntilDate,
			ObjectLockMode:            objLock.ObjectLockMode,
			ObjectLockLegalHoldStatus: objLock.LegalHoldStatus,
			ChecksumAlgorithm:         algorithm,
			ChecksumCRC32:             utils.GetStringPtr(checksums[types.ChecksumAlgorithmCrc32]),
			ChecksumCRC32C:            utils.GetStringPtr(checksums[types.ChecksumAlgorithmCrc32c]),
			ChecksumSHA1:              utils.GetStringPtr(checksums[types.ChecksumAlgorithmSha1]),
			ChecksumSHA256:            utils.GetStringPtr(checksums[types.ChecksumAlgorithmSha256]),
			ChecksumCRC64NVME:         utils.GetStringPtr(checksums[types.ChecksumAlgorithmCrc64nvme]),
			IfMatch:                   ifMatch,
			IfNoneMatch:               ifNoneMatch,
		})
	return &Response{
		Headers: map[string]*string{
			"ETag":                     &res.ETag,
			"x-amz-checksum-crc32":     res.ChecksumCRC32,
			"x-amz-checksum-crc32c":    res.ChecksumCRC32C,
			"x-amz-checksum-crc64nvme": res.ChecksumCRC64NVME,
			"x-amz-checksum-sha1":      res.ChecksumSHA1,
			"x-amz-checksum-sha256":    res.ChecksumSHA256,
			"x-amz-checksum-type":      utils.ConvertToStringPtr(res.ChecksumType),
			"x-amz-version-id":         &res.VersionID,
			"x-amz-object-size":        utils.ConvertPtrToStringPtr(res.Size),
		},
		MetaOpts: &MetaOptions{
			ContentLength: contentLength,
			BucketOwner:   parsedAcl.Owner,
			ObjectETag:    &res.ETag,
			ObjectSize:    contentLength,
			EventName:     s3event.EventObjectCreatedPut,
		},
	}, err
}
