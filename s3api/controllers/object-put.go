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
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/s3api/debuglogger"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3event"
	"github.com/versity/versitygw/s3response"
)

func (c S3ApiController) PutObjectTagging(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	key := strings.TrimPrefix(ctx.Path(), fmt.Sprintf("/%s/", bucket))
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	IsBucketPublic := utils.ContextKeyPublicBucket.IsSet(ctx)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	tagging, err := utils.ParseTagging(ctx.Body(), utils.TagLimitObject)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutObjectTagging,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	err = auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:       c.readonly,
		Acl:            parsedAcl,
		AclPermission:  auth.PermissionWrite,
		IsRoot:         isRoot,
		Acc:            acct,
		Bucket:         bucket,
		Object:         key,
		Action:         auth.PutBucketTaggingAction,
		IsBucketPublic: IsBucketPublic,
	})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutObjectTagging,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	err = c.be.PutObjectTagging(ctx.Context(), bucket, key, tagging)
	return &Response{
		MetaOpts: &MetaOptions{
			Action:      metrics.ActionPutObjectTagging,
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

	if err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:       c.readonly,
		Acl:            parsedAcl,
		AclPermission:  auth.PermissionWrite,
		IsRoot:         isRoot,
		Acc:            acct,
		Bucket:         bucket,
		Object:         key,
		Action:         auth.PutObjectRetentionAction,
		IsBucketPublic: IsBucketPublic,
	}); err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutObjectRetention,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	if bypass {
		policy, err := c.be.GetBucketPolicy(ctx.Context(), bucket)
		if err != nil {
			bypass = false
		} else {
			if err := auth.VerifyBucketPolicy(policy, acct.Access, bucket, key, auth.BypassGovernanceRetentionAction); err != nil {
				bypass = false
			}
		}
	}

	retention, err := auth.ParseObjectLockRetentionInput(ctx.Body())
	if err != nil {
		debuglogger.Logf("failed to parse object lock configuration input: %v", err)
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutObjectRetention,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	err = c.be.PutObjectRetention(ctx.Context(), bucket, key, versionId, bypass, retention)
	return &Response{
		MetaOpts: &MetaOptions{
			Action:      metrics.ActionPutObjectRetention,
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

	var legalHold types.ObjectLockLegalHold
	if err := xml.Unmarshal(ctx.Body(), &legalHold); err != nil {
		debuglogger.Logf("failed to parse request body: %v", err)
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutObjectLegalHold,
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrMalformedXML)
	}

	if legalHold.Status != types.ObjectLockLegalHoldStatusOff && legalHold.Status != types.ObjectLockLegalHoldStatusOn {
		debuglogger.Logf("invalid legal hold status: %v", legalHold.Status)
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutObjectLegalHold,
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrMalformedXML)
	}

	if err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:       c.readonly,
		Acl:            parsedAcl,
		AclPermission:  auth.PermissionWrite,
		IsRoot:         isRoot,
		Acc:            acct,
		Bucket:         bucket,
		Object:         key,
		Action:         auth.PutObjectLegalHoldAction,
		IsBucketPublic: IsBucketPublic,
	}); err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutObjectLegalHold,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	err := c.be.PutObjectLegalHold(ctx.Context(), bucket, key, versionId, legalHold.Status == types.ObjectLockLegalHoldStatusOn)
	return &Response{
		MetaOpts: &MetaOptions{
			Action:      metrics.ActionPutObjectLegalHold,
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

	if partNumber < 1 || partNumber > 10000 {
		debuglogger.Logf("invalid part number: %d", partNumber)
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionUploadPart,
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrInvalidPartNumber)
	}

	err := auth.VerifyAccess(ctx.Context(), c.be,
		auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionWrite,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Object:         key,
			Action:         auth.PutObjectAction,
			IsBucketPublic: IsBucketPublic,
		})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionUploadPart,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	contentLength, err := strconv.ParseInt(contentLengthStr, 10, 64)
	if err != nil {
		debuglogger.Logf("error parsing content length %q: %v", contentLengthStr, err)
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionUploadPart,
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrInvalidRequest)
	}

	algorithm, checksums, err := utils.ParseChecksumHeaders(ctx)
	if err != nil {
		debuglogger.Logf("err parsing checksum headers: %v", err)
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionUploadPart,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	var body io.Reader
	bodyi := utils.ContextKeyBodyReader.Get(ctx)
	if bodyi != nil {
		body = bodyi.(io.Reader)
	} else {
		body = ctx.Request().BodyStream()
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
			Action:        metrics.ActionUploadPart,
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

	cs := copySource
	copySource, err := url.QueryUnescape(copySource)
	if err != nil {
		debuglogger.Logf("error unescaping copy source %q: %v", cs, err)
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionUploadPartCopy,
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrInvalidCopySource)
	}

	if partNumber < 1 || partNumber > 10000 {
		debuglogger.Logf("invalid part number: %d", partNumber)
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionUploadPartCopy,
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrInvalidPartNumber)
	}

	err = auth.VerifyObjectCopyAccess(ctx.Context(), c.be, copySource,
		auth.AccessOptions{
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionWrite,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Object:         key,
			Action:         auth.PutObjectAction,
			IsBucketPublic: IsBucketPublic,
		})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionUploadPartCopy,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	resp, err := c.be.UploadPartCopy(ctx.Context(),
		&s3.UploadPartCopyInput{
			Bucket:          &bucket,
			Key:             &key,
			CopySource:      &copySource,
			PartNumber:      &partNumber,
			UploadId:        &uploadId,
			CopySourceRange: &copySrcRange,
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
			Action:      metrics.ActionUploadPartCopy,
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
	granWrite := ctx.Get("X-Amz-Grant-Write")
	grantWriteACP := ctx.Get("X-Amz-Grant-Write-Acp")
	grants := grantFullControl + grantRead + grantReadACP + granWrite + grantWriteACP
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
				Action:      metrics.ActionPutObjectAcl,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	var input *s3.PutObjectAclInput
	if len(ctx.Body()) > 0 {
		if grants+acl != "" {
			debuglogger.Logf("invalid request: %q (grants) %q (acl)", grants, acl)
			return &Response{
				MetaOpts: &MetaOptions{
					Action:      metrics.ActionPutObjectAcl,
					BucketOwner: parsedAcl.Owner,
				},
			}, s3err.GetAPIError(s3err.ErrInvalidRequest)
		}

		var accessControlPolicy auth.AccessControlPolicy
		err := xml.Unmarshal(ctx.Body(), &accessControlPolicy)
		if err != nil {
			debuglogger.Logf("error unmarshalling access control policy: %v", err)
			return &Response{
				MetaOpts: &MetaOptions{
					Action:      metrics.ActionPutObjectAcl,
					BucketOwner: parsedAcl.Owner,
				},
			}, s3err.GetAPIError(s3err.ErrInvalidRequest)
		}

		//TODO: This part will be changed when object acls are implemented

		grants := []types.Grant{}
		for _, grt := range accessControlPolicy.AccessControlList.Grants {
			grants = append(grants, types.Grant{
				Grantee: &types.Grantee{
					ID:   &grt.Grantee.ID,
					Type: grt.Grantee.Type,
				},
				Permission: types.Permission(grt.Permission),
			})
		}

		input = &s3.PutObjectAclInput{
			Bucket: &bucket,
			Key:    &key,
			ACL:    "",
			AccessControlPolicy: &types.AccessControlPolicy{
				Owner:  accessControlPolicy.Owner,
				Grants: grants,
			},
		}
	}
	if acl != "" {
		if acl != "private" && acl != "public-read" && acl != "public-read-write" {
			debuglogger.Logf("invalid acl: %q", acl)
			return &Response{
				MetaOpts: &MetaOptions{
					Action:      metrics.ActionPutObjectAcl,
					BucketOwner: parsedAcl.Owner,
				},
			}, s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
		if len(ctx.Body()) > 0 || grants != "" {
			debuglogger.Logf("invalid request: %q (grants) %q (acl) %v (body len)", grants, acl, len(ctx.Body()))
			return &Response{
				MetaOpts: &MetaOptions{
					Action:      metrics.ActionPutObjectAcl,
					BucketOwner: parsedAcl.Owner,
				},
			}, s3err.GetAPIError(s3err.ErrInvalidRequest)
		}

		input = &s3.PutObjectAclInput{
			Bucket: &bucket,
			Key:    &key,
			ACL:    types.ObjectCannedACL(acl),
			AccessControlPolicy: &types.AccessControlPolicy{
				Owner: &types.Owner{ID: &parsedAcl.Owner},
			},
		}
	}
	if grants != "" {
		input = &s3.PutObjectAclInput{
			Bucket:           &bucket,
			Key:              &key,
			GrantFullControl: &grantFullControl,
			GrantRead:        &grantRead,
			GrantReadACP:     &grantReadACP,
			GrantWrite:       &granWrite,
			GrantWriteACP:    &grantWriteACP,
			AccessControlPolicy: &types.AccessControlPolicy{
				Owner: &types.Owner{ID: &parsedAcl.Owner},
			},
			ACL: "",
		}
	}

	err = c.be.PutObjectAcl(ctx.Context(), input)
	return &Response{
		MetaOpts: &MetaOptions{
			Action:      metrics.ActionPutObjectAcl,
			BucketOwner: parsedAcl.Owner,
			EventName:   s3event.EventObjectAclPut,
		},
	}, err
}

func (c S3ApiController) CopyObject(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	key := strings.TrimPrefix(ctx.Path(), fmt.Sprintf("/%s/", bucket))
	copySource := strings.TrimPrefix(ctx.Get("X-Amz-Copy-Source"), "/")
	copySrcIfMatch := ctx.Get("X-Amz-Copy-Source-If-Match")
	copySrcIfNoneMatch := ctx.Get("X-Amz-Copy-Source-If-None-Match")
	copySrcModifSince := ctx.Get("X-Amz-Copy-Source-If-Modified-Since")
	copySrcUnmodifSince := ctx.Get("X-Amz-Copy-Source-If-Unmodified-Since")
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

	cs := copySource
	copySource, err := url.QueryUnescape(copySource)
	if err != nil {
		debuglogger.Logf("error unescaping copy source %q: %v", cs, err)
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionCopyObject,
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrInvalidCopySource)
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
				Action:      metrics.ActionCopyObject,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	var mtime *time.Time
	if copySrcModifSince != "" {
		tm, err := time.Parse(iso8601Format, copySrcModifSince)
		if err != nil {
			debuglogger.Logf("error parsing copy source modified since %q: %v", copySrcModifSince, err)
			return &Response{
				MetaOpts: &MetaOptions{
					Action:      metrics.ActionCopyObject,
					BucketOwner: parsedAcl.Owner,
				},
			}, s3err.GetAPIError(s3err.ErrInvalidCopySource)
		}
		mtime = &tm
	}
	var umtime *time.Time
	if copySrcUnmodifSince != "" {
		tm, err := time.Parse(iso8601Format, copySrcUnmodifSince)
		if err != nil {
			debuglogger.Logf("error parsing copy source unmodified since %q: %v", copySrcUnmodifSince, err)
			return &Response{
				MetaOpts: &MetaOptions{
					Action:      metrics.ActionCopyObject,
					BucketOwner: parsedAcl.Owner,
				},
			}, s3err.GetAPIError(s3err.ErrInvalidCopySource)
		}
		umtime = &tm
	}

	metadata := utils.GetUserMetaData(&ctx.Request().Header)

	if metaDirective != "" && metaDirective != types.MetadataDirectiveCopy && metaDirective != types.MetadataDirectiveReplace {
		debuglogger.Logf("invalid metadata directive: %v", metaDirective)
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionCopyObject,
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrInvalidMetadataDirective)
	}

	if taggingDirective != "" && taggingDirective != types.TaggingDirectiveCopy && taggingDirective != types.TaggingDirectiveReplace {
		debuglogger.Logf("invalid tagging direcrive: %v", taggingDirective)
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionCopyObject,
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrInvalidTaggingDirective)
	}

	checksumAlgorithm := types.ChecksumAlgorithm(ctx.Get("x-amz-checksum-algorithm"))
	err = utils.IsChecksumAlgorithmValid(checksumAlgorithm)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionCopyObject,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	objLock, err := utils.ParsObjectLockHdrs(ctx)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionCopyObject,
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
			CopySourceIfMatch:           &copySrcIfMatch,
			CopySourceIfNoneMatch:       &copySrcIfNoneMatch,
			CopySourceIfModifiedSince:   mtime,
			CopySourceIfUnmodifiedSince: umtime,
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
			Action:      metrics.ActionCopyObject,
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
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionWrite,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Object:         key,
			Action:         auth.PutObjectAction,
			IsBucketPublic: IsBucketPublic,
		})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutObject,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	err = auth.CheckObjectAccess(ctx.Context(), bucket, acct.Access, []types.ObjectIdentifier{{Key: &key}}, true, IsBucketPublic, c.be)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutObject,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	contentLength, err := strconv.ParseInt(contentLengthStr, 10, 64)
	if err != nil {
		debuglogger.Logf("error parsing content length %q: %v", contentLengthStr, err)
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutObject,
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrInvalidRequest)
	}

	objLock, err := utils.ParsObjectLockHdrs(ctx)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutObject,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	algorithm, checksums, err := utils.ParseChecksumHeaders(ctx)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				Action:      metrics.ActionPutObject,
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	var body io.Reader
	bodyi := utils.ContextKeyBodyReader.Get(ctx)
	if bodyi != nil {
		body = bodyi.(io.Reader)
	} else {
		body = ctx.Request().BodyStream()
	}

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
		},
		MetaOpts: &MetaOptions{
			ContentLength: contentLength,
			Action:        metrics.ActionPutObject,
			BucketOwner:   parsedAcl.Owner,
			ObjectETag:    &res.ETag,
			ObjectSize:    contentLength,
			EventName:     s3event.EventObjectCreatedPut,
		},
	}, err
}
