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
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

func (c S3ApiController) GetObjectTagging(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	key := strings.TrimPrefix(ctx.Path(), fmt.Sprintf("/%s/", bucket))
	versionId := ctx.Query("versionId")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)

	action := auth.GetObjectTaggingAction
	if versionId != "" {
		action = auth.GetObjectVersionTaggingAction
	}

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:        c.readonly,
		Acl:             parsedAcl,
		AclPermission:   auth.PermissionRead,
		IsRoot:          isRoot,
		Acc:             acct,
		Bucket:          bucket,
		Object:          key,
		Action:          action,
		IsPublicRequest: isPublicBucket,
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

	data, err := c.be.GetObjectTagging(ctx.Context(), bucket, key, versionId)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}
	tags := s3response.Tagging{
		TagSet: s3response.TagSet{Tags: []s3response.Tag{}},
	}

	for key, val := range data {
		tags.TagSet.Tags = append(tags.TagSet.Tags,
			s3response.Tag{Key: key, Value: val})
	}

	return &Response{
		Data: tags,
		Headers: map[string]*string{
			"x-amz-version-id": &versionId,
		},
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
		},
	}, nil
}

func (c S3ApiController) GetObjectRetention(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	key := strings.TrimPrefix(ctx.Path(), fmt.Sprintf("/%s/", bucket))
	versionId := ctx.Query("versionId")
	// context locals
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:        c.readonly,
		Acl:             parsedAcl,
		AclPermission:   auth.PermissionRead,
		IsRoot:          isRoot,
		Acc:             acct,
		Bucket:          bucket,
		Object:          key,
		Action:          auth.GetObjectRetentionAction,
		IsPublicRequest: isPublicBucket,
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

	data, err := c.be.GetObjectRetention(ctx.Context(), bucket, key, versionId)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	retention, err := auth.ParseObjectLockRetentionOutput(data)
	return &Response{
		Data: retention,
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
		},
	}, err
}

func (c S3ApiController) GetObjectLegalHold(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	key := strings.TrimPrefix(ctx.Path(), fmt.Sprintf("/%s/", bucket))
	versionId := ctx.Query("versionId")
	// context locals
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:        c.readonly,
		Acl:             parsedAcl,
		AclPermission:   auth.PermissionRead,
		IsRoot:          isRoot,
		Acc:             acct,
		Bucket:          bucket,
		Object:          key,
		Action:          auth.GetObjectLegalHoldAction,
		IsPublicRequest: isPublicBucket,
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

	data, err := c.be.GetObjectLegalHold(ctx.Context(), bucket, key, versionId)
	return &Response{
		Data: auth.ParseObjectLegalHoldOutput(data),
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
		},
	}, err
}

func (c S3ApiController) GetObjectAcl(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	key := strings.TrimPrefix(ctx.Path(), fmt.Sprintf("/%s/", bucket))
	// context locals
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:        c.readonly,
		Acl:             parsedAcl,
		AclPermission:   auth.PermissionReadAcp,
		IsRoot:          isRoot,
		Acc:             acct,
		Bucket:          bucket,
		Object:          key,
		Action:          auth.GetObjectAclAction,
		IsPublicRequest: isPublicBucket,
	})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}
	res, err := c.be.GetObjectAcl(ctx.Context(), &s3.GetObjectAclInput{
		Bucket: &bucket,
		Key:    &key,
	})
	return &Response{
		Data: res,
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
		},
	}, err
}

func (c S3ApiController) ListParts(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	key := strings.TrimPrefix(ctx.Path(), fmt.Sprintf("/%s/", bucket))
	uploadId := ctx.Query("uploadId")
	partNumberMarker := ctx.Query("part-number-marker")
	maxPartsStr := ctx.Query("max-parts")
	// context locals
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:        c.readonly,
		Acl:             parsedAcl,
		AclPermission:   auth.PermissionRead,
		IsRoot:          isRoot,
		Acc:             acct,
		Bucket:          bucket,
		Object:          key,
		Action:          auth.ListMultipartUploadPartsAction,
		IsPublicRequest: isPublicBucket,
	})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	// parse the part number marker
	if partNumberMarker != "" {
		n, err := strconv.Atoi(partNumberMarker)
		if err != nil || n < 0 {
			debuglogger.Logf("invalid part number marker %q: %v",
				partNumberMarker, err)

			return &Response{
				MetaOpts: &MetaOptions{
					BucketOwner: parsedAcl.Owner,
				},
			}, s3err.GetAPIError(s3err.ErrInvalidPartNumberMarker)
		}
	}

	// parse the max parts
	maxParts, err := utils.ParseUint(maxPartsStr)
	if err != nil {
		debuglogger.Logf("error parsing max parts %q: %v",
			maxPartsStr, err)
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrInvalidMaxParts)
	}

	res, err := c.be.ListParts(ctx.Context(), &s3.ListPartsInput{
		Bucket:           &bucket,
		Key:              &key,
		UploadId:         &uploadId,
		PartNumberMarker: &partNumberMarker,
		MaxParts:         &maxParts,
	})
	return &Response{
		Data: res,
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
		},
	}, err
}

func (c S3ApiController) GetObjectAttributes(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	key := strings.TrimPrefix(ctx.Path(), fmt.Sprintf("/%s/", bucket))
	versionId := ctx.Query("versionId")
	maxPartsStr := ctx.Get("X-Amz-Max-Parts")
	partNumberMarker := ctx.Get("X-Amz-Part-Number-Marker")
	// context locals
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)

	action := auth.GetObjectAttributesAction
	if versionId != "" {
		action = auth.GetObjectVersionAttributesAction
	}

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:        c.readonly,
		Acl:             parsedAcl,
		AclPermission:   auth.PermissionRead,
		IsRoot:          isRoot,
		Acc:             acct,
		Bucket:          bucket,
		Object:          key,
		Action:          action,
		IsPublicRequest: isPublicBucket,
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

	// parse max parts
	maxParts, err := utils.ParseUint(maxPartsStr)
	if err != nil {
		debuglogger.Logf("error parsing max parts %q: %v",
			maxPartsStr, err)
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrInvalidMaxParts)
	}

	// parse the object attributes
	attrs, err := utils.ParseObjectAttributes(ctx)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	res, err := c.be.GetObjectAttributes(ctx.Context(),
		&s3.GetObjectAttributesInput{
			Bucket:           &bucket,
			Key:              &key,
			PartNumberMarker: &partNumberMarker,
			MaxParts:         &maxParts,
			VersionId:        &versionId,
		})
	if err != nil {
		headers := map[string]*string{
			"x-amz-version-id": res.VersionId,
		}
		if res.DeleteMarker != nil && *res.DeleteMarker {
			headers["x-amz-delete-marker"] = utils.GetStringPtr("true")
		}
		return &Response{
			Headers: headers,
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	headers := map[string]*string{
		"x-amz-version-id": res.VersionId,
		"Last-Modified":    utils.FormatDatePtrToString(res.LastModified, iso8601TimeFormatExtended),
	}
	if res.DeleteMarker != nil && *res.DeleteMarker {
		headers["x-amz-delete-marker"] = utils.GetStringPtr("true")
	}

	return &Response{
		Headers: headers,
		Data:    utils.FilterObjectAttributes(attrs, res),
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
		},
	}, err
}

func (c S3ApiController) GetObject(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	key := strings.TrimPrefix(ctx.Path(), fmt.Sprintf("/%s/", bucket))
	versionId := ctx.Query("versionId")
	acceptRange := ctx.Get("Range")
	checksumMode := types.ChecksumMode(strings.ToUpper(ctx.Get("x-amz-checksum-mode")))
	partNumberQuery := int32(ctx.QueryInt("partNumber", -1))

	// Extract response override query parameters
	responseOverrides := map[string]*string{
		"Cache-Control":       utils.GetQueryParam(ctx, "response-cache-control"),
		"Content-Disposition": utils.GetQueryParam(ctx, "response-content-disposition"),
		"Content-Encoding":    utils.GetQueryParam(ctx, "response-content-encoding"),
		"Content-Language":    utils.GetQueryParam(ctx, "response-content-language"),
		"Content-Type":        utils.GetQueryParam(ctx, "response-content-type"),
		"Expires":             utils.GetQueryParam(ctx, "response-expires"),
	}

	// Check if any response override parameters are present
	hasResponseOverrides := false
	for _, override := range responseOverrides {
		if override != nil {
			hasResponseOverrides = true
			break
		}
	}

	// context locals
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	isPublicBucketRequest := utils.ContextKeyPublicBucket.IsSet(ctx)
	utils.ContextKeySkipResBodyLog.Set(ctx, true)

	// Validate that response override parameters are not used with anonymous requests
	if hasResponseOverrides && isPublicBucketRequest {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrAnonymousResponseHeaders)
	}

	action := auth.GetObjectAction
	if ctx.Request().URI().QueryArgs().Has("versionId") {
		action = auth.GetObjectVersionAction
	}

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:        c.readonly,
		Acl:             parsedAcl,
		AclPermission:   auth.PermissionRead,
		IsRoot:          isRoot,
		Acc:             acct,
		Bucket:          bucket,
		Object:          key,
		Action:          action,
		IsPublicRequest: isPublicBucketRequest,
	})
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	var partNumber *int32
	if ctx.Request().URI().QueryArgs().Has("partNumber") {
		if partNumberQuery < minPartNumber || partNumberQuery > maxPartNumber {
			debuglogger.Logf("invalid part number: %d", partNumberQuery)
			return &Response{
				MetaOpts: &MetaOptions{
					BucketOwner: parsedAcl.Owner,
				},
			}, s3err.GetAPIError(s3err.ErrInvalidPartNumber)
		}

		partNumber = &partNumberQuery
	}

	err = utils.ValidateVersionId(versionId)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	// validate the checksum mode
	if checksumMode != "" && checksumMode != types.ChecksumModeEnabled {
		debuglogger.Logf("invalid x-amz-checksum-mode header value: %v", checksumMode)
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetInvalidChecksumHeaderErr("x-amz-checksum-mode")
	}

	conditionalHeaders := utils.ParsePreconditionHeaders(ctx)

	res, err := c.be.GetObject(ctx.Context(), &s3.GetObjectInput{
		Bucket:            &bucket,
		Key:               &key,
		Range:             &acceptRange,
		IfMatch:           conditionalHeaders.IfMatch,
		IfNoneMatch:       conditionalHeaders.IfNoneMatch,
		IfModifiedSince:   conditionalHeaders.IfModSince,
		IfUnmodifiedSince: conditionalHeaders.IfUnmodeSince,
		VersionId:         &versionId,
		ChecksumMode:      checksumMode,
		PartNumber:        partNumber,
	})
	if err != nil {
		var headers map[string]*string
		if res != nil {
			headers = map[string]*string{
				"x-amz-delete-marker": utils.GetStringPtr("true"),
				"Last-Modified":       utils.FormatDatePtrToString(res.LastModified, timefmt),
			}
		}
		return &Response{
			Headers: headers,
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	// Set x-amz-meta-... headers
	utils.SetMetaHeaders(ctx, res.Metadata)

	status := http.StatusOK
	if acceptRange != "" {
		status = http.StatusPartialContent
	}

	if res.Body != nil {
		// -1 will stream response body until EOF if content length not set
		contentLen := -1
		if res.ContentLength != nil {
			if *res.ContentLength > int64(math.MaxInt) {
				debuglogger.Logf("content length %v int overflow",
					*res.ContentLength)
				return &Response{
					MetaOpts: &MetaOptions{
						ContentLength: utils.GetInt64(res.ContentLength),
						BucketOwner:   parsedAcl.Owner,
						Status:        status,
					},
				}, s3err.GetAPIError(s3err.ErrInvalidRange)
			}
			contentLen = int(*res.ContentLength)
		}
		utils.StreamResponseBody(ctx, res.Body, contentLen)
	}

	return &Response{
		Headers: map[string]*string{
			"ETag":                                res.ETag,
			"x-amz-restore":                       res.Restore,
			"accept-ranges":                       res.AcceptRanges,
			"Content-Range":                       res.ContentRange,
			"Content-Disposition":                 utils.ApplyOverride(res.ContentDisposition, responseOverrides["Content-Disposition"]),
			"Content-Encoding":                    utils.ApplyOverride(res.ContentEncoding, responseOverrides["Content-Encoding"]),
			"Content-Language":                    utils.ApplyOverride(res.ContentLanguage, responseOverrides["Content-Language"]),
			"Cache-Control":                       utils.ApplyOverride(res.CacheControl, responseOverrides["Cache-Control"]),
			"Expires":                             utils.ApplyOverride(res.ExpiresString, responseOverrides["Expires"]),
			"x-amz-checksum-crc32":                res.ChecksumCRC32,
			"x-amz-checksum-crc64nvme":            res.ChecksumCRC64NVME,
			"x-amz-checksum-crc32c":               res.ChecksumCRC32C,
			"x-amz-checksum-sha1":                 res.ChecksumSHA1,
			"x-amz-checksum-sha256":               res.ChecksumSHA256,
			"Content-Type":                        utils.ApplyOverride(res.ContentType, responseOverrides["Content-Type"]),
			"x-amz-version-id":                    res.VersionId,
			"Content-Length":                      utils.ConvertPtrToStringPtr(res.ContentLength),
			"x-amz-mp-parts-count":                utils.ConvertPtrToStringPtr(res.PartsCount),
			"x-amz-tagging-count":                 utils.ConvertPtrToStringPtr(res.TagCount),
			"x-amz-object-lock-mode":              utils.ConvertToStringPtr(res.ObjectLockMode),
			"x-amz-object-lock-legal-hold":        utils.ConvertToStringPtr(res.ObjectLockLegalHoldStatus),
			"x-amz-storage-class":                 utils.ConvertToStringPtr(res.StorageClass),
			"x-amz-checksum-type":                 utils.ConvertToStringPtr(res.ChecksumType),
			"x-amz-object-lock-retain-until-date": utils.FormatDatePtrToString(res.ObjectLockRetainUntilDate, time.RFC3339),
			"Last-Modified":                       utils.FormatDatePtrToString(res.LastModified, timefmt),
		},
		MetaOpts: &MetaOptions{
			ContentLength: utils.GetInt64(res.ContentLength),
			BucketOwner:   parsedAcl.Owner,
			Status:        status,
		},
	}, nil
}
