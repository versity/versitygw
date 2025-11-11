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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
)

func (c S3ApiController) HeadObject(ctx *fiber.Ctx) (*Response, error) {
	// context locals
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)
	// url values
	bucket := ctx.Params("bucket")
	partNumberQuery := int32(ctx.QueryInt("partNumber", -1))
	versionId := ctx.Query("versionId")
	objRange := ctx.Get("Range")
	key := strings.TrimPrefix(ctx.Path(), fmt.Sprintf("/%s/", bucket))

	action := auth.GetObjectAction
	if ctx.Request().URI().QueryArgs().Has("versionId") {
		action = auth.GetObjectVersionAction
	}

	err := auth.VerifyAccess(ctx.Context(), c.be,
		auth.AccessOptions{
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

	checksumMode := types.ChecksumMode(strings.ToUpper(ctx.Get("x-amz-checksum-mode")))
	if checksumMode != "" && checksumMode != types.ChecksumModeEnabled {
		debuglogger.Logf("invalid x-amz-checksum-mode header value: %v", checksumMode)
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetInvalidChecksumHeaderErr("x-amz-checksum-mode")
	}

	conditionalHeaders := utils.ParsePreconditionHeaders(ctx)

	res, err := c.be.HeadObject(ctx.Context(),
		&s3.HeadObjectInput{
			Bucket:            &bucket,
			Key:               &key,
			PartNumber:        partNumber,
			VersionId:         &versionId,
			ChecksumMode:      checksumMode,
			Range:             &objRange,
			IfMatch:           conditionalHeaders.IfMatch,
			IfNoneMatch:       conditionalHeaders.IfNoneMatch,
			IfModifiedSince:   conditionalHeaders.IfModSince,
			IfUnmodifiedSince: conditionalHeaders.IfUnmodeSince,
		})
	if err != nil {
		var headers map[string]*string
		if res != nil {
			headers = map[string]*string{
				"x-amz-delete-marker": utils.GetStringPtr("true"),
				"Last-Modified":       utils.GetStringPtr(res.LastModified.UTC().Format(timefmt)),
			}
		}
		return &Response{
			Headers: headers,
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	// Set the metadata headers
	utils.SetMetaHeaders(ctx, res.Metadata)

	return &Response{
		Headers: map[string]*string{
			"Content-Range":                       res.ContentRange,
			"Content-Disposition":                 res.ContentDisposition,
			"Content-Encoding":                    res.ContentEncoding,
			"Content-Language":                    res.ContentLanguage,
			"Cache-Control":                       res.CacheControl,
			"Content-Length":                      utils.ConvertPtrToStringPtr(res.ContentLength),
			"Content-Type":                        res.ContentType,
			"Expires":                             res.ExpiresString,
			"ETag":                                res.ETag,
			"Last-Modified":                       utils.FormatDatePtrToString(res.LastModified, timefmt),
			"x-amz-restore":                       res.Restore,
			"accept-ranges":                       res.AcceptRanges,
			"x-amz-checksum-crc32":                res.ChecksumCRC32,
			"x-amz-checksum-crc64nvme":            res.ChecksumCRC64NVME,
			"x-amz-checksum-crc32c":               res.ChecksumCRC32C,
			"x-amz-checksum-sha1":                 res.ChecksumSHA1,
			"x-amz-checksum-sha256":               res.ChecksumSHA256,
			"x-amz-version-id":                    res.VersionId,
			"x-amz-mp-parts-count":                utils.ConvertPtrToStringPtr(res.PartsCount),
			"x-amz-object-lock-mode":              utils.ConvertToStringPtr(res.ObjectLockMode),
			"x-amz-object-lock-legal-hold":        utils.ConvertToStringPtr(res.ObjectLockLegalHoldStatus),
			"x-amz-storage-class":                 utils.ConvertToStringPtr(res.StorageClass),
			"x-amz-checksum-type":                 utils.ConvertToStringPtr(res.ChecksumType),
			"x-amz-object-lock-retain-until-date": utils.FormatDatePtrToString(res.ObjectLockRetainUntilDate, time.RFC3339),
			"x-amz-tagging-count":                 utils.ConvertPtrToStringPtr(res.TagCount),
		},
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
		},
	}, nil
}
