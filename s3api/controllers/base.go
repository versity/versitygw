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
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/s3api/debuglogger"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3event"
	"github.com/versity/versitygw/s3log"
	"github.com/versity/versitygw/s3response"
)

type S3ApiController struct {
	be       backend.Backend
	iam      auth.IAMService
	logger   s3log.AuditLogger
	evSender s3event.S3EventSender
	mm       *metrics.Manager
	debug    bool
	readonly bool
}

const (
	iso8601Format             = "20060102T150405Z"
	iso8601TimeFormatExtended = "Mon Jan _2 15:04:05 2006"
	defaultContentType        = "binary/octet-stream"
)

func New(be backend.Backend, iam auth.IAMService, logger s3log.AuditLogger, evs s3event.S3EventSender, mm *metrics.Manager, debug bool, readonly bool) S3ApiController {
	if debug {
		debuglogger.SetDebugEnabled()
	}

	return S3ApiController{
		be:       be,
		iam:      iam,
		logger:   logger,
		evSender: evs,
		debug:    debug,
		readonly: readonly,
		mm:       mm,
	}
}

func (c S3ApiController) ListBuckets(ctx *fiber.Ctx) error {
	cToken := ctx.Query("continuation-token")
	prefix := ctx.Query("prefix")
	maxBucketsStr := ctx.Query("max-buckets")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)

	var maxBuckets int32 = 10000
	if maxBucketsStr != "" {
		maxBucketsParsed, err := strconv.ParseInt(maxBucketsStr, 10, 32)
		if err != nil || maxBucketsParsed < 0 || maxBucketsParsed > 10000 {
			if c.debug {
				debuglogger.Logf("error parsing max-buckets %q: %v", maxBucketsStr, err)
			}
			return SendXMLResponse(ctx, nil, s3err.GetAPIError(s3err.ErrInvalidMaxBuckets),
				&MetaOpts{
					Logger:     c.logger,
					MetricsMng: c.mm,
					Action:     metrics.ActionListAllMyBuckets,
				})
		}
		maxBuckets = int32(maxBucketsParsed)
	}

	res, err := c.be.ListBuckets(ctx.Context(),
		s3response.ListBucketsInput{
			Owner:             acct.Access,
			IsAdmin:           acct.Role == auth.RoleAdmin,
			MaxBuckets:        int32(maxBuckets),
			ContinuationToken: cToken,
			Prefix:            prefix,
		})
	return SendXMLResponse(ctx, res, err,
		&MetaOpts{
			Logger:     c.logger,
			MetricsMng: c.mm,
			Action:     metrics.ActionListAllMyBuckets,
		})
}

func (c S3ApiController) GetActions(ctx *fiber.Ctx) error {
	bucket := ctx.Params("bucket")
	key := ctx.Params("key")
	keyEnd := ctx.Params("*1")
	uploadId := ctx.Query("uploadId")
	partNumberMarker := ctx.Query("part-number-marker")
	acceptRange := ctx.Get("Range")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)
	versionId := ctx.Query("versionId")
	if keyEnd != "" {
		key = strings.Join([]string{key, keyEnd}, "/")
	}
	path := ctx.Path()
	if path[len(path)-1:] == "/" && key[len(key)-1:] != "/" {
		key = key + "/"
	}

	if ctx.Request().URI().QueryArgs().Has("tagging") {
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionRead,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Object:         key,
			Action:         auth.GetObjectTaggingAction,
			IsBucketPublic: isPublicBucket,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionGetObjectTagging,
					BucketOwner: parsedAcl.Owner,
				})
		}

		tags, err := c.be.GetObjectTagging(ctx.Context(), bucket, key)
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionGetObjectTagging,
					BucketOwner: parsedAcl.Owner,
				})
		}
		res := s3response.Tagging{
			TagSet: s3response.TagSet{Tags: []s3response.Tag{}},
		}

		for key, val := range tags {
			res.TagSet.Tags = append(res.TagSet.Tags,
				s3response.Tag{Key: key, Value: val})
		}

		return SendXMLResponse(ctx, res, nil,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionGetObjectTagging,
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("retention") {
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionRead,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Object:         key,
			Action:         auth.GetObjectRetentionAction,
			IsBucketPublic: isPublicBucket,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionGetObjectRetention,
					BucketOwner: parsedAcl.Owner,
				})
		}

		data, err := c.be.GetObjectRetention(ctx.Context(), bucket, key, versionId)
		if err != nil {
			return SendXMLResponse(ctx, data, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionGetObjectRetention,
					BucketOwner: parsedAcl.Owner,
				})
		}

		retention, err := auth.ParseObjectLockRetentionOutput(data)
		return SendXMLResponse(ctx, retention, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionGetObjectRetention,
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("legal-hold") {
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionRead,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Object:         key,
			Action:         auth.GetObjectLegalHoldAction,
			IsBucketPublic: isPublicBucket,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionGetObjectLegalHold,
					BucketOwner: parsedAcl.Owner,
				})
		}

		data, err := c.be.GetObjectLegalHold(ctx.Context(), bucket, key, versionId)
		return SendXMLResponse(ctx, auth.ParseObjectLegalHoldOutput(data), err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionGetObjectLegalHold,
				BucketOwner: parsedAcl.Owner,
			})
	}

	if uploadId != "" {
		if partNumberMarker != "" {
			n, err := strconv.Atoi(partNumberMarker)
			if err != nil || n < 0 {
				if err != nil && c.debug {
					debuglogger.Logf("error parsing part number marker %q: %v",
						partNumberMarker, err)
				}
				return SendResponse(ctx,
					s3err.GetAPIError(s3err.ErrInvalidPartNumberMarker),
					&MetaOpts{
						Logger:      c.logger,
						MetricsMng:  c.mm,
						Action:      metrics.ActionListParts,
						BucketOwner: parsedAcl.Owner,
					})
			}
		}
		mxParts := ctx.Query("max-parts")
		maxParts, err := utils.ParseUint(mxParts)
		if err != nil {
			if c.debug {
				debuglogger.Logf("error parsing max parts %q: %v",
					mxParts, err)
			}
			return SendResponse(ctx,
				s3err.GetAPIError(s3err.ErrInvalidMaxParts),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionListParts,
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionRead,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Object:         key,
			Action:         auth.ListMultipartUploadPartsAction,
			IsBucketPublic: isPublicBucket,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionListParts,
					BucketOwner: parsedAcl.Owner,
				})
		}

		res, err := c.be.ListParts(ctx.Context(), &s3.ListPartsInput{
			Bucket:           &bucket,
			Key:              &key,
			UploadId:         &uploadId,
			PartNumberMarker: &partNumberMarker,
			MaxParts:         &maxParts,
		})
		return SendXMLResponse(ctx, res, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionListParts,
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("acl") {
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionReadAcp,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Object:         key,
			Action:         auth.GetObjectAclAction,
			IsBucketPublic: isPublicBucket,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionGetObjectAcl,
					BucketOwner: parsedAcl.Owner,
				})
		}
		res, err := c.be.GetObjectAcl(ctx.Context(), &s3.GetObjectAclInput{
			Bucket: &bucket,
			Key:    &key,
		})
		return SendXMLResponse(ctx, res, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionGetObjectAcl,
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("attributes") {
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionRead,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Object:         key,
			Action:         auth.GetObjectAttributesAction,
			IsBucketPublic: isPublicBucket,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionGetObjectAttributes,
					BucketOwner: parsedAcl.Owner,
				})
		}
		maxParts := ctx.Get("X-Amz-Max-Parts")
		partNumberMarker := ctx.Get("X-Amz-Part-Number-Marker")
		maxPartsParsed, err := utils.ParseUint(maxParts)
		if err != nil {
			if c.debug {
				debuglogger.Logf("error parsing max parts %q: %v",
					maxParts, err)
			}
			return SendXMLResponse(ctx, nil, s3err.GetAPIError(s3err.ErrInvalidMaxParts),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionGetObjectAttributes,
					BucketOwner: parsedAcl.Owner,
				})
		}
		attrs, err := utils.ParseObjectAttributes(ctx)
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionGetObjectAttributes,
					BucketOwner: parsedAcl.Owner,
				})
		}

		res, err := c.be.GetObjectAttributes(ctx.Context(),
			&s3.GetObjectAttributesInput{
				Bucket:           &bucket,
				Key:              &key,
				PartNumberMarker: &partNumberMarker,
				MaxParts:         &maxPartsParsed,
				VersionId:        &versionId,
			})
		if err != nil {
			hdrs := []utils.CustomHeader{}

			if res.DeleteMarker != nil {
				hdrs = append(hdrs, utils.CustomHeader{
					Key:   "x-amz-delete-marker",
					Value: "true",
				})
			}
			if getstring(res.VersionId) != "" {
				hdrs = append(hdrs, utils.CustomHeader{
					Key:   "x-amz-version-id",
					Value: getstring(res.VersionId),
				})
			}

			utils.SetResponseHeaders(ctx, hdrs)
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionGetObjectAttributes,
					BucketOwner: parsedAcl.Owner,
				})
		}

		hdrs := []utils.CustomHeader{}

		if getstring(res.VersionId) != "" {
			hdrs = append(hdrs, utils.CustomHeader{
				Key:   "x-amz-version-id",
				Value: getstring(res.VersionId),
			})
		}
		if res.DeleteMarker != nil && *res.DeleteMarker {
			hdrs = append(hdrs, utils.CustomHeader{
				Key:   "x-amz-delete-marker",
				Value: "true",
			})
		}
		if res.LastModified != nil {
			hdrs = append(hdrs, utils.CustomHeader{
				Key:   "Last-Modified",
				Value: res.LastModified.UTC().Format(iso8601TimeFormatExtended),
			})
		}

		utils.SetResponseHeaders(ctx, hdrs)

		return SendXMLResponse(ctx, utils.FilterObjectAttributes(attrs, res), nil,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionGetObjectAttributes,
				BucketOwner: parsedAcl.Owner,
			})
	}

	action := auth.GetObjectAction
	if versionId != "" {
		action = auth.GetObjectVersionAction
	}

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:       c.readonly,
		Acl:            parsedAcl,
		AclPermission:  auth.PermissionRead,
		IsRoot:         isRoot,
		Acc:            acct,
		Bucket:         bucket,
		Object:         key,
		Action:         action,
		IsBucketPublic: isPublicBucket,
	})
	if err != nil {
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionGetObject,
				BucketOwner: parsedAcl.Owner,
			})
	}

	checksumMode := types.ChecksumMode(ctx.Get("x-amz-checksum-mode"))
	if checksumMode != "" && checksumMode != types.ChecksumModeEnabled {
		if c.debug {
			debuglogger.Logf("invalid x-amz-checksum-mode header value: %v", checksumMode)
		}
		return SendResponse(ctx, s3err.GetInvalidChecksumHeaderErr("x-amz-checksum-mode"),
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionGetObject,
				BucketOwner: parsedAcl.Owner,
			})
	}

	utils.ContextKeySkipResBodyLog.Set(ctx, true)
	res, err := c.be.GetObject(ctx.Context(), &s3.GetObjectInput{
		Bucket:       &bucket,
		Key:          &key,
		Range:        &acceptRange,
		VersionId:    &versionId,
		ChecksumMode: checksumMode,
	})
	if err != nil {
		if res != nil {
			utils.SetResponseHeaders(ctx, []utils.CustomHeader{
				{
					Key:   "x-amz-delete-marker",
					Value: "true",
				},
				{
					Key:   "Last-Modified",
					Value: res.LastModified.UTC().Format(timefmt),
				},
			})
		}
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionHeadObject,
				BucketOwner: parsedAcl.Owner,
			})
	}

	contentType := getstring(res.ContentType)
	if contentType == "" {
		contentType = defaultContentType
	}
	acceptRanges := getstring(res.AcceptRanges)
	if acceptRanges == "" {
		acceptRanges = "bytes"
	}

	hdrs := []utils.CustomHeader{
		{
			Key:   "Content-Type",
			Value: contentType,
		},
		{
			Key:   "ETag",
			Value: getstring(res.ETag),
		},
		{
			Key:   "accept-ranges",
			Value: acceptRanges,
		},
	}
	if getstring(res.ContentDisposition) != "" {
		hdrs = append(hdrs, utils.CustomHeader{
			Key:   "Content-Disposition",
			Value: getstring(res.ContentDisposition),
		})
	}
	if getstring(res.ContentEncoding) != "" {
		hdrs = append(hdrs, utils.CustomHeader{
			Key:   "Content-Encoding",
			Value: getstring(res.ContentEncoding),
		})
	}
	if getstring(res.ContentLanguage) != "" {
		hdrs = append(hdrs, utils.CustomHeader{
			Key:   "Content-Language",
			Value: getstring(res.ContentLanguage),
		})
	}
	if getstring(res.CacheControl) != "" {
		hdrs = append(hdrs, utils.CustomHeader{
			Key:   "Cache-Control",
			Value: getstring(res.CacheControl),
		})
	}
	if getstring(res.ExpiresString) != "" {
		hdrs = append(hdrs, utils.CustomHeader{
			Key:   "Expires",
			Value: getstring(res.ExpiresString),
		})
	}
	if getstring(res.ContentRange) != "" {
		hdrs = append(hdrs, utils.CustomHeader{
			Key:   "Content-Range",
			Value: getstring(res.ContentRange),
		})
	}
	if res.LastModified != nil {
		hdrs = append(hdrs, utils.CustomHeader{
			Key:   "Last-Modified",
			Value: res.LastModified.UTC().Format(timefmt),
		})
	}
	if res.TagCount != nil {
		hdrs = append(hdrs, utils.CustomHeader{
			Key:   "x-amz-tagging-count",
			Value: fmt.Sprint(*res.TagCount),
		})
	}
	if res.StorageClass != "" {
		hdrs = append(hdrs, utils.CustomHeader{
			Key:   "x-amz-storage-class",
			Value: string(res.StorageClass),
		})
	}
	if res.ChecksumCRC32 != nil {
		hdrs = append(hdrs, utils.CustomHeader{
			Key:   "x-amz-checksum-crc32",
			Value: *res.ChecksumCRC32,
		})
	}
	if res.ChecksumCRC32C != nil {
		hdrs = append(hdrs, utils.CustomHeader{
			Key:   "x-amz-checksum-crc32c",
			Value: *res.ChecksumCRC32C,
		})
	}
	if res.ChecksumSHA1 != nil {
		hdrs = append(hdrs, utils.CustomHeader{
			Key:   "x-amz-checksum-sha1",
			Value: *res.ChecksumSHA1,
		})
	}
	if res.ChecksumSHA256 != nil {
		hdrs = append(hdrs, utils.CustomHeader{
			Key:   "x-amz-checksum-sha256",
			Value: *res.ChecksumSHA256,
		})
	}
	if res.ChecksumCRC64NVME != nil {
		hdrs = append(hdrs, utils.CustomHeader{
			Key:   "x-amz-checksum-crc64nvme",
			Value: *res.ChecksumCRC64NVME,
		})
	}
	if res.ChecksumType != "" {
		hdrs = append(hdrs, utils.CustomHeader{
			Key:   "x-amz-checksum-type",
			Value: string(res.ChecksumType),
		})
	}

	// Set x-amz-meta-... headers
	utils.SetMetaHeaders(ctx, res.Metadata)
	// Set other response headers
	utils.SetResponseHeaders(ctx, hdrs)
	// Set version id header
	if getstring(res.VersionId) != "" {
		utils.SetResponseHeaders(ctx, []utils.CustomHeader{
			{
				Key:   "x-amz-version-id",
				Value: getstring(res.VersionId),
			},
		})
	}

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
				return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRange),
					&MetaOpts{
						Logger:      c.logger,
						MetricsMng:  c.mm,
						Action:      metrics.ActionGetObject,
						BucketOwner: parsedAcl.Owner,
					})
			}
			contentLen = int(*res.ContentLength)
		}
		utils.StreamResponseBody(ctx, res.Body, contentLen)
	}

	return SendResponse(ctx, nil,
		&MetaOpts{
			Logger:        c.logger,
			MetricsMng:    c.mm,
			Action:        metrics.ActionGetObject,
			ContentLength: getint64(res.ContentLength),
			BucketOwner:   parsedAcl.Owner,
			Status:        status,
		})
}

func getstring(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func getint64(i *int64) int64 {
	if i == nil {
		return 0
	}
	return *i
}

func (c S3ApiController) ListActions(ctx *fiber.Ctx) error {
	bucket := ctx.Params("bucket")
	prefix := ctx.Query("prefix")
	cToken := ctx.Query("continuation-token")
	sAfter := ctx.Query("start-after")
	marker := ctx.Query("marker")
	delimiter := ctx.Query("delimiter")
	maxkeysStr := ctx.Query("max-keys")
	keyMarker := ctx.Query("key-marker")
	maxUploadsStr := ctx.Query("max-uploads")
	uploadIdMarker := ctx.Query("upload-id-marker")
	versionIdMarker := ctx.Query("version-id-marker")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	if ctx.Request().URI().QueryArgs().Has("tagging") {
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionRead,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Action:         auth.GetBucketTaggingAction,
			IsBucketPublic: isPublicBucket,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionGetBucketTagging,
					BucketOwner: parsedAcl.Owner,
				})
		}

		tags, err := c.be.GetBucketTagging(ctx.Context(), bucket)
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionGetBucketTagging,
					BucketOwner: parsedAcl.Owner,
				})
		}
		resp := s3response.Tagging{
			TagSet: s3response.TagSet{Tags: []s3response.Tag{}},
		}

		for key, val := range tags {
			resp.TagSet.Tags = append(resp.TagSet.Tags,
				s3response.Tag{Key: key, Value: val})
		}

		return SendXMLResponse(ctx, resp, nil,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionGetBucketTagging,
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("ownershipControls") {
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionRead,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Action:         auth.GetBucketOwnershipControlsAction,
			IsBucketPublic: isPublicBucket,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionGetBucketOwnershipControls,
					BucketOwner: parsedAcl.Owner,
				})
		}

		data, err := c.be.GetBucketOwnershipControls(ctx.Context(), bucket)
		return SendXMLResponse(ctx,
			s3response.OwnershipControls{
				Rules: []types.OwnershipControlsRule{
					{
						ObjectOwnership: data,
					},
				},
			}, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionGetBucketOwnershipControls,
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("versioning") {
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionRead,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Action:         auth.GetBucketVersioningAction,
			IsBucketPublic: isPublicBucket,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionGetBucketVersioning,
					BucketOwner: parsedAcl.Owner,
				})
		}
		// Only admin users and the bucket owner are allowed to get the versioning state of a bucket.
		if err := auth.IsAdminOrOwner(acct, isRoot, parsedAcl); err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionGetBucketVersioning,
					BucketOwner: parsedAcl.Owner,
				})
		}

		data, err := c.be.GetBucketVersioning(ctx.Context(), bucket)
		return SendXMLResponse(ctx, data, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionGetBucketVersioning,
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("policy") {
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionRead,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Action:         auth.GetBucketPolicyAction,
			IsBucketPublic: isPublicBucket,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionGetBucketPolicy,
					BucketOwner: parsedAcl.Owner,
				})
		}

		data, err := c.be.GetBucketPolicy(ctx.Context(), bucket)
		return SendXMLResponse(ctx, data, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionGetBucketPolicy,
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("cors") {
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionRead,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Action:         auth.GetBucketCorsAction,
			IsBucketPublic: isPublicBucket,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionGetBucketCors,
					BucketOwner: parsedAcl.Owner,
				})
		}

		data, err := c.be.GetBucketCors(ctx.Context(), bucket)
		return SendXMLResponse(ctx, data, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionGetBucketCors,
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("versions") {
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionRead,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Action:         auth.ListBucketVersionsAction,
			IsBucketPublic: isPublicBucket,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionListObjectVersions,
					BucketOwner: parsedAcl.Owner,
				})
		}

		maxkeys, err := utils.ParseUint(maxkeysStr)
		if err != nil {
			if c.debug {
				debuglogger.Logf("error parsing max keys %q: %v",
					maxkeysStr, err)
			}
			return SendXMLResponse(ctx, nil, s3err.GetAPIError(s3err.ErrInvalidMaxKeys),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionListObjectVersions,
					BucketOwner: parsedAcl.Owner,
				})
		}

		data, err := c.be.ListObjectVersions(ctx.Context(),
			&s3.ListObjectVersionsInput{
				Bucket:          &bucket,
				Delimiter:       &delimiter,
				KeyMarker:       &keyMarker,
				MaxKeys:         &maxkeys,
				Prefix:          &prefix,
				VersionIdMarker: &versionIdMarker,
			})
		return SendXMLResponse(ctx, data, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionListObjectVersions,
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("object-lock") {
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionRead,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Action:         auth.GetBucketObjectLockConfigurationAction,
			IsBucketPublic: isPublicBucket,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionGetObjectLockConfiguration,
					BucketOwner: parsedAcl.Owner,
				})
		}

		data, err := c.be.GetObjectLockConfiguration(ctx.Context(), bucket)
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionGetObjectLockConfiguration,
					BucketOwner: parsedAcl.Owner,
				})
		}

		resp, err := auth.ParseBucketLockConfigurationOutput(data)
		return SendXMLResponse(ctx, resp, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionGetObjectLockConfiguration,
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("acl") {
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionReadAcp,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Action:         auth.GetBucketAclAction,
			IsBucketPublic: isPublicBucket,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionGetBucketAcl,
					BucketOwner: parsedAcl.Owner,
				})
		}

		data, err := c.be.GetBucketAcl(ctx.Context(),
			&s3.GetBucketAclInput{Bucket: &bucket})
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:     c.logger,
					MetricsMng: c.mm,
				})
		}

		res, err := auth.ParseACLOutput(data, parsedAcl.Owner)
		return SendXMLResponse(ctx, res, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionGetBucketAcl,
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("uploads") {
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionRead,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Action:         auth.ListBucketMultipartUploadsAction,
			IsBucketPublic: isPublicBucket,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionListMultipartUploads,
					BucketOwner: parsedAcl.Owner,
				})
		}
		maxUploads, err := utils.ParseUint(maxUploadsStr)
		if err != nil {
			if c.debug {
				debuglogger.Logf("error parsing max uploads %q: %v",
					maxUploadsStr, err)
			}
			return SendXMLResponse(ctx, nil, s3err.GetAPIError(s3err.ErrInvalidMaxUploads),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionListMultipartUploads,
					BucketOwner: parsedAcl.Owner,
				})
		}
		res, err := c.be.ListMultipartUploads(ctx.Context(),
			&s3.ListMultipartUploadsInput{
				Bucket:         &bucket,
				Delimiter:      &delimiter,
				Prefix:         &prefix,
				UploadIdMarker: &uploadIdMarker,
				MaxUploads:     &maxUploads,
				KeyMarker:      &keyMarker,
			})
		return SendXMLResponse(ctx, res, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionListMultipartUploads,
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.QueryInt("list-type") == 2 {
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionRead,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Action:         auth.ListBucketAction,
			IsBucketPublic: isPublicBucket,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionListObjectsV2,
					BucketOwner: parsedAcl.Owner,
				})
		}
		maxkeys, err := utils.ParseUint(maxkeysStr)
		if err != nil {
			if c.debug {
				debuglogger.Logf("error parsing max keys %q: %v",
					maxkeysStr, err)
			}
			return SendXMLResponse(ctx, nil, s3err.GetAPIError(s3err.ErrInvalidMaxKeys),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionListObjectsV2,
					BucketOwner: parsedAcl.Owner,
				})
		}

		fetchOwner := strings.EqualFold(ctx.Query("fetch-owner"), "true")
		res, err := c.be.ListObjectsV2(ctx.Context(),
			&s3.ListObjectsV2Input{
				Bucket:            &bucket,
				Prefix:            &prefix,
				ContinuationToken: &cToken,
				Delimiter:         &delimiter,
				MaxKeys:           &maxkeys,
				StartAfter:        &sAfter,
				FetchOwner:        &fetchOwner,
			})
		return SendXMLResponse(ctx, res, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionListObjectsV2,
				BucketOwner: parsedAcl.Owner,
			})
	}

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:       c.readonly,
		Acl:            parsedAcl,
		AclPermission:  auth.PermissionRead,
		IsRoot:         isRoot,
		Acc:            acct,
		Bucket:         bucket,
		Action:         auth.ListBucketAction,
		IsBucketPublic: isPublicBucket,
	})
	if err != nil {
		return SendXMLResponse(ctx, nil, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionListObjects,
				BucketOwner: parsedAcl.Owner,
			})
	}

	maxkeys, err := utils.ParseUint(maxkeysStr)
	if err != nil {
		if c.debug {
			debuglogger.Logf("error parsing max keys %q: %v",
				maxkeysStr, err)
		}
		return SendXMLResponse(ctx, nil, s3err.GetAPIError(s3err.ErrInvalidMaxKeys),
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionListObjects,
				BucketOwner: parsedAcl.Owner,
			})
	}

	res, err := c.be.ListObjects(ctx.Context(),
		&s3.ListObjectsInput{
			Bucket:    &bucket,
			Prefix:    &prefix,
			Marker:    &marker,
			Delimiter: &delimiter,
			MaxKeys:   &maxkeys,
		})
	return SendXMLResponse(ctx, res, err,
		&MetaOpts{
			Logger:      c.logger,
			MetricsMng:  c.mm,
			Action:      metrics.ActionListObjects,
			BucketOwner: parsedAcl.Owner,
		})
}

func (c S3ApiController) PutBucketActions(ctx *fiber.Ctx) error {
	bucket := ctx.Params("bucket")
	acl := ctx.Get("X-Amz-Acl")
	grantFullControl := ctx.Get("X-Amz-Grant-Full-Control")
	grantRead := ctx.Get("X-Amz-Grant-Read")
	grantReadACP := ctx.Get("X-Amz-Grant-Read-Acp")
	granWrite := ctx.Get("X-Amz-Grant-Write")
	grantWriteACP := ctx.Get("X-Amz-Grant-Write-Acp")
	objectOwnership := types.ObjectOwnership(
		ctx.Get("X-Amz-Object-Ownership", string(types.ObjectOwnershipBucketOwnerEnforced)),
	)
	// mfa := ctx.Get("X-Amz-Mfa")
	// contentMD5 := ctx.Get("Content-MD5")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)

	if ctx.Request().URI().QueryArgs().Has("tagging") {
		parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

		tagging, err := utils.ParseTagging(ctx.Body(), utils.TagLimitBucket)
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionPutBucketTagging,
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionWrite,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Action:         auth.PutBucketTaggingAction,
			IsBucketPublic: isPublicBucket,
		})
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionPutBucketTagging,
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = c.be.PutBucketTagging(ctx.Context(), bucket, tagging)
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionPutBucketTagging,
				BucketOwner: parsedAcl.Owner,
				Status:      http.StatusNoContent,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("ownershipControls") {
		parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
		var ownershipControls s3response.OwnershipControls
		if err := xml.Unmarshal(ctx.Body(), &ownershipControls); err != nil {
			if c.debug {
				debuglogger.Logf("failed to unmarshal request body: %v", err)
			}
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrMalformedXML),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionPutBucketOwnershipControls,
					BucketOwner: parsedAcl.Owner,
				})
		}

		rulesCount := len(ownershipControls.Rules)
		isValidOwnership := utils.IsValidOwnership(ownershipControls.Rules[0].ObjectOwnership)
		if rulesCount != 1 || !isValidOwnership {
			if c.debug && rulesCount != 1 {
				debuglogger.Logf("ownership control rules should be 1, got %v", rulesCount)
			}
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrMalformedXML),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionPutBucketOwnershipControls,
					BucketOwner: parsedAcl.Owner,
				})
		}

		if err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: auth.PermissionWrite,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Action:        auth.PutBucketOwnershipControlsAction,
		}); err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionPutBucketOwnershipControls,
					BucketOwner: parsedAcl.Owner,
				})
		}

		err := c.be.PutBucketOwnershipControls(ctx.Context(), bucket, ownershipControls.Rules[0].ObjectOwnership)
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionPutBucketOwnershipControls,
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("versioning") {
		parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionWrite,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Action:         auth.PutBucketVersioningAction,
			IsBucketPublic: isPublicBucket,
		})
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionPutBucketVersioning,
					BucketOwner: parsedAcl.Owner,
				})
		}

		var versioningConf types.VersioningConfiguration
		err = xml.Unmarshal(ctx.Body(), &versioningConf)
		if err != nil {
			if c.debug {
				debuglogger.Logf("error unmarshalling versioning configuration: %v",
					err)
			}
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionPutBucketVersioning,
					BucketOwner: parsedAcl.Owner,
				})
		}

		if versioningConf.Status != types.BucketVersioningStatusEnabled &&
			versioningConf.Status != types.BucketVersioningStatusSuspended {
			if c.debug {
				debuglogger.Logf("invalid versioning configuration status: %v", versioningConf.Status)
			}
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrMalformedXML),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionPutBucketVersioning,
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = c.be.PutBucketVersioning(ctx.Context(), bucket, versioningConf.Status)
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionPutBucketVersioning,
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("object-lock") {
		parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

		if err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionWrite,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Action:         auth.PutBucketObjectLockConfigurationAction,
			IsBucketPublic: isPublicBucket,
		}); err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionPutObjectLockConfiguration,
					BucketOwner: parsedAcl.Owner,
				})
		}

		config, err := auth.ParseBucketLockConfigurationInput(ctx.Body())
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionPutObjectLockConfiguration,
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = c.be.PutObjectLockConfiguration(ctx.Context(), bucket, config)
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionPutObjectLockConfiguration,
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("cors") {
		parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionWrite,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Action:         auth.PutBucketCorsAction,
			IsBucketPublic: isPublicBucket,
		})
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionPutBucketCors,
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = c.be.PutBucketCors(ctx.Context(), []byte{})
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionPutBucketCors,
					BucketOwner: parsedAcl.Owner,
				},
			)
		}
	}
	if ctx.Request().URI().QueryArgs().Has("policy") {
		parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: auth.PermissionWrite,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Action:        auth.PutBucketPolicyAction,
		})
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionPutBucketPolicy,
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = auth.ValidatePolicyDocument(ctx.Body(), bucket, c.iam)
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionPutBucketPolicy,
					BucketOwner: parsedAcl.Owner,
				},
			)
		}

		err = c.be.PutBucketPolicy(ctx.Context(), bucket, ctx.Body())
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionPutBucketPolicy,
				BucketOwner: parsedAcl.Owner,
			})
	}

	grants := grantFullControl + grantRead + grantReadACP + granWrite + grantWriteACP

	if ctx.Request().URI().QueryArgs().Has("acl") {
		parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
		var input *auth.PutBucketAclInput

		ownership, err := c.be.GetBucketOwnershipControls(ctx.Context(), bucket)
		if err != nil && !errors.Is(err, s3err.GetAPIError(s3err.ErrOwnershipControlsNotFound)) {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionPutBucketAcl,
					BucketOwner: parsedAcl.Owner,
				})
		}
		if ownership == types.ObjectOwnershipBucketOwnerEnforced {
			if c.debug {
				debuglogger.Logf("bucket acls are disabled")
			}
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrAclNotSupported),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionPutBucketAcl,
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = auth.VerifyAccess(ctx.Context(), c.be,
			auth.AccessOptions{
				Readonly:      c.readonly,
				Acl:           parsedAcl,
				AclPermission: auth.PermissionWriteAcp,
				IsRoot:        isRoot,
				Acc:           acct,
				Bucket:        bucket,
				Action:        auth.PutBucketAclAction,
			})
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionPutBucketAcl,
					BucketOwner: parsedAcl.Owner,
				})
		}

		if len(ctx.Body()) > 0 {
			var accessControlPolicy auth.AccessControlPolicy
			err := xml.Unmarshal(ctx.Body(), &accessControlPolicy)
			if err != nil {
				if c.debug {
					debuglogger.Logf("error unmarshalling access control policy: %v", err)
				}
				return SendResponse(ctx, s3err.GetAPIError(s3err.ErrMalformedACL),
					&MetaOpts{
						Logger:      c.logger,
						Action:      metrics.ActionPutBucketAcl,
						BucketOwner: parsedAcl.Owner,
					})
			}

			err = accessControlPolicy.Validate()
			if err != nil {
				if c.debug {
					debuglogger.Logf("invalid access control policy: %v", err)
				}
				return SendResponse(ctx, err,
					&MetaOpts{
						Logger:      c.logger,
						Action:      metrics.ActionPutBucketAcl,
						BucketOwner: parsedAcl.Owner,
					})
			}

			if *accessControlPolicy.Owner.ID != parsedAcl.Owner {
				if c.debug {
					debuglogger.Logf("invalid access control policy owner id: %v, expected %v", *accessControlPolicy.Owner.ID, parsedAcl.Owner)
				}
				return SendResponse(ctx, s3err.APIError{
					Code:           "InvalidArgument",
					Description:    "Invalid id",
					HTTPStatusCode: http.StatusBadRequest,
				},
					&MetaOpts{
						Logger:      c.logger,
						Action:      metrics.ActionPutBucketAcl,
						BucketOwner: parsedAcl.Owner,
					})
			}

			if grants+acl != "" {
				if c.debug {
					debuglogger.Logf("invalid request: %q (grants) %q (acl)",
						grants, acl)
				}
				return SendResponse(ctx,
					s3err.GetAPIError(s3err.ErrUnexpectedContent),
					&MetaOpts{
						Logger:      c.logger,
						MetricsMng:  c.mm,
						Action:      metrics.ActionPutBucketAcl,
						BucketOwner: parsedAcl.Owner,
					})
			}

			input = &auth.PutBucketAclInput{
				Bucket:              &bucket,
				AccessControlPolicy: &accessControlPolicy,
			}
		} else if acl != "" {
			if acl != "private" && acl != "public-read" && acl != "public-read-write" {
				if c.debug {
					debuglogger.Logf("invalid acl: %q", acl)
				}
				return SendResponse(ctx,
					s3err.GetAPIError(s3err.ErrInvalidRequest),
					&MetaOpts{
						Logger:      c.logger,
						MetricsMng:  c.mm,
						Action:      metrics.ActionPutBucketAcl,
						BucketOwner: parsedAcl.Owner,
					})
			}
			if grants != "" {
				if c.debug {
					debuglogger.Logf("invalid request: %q (grants) %q (acl)",
						grants, acl)
				}
				return SendResponse(ctx,
					s3err.GetAPIError(s3err.ErrBothCannedAndHeaderGrants),
					&MetaOpts{
						Logger:      c.logger,
						MetricsMng:  c.mm,
						Action:      metrics.ActionPutBucketAcl,
						BucketOwner: parsedAcl.Owner,
					})
			}

			input = &auth.PutBucketAclInput{
				Bucket: &bucket,
				ACL:    types.BucketCannedACL(acl),
			}
		} else if grants != "" {
			input = &auth.PutBucketAclInput{
				Bucket:           &bucket,
				GrantFullControl: &grantFullControl,
				GrantRead:        &grantRead,
				GrantReadACP:     &grantReadACP,
				GrantWrite:       &granWrite,
				GrantWriteACP:    &grantWriteACP,
			}
		} else {
			if c.debug {
				debuglogger.Logf("none of the bucket acl options has been specified: canned, req headers, req body")
			}
			return SendResponse(ctx,
				s3err.GetAPIError(s3err.ErrMissingSecurityHeader),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionPutBucketAcl,
					BucketOwner: parsedAcl.Owner,
				})
		}

		updAcl, err := auth.UpdateACL(input, parsedAcl, c.iam, acct.Role == auth.RoleAdmin)
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionPutBucketAcl,
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = c.be.PutBucketAcl(ctx.Context(), bucket, updAcl)
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionPutBucketAcl,
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ok := utils.IsValidOwnership(objectOwnership); !ok {
		return SendResponse(ctx, s3err.APIError{
			Code:           "InvalidArgument",
			Description:    fmt.Sprintf("Invalid x-amz-object-ownership header: %v", objectOwnership),
			HTTPStatusCode: http.StatusBadRequest,
		},
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionCreateBucket,
				BucketOwner: acct.Access,
			})
	}

	if acl+grants != "" && objectOwnership == types.ObjectOwnershipBucketOwnerEnforced {
		if c.debug {
			debuglogger.Logf("bucket acls are disabled for %v object ownership", objectOwnership)
		}
		return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidBucketAclWithObjectOwnership),
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionCreateBucket,
				BucketOwner: acct.Access,
			})
	}

	if acl != "" && grants != "" {
		if c.debug {
			debuglogger.Logf("invalid request: %q (grants) %q (acl)", grants, acl)
		}
		return SendResponse(ctx, s3err.GetAPIError(s3err.ErrBothCannedAndHeaderGrants),
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionCreateBucket,
				BucketOwner: acct.Access,
			})
	}

	defACL := auth.ACL{
		Owner: acct.Access,
	}

	updAcl, err := auth.UpdateACL(&auth.PutBucketAclInput{
		GrantFullControl: &grantFullControl,
		GrantRead:        &grantRead,
		GrantReadACP:     &grantReadACP,
		GrantWrite:       &granWrite,
		GrantWriteACP:    &grantWriteACP,
		AccessControlPolicy: &auth.AccessControlPolicy{
			Owner: &types.Owner{
				ID: &acct.Access,
			}},
		ACL: types.BucketCannedACL(acl),
	}, defACL, c.iam, acct.Role == auth.RoleAdmin)
	if err != nil {
		if c.debug {
			debuglogger.Logf("failed to update bucket acl: %v", err)
		}
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionCreateBucket,
				BucketOwner: acct.Access,
			})
	}

	lockHeader := ctx.Get("X-Amz-Bucket-Object-Lock-Enabled")
	// CLI provides "True", SDK - "true"
	lockEnabled := lockHeader == "True" || lockHeader == "true"

	err = c.be.CreateBucket(ctx.Context(), &s3.CreateBucketInput{
		Bucket:                     &bucket,
		ObjectOwnership:            objectOwnership,
		ObjectLockEnabledForBucket: &lockEnabled,
	}, updAcl)
	return SendResponse(ctx, err,
		&MetaOpts{
			Logger:      c.logger,
			MetricsMng:  c.mm,
			Action:      metrics.ActionCreateBucket,
			BucketOwner: acct.Access,
		})
}

func (c S3ApiController) PutActions(ctx *fiber.Ctx) error {
	bucket := ctx.Params("bucket")
	keyStart := ctx.Params("key")
	keyEnd := ctx.Params("*1")
	uploadId := ctx.Query("uploadId")
	versionId := ctx.Query("versionId")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	IsBucketPublic := utils.ContextKeyPublicBucket.IsSet(ctx)
	contentType := ctx.Get("Content-Type")
	contentEncoding := ctx.Get("Content-Encoding")
	contentDisposition := ctx.Get("Content-Disposition")
	contentLanguage := ctx.Get("Content-Language")
	cacheControl := ctx.Get("Cache-Control")
	expires := ctx.Get("Expires")
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	tagging := ctx.Get("x-amz-tagging")

	// Copy source headers
	copySource := ctx.Get("X-Amz-Copy-Source")
	if len(copySource) > 0 && copySource[0] == '/' {
		copySource = copySource[1:]
	}
	copySrcIfMatch := ctx.Get("X-Amz-Copy-Source-If-Match")
	copySrcIfNoneMatch := ctx.Get("X-Amz-Copy-Source-If-None-Match")
	copySrcModifSince := ctx.Get("X-Amz-Copy-Source-If-Modified-Since")
	copySrcUnmodifSince := ctx.Get("X-Amz-Copy-Source-If-Unmodified-Since")
	copySrcRange := ctx.Get("X-Amz-Copy-Source-Range")
	directive := ctx.Get("X-Amz-Metadata-Directive")

	// Permission headers
	acl := ctx.Get("X-Amz-Acl")
	grantFullControl := ctx.Get("X-Amz-Grant-Full-Control")
	grantRead := ctx.Get("X-Amz-Grant-Read")
	grantReadACP := ctx.Get("X-Amz-Grant-Read-Acp")
	granWrite := ctx.Get("X-Amz-Grant-Write")
	grantWriteACP := ctx.Get("X-Amz-Grant-Write-Acp")

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

	// Other headers
	bucketOwner := ctx.Get("X-Amz-Expected-Bucket-Owner")
	storageClass := ctx.Get("X-Amz-Storage-Class")

	grants := grantFullControl + grantRead + grantReadACP + granWrite + grantWriteACP

	if keyEnd != "" {
		keyStart = strings.Join([]string{keyStart, keyEnd}, "/")
	}
	path := ctx.Path()
	if path[len(path)-1:] == "/" && keyStart[len(keyStart)-1:] != "/" {
		keyStart = keyStart + "/"
	}

	if ctx.Request().URI().QueryArgs().Has("tagging") {
		tagging, err := utils.ParseTagging(ctx.Body(), utils.TagLimitObject)
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionPutObjectTagging,
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionWrite,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Object:         keyStart,
			Action:         auth.PutBucketTaggingAction,
			IsBucketPublic: IsBucketPublic,
		})
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionPutObjectTagging,
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = c.be.PutObjectTagging(ctx.Context(), bucket, keyStart, tagging)
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				EvSender:    c.evSender,
				Action:      metrics.ActionPutObjectTagging,
				BucketOwner: parsedAcl.Owner,
				EventName:   s3event.EventObjectTaggingPut,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("retention") {
		if err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionWrite,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Object:         keyStart,
			Action:         auth.PutObjectRetentionAction,
			IsBucketPublic: IsBucketPublic,
		}); err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionPutObjectRetention,
					BucketOwner: parsedAcl.Owner,
				})
		}

		bypassHdr := ctx.Get("X-Amz-Bypass-Governance-Retention")
		bypass := strings.EqualFold(bypassHdr, "true")
		if bypass {
			policy, err := c.be.GetBucketPolicy(ctx.Context(), bucket)
			if err != nil {
				bypass = false
			} else {
				if err := auth.VerifyBucketPolicy(policy, acct.Access, bucket, keyStart, auth.BypassGovernanceRetentionAction); err != nil {
					bypass = false
				}
			}
		}

		retention, err := auth.ParseObjectLockRetentionInput(ctx.Body())
		if err != nil {
			if c.debug {
				debuglogger.Logf("failed to parse object lock configuration input: %v", err)
			}
			return SendResponse(ctx, err, &MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionPutObjectRetention,
				BucketOwner: parsedAcl.Owner,
			})
		}

		err = c.be.PutObjectRetention(ctx.Context(), bucket, keyStart, versionId, bypass, retention)
		return SendResponse(ctx, err, &MetaOpts{
			Logger:      c.logger,
			MetricsMng:  c.mm,
			Action:      metrics.ActionPutObjectRetention,
			BucketOwner: parsedAcl.Owner,
		})
	}

	if ctx.Request().URI().QueryArgs().Has("legal-hold") {
		var legalHold types.ObjectLockLegalHold
		if err := xml.Unmarshal(ctx.Body(), &legalHold); err != nil {
			if c.debug {
				debuglogger.Logf("failed to parse request body: %v", err)
			}
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrMalformedXML),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionPutObjectLegalHold,
					BucketOwner: parsedAcl.Owner,
				})
		}

		if legalHold.Status != types.ObjectLockLegalHoldStatusOff && legalHold.Status != types.ObjectLockLegalHoldStatusOn {
			if c.debug {
				debuglogger.Logf("invalid legal hold status: %v", legalHold.Status)
			}
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrMalformedXML),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionPutObjectLegalHold,
					BucketOwner: parsedAcl.Owner,
				})
		}

		if err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionWrite,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Object:         keyStart,
			Action:         auth.PutObjectLegalHoldAction,
			IsBucketPublic: IsBucketPublic,
		}); err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionPutObjectLegalHold,
					BucketOwner: parsedAcl.Owner,
				})
		}

		err := c.be.PutObjectLegalHold(ctx.Context(), bucket, keyStart, versionId, legalHold.Status == types.ObjectLockLegalHoldStatusOn)
		return SendResponse(ctx, err, &MetaOpts{
			Logger:      c.logger,
			MetricsMng:  c.mm,
			Action:      metrics.ActionPutObjectLegalHold,
			BucketOwner: parsedAcl.Owner,
		})
	}

	if ctx.Request().URI().QueryArgs().Has("uploadId") &&
		ctx.Request().URI().QueryArgs().Has("partNumber") &&
		copySource != "" {

		cs := copySource
		copySource, err := url.QueryUnescape(copySource)
		if err != nil {
			if c.debug {
				debuglogger.Logf("error unescaping copy source %q: %v",
					cs, err)
			}
			return SendXMLResponse(ctx, nil,
				s3err.GetAPIError(s3err.ErrInvalidCopySource),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionUploadPartCopy,
					BucketOwner: parsedAcl.Owner,
				})
		}

		partNumber := int32(ctx.QueryInt("partNumber", -1))
		if partNumber < 1 || partNumber > 10000 {
			if c.debug {
				debuglogger.Logf("invalid part number: %d", partNumber)
			}
			return SendXMLResponse(ctx, nil,
				s3err.GetAPIError(s3err.ErrInvalidPartNumber),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionUploadPartCopy,
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = auth.VerifyObjectCopyAccess(ctx.Context(), c.be, copySource,
			auth.AccessOptions{
				Acl:            parsedAcl,
				AclPermission:  auth.PermissionWrite,
				IsRoot:         isRoot,
				Acc:            acct,
				Bucket:         bucket,
				Object:         keyStart,
				Action:         auth.PutObjectAction,
				IsBucketPublic: IsBucketPublic,
			})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionUploadPartCopy,
					BucketOwner: parsedAcl.Owner,
				})
		}

		resp, err := c.be.UploadPartCopy(ctx.Context(),
			&s3.UploadPartCopyInput{
				Bucket:              &bucket,
				Key:                 &keyStart,
				CopySource:          &copySource,
				PartNumber:          &partNumber,
				UploadId:            &uploadId,
				ExpectedBucketOwner: &bucketOwner,
				CopySourceRange:     &copySrcRange,
			})
		if err == nil && resp.CopySourceVersionId != "" {
			utils.SetResponseHeaders(ctx, []utils.CustomHeader{
				{
					Key:   "x-amz-copy-source-version-id",
					Value: resp.CopySourceVersionId,
				},
			})
		}
		return SendXMLResponse(ctx, resp, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionUploadPartCopy,
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("uploadId") &&
		ctx.Request().URI().QueryArgs().Has("partNumber") {
		partNumber := int32(ctx.QueryInt("partNumber", -1))
		if partNumber < 1 || partNumber > 10000 {
			if c.debug {
				debuglogger.Logf("invalid part number: %d", partNumber)
			}
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidPartNumber),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionUploadPart,
					BucketOwner: parsedAcl.Owner,
				})
		}

		err := auth.VerifyAccess(ctx.Context(), c.be,
			auth.AccessOptions{
				Readonly:       c.readonly,
				Acl:            parsedAcl,
				AclPermission:  auth.PermissionWrite,
				IsRoot:         isRoot,
				Acc:            acct,
				Bucket:         bucket,
				Object:         keyStart,
				Action:         auth.PutObjectAction,
				IsBucketPublic: IsBucketPublic,
			})
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionUploadPart,
					BucketOwner: parsedAcl.Owner,
				})
		}

		contentLength, err := strconv.ParseInt(contentLengthStr, 10, 64)
		if err != nil {
			if c.debug {
				debuglogger.Logf("error parsing content length %q: %v",
					contentLengthStr, err)
			}
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionUploadPart,
					BucketOwner: parsedAcl.Owner,
				})
		}

		algorithm, checksums, err := utils.ParseChecksumHeaders(ctx)
		if err != nil {
			if c.debug {
				debuglogger.Logf("err parsing checksum headers: %v", err)
			}
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionPutObject,
					BucketOwner: parsedAcl.Owner,
				})
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
				Key:               &keyStart,
				UploadId:          &uploadId,
				PartNumber:        &partNumber,
				ContentLength:     &contentLength,
				Body:              body,
				ChecksumAlgorithm: algorithm,
				ChecksumCRC32:     backend.GetPtrFromString(checksums[types.ChecksumAlgorithmCrc32]),
				ChecksumCRC32C:    backend.GetPtrFromString(checksums[types.ChecksumAlgorithmCrc32c]),
				ChecksumSHA1:      backend.GetPtrFromString(checksums[types.ChecksumAlgorithmSha1]),
				ChecksumSHA256:    backend.GetPtrFromString(checksums[types.ChecksumAlgorithmSha256]),
				ChecksumCRC64NVME: backend.GetPtrFromString(checksums[types.ChecksumAlgorithmCrc64nvme]),
			})
		if err == nil {
			headers := []utils.CustomHeader{}
			if res.ETag != nil {
				headers = append(headers, utils.CustomHeader{
					Key:   "ETag",
					Value: *res.ETag,
				})
			}
			switch {
			case res.ChecksumCRC32 != nil:
				headers = append(headers, utils.CustomHeader{
					Key:   "x-amz-checksum-crc32",
					Value: *res.ChecksumCRC32,
				})
			case res.ChecksumCRC32C != nil:
				headers = append(headers, utils.CustomHeader{
					Key:   "x-amz-checksum-crc32c",
					Value: *res.ChecksumCRC32C,
				})
			case res.ChecksumCRC64NVME != nil:
				headers = append(headers, utils.CustomHeader{
					Key:   "x-amz-checksum-crc64nvme",
					Value: *res.ChecksumCRC64NVME,
				})
			case res.ChecksumSHA1 != nil:
				headers = append(headers, utils.CustomHeader{
					Key:   "x-amz-checksum-sha1",
					Value: *res.ChecksumSHA1,
				})
			case res.ChecksumSHA256 != nil:
				headers = append(headers, utils.CustomHeader{
					Key:   "x-amz-checksum-sha256",
					Value: *res.ChecksumSHA256,
				})
			}

			utils.SetResponseHeaders(ctx, headers)
		}
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:        c.logger,
				MetricsMng:    c.mm,
				ContentLength: contentLength,
				Action:        metrics.ActionUploadPart,
				BucketOwner:   parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("acl") {
		var input *s3.PutObjectAclInput

		if len(ctx.Body()) > 0 {
			if grants+acl != "" {
				if c.debug {
					debuglogger.Logf("invalid request: %q (grants) %q (acl)",
						grants, acl)
				}
				return SendResponse(ctx,
					s3err.GetAPIError(s3err.ErrInvalidRequest),
					&MetaOpts{
						Logger:      c.logger,
						MetricsMng:  c.mm,
						Action:      metrics.ActionPutObjectAcl,
						BucketOwner: parsedAcl.Owner,
					})
			}

			var accessControlPolicy auth.AccessControlPolicy
			err := xml.Unmarshal(ctx.Body(), &accessControlPolicy)
			if err != nil {
				if c.debug {
					debuglogger.Logf("error unmarshalling access control policy: %v",
						err)
				}
				return SendResponse(ctx,
					s3err.GetAPIError(s3err.ErrInvalidRequest),
					&MetaOpts{
						Logger:      c.logger,
						MetricsMng:  c.mm,
						Action:      metrics.ActionPutObjectAcl,
						BucketOwner: parsedAcl.Owner,
					})
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
				Key:    &keyStart,
				ACL:    "",
				AccessControlPolicy: &types.AccessControlPolicy{
					Owner:  accessControlPolicy.Owner,
					Grants: grants,
				},
			}
		}
		if acl != "" {
			if acl != "private" && acl != "public-read" && acl != "public-read-write" {
				if c.debug {
					debuglogger.Logf("invalid acl: %q", acl)
				}
				return SendResponse(ctx,
					s3err.GetAPIError(s3err.ErrInvalidRequest),
					&MetaOpts{
						Logger:      c.logger,
						MetricsMng:  c.mm,
						Action:      metrics.ActionPutObjectAcl,
						BucketOwner: parsedAcl.Owner,
					})
			}
			if len(ctx.Body()) > 0 || grants != "" {
				if c.debug {
					debuglogger.Logf("invalid request: %q (grants) %q (acl) %v (body len)",
						grants, acl, len(ctx.Body()))
				}
				return SendResponse(ctx,
					s3err.GetAPIError(s3err.ErrInvalidRequest),
					&MetaOpts{
						Logger:      c.logger,
						MetricsMng:  c.mm,
						Action:      metrics.ActionPutObjectAcl,
						BucketOwner: parsedAcl.Owner,
					})
			}

			input = &s3.PutObjectAclInput{
				Bucket: &bucket,
				Key:    &keyStart,
				ACL:    types.ObjectCannedACL(acl),
				AccessControlPolicy: &types.AccessControlPolicy{
					Owner: &types.Owner{ID: &bucketOwner},
				},
			}
		}
		if grants != "" {
			input = &s3.PutObjectAclInput{
				Bucket:           &bucket,
				Key:              &keyStart,
				GrantFullControl: &grantFullControl,
				GrantRead:        &grantRead,
				GrantReadACP:     &grantReadACP,
				GrantWrite:       &granWrite,
				GrantWriteACP:    &grantWriteACP,
				AccessControlPolicy: &types.AccessControlPolicy{
					Owner: &types.Owner{ID: &bucketOwner},
				},
				ACL: "",
			}
		}

		err := c.be.PutObjectAcl(ctx.Context(), input)
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				EvSender:    c.evSender,
				Action:      metrics.ActionPutObjectAcl,
				BucketOwner: parsedAcl.Owner,
				EventName:   s3event.EventObjectAclPut,
			})
	}

	if copySource != "" {
		cs := copySource
		copySource, err := url.QueryUnescape(copySource)
		if err != nil {
			if c.debug {
				debuglogger.Logf("error unescaping copy source %q: %v",
					cs, err)
			}
			return SendXMLResponse(ctx, nil,
				s3err.GetAPIError(s3err.ErrInvalidCopySource),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionCopyObject,
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = auth.VerifyObjectCopyAccess(ctx.Context(), c.be, copySource,
			auth.AccessOptions{
				Acl:           parsedAcl,
				AclPermission: auth.PermissionWrite,
				IsRoot:        isRoot,
				Acc:           acct,
				Bucket:        bucket,
				Object:        keyStart,
				Action:        auth.PutObjectAction,
			})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionCopyObject,
					BucketOwner: parsedAcl.Owner,
				})
		}

		var mtime *time.Time
		var umtime *time.Time
		if copySrcModifSince != "" {
			tm, err := time.Parse(iso8601Format, copySrcModifSince)
			if err != nil {
				if c.debug {
					debuglogger.Logf("error parsing copy source modified since %q: %v",
						copySrcModifSince, err)
				}
				return SendXMLResponse(ctx, nil,
					s3err.GetAPIError(s3err.ErrInvalidCopySource),
					&MetaOpts{
						Logger:      c.logger,
						MetricsMng:  c.mm,
						Action:      metrics.ActionCopyObject,
						BucketOwner: parsedAcl.Owner,
					})
			}
			mtime = &tm
		}
		if copySrcUnmodifSince != "" {
			tm, err := time.Parse(iso8601Format, copySrcUnmodifSince)
			if err != nil {
				if c.debug {
					debuglogger.Logf("error parsing copy source unmodified since %q: %v",
						copySrcUnmodifSince, err)
				}
				return SendXMLResponse(ctx, nil,
					s3err.GetAPIError(s3err.ErrInvalidCopySource),
					&MetaOpts{
						Logger:      c.logger,
						MetricsMng:  c.mm,
						Action:      metrics.ActionCopyObject,
						BucketOwner: parsedAcl.Owner,
					})
			}
			umtime = &tm
		}

		metadata := utils.GetUserMetaData(&ctx.Request().Header)

		if directive != "" && directive != "COPY" && directive != "REPLACE" {
			if c.debug {
				debuglogger.Logf("invalid metadata directive: %v", directive)
			}
			return SendXMLResponse(ctx, nil,
				s3err.GetAPIError(s3err.ErrInvalidMetadataDirective),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionCopyObject,
					BucketOwner: parsedAcl.Owner,
				})
		}

		metaDirective := types.MetadataDirectiveCopy
		if directive == "REPLACE" {
			metaDirective = types.MetadataDirectiveReplace
		}

		tDirective := types.TaggingDirective(ctx.Get("X-Amz-Tagging-Directive"))
		if tDirective != "" && tDirective != types.TaggingDirectiveCopy && tDirective != types.TaggingDirectiveReplace {
			if c.debug {
				debuglogger.Logf("invalid tagging direcrive: %v", tDirective)
			}
			return SendXMLResponse(ctx, nil,
				s3err.GetAPIError(s3err.ErrInvalidTaggingDirective),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionCopyObject,
					BucketOwner: parsedAcl.Owner,
				})
		}

		taggingDirective := types.TaggingDirectiveCopy
		if tDirective == types.TaggingDirectiveReplace {
			taggingDirective = types.TaggingDirectiveReplace
		}

		checksumAlgorithm := types.ChecksumAlgorithm(ctx.Get("x-amz-checksum-algorithm"))
		err = utils.IsChecksumAlgorithmValid(checksumAlgorithm)
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionCopyObject,
					BucketOwner: parsedAcl.Owner,
				})
		}

		objLock, err := utils.ParsObjectLockHdrs(ctx)
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionPutObject,
					BucketOwner: parsedAcl.Owner,
				})
		}

		res, err := c.be.CopyObject(ctx.Context(),
			s3response.CopyObjectInput{
				Bucket:                      &bucket,
				Key:                         &keyStart,
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
		if err == nil {
			hdrs := []utils.CustomHeader{}
			if getstring(res.VersionId) != "" {
				hdrs = append(hdrs, utils.CustomHeader{
					Key:   "x-amz-version-id",
					Value: getstring(res.VersionId),
				})
			}
			if getstring(res.CopySourceVersionId) != "" {
				hdrs = append(hdrs, utils.CustomHeader{
					Key:   "x-amz-copy-source-version-id",
					Value: getstring(res.CopySourceVersionId),
				})
			}
			utils.SetResponseHeaders(ctx, hdrs)

			return SendXMLResponse(ctx, res.CopyObjectResult, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					EvSender:    c.evSender,
					Action:      metrics.ActionCopyObject,
					BucketOwner: parsedAcl.Owner,
					ObjectETag:  res.CopyObjectResult.ETag,
					VersionId:   res.VersionId,
					EventName:   s3event.EventObjectCreatedCopy,
				})
		} else {
			return SendXMLResponse(ctx, res, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionCopyObject,
					BucketOwner: parsedAcl.Owner,
				})
		}
	}

	metadata := utils.GetUserMetaData(&ctx.Request().Header)

	err := auth.VerifyAccess(ctx.Context(), c.be,
		auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionWrite,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Object:         keyStart,
			Action:         auth.PutObjectAction,
			IsBucketPublic: IsBucketPublic,
		})
	if err != nil {
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionPutObject,
				BucketOwner: parsedAcl.Owner,
			})
	}

	err = auth.CheckObjectAccess(ctx.Context(), bucket, acct.Access, []types.ObjectIdentifier{{Key: &keyStart}}, true, IsBucketPublic, c.be)
	if err != nil {
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionPutObject,
				BucketOwner: parsedAcl.Owner,
			})
	}

	contentLength, err := strconv.ParseInt(contentLengthStr, 10, 64)
	if err != nil {
		if c.debug {
			debuglogger.Logf("error parsing content length %q: %v",
				contentLengthStr, err)
		}
		return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest),
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionPutObject,
				BucketOwner: parsedAcl.Owner,
			})
	}

	objLock, err := utils.ParsObjectLockHdrs(ctx)
	if err != nil {
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionPutObject,
				BucketOwner: parsedAcl.Owner,
			})
	}

	algorithm, checksums, err := utils.ParseChecksumHeaders(ctx)
	if err != nil {
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionPutObject,
				BucketOwner: parsedAcl.Owner,
			})
	}

	var body io.Reader
	bodyi := utils.ContextKeyBodyReader.Get(ctx)
	if bodyi != nil {
		body = bodyi.(io.Reader)
	} else {
		body = bytes.NewReader([]byte{})
	}

	res, err := c.be.PutObject(ctx.Context(),
		s3response.PutObjectInput{
			Bucket:                    &bucket,
			Key:                       &keyStart,
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
			ChecksumCRC32:             backend.GetPtrFromString(checksums[types.ChecksumAlgorithmCrc32]),
			ChecksumCRC32C:            backend.GetPtrFromString(checksums[types.ChecksumAlgorithmCrc32c]),
			ChecksumSHA1:              backend.GetPtrFromString(checksums[types.ChecksumAlgorithmSha1]),
			ChecksumSHA256:            backend.GetPtrFromString(checksums[types.ChecksumAlgorithmSha256]),
			ChecksumCRC64NVME:         backend.GetPtrFromString(checksums[types.ChecksumAlgorithmCrc64nvme]),
		})
	if err != nil {
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:        c.logger,
				MetricsMng:    c.mm,
				ContentLength: contentLength,
				EvSender:      c.evSender,
				Action:        metrics.ActionPutObject,
				BucketOwner:   parsedAcl.Owner,
				ObjectSize:    contentLength,
				EventName:     s3event.EventObjectCreatedPut,
			})
	}
	hdrs := []utils.CustomHeader{
		{
			Key:   "ETag",
			Value: res.ETag,
		},
	}

	if res.VersionID != "" {
		hdrs = append(hdrs, utils.CustomHeader{
			Key:   "x-amz-version-id",
			Value: res.VersionID,
		})
	}
	switch {
	case res.ChecksumCRC32 != nil:
		hdrs = append(hdrs, utils.CustomHeader{
			Key:   "x-amz-checksum-crc32",
			Value: *res.ChecksumCRC32,
		})
	case res.ChecksumCRC32C != nil:
		hdrs = append(hdrs, utils.CustomHeader{
			Key:   "x-amz-checksum-crc32c",
			Value: *res.ChecksumCRC32C,
		})
	case res.ChecksumCRC64NVME != nil:
		hdrs = append(hdrs, utils.CustomHeader{
			Key:   "x-amz-checksum-crc64nvme",
			Value: *res.ChecksumCRC64NVME,
		})
	case res.ChecksumSHA1 != nil:
		hdrs = append(hdrs, utils.CustomHeader{
			Key:   "x-amz-checksum-sha1",
			Value: *res.ChecksumSHA1,
		})
	case res.ChecksumSHA256 != nil:
		hdrs = append(hdrs, utils.CustomHeader{
			Key:   "x-amz-checksum-sha256",
			Value: *res.ChecksumSHA256,
		})
	}
	if res.ChecksumType != "" {
		hdrs = append(hdrs, utils.CustomHeader{
			Key:   "x-amz-checksum-type",
			Value: string(res.ChecksumType),
		})
	}

	utils.SetResponseHeaders(ctx, hdrs)

	return SendResponse(ctx, nil,
		&MetaOpts{
			Logger:        c.logger,
			MetricsMng:    c.mm,
			ContentLength: contentLength,
			EvSender:      c.evSender,
			Action:        metrics.ActionPutObject,
			BucketOwner:   parsedAcl.Owner,
			ObjectETag:    &res.ETag,
			ObjectSize:    contentLength,
			EventName:     s3event.EventObjectCreatedPut,
		})
}

func (c S3ApiController) DeleteBucket(ctx *fiber.Ctx) error {
	bucket := ctx.Params("bucket")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	IsBucketPublic := utils.ContextKeyPublicBucket.IsSet(ctx)

	if ctx.Request().URI().QueryArgs().Has("tagging") {
		err := auth.VerifyAccess(ctx.Context(), c.be,
			auth.AccessOptions{
				Readonly:       c.readonly,
				Acl:            parsedAcl,
				AclPermission:  auth.PermissionWrite,
				IsRoot:         isRoot,
				Acc:            acct,
				Bucket:         bucket,
				Action:         auth.PutBucketTaggingAction,
				IsBucketPublic: IsBucketPublic,
			})
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionDeleteBucketTagging,
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = c.be.DeleteBucketTagging(ctx.Context(), bucket)
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionDeleteBucketTagging,
				BucketOwner: parsedAcl.Owner,
				Status:      http.StatusNoContent,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("ownershipControls") {
		err := auth.VerifyAccess(ctx.Context(), c.be,
			auth.AccessOptions{
				Readonly:      c.readonly,
				Acl:           parsedAcl,
				AclPermission: auth.PermissionWrite,
				IsRoot:        isRoot,
				Acc:           acct,
				Bucket:        bucket,
				Action:        auth.PutBucketOwnershipControlsAction,
			})
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionDeleteBucketOwnershipControls,
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = c.be.DeleteBucketOwnershipControls(ctx.Context(), bucket)
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionDeleteBucketOwnershipControls,
				BucketOwner: parsedAcl.Owner,
				Status:      http.StatusNoContent,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("policy") {
		err := auth.VerifyAccess(ctx.Context(), c.be,
			auth.AccessOptions{
				Readonly:      c.readonly,
				Acl:           parsedAcl,
				AclPermission: auth.PermissionWrite,
				IsRoot:        isRoot,
				Acc:           acct,
				Bucket:        bucket,
				Action:        auth.DeleteBucketPolicyAction,
			})
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionDeleteBucketPolicy,
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = c.be.DeleteBucketPolicy(ctx.Context(), bucket)
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionDeleteBucketPolicy,
				BucketOwner: parsedAcl.Owner,
				Status:      http.StatusNoContent,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("cors") {
		err := auth.VerifyAccess(ctx.Context(), c.be,
			auth.AccessOptions{
				Readonly:       c.readonly,
				Acl:            parsedAcl,
				AclPermission:  auth.PermissionWrite,
				IsRoot:         isRoot,
				Acc:            acct,
				Bucket:         bucket,
				Action:         auth.PutBucketCorsAction,
				IsBucketPublic: IsBucketPublic,
			})
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionDeleteBucketCors,
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = c.be.DeleteBucketCors(ctx.Context(), bucket)
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionDeleteBucketCors,
				BucketOwner: parsedAcl.Owner,
			})
	}

	err := auth.VerifyAccess(ctx.Context(), c.be,
		auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionWrite,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Action:         auth.DeleteBucketAction,
			IsBucketPublic: IsBucketPublic,
		})
	if err != nil {
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionDeleteBucket,
				BucketOwner: parsedAcl.Owner,
			})
	}

	err = c.be.DeleteBucket(ctx.Context(), bucket)
	return SendResponse(ctx, err,
		&MetaOpts{
			Logger:      c.logger,
			MetricsMng:  c.mm,
			Action:      metrics.ActionDeleteBucket,
			BucketOwner: parsedAcl.Owner,
			Status:      http.StatusNoContent,
		})
}

func (c S3ApiController) DeleteObjects(ctx *fiber.Ctx) error {
	bucket := ctx.Params("bucket")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	IsBucketPublic := utils.ContextKeyPublicBucket.IsSet(ctx)
	bypassHdr := ctx.Get("X-Amz-Bypass-Governance-Retention")
	var dObj s3response.DeleteObjects

	err := xml.Unmarshal(ctx.Body(), &dObj)
	if err != nil {
		if c.debug {
			debuglogger.Logf("error unmarshalling delete objects: %v", err)
		}
		return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest),
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionDeleteObjects,
				BucketOwner: parsedAcl.Owner,
			})
	}

	err = auth.VerifyAccess(ctx.Context(), c.be,
		auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionWrite,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Action:         auth.DeleteObjectAction,
			IsBucketPublic: IsBucketPublic,
		})
	if err != nil {
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionDeleteObjects,
				BucketOwner: parsedAcl.Owner,
			})
	}

	// The AWS CLI sends 'True', while Go SDK sends 'true'
	bypass := strings.EqualFold(bypassHdr, "true")

	err = auth.CheckObjectAccess(ctx.Context(), bucket, acct.Access, dObj.Objects, bypass, IsBucketPublic, c.be)
	if err != nil {
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionDeleteObjects,
				BucketOwner: parsedAcl.Owner,
			})
	}

	res, err := c.be.DeleteObjects(ctx.Context(),
		&s3.DeleteObjectsInput{
			Bucket: &bucket,
			Delete: &types.Delete{
				Objects: dObj.Objects,
			},
		})
	return SendXMLResponse(ctx, res, err,
		&MetaOpts{
			Logger:      c.logger,
			MetricsMng:  c.mm,
			Action:      metrics.ActionDeleteObjects,
			ObjectCount: int64(len(dObj.Objects)),
			BucketOwner: parsedAcl.Owner,
			EvSender:    c.evSender,
			EventName:   s3event.EventObjectRemovedDeleteObjects,
		})
}

func (c S3ApiController) DeleteActions(ctx *fiber.Ctx) error {
	bucket := ctx.Params("bucket")
	key := ctx.Params("key")
	keyEnd := ctx.Params("*1")
	uploadId := ctx.Query("uploadId")
	versionId := ctx.Query("versionId")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	IsBucketPublic := utils.ContextKeyPublicBucket.IsSet(ctx)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	bypassHdr := ctx.Get("X-Amz-Bypass-Governance-Retention")

	if keyEnd != "" {
		key = strings.Join([]string{key, keyEnd}, "/")
	}
	path := ctx.Path()
	if path[len(path)-1:] == "/" && key[len(key)-1:] != "/" {
		key = key + "/"
	}

	if ctx.Request().URI().QueryArgs().Has("tagging") {
		err := auth.VerifyAccess(ctx.Context(), c.be,
			auth.AccessOptions{
				Readonly:       c.readonly,
				Acl:            parsedAcl,
				AclPermission:  auth.PermissionWrite,
				IsRoot:         isRoot,
				Acc:            acct,
				Bucket:         bucket,
				Object:         key,
				Action:         auth.DeleteObjectTaggingAction,
				IsBucketPublic: IsBucketPublic,
			})
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionDeleteObjectTagging,
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = c.be.DeleteObjectTagging(ctx.Context(), bucket, key)
		return SendResponse(ctx, err,
			&MetaOpts{
				Status:      http.StatusNoContent,
				Logger:      c.logger,
				MetricsMng:  c.mm,
				EvSender:    c.evSender,
				Action:      metrics.ActionDeleteObjectTagging,
				BucketOwner: parsedAcl.Owner,
				EventName:   s3event.EventObjectTaggingDelete,
			})
	}

	if uploadId != "" {
		expectedBucketOwner := ctx.Get("X-Amz-Expected-Bucket-Owner")
		requestPayer := ctx.Get("X-Amz-Request-Payer")

		err := auth.VerifyAccess(ctx.Context(), c.be,
			auth.AccessOptions{
				Readonly:       c.readonly,
				Acl:            parsedAcl,
				AclPermission:  auth.PermissionWrite,
				IsRoot:         isRoot,
				Acc:            acct,
				Bucket:         bucket,
				Object:         key,
				Action:         auth.AbortMultipartUploadAction,
				IsBucketPublic: IsBucketPublic,
			})
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionAbortMultipartUpload,
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = c.be.AbortMultipartUpload(ctx.Context(),
			&s3.AbortMultipartUploadInput{
				UploadId:            &uploadId,
				Bucket:              &bucket,
				Key:                 &key,
				ExpectedBucketOwner: &expectedBucketOwner,
				RequestPayer:        types.RequestPayer(requestPayer),
			})
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionAbortMultipartUpload,
				BucketOwner: parsedAcl.Owner,
				Status:      http.StatusNoContent,
			})
	}

	//TODO: check s3:DeleteObjectVersion policy in case a use tries to delete a version of an object

	err := auth.VerifyAccess(ctx.Context(), c.be,
		auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionWrite,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Object:         key,
			Action:         auth.DeleteObjectAction,
			IsBucketPublic: IsBucketPublic,
		})
	if err != nil {
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionDeleteObject,
				BucketOwner: parsedAcl.Owner,
			})
	}

	// The AWS CLI sends 'True', while Go SDK sends 'true'
	bypass := strings.EqualFold(bypassHdr, "true")

	err = auth.CheckObjectAccess(ctx.Context(), bucket, acct.Access, []types.ObjectIdentifier{{Key: &key, VersionId: &versionId}}, bypass, IsBucketPublic, c.be)
	if err != nil {
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionDeleteObject,
				BucketOwner: parsedAcl.Owner,
			})
	}

	res, err := c.be.DeleteObject(ctx.Context(),
		&s3.DeleteObjectInput{
			Bucket:    &bucket,
			Key:       &key,
			VersionId: &versionId,
		})
	if err != nil {
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				EvSender:    c.evSender,
				Action:      metrics.ActionDeleteObject,
				BucketOwner: parsedAcl.Owner,
				EventName:   s3event.EventObjectRemovedDelete,
				Status:      http.StatusNoContent,
			})
	}

	hdrs := []utils.CustomHeader{}
	if res.VersionId != nil && *res.VersionId != "" {
		hdrs = append(hdrs, utils.CustomHeader{
			Key:   "x-amz-version-id",
			Value: *res.VersionId,
		})
	}
	if res.DeleteMarker != nil && *res.DeleteMarker {
		hdrs = append(hdrs, utils.CustomHeader{
			Key:   "x-amz-delete-marker",
			Value: "true",
		})
	}

	utils.SetResponseHeaders(ctx, hdrs)

	return SendResponse(ctx, nil,
		&MetaOpts{
			Logger:      c.logger,
			MetricsMng:  c.mm,
			EvSender:    c.evSender,
			Action:      metrics.ActionDeleteObject,
			BucketOwner: parsedAcl.Owner,
			EventName:   s3event.EventObjectRemovedDelete,
			Status:      http.StatusNoContent,
		})
}

func (c S3ApiController) HeadBucket(ctx *fiber.Ctx) error {
	bucket := ctx.Params("bucket")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	region := utils.ContextKeyRegion.Get(ctx).(string)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)

	err := auth.VerifyAccess(ctx.Context(), c.be,
		auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionRead,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Action:         auth.ListBucketAction,
			IsBucketPublic: isPublicBucket,
		})
	if err != nil {
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionHeadBucket,
				BucketOwner: parsedAcl.Owner,
			})
	}

	_, err = c.be.HeadBucket(ctx.Context(),
		&s3.HeadBucketInput{
			Bucket: &bucket,
		})

	utils.SetResponseHeaders(ctx, []utils.CustomHeader{
		{
			Key:   "X-Amz-Access-Point-Alias",
			Value: "false",
		},
		{
			Key:   "X-Amz-Bucket-Region",
			Value: region,
		},
	})
	return SendResponse(ctx, err,
		&MetaOpts{
			Logger:      c.logger,
			MetricsMng:  c.mm,
			Action:      metrics.ActionHeadBucket,
			BucketOwner: parsedAcl.Owner,
		})
}

const (
	timefmt = "Mon, 02 Jan 2006 15:04:05 GMT"
)

func (c S3ApiController) HeadObject(ctx *fiber.Ctx) error {
	bucket := ctx.Params("bucket")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)
	partNumberQuery := int32(ctx.QueryInt("partNumber", -1))
	versionId := ctx.Query("versionId")
	objRange := ctx.Get("Range")
	key := ctx.Params("key")
	keyEnd := ctx.Params("*1")
	if keyEnd != "" {
		key = strings.Join([]string{key, keyEnd}, "/")
	}
	path := ctx.Path()
	if path[len(path)-1:] == "/" && key[len(key)-1:] != "/" {
		key = key + "/"
	}

	var partNumber *int32
	if ctx.Request().URI().QueryArgs().Has("partNumber") {
		if partNumberQuery < 1 || partNumberQuery > 10000 {
			if c.debug {
				debuglogger.Logf("invalid part number: %d", partNumberQuery)
			}
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidPartNumber),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionHeadObject,
					BucketOwner: parsedAcl.Owner,
				})
		}

		partNumber = &partNumberQuery
	}

	err := auth.VerifyAccess(ctx.Context(), c.be,
		auth.AccessOptions{
			Readonly:       c.readonly,
			Acl:            parsedAcl,
			AclPermission:  auth.PermissionRead,
			IsRoot:         isRoot,
			Acc:            acct,
			Bucket:         bucket,
			Object:         key,
			Action:         auth.GetObjectAction,
			IsBucketPublic: isPublicBucket,
		})
	if err != nil {
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionHeadObject,
				BucketOwner: parsedAcl.Owner,
			})
	}

	checksumMode := types.ChecksumMode(ctx.Get("x-amz-checksum-mode"))
	if checksumMode != "" && checksumMode != types.ChecksumModeEnabled {
		if c.debug {
			debuglogger.Logf("invalid x-amz-checksum-mode header value: %v", checksumMode)
		}
		return SendResponse(ctx, s3err.GetInvalidChecksumHeaderErr("x-amz-checksum-mode"),
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionHeadObject,
				BucketOwner: parsedAcl.Owner,
			})
	}

	res, err := c.be.HeadObject(ctx.Context(),
		&s3.HeadObjectInput{
			Bucket:       &bucket,
			Key:          &key,
			PartNumber:   partNumber,
			VersionId:    &versionId,
			ChecksumMode: checksumMode,
			Range:        &objRange,
		})
	if err != nil {
		if res != nil {
			utils.SetResponseHeaders(ctx, []utils.CustomHeader{
				{
					Key:   "x-amz-delete-marker",
					Value: "true",
				},
				{
					Key:   "Last-Modified",
					Value: res.LastModified.UTC().Format(timefmt),
				},
			})
		}
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionHeadObject,
				BucketOwner: parsedAcl.Owner,
			})
	}

	utils.SetMetaHeaders(ctx, res.Metadata)
	headers := []utils.CustomHeader{
		{
			Key:   "Content-Length",
			Value: fmt.Sprint(getint64(res.ContentLength)),
		},
		{
			Key:   "ETag",
			Value: getstring(res.ETag),
		},
		{
			Key:   "x-amz-restore",
			Value: getstring(res.Restore),
		},
	}
	if getstring(res.AcceptRanges) != "" {
		headers = append(headers, utils.CustomHeader{
			Key:   "accept-ranges",
			Value: getstring(res.AcceptRanges),
		})
	}
	if getstring(res.ContentRange) != "" {
		headers = append(headers, utils.CustomHeader{
			Key:   "Content-Range",
			Value: getstring(res.ContentRange),
		})
	}
	if getstring(res.ContentDisposition) != "" {
		headers = append(headers, utils.CustomHeader{
			Key:   "Content-Disposition",
			Value: getstring(res.ContentDisposition),
		})
	}
	if getstring(res.ContentEncoding) != "" {
		headers = append(headers, utils.CustomHeader{
			Key:   "Content-Encoding",
			Value: getstring(res.ContentEncoding),
		})
	}
	if getstring(res.ContentLanguage) != "" {
		headers = append(headers, utils.CustomHeader{
			Key:   "Content-Language",
			Value: getstring(res.ContentLanguage),
		})
	}
	if getstring(res.CacheControl) != "" {
		headers = append(headers, utils.CustomHeader{
			Key:   "Cache-Control",
			Value: getstring(res.CacheControl),
		})
	}
	if getstring(res.ExpiresString) != "" {
		headers = append(headers, utils.CustomHeader{
			Key:   "Expires",
			Value: getstring(res.ExpiresString),
		})
	}
	if res.ObjectLockMode != "" {
		headers = append(headers, utils.CustomHeader{
			Key:   "x-amz-object-lock-mode",
			Value: string(res.ObjectLockMode),
		})
	}
	if res.ObjectLockLegalHoldStatus != "" {
		headers = append(headers, utils.CustomHeader{
			Key:   "x-amz-object-lock-legal-hold",
			Value: string(res.ObjectLockLegalHoldStatus),
		})
	}
	if res.ObjectLockRetainUntilDate != nil {
		retainUntilDate := res.ObjectLockRetainUntilDate.Format(time.RFC3339)
		headers = append(headers, utils.CustomHeader{
			Key:   "x-amz-object-lock-retain-until-date",
			Value: retainUntilDate,
		})
	}
	if res.PartsCount != nil {
		headers = append(headers, utils.CustomHeader{
			Key:   "x-amz-mp-parts-count",
			Value: fmt.Sprintf("%v", *res.PartsCount),
		})
	}
	if res.LastModified != nil {
		lastmod := res.LastModified.UTC().Format(timefmt)
		headers = append(headers, utils.CustomHeader{
			Key:   "Last-Modified",
			Value: lastmod,
		})
	}
	if res.StorageClass != "" {
		headers = append(headers, utils.CustomHeader{
			Key:   "x-amz-storage-class",
			Value: string(res.StorageClass),
		})
	}
	switch {
	case res.ChecksumCRC32 != nil:
		headers = append(headers, utils.CustomHeader{
			Key:   "x-amz-checksum-crc32",
			Value: *res.ChecksumCRC32,
		})
	case res.ChecksumCRC32C != nil:
		headers = append(headers, utils.CustomHeader{
			Key:   "x-amz-checksum-crc32c",
			Value: *res.ChecksumCRC32C,
		})
	case res.ChecksumCRC64NVME != nil:
		headers = append(headers, utils.CustomHeader{
			Key:   "x-amz-checksum-crc64nvme",
			Value: *res.ChecksumCRC64NVME,
		})
	case res.ChecksumSHA1 != nil:
		headers = append(headers, utils.CustomHeader{
			Key:   "x-amz-checksum-sha1",
			Value: *res.ChecksumSHA1,
		})
	case res.ChecksumSHA256 != nil:
		headers = append(headers, utils.CustomHeader{
			Key:   "x-amz-checksum-sha256",
			Value: *res.ChecksumSHA256,
		})
	}
	if res.ChecksumType != "" {
		headers = append(headers, utils.CustomHeader{
			Key:   "x-amz-checksum-type",
			Value: string(res.ChecksumType),
		})
	}

	contentType := getstring(res.ContentType)
	if contentType == "" {
		contentType = defaultContentType
	}
	headers = append(headers, utils.CustomHeader{
		Key:   "Content-Type",
		Value: contentType,
	})

	if getstring(res.VersionId) != "" {
		headers = append(headers, utils.CustomHeader{
			Key:   "x-amz-version-id",
			Value: getstring(res.VersionId),
		})
	}

	utils.SetResponseHeaders(ctx, headers)

	return SendResponse(ctx, nil,
		&MetaOpts{
			Logger:      c.logger,
			MetricsMng:  c.mm,
			Action:      metrics.ActionHeadObject,
			BucketOwner: parsedAcl.Owner,
		})
}

func (c S3ApiController) CreateActions(ctx *fiber.Ctx) error {
	bucket := ctx.Params("bucket")
	key := ctx.Params("key")
	keyEnd := ctx.Params("*1")
	uploadId := ctx.Query("uploadId")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	IsBucketPublic := utils.ContextKeyPublicBucket.IsSet(ctx)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	contentType := ctx.Get("Content-Type")
	contentDisposition := ctx.Get("Content-Disposition")
	contentLanguage := ctx.Get("Content-Language")
	cacheControl := ctx.Get("Cache-Control")
	contentEncoding := ctx.Get("Content-Encoding")
	tagging := ctx.Get("X-Amz-Tagging")

	if keyEnd != "" {
		key = strings.Join([]string{key, keyEnd}, "/")
	}

	path := ctx.Path()
	if path[len(path)-1:] == "/" && key[len(key)-1:] != "/" {
		key = key + "/"
	}

	if ctx.Request().URI().QueryArgs().Has("restore") {
		var restoreRequest types.RestoreRequest
		if err := xml.Unmarshal(ctx.Body(), &restoreRequest); err != nil {
			if !errors.Is(err, io.EOF) {
				if c.debug {
					debuglogger.Logf("failed to parse the request body: %v", err)
				}
				return SendResponse(ctx, s3err.GetAPIError(s3err.ErrMalformedXML),
					&MetaOpts{
						Logger:      c.logger,
						MetricsMng:  c.mm,
						Action:      metrics.ActionRestoreObject,
						BucketOwner: parsedAcl.Owner,
					})
			}
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
				Action:         auth.RestoreObjectAction,
				IsBucketPublic: IsBucketPublic,
			})
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionRestoreObject,
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = c.be.RestoreObject(ctx.Context(), &s3.RestoreObjectInput{
			Bucket:         &bucket,
			Key:            &key,
			RestoreRequest: &restoreRequest,
		})
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				EvSender:    c.evSender,
				Action:      metrics.ActionRestoreObject,
				BucketOwner: parsedAcl.Owner,
				EventName:   s3event.EventObjectRestoreCompleted,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("select") && ctx.Query("select-type") == "2" {
		var payload s3response.SelectObjectContentPayload

		err := xml.Unmarshal(ctx.Body(), &payload)
		if err != nil {
			if c.debug {
				debuglogger.Logf("error unmarshalling select object content: %v", err)
			}
			return SendXMLResponse(ctx, nil,
				s3err.GetAPIError(s3err.ErrMalformedXML),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionSelectObjectContent,
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = auth.VerifyAccess(ctx.Context(), c.be,
			auth.AccessOptions{
				Readonly:       c.readonly,
				Acl:            parsedAcl,
				AclPermission:  auth.PermissionRead,
				IsRoot:         isRoot,
				Acc:            acct,
				Bucket:         bucket,
				Object:         key,
				Action:         auth.GetObjectAction,
				IsBucketPublic: IsBucketPublic,
			})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionSelectObjectContent,
					BucketOwner: parsedAcl.Owner,
				})
		}

		sw := c.be.SelectObjectContent(ctx.Context(),
			&s3.SelectObjectContentInput{
				Bucket:              &bucket,
				Key:                 &key,
				Expression:          payload.Expression,
				ExpressionType:      payload.ExpressionType,
				InputSerialization:  payload.InputSerialization,
				OutputSerialization: payload.OutputSerialization,
				RequestProgress:     payload.RequestProgress,
				ScanRange:           payload.ScanRange,
			})

		ctx.Context().SetBodyStreamWriter(sw)

		return nil
	}

	if uploadId != "" {
		data := struct {
			Parts []types.CompletedPart `xml:"Part"`
		}{}

		err := xml.Unmarshal(ctx.Body(), &data)
		if err != nil {
			if c.debug {
				debuglogger.Logf("error unmarshalling complete multipart upload: %v", err)
			}
			return SendXMLResponse(ctx, nil,
				s3err.GetAPIError(s3err.ErrMalformedXML),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionCompleteMultipartUpload,
					BucketOwner: parsedAcl.Owner,
				})
		}

		if len(data.Parts) == 0 {
			if c.debug {
				debuglogger.Logf("empty parts provided for complete multipart upload")
			}
			return SendXMLResponse(ctx, nil,
				s3err.GetAPIError(s3err.ErrEmptyParts),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionCompleteMultipartUpload,
					BucketOwner: parsedAcl.Owner,
				})
		}

		var mpuObjectSize *int64
		mpuObjSizeHdr := ctx.Get("X-Amz-Mp-Object-Size")
		if mpuObjSizeHdr != "" {
			val, err := strconv.ParseInt(mpuObjSizeHdr, 10, 64)
			//TODO: Not sure if invalid request should be returned
			if err != nil {
				if c.debug {
					debuglogger.Logf("invalid value for 'x-amz-mp-objects-size' header: %v", err)
				}
				return SendXMLResponse(ctx, nil,
					s3err.GetAPIError(s3err.ErrInvalidRequest),
					&MetaOpts{
						Logger:      c.logger,
						MetricsMng:  c.mm,
						Action:      metrics.ActionCompleteMultipartUpload,
						BucketOwner: parsedAcl.Owner,
					})
			}

			if val < 0 {
				debuglogger.Logf("value for 'x-amz-mp-objects-size' header is less than 0: %v", val)
				return SendXMLResponse(ctx, nil,
					s3err.GetInvalidMpObjectSizeErr(val),
					&MetaOpts{
						Logger:      c.logger,
						MetricsMng:  c.mm,
						Action:      metrics.ActionCompleteMultipartUpload,
						BucketOwner: parsedAcl.Owner,
					})
			}

			mpuObjectSize = &val
		}

		err = auth.VerifyAccess(ctx.Context(), c.be,
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
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionCompleteMultipartUpload,
					BucketOwner: parsedAcl.Owner,
				})
		}

		_, checksums, err := utils.ParseChecksumHeaders(ctx)
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionCompleteMultipartUpload,
					BucketOwner: parsedAcl.Owner,
				})
		}

		checksumType := types.ChecksumType(ctx.Get("x-amz-checksum-type"))
		err = utils.IsChecksumTypeValid(checksumType)
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      metrics.ActionCompleteMultipartUpload,
					BucketOwner: parsedAcl.Owner,
				})
		}

		res, versid, err := c.be.CompleteMultipartUpload(ctx.Context(),
			&s3.CompleteMultipartUploadInput{
				Bucket:   &bucket,
				Key:      &key,
				UploadId: &uploadId,
				MultipartUpload: &types.CompletedMultipartUpload{
					Parts: data.Parts,
				},
				MpuObjectSize:     mpuObjectSize,
				ChecksumCRC32:     backend.GetPtrFromString(checksums[types.ChecksumAlgorithmCrc32]),
				ChecksumCRC32C:    backend.GetPtrFromString(checksums[types.ChecksumAlgorithmCrc32c]),
				ChecksumSHA1:      backend.GetPtrFromString(checksums[types.ChecksumAlgorithmSha1]),
				ChecksumSHA256:    backend.GetPtrFromString(checksums[types.ChecksumAlgorithmSha256]),
				ChecksumCRC64NVME: backend.GetPtrFromString(checksums[types.ChecksumAlgorithmCrc64nvme]),
				ChecksumType:      checksumType,
			})
		if err == nil {
			if versid != "" {
				utils.SetResponseHeaders(ctx, []utils.CustomHeader{
					{
						Key:   "x-amz-version-id",
						Value: versid,
					},
				})
			}
			return SendXMLResponse(ctx, res, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					EvSender:    c.evSender,
					Action:      metrics.ActionCompleteMultipartUpload,
					BucketOwner: parsedAcl.Owner,
					ObjectETag:  res.ETag,
					EventName:   s3event.EventCompleteMultipartUpload,
					VersionId:   backend.GetPtrFromString(versid),
				})
		}
		return SendXMLResponse(ctx, res, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionCompleteMultipartUpload,
				BucketOwner: parsedAcl.Owner,
			})
	}

	err := auth.VerifyAccess(ctx.Context(), c.be,
		auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: auth.PermissionWrite,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Object:        key,
			Action:        auth.PutObjectAction,
		})
	if err != nil {
		return SendXMLResponse(ctx, nil, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionCreateMultipartUpload,
				BucketOwner: parsedAcl.Owner,
			})
	}

	objLockState, err := utils.ParsObjectLockHdrs(ctx)
	if err != nil {
		return SendXMLResponse(ctx, nil, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionCreateMultipartUpload,
				BucketOwner: parsedAcl.Owner,
			})
	}

	metadata := utils.GetUserMetaData(&ctx.Request().Header)

	checksumAlgorithm, checksumType, err := utils.ParseCreateMpChecksumHeaders(ctx)
	if err != nil {
		return SendXMLResponse(ctx, nil, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      metrics.ActionCreateMultipartUpload,
				BucketOwner: parsedAcl.Owner,
			})
	}

	expires := ctx.Get("Expires")

	res, err := c.be.CreateMultipartUpload(ctx.Context(),
		s3response.CreateMultipartUploadInput{
			Bucket:                    &bucket,
			Key:                       &key,
			Tagging:                   &tagging,
			ContentType:               &contentType,
			ContentEncoding:           &contentEncoding,
			ContentDisposition:        &contentDisposition,
			ContentLanguage:           &contentLanguage,
			CacheControl:              &cacheControl,
			Expires:                   &expires,
			ObjectLockRetainUntilDate: &objLockState.RetainUntilDate,
			ObjectLockMode:            objLockState.ObjectLockMode,
			ObjectLockLegalHoldStatus: objLockState.LegalHoldStatus,
			Metadata:                  metadata,
			ChecksumAlgorithm:         checksumAlgorithm,
			ChecksumType:              checksumType,
		})
	if err == nil {
		if checksumAlgorithm != "" {
			utils.SetResponseHeaders(ctx, []utils.CustomHeader{
				{
					Key:   "x-amz-checksum-algorithm",
					Value: string(checksumAlgorithm),
				},
			})
		}
	}
	return SendXMLResponse(ctx, res, err,
		&MetaOpts{
			Logger:      c.logger,
			MetricsMng:  c.mm,
			Action:      metrics.ActionCreateMultipartUpload,
			BucketOwner: parsedAcl.Owner,
		})
}

type MetaOpts struct {
	Logger        s3log.AuditLogger
	EvSender      s3event.S3EventSender
	MetricsMng    *metrics.Manager
	ContentLength int64
	Action        string
	BucketOwner   string
	ObjectSize    int64
	ObjectCount   int64
	EventName     s3event.EventType
	ObjectETag    *string
	VersionId     *string
	Status        int
}

func SendResponse(ctx *fiber.Ctx, err error, l *MetaOpts) error {
	if l.Logger != nil {
		l.Logger.Log(ctx, err, nil, s3log.LogMeta{
			Action:      l.Action,
			BucketOwner: l.BucketOwner,
			ObjectSize:  l.ObjectSize,
		})
	}
	if l.MetricsMng != nil {
		if l.ObjectCount > 0 {
			l.MetricsMng.Send(ctx, err, l.Action, l.ObjectCount, l.Status)
		} else {
			l.MetricsMng.Send(ctx, err, l.Action, l.ContentLength, l.Status)
		}
	}
	if err != nil {
		var apierr s3err.APIError
		if errors.As(err, &apierr) {
			ctx.Status(apierr.HTTPStatusCode)
			return ctx.Send(s3err.GetAPIErrorResponse(apierr, "", "", ""))
		}

		fmt.Fprintf(os.Stderr, "Internal Error, %v\n", err)
		ctx.Status(http.StatusInternalServerError)
		return ctx.Send(s3err.GetAPIErrorResponse(
			s3err.GetAPIError(s3err.ErrInternalError), "", "", ""))
	}
	if l.EvSender != nil {
		l.EvSender.SendEvent(ctx, s3event.EventMeta{
			ObjectSize:  l.ObjectSize,
			ObjectETag:  l.ObjectETag,
			EventName:   l.EventName,
			BucketOwner: l.BucketOwner,
			VersionId:   l.VersionId,
		})
	}

	if l.Status == 0 {
		l.Status = http.StatusOK
	}
	// https://github.com/gofiber/fiber/issues/2080
	// ctx.SendStatus() sets incorrect content length on HEAD request
	ctx.Status(l.Status)
	return nil
}

var (
	xmlhdr = []byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
)

const (
	maxXMLBodyLen = 4 * 1024 * 1024
)

func SendXMLResponse(ctx *fiber.Ctx, resp any, err error, l *MetaOpts) error {
	if l.MetricsMng != nil {
		if l.ObjectCount > 0 {
			l.MetricsMng.Send(ctx, err, l.Action, l.ObjectCount, l.Status)
		} else {
			l.MetricsMng.Send(ctx, err, l.Action, l.ContentLength, l.Status)
		}
	}
	if err != nil {
		if l.Logger != nil {
			l.Logger.Log(ctx, err, nil, s3log.LogMeta{
				Action:      l.Action,
				BucketOwner: l.BucketOwner,
				ObjectSize:  l.ObjectSize,
			})
		}
		serr, ok := err.(s3err.APIError)
		if ok {
			ctx.Status(serr.HTTPStatusCode)
			return ctx.Send(s3err.GetAPIErrorResponse(serr, "", "", ""))
		}

		fmt.Fprintf(os.Stderr, "Internal Error, %v\n", err)
		ctx.Status(http.StatusInternalServerError)

		return ctx.Send(s3err.GetAPIErrorResponse(
			s3err.GetAPIError(s3err.ErrInternalError), "", "", ""))
	}

	var b []byte

	// Handle already encoded responses(text, json...)
	encodedResp, ok := resp.([]byte)
	if ok {
		b = encodedResp
	}

	if resp != nil && !ok {
		if b, err = xml.Marshal(resp); err != nil {
			return err
		}

		if len(b) > 0 {
			ctx.Response().Header.Set("Content-Length", fmt.Sprint(len(b)))
			ctx.Response().Header.SetContentType(fiber.MIMEApplicationXML)
		}
	}

	if l.Logger != nil {
		l.Logger.Log(ctx, nil, b, s3log.LogMeta{
			Action:      l.Action,
			BucketOwner: l.BucketOwner,
			ObjectSize:  l.ObjectSize,
		})
	}

	if l.EvSender != nil {
		l.EvSender.SendEvent(ctx, s3event.EventMeta{
			BucketOwner: l.BucketOwner,
			ObjectSize:  l.ObjectSize,
			ObjectETag:  l.ObjectETag,
			VersionId:   l.VersionId,
			EventName:   l.EventName,
		})
	}

	if ok {
		if len(b) > 0 {
			ctx.Response().Header.Set("Content-Length", fmt.Sprint(len(b)))
		}

		return ctx.Send(b)
	}

	msglen := len(xmlhdr) + len(b)
	if msglen > maxXMLBodyLen {
		debuglogger.Logf("XML encoded body len %v exceeds max len %v",
			msglen, maxXMLBodyLen)
		ctx.Status(http.StatusInternalServerError)

		return ctx.Send(s3err.GetAPIErrorResponse(
			s3err.GetAPIError(s3err.ErrInternalError), "", "", ""))
	}
	res := make([]byte, 0, msglen)
	res = append(res, xmlhdr...)
	res = append(res, b...)

	return ctx.Send(res)
}
