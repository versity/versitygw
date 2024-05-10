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
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/metrics"
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
	iso8601Format = "20060102T150405Z"
)

func New(be backend.Backend, iam auth.IAMService, logger s3log.AuditLogger, evs s3event.S3EventSender, mm *metrics.Manager, debug bool, readonly bool) S3ApiController {
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
	acct := ctx.Locals("account").(auth.Account)
	res, err := c.be.ListBuckets(ctx.Context(), acct.Access, acct.Role == "admin")
	return SendXMLResponse(ctx, res, err,
		&MetaOpts{
			Logger:     c.logger,
			MetricsMng: c.mm,
			Action:     "s3:ListAllMyBuckets",
		})
}

func (c S3ApiController) GetActions(ctx *fiber.Ctx) error {
	bucket := ctx.Params("bucket")
	key := ctx.Params("key")
	keyEnd := ctx.Params("*1")
	uploadId := ctx.Query("uploadId")
	maxParts := int32(ctx.QueryInt("max-parts", -1))
	partNumberMarker := ctx.Query("part-number-marker")
	acceptRange := ctx.Get("Range")
	acct := ctx.Locals("account").(auth.Account)
	isRoot := ctx.Locals("isRoot").(bool)
	parsedAcl := ctx.Locals("parsedAcl").(auth.ACL)
	versionId := ctx.Query("versionId")
	if keyEnd != "" {
		key = strings.Join([]string{key, keyEnd}, "/")
	}

	if ctx.Request().URI().QueryArgs().Has("tagging") {
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: types.PermissionRead,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Object:        key,
			Action:        auth.GetObjectTaggingAction,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:GetObjectTagging",
					BucketOwner: parsedAcl.Owner,
				})
		}

		tags, err := c.be.GetObjectTagging(ctx.Context(), bucket, key)
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:GetObjectTagging",
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
				Action:      "s3:GetObjectTagging",
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("retention") {
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: types.PermissionRead,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Object:        key,
			Action:        auth.GetObjectRetentionAction,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:GetObjectRetention",
					BucketOwner: parsedAcl.Owner,
				})
		}

		data, err := c.be.GetObjectRetention(ctx.Context(), bucket, key, versionId)
		if err != nil {
			return SendXMLResponse(ctx, data, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:GetObjectRetention",
					BucketOwner: parsedAcl.Owner,
				})
		}

		retention, err := auth.ParseObjectLockRetentionOutput(data)
		return SendXMLResponse(ctx, retention, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:GetObjectRetention",
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("legal-hold") {
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: types.PermissionRead,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Object:        key,
			Action:        auth.GetObjectLegalHoldAction,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:GetObjectLegalHold",
					BucketOwner: parsedAcl.Owner,
				})
		}

		data, err := c.be.GetObjectLegalHold(ctx.Context(), bucket, key, versionId)
		return SendXMLResponse(ctx, auth.ParseObjectLegalHoldOutput(data), err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:GetObjectLegalHold",
				BucketOwner: parsedAcl.Owner,
			})
	}

	if uploadId != "" {
		if maxParts < 0 && ctx.Request().URI().QueryArgs().Has("max-parts") {
			return SendResponse(ctx,
				s3err.GetAPIError(s3err.ErrInvalidMaxParts),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:ListParts",
					BucketOwner: parsedAcl.Owner,
				})
		}
		if partNumberMarker != "" {
			n, err := strconv.Atoi(partNumberMarker)
			if err != nil || n < 0 {
				if err != nil && c.debug {
					log.Printf("error parsing part number marker %q: %v",
						partNumberMarker, err)
				}
				return SendResponse(ctx,
					s3err.GetAPIError(s3err.ErrInvalidPartNumberMarker),
					&MetaOpts{
						Logger:      c.logger,
						MetricsMng:  c.mm,
						Action:      "s3:ListParts",
						BucketOwner: parsedAcl.Owner,
					})
			}
		}

		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: types.PermissionRead,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Object:        key,
			Action:        auth.ListMultipartUploadPartsAction,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:ListParts",
					BucketOwner: parsedAcl.Owner,
				})
		}
		var mxParts *int32
		if ctx.Request().URI().QueryArgs().Has("max-parts") {
			mxParts = &maxParts
		}

		res, err := c.be.ListParts(ctx.Context(), &s3.ListPartsInput{
			Bucket:           &bucket,
			Key:              &key,
			UploadId:         &uploadId,
			PartNumberMarker: &partNumberMarker,
			MaxParts:         mxParts,
		})
		return SendXMLResponse(ctx, res, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:ListParts",
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("acl") {
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: types.PermissionReadAcp,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Object:        key,
			Action:        auth.GetObjectAclAction,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:GetObjectAcl",
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
				Action:      "s3:GetObjectAcl",
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("attributes") {
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: types.PermissionRead,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Object:        key,
			Action:        auth.GetObjectAttributesAction,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:GetObjectAttributes",
					BucketOwner: parsedAcl.Owner,
				})
		}
		maxParts := ctx.Get("X-Amz-Max-Parts")
		partNumberMarker := ctx.Get("X-Amz-Part-Number-Marker")
		maxPartsParsed, err := utils.ParseUint(maxParts)
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:GetObjectAttributes",
					BucketOwner: parsedAcl.Owner,
				})
		}
		attrs := utils.ParseObjectAttributes(ctx)

		res, err := c.be.GetObjectAttributes(ctx.Context(),
			&s3.GetObjectAttributesInput{
				Bucket:           &bucket,
				Key:              &key,
				PartNumberMarker: &partNumberMarker,
				MaxParts:         &maxPartsParsed,
				VersionId:        &versionId,
			})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:GetObjectAttributes",
					BucketOwner: parsedAcl.Owner,
				})
		}
		return SendXMLResponse(ctx, utils.FilterObjectAttributes(attrs, res), err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:GetObjectAttributes",
				BucketOwner: parsedAcl.Owner,
			})
	}

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:      c.readonly,
		Acl:           parsedAcl,
		AclPermission: types.PermissionRead,
		IsRoot:        isRoot,
		Acc:           acct,
		Bucket:        bucket,
		Object:        key,
		Action:        auth.GetObjectAction,
	})
	if err != nil {
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:GetObject",
				BucketOwner: parsedAcl.Owner,
			})
	}

	ctx.Locals("logResBody", false)
	res, err := c.be.GetObject(ctx.Context(), &s3.GetObjectInput{
		Bucket:    &bucket,
		Key:       &key,
		Range:     &acceptRange,
		VersionId: &versionId,
	}, ctx.Response().BodyWriter())
	if err != nil {
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:GetObject",
				BucketOwner: parsedAcl.Owner,
			})
	}
	if res == nil {
		return SendResponse(ctx, fmt.Errorf("get object nil response"),
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:GetObject",
				BucketOwner: parsedAcl.Owner,
			})
	}

	utils.SetMetaHeaders(ctx, res.Metadata)
	var lastmod string
	if res.LastModified != nil {
		lastmod = res.LastModified.Format(timefmt)
	}

	utils.SetResponseHeaders(ctx, []utils.CustomHeader{
		{
			Key:   "Content-Length",
			Value: fmt.Sprint(getint64(res.ContentLength)),
		},
		{
			Key:   "Content-Type",
			Value: getstring(res.ContentType),
		},
		{
			Key:   "Content-Encoding",
			Value: getstring(res.ContentEncoding),
		},
		{
			Key:   "ETag",
			Value: getstring(res.ETag),
		},
		{
			Key:   "Last-Modified",
			Value: lastmod,
		},
		{
			Key:   "x-amz-storage-class",
			Value: string(res.StorageClass),
		},
		{
			Key:   "Content-Range",
			Value: getstring(res.ContentRange),
		},
		{
			Key:   "accept-ranges",
			Value: getstring(res.AcceptRanges),
		},
	})

	if res.TagCount != nil {
		utils.SetResponseHeaders(ctx, []utils.CustomHeader{
			{
				Key:   "x-amz-tagging-count",
				Value: fmt.Sprint(*res.TagCount),
			},
		})
	}

	status := http.StatusOK
	if acceptRange != "" {
		status = http.StatusPartialContent
	}

	return SendResponse(ctx, nil,
		&MetaOpts{
			Logger:        c.logger,
			MetricsMng:    c.mm,
			Action:        "s3:GetObject",
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
	acct := ctx.Locals("account").(auth.Account)
	isRoot := ctx.Locals("isRoot").(bool)
	parsedAcl := ctx.Locals("parsedAcl").(auth.ACL)

	if ctx.Request().URI().QueryArgs().Has("tagging") {
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: types.PermissionRead,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Action:        auth.GetBucketTaggingAction,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:GetBucketTagging",
					BucketOwner: parsedAcl.Owner,
				})
		}

		tags, err := c.be.GetBucketTagging(ctx.Context(), bucket)
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:GetBucketTagging",
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
				Action:      "s3:GetBucketTagging",
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("versioning") {
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: types.PermissionRead,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Action:        auth.GetBucketVersioningAction,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:GetBucketVersioning",
					BucketOwner: parsedAcl.Owner,
				})
		}
		// Only admin users and the bucket owner are allowed to get the versioning state of a bucket.
		if err := auth.IsAdminOrOwner(acct, isRoot, parsedAcl); err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:GetBucketVersioning",
					BucketOwner: parsedAcl.Owner,
				})
		}

		data, err := c.be.GetBucketVersioning(ctx.Context(), bucket)
		return SendXMLResponse(ctx, data, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:GetBucketVersioning",
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("policy") {
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: types.PermissionRead,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Action:        auth.GetBucketPolicyAction,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:GetBucketPolicy",
					BucketOwner: parsedAcl.Owner,
				})
		}

		data, err := c.be.GetBucketPolicy(ctx.Context(), bucket)
		return SendXMLResponse(ctx, data, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:GetBucketPolicy",
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("versions") {
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: types.PermissionRead,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Action:        auth.ListBucketVersionsAction,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:ListObjectVersions",
					BucketOwner: parsedAcl.Owner,
				})
		}

		maxkeys, err := utils.ParseUint(maxkeysStr)
		if err != nil {
			if c.debug {
				log.Printf("error parsing max keys %q: %v",
					maxkeysStr, err)
			}
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:ListObjectVersions",
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
				Action:      "s3:ListObjectVersions",
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("object-lock") {
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: types.PermissionRead,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Action:        auth.GetBucketObjectLockConfigurationAction,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:GetObjectLockConfiguration",
					BucketOwner: parsedAcl.Owner,
				})
		}

		data, err := c.be.GetObjectLockConfiguration(ctx.Context(), bucket)
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:GetObjectLockConfiguration",
					BucketOwner: parsedAcl.Owner,
				})
		}

		resp, err := auth.ParseBucketLockConfigurationOutput(data)
		return SendXMLResponse(ctx, resp, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:GetObjectLockConfiguration",
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("acl") {
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: types.PermissionReadAcp,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Action:        auth.GetBucketAclAction,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:GetBucketAcl",
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

		res, err := auth.ParseACLOutput(data)
		return SendXMLResponse(ctx, res, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:GetBucketAcl",
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("uploads") {
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: types.PermissionRead,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Action:        auth.ListBucketMultipartUploadsAction,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:ListMultipartUploads",
					BucketOwner: parsedAcl.Owner,
				})
		}
		maxUploads, err := utils.ParseUint(maxUploadsStr)
		if err != nil {
			if c.debug {
				log.Printf("error parsing max uploads %q: %v",
					maxUploadsStr, err)
			}
			return SendXMLResponse(ctx, nil, err, &MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:ListMultipartUploads",
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
				Action:      "s3:ListMultipartUploads",
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.QueryInt("list-type") == 2 {
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: types.PermissionRead,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Action:        auth.ListBucketAction,
		})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:ListObjectsV2",
					BucketOwner: parsedAcl.Owner,
				})
		}
		maxkeys, err := utils.ParseUint(maxkeysStr)
		if err != nil {
			if c.debug {
				log.Printf("error parsing max keys %q: %v",
					maxkeysStr, err)
			}
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:ListObjectsV2",
					BucketOwner: parsedAcl.Owner,
				})
		}
		res, err := c.be.ListObjectsV2(ctx.Context(),
			&s3.ListObjectsV2Input{
				Bucket:            &bucket,
				Prefix:            &prefix,
				ContinuationToken: &cToken,
				Delimiter:         &delimiter,
				MaxKeys:           &maxkeys,
				StartAfter:        &sAfter,
			})
		return SendXMLResponse(ctx, res, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:ListObjectsV2",
				BucketOwner: parsedAcl.Owner,
			})
	}

	err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
		Readonly:      c.readonly,
		Acl:           parsedAcl,
		AclPermission: types.PermissionRead,
		IsRoot:        isRoot,
		Acc:           acct,
		Bucket:        bucket,
		Action:        auth.ListBucketAction,
	})
	if err != nil {
		return SendXMLResponse(ctx, nil, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:ListObjects",
				BucketOwner: parsedAcl.Owner,
			})
	}

	maxkeys, err := utils.ParseUint(maxkeysStr)
	if err != nil {
		if c.debug {
			log.Printf("error parsing max keys %q: %v",
				maxkeysStr, err)
		}
		return SendXMLResponse(ctx, nil, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:ListObjects",
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
	return SendXMLResponse(ctx, struct {
		*s3.ListObjectsOutput
		XMLName struct{} `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult"`
	}{ListObjectsOutput: res}, err,
		&MetaOpts{
			Logger:      c.logger,
			MetricsMng:  c.mm,
			Action:      "s3:ListObjects",
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
	mfa := ctx.Get("X-Amz-Mfa")
	contentMD5 := ctx.Get("Content-MD5")
	acct := ctx.Locals("account").(auth.Account)
	isRoot := ctx.Locals("isRoot").(bool)

	if ctx.Request().URI().QueryArgs().Has("tagging") {
		parsedAcl := ctx.Locals("parsedAcl").(auth.ACL)

		var bucketTagging s3response.TaggingInput
		err := xml.Unmarshal(ctx.Body(), &bucketTagging)
		if err != nil {
			if c.debug {
				log.Printf("error unmarshalling bucket tagging: %v", err)
			}
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:PutBucketTagging",
					BucketOwner: parsedAcl.Owner,
				})
		}

		tags := make(map[string]string, len(bucketTagging.TagSet.Tags))

		for _, tag := range bucketTagging.TagSet.Tags {
			if len(tag.Key) > 128 || len(tag.Value) > 256 {
				return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidTag),
					&MetaOpts{
						Logger:      c.logger,
						MetricsMng:  c.mm,
						Action:      "s3:PutBucketTagging",
						BucketOwner: parsedAcl.Owner,
					})
			}
			tags[tag.Key] = tag.Value
		}

		err = auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: types.PermissionWrite,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Action:        auth.PutBucketTaggingAction,
		})
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:PutBucketTagging",
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = c.be.PutBucketTagging(ctx.Context(), bucket, tags)
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:PutBucketTagging",
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("versioning") {
		parsedAcl := ctx.Locals("parsedAcl").(auth.ACL)
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: types.PermissionWrite,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Action:        auth.PutBucketVersioningAction,
		})
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:PutBucketVersioning",
					BucketOwner: parsedAcl.Owner,
				})
		}

		var versioningConf types.VersioningConfiguration
		err = xml.Unmarshal(ctx.Body(), &versioningConf)
		if err != nil {
			if c.debug {
				log.Printf("error unmarshalling versioning configuration: %v",
					err)
			}
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:PutBucketVersioning",
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = c.be.PutBucketVersioning(ctx.Context(),
			&s3.PutBucketVersioningInput{
				Bucket:                  &bucket,
				MFA:                     &mfa,
				VersioningConfiguration: &versioningConf,
				ContentMD5:              &contentMD5,
			})
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:PutBucketVersioning",
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("object-lock") {
		parsedAcl := ctx.Locals("parsedAcl").(auth.ACL)

		if err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: types.PermissionWrite,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Action:        auth.PutBucketObjectLockConfigurationAction,
		}); err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:PutObjectLockConfiguration",
					BucketOwner: parsedAcl.Owner,
				})
		}

		config, err := auth.ParseBucketLockConfigurationInput(ctx.Body())
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:PutObjectLockConfiguration",
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = c.be.PutObjectLockConfiguration(ctx.Context(), bucket, config)
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:PutObjectLockConfiguration",
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("policy") {
		parsedAcl := ctx.Locals("parsedAcl").(auth.ACL)
		err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: types.PermissionWrite,
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
					Action:      "s3:PutBucketPolicy",
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = auth.ValidatePolicyDocument(ctx.Body(), bucket, c.iam)
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:PutBucketPolicy",
					BucketOwner: parsedAcl.Owner,
				},
			)
		}

		err = c.be.PutBucketPolicy(ctx.Context(), bucket, ctx.Body())
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:PutBucketPolicy",
				BucketOwner: parsedAcl.Owner,
			})
	}

	grants := grantFullControl + grantRead + grantReadACP + granWrite + grantWriteACP

	if ctx.Request().URI().QueryArgs().Has("acl") {
		var input *s3.PutBucketAclInput
		var accessControlPolicy auth.AccessControlPolicy

		parsedAcl := ctx.Locals("parsedAcl").(auth.ACL)
		err := auth.VerifyAccess(ctx.Context(), c.be,
			auth.AccessOptions{
				Readonly:      c.readonly,
				Acl:           parsedAcl,
				AclPermission: types.PermissionWriteAcp,
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
					Action:      "s3:PutBucketAcl",
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = xml.Unmarshal(ctx.Body(), &accessControlPolicy)
		if err != nil {
			if c.debug {
				log.Printf("error unmarshalling access control policy: %v", err)
			}
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:PutBucketAcl",
					BucketOwner: parsedAcl.Owner,
				})
		}

		if len(accessControlPolicy.AccessControlList.Grants) > 0 {
			if grants+acl != "" {
				if c.debug {
					log.Printf("invalid request: %q (grants) %q (acl)",
						grants, acl)
				}
				return SendResponse(ctx,
					s3err.GetAPIError(s3err.ErrInvalidRequest),
					&MetaOpts{
						Logger:      c.logger,
						MetricsMng:  c.mm,
						Action:      "s3:PutBucketAcl",
						BucketOwner: parsedAcl.Owner,
					})
			}

			input = &s3.PutBucketAclInput{
				Bucket: &bucket,
				ACL:    "",
				AccessControlPolicy: &types.AccessControlPolicy{
					Owner:  &accessControlPolicy.Owner,
					Grants: accessControlPolicy.AccessControlList.Grants,
				},
			}
		}
		if acl != "" {
			if acl != "private" && acl != "public-read" && acl != "public-read-write" {
				if c.debug {
					log.Printf("invalid acl: %q", acl)
				}
				return SendResponse(ctx,
					s3err.GetAPIError(s3err.ErrInvalidRequest),
					&MetaOpts{
						Logger:      c.logger,
						MetricsMng:  c.mm,
						Action:      "s3:PutBucketAcl",
						BucketOwner: parsedAcl.Owner,
					})
			}
			if len(accessControlPolicy.AccessControlList.Grants) > 0 || grants != "" {
				if c.debug {
					log.Printf("invalid request: %q (grants) %q (acl)",
						grants, acl)
				}
				return SendResponse(ctx,
					s3err.GetAPIError(s3err.ErrInvalidRequest),
					&MetaOpts{
						Logger:      c.logger,
						MetricsMng:  c.mm,
						Action:      "s3:PutBucketAcl",
						BucketOwner: parsedAcl.Owner,
					})
			}

			input = &s3.PutBucketAclInput{
				Bucket: &bucket,
				ACL:    types.BucketCannedACL(acl),
				AccessControlPolicy: &types.AccessControlPolicy{
					Owner: &accessControlPolicy.Owner,
				},
			}
		}
		if grants != "" {
			input = &s3.PutBucketAclInput{
				Bucket:           &bucket,
				GrantFullControl: &grantFullControl,
				GrantRead:        &grantRead,
				GrantReadACP:     &grantReadACP,
				GrantWrite:       &granWrite,
				GrantWriteACP:    &grantWriteACP,
				AccessControlPolicy: &types.AccessControlPolicy{
					Owner: &accessControlPolicy.Owner,
				},
				ACL: "",
			}
		}

		updAcl, err := auth.UpdateACL(input, parsedAcl, c.iam)
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:PutBucketAcl",
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = c.be.PutBucketAcl(ctx.Context(), bucket, updAcl)
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:PutBucketAcl",
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ok := utils.IsValidBucketName(bucket); !ok {
		return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidBucketName),
			&MetaOpts{
				Logger:     c.logger,
				MetricsMng: c.mm,
				Action:     "s3:CreateBucket",
			})
	}

	if acl != "" && grants != "" {
		if c.debug {
			log.Printf("invalid request: %q (grants) %q (acl)", grants, acl)
		}
		return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest),
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:PutBucketAcl",
				BucketOwner: acct.Access,
			})
	}

	defACL := auth.ACL{
		Owner: acct.Access,
	}

	updAcl, err := auth.UpdateACL(&s3.PutBucketAclInput{
		GrantFullControl: &grantFullControl,
		GrantRead:        &grantRead,
		GrantReadACP:     &grantReadACP,
		GrantWrite:       &granWrite,
		GrantWriteACP:    &grantWriteACP,
		AccessControlPolicy: &types.AccessControlPolicy{Owner: &types.Owner{
			ID: &acct.Access,
		}},
		ACL: types.BucketCannedACL(acl),
	}, defACL, c.iam)
	if err != nil {
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:CreateBucket",
				BucketOwner: acct.Access,
			})
	}

	lockHeader := ctx.Get("X-Amz-Bucket-Object-Lock-Enabled")
	// CLI provides "True", SDK - "true"
	lockEnabled := lockHeader == "True" || lockHeader == "true"

	err = c.be.CreateBucket(ctx.Context(), &s3.CreateBucketInput{
		Bucket:                     &bucket,
		ObjectOwnership:            types.ObjectOwnership(acct.Access),
		ObjectLockEnabledForBucket: &lockEnabled,
	}, updAcl)
	return SendResponse(ctx, err,
		&MetaOpts{
			Logger:      c.logger,
			MetricsMng:  c.mm,
			Action:      "s3:CreateBucket",
			BucketOwner: acct.Access,
		})
}

func (c S3ApiController) PutActions(ctx *fiber.Ctx) error {
	bucket := ctx.Params("bucket")
	keyStart := ctx.Params("key")
	keyEnd := ctx.Params("*1")
	uploadId := ctx.Query("uploadId")
	versionId := ctx.Query("versionId")
	acct := ctx.Locals("account").(auth.Account)
	isRoot := ctx.Locals("isRoot").(bool)
	parsedAcl := ctx.Locals("parsedAcl").(auth.ACL)
	tagging := ctx.Get("x-amz-tagging")

	// Copy source headers
	copySource := ctx.Get("X-Amz-Copy-Source")
	copySrcIfMatch := ctx.Get("X-Amz-Copy-Source-If-Match")
	copySrcIfNoneMatch := ctx.Get("X-Amz-Copy-Source-If-None-Match")
	copySrcModifSince := ctx.Get("X-Amz-Copy-Source-If-Modified-Since")
	copySrcUnmodifSince := ctx.Get("X-Amz-Copy-Source-If-Unmodified-Since")
	copySrcRange := ctx.Get("X-Amz-Copy-Source-Range")

	// Permission headers
	acl := ctx.Get("X-Amz-Acl")
	grantFullControl := ctx.Get("X-Amz-Grant-Full-Control")
	grantRead := ctx.Get("X-Amz-Grant-Read")
	grantReadACP := ctx.Get("X-Amz-Grant-Read-Acp")
	granWrite := ctx.Get("X-Amz-Grant-Write")
	grantWriteACP := ctx.Get("X-Amz-Grant-Write-Acp")

	// Other headers
	contentLengthStr := ctx.Get("Content-Length")
	if contentLengthStr == "" {
		contentLengthStr = "0"
	}
	bucketOwner := ctx.Get("X-Amz-Expected-Bucket-Owner")

	grants := grantFullControl + grantRead + grantReadACP + granWrite + grantWriteACP

	if keyEnd != "" {
		keyStart = strings.Join([]string{keyStart, keyEnd}, "/")
	}
	path := ctx.Path()
	if path[len(path)-1:] == "/" && keyStart[len(keyStart)-1:] != "/" {
		keyStart = keyStart + "/"
	}

	if ctx.Request().URI().QueryArgs().Has("tagging") {
		var objTagging s3response.TaggingInput
		err := xml.Unmarshal(ctx.Body(), &objTagging)
		if err != nil {
			if c.debug {
				log.Printf("error unmarshalling object tagging: %v", err)
			}
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:PutObjectTagging",
					BucketOwner: parsedAcl.Owner,
				})
		}

		tags := make(map[string]string, len(objTagging.TagSet.Tags))

		for _, tag := range objTagging.TagSet.Tags {
			if len(tag.Key) > 128 || len(tag.Value) > 256 {
				if c.debug {
					log.Printf("invalid tag key/value len: %q %q",
						tag.Key, tag.Value)
				}
				return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidTag),
					&MetaOpts{
						Logger:      c.logger,
						MetricsMng:  c.mm,
						Action:      "s3:PutObjectTagging",
						BucketOwner: parsedAcl.Owner,
					})
			}
			tags[tag.Key] = tag.Value
		}

		err = auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: types.PermissionWrite,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Object:        keyStart,
			Action:        auth.PutBucketTaggingAction,
		})
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:PutObjectTagging",
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = c.be.PutObjectTagging(ctx.Context(), bucket, keyStart, tags)
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				EvSender:    c.evSender,
				Action:      "s3:PutObjectTagging",
				BucketOwner: parsedAcl.Owner,
				EventName:   s3event.EventObjectTaggingPut,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("retention") {
		if err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: types.PermissionWrite,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Object:        keyStart,
			Action:        auth.PutObjectRetentionAction,
		}); err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:PutObjectRetention",
					BucketOwner: parsedAcl.Owner,
				})
		}

		bypassHdr := ctx.Get("X-Amz-Bypass-Governance-Retention")
		bypass := bypassHdr == "true"
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
			return SendResponse(ctx, err, &MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:PutObjectRetention",
				BucketOwner: parsedAcl.Owner,
			})
		}

		err = c.be.PutObjectRetention(ctx.Context(), bucket, keyStart, versionId, bypass, retention)
		return SendResponse(ctx, err, &MetaOpts{
			Logger:      c.logger,
			MetricsMng:  c.mm,
			Action:      "s3:PutObjectRetention",
			BucketOwner: parsedAcl.Owner,
		})
	}

	if ctx.Request().URI().QueryArgs().Has("legal-hold") {
		var legalHold types.ObjectLockLegalHold
		if err := xml.Unmarshal(ctx.Body(), &legalHold); err != nil {
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:PutObjectLegalHold",
					BucketOwner: parsedAcl.Owner,
				})
		}

		if legalHold.Status != types.ObjectLockLegalHoldStatusOff && legalHold.Status != types.ObjectLockLegalHoldStatusOn {
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrMalformedXML),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:PutObjectLegalHold",
					BucketOwner: parsedAcl.Owner,
				})
		}

		if err := auth.VerifyAccess(ctx.Context(), c.be, auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: types.PermissionWrite,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Object:        keyStart,
			Action:        auth.PutObjectLegalHoldAction,
		}); err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:PutObjectLegalHold",
					BucketOwner: parsedAcl.Owner,
				})
		}

		err := c.be.PutObjectLegalHold(ctx.Context(), bucket, keyStart, versionId, legalHold.Status == types.ObjectLockLegalHoldStatusOn)
		return SendResponse(ctx, err, &MetaOpts{
			Logger:      c.logger,
			MetricsMng:  c.mm,
			Action:      "s3:PutObjectLegalHold",
			BucketOwner: parsedAcl.Owner,
		})
	}

	if ctx.Request().URI().QueryArgs().Has("uploadId") &&
		ctx.Request().URI().QueryArgs().Has("partNumber") &&
		copySource != "" {
		partNumber := int32(ctx.QueryInt("partNumber", -1))
		if partNumber < 1 || partNumber > 10000 {
			if c.debug {
				log.Printf("invalid part number: %d", partNumber)
			}
			return SendXMLResponse(ctx, nil,
				s3err.GetAPIError(s3err.ErrInvalidPartNumber),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:UploadPartCopy",
					BucketOwner: parsedAcl.Owner,
				})
		}

		err := auth.VerifyObjectCopyAccess(ctx.Context(), c.be, copySource,
			auth.AccessOptions{
				Acl:           parsedAcl,
				AclPermission: types.PermissionWrite,
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
					Action:      "s3:UploadPartCopy",
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
		return SendXMLResponse(ctx, resp, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:UploadPartCopy",
				BucketOwner: parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("uploadId") &&
		ctx.Request().URI().QueryArgs().Has("partNumber") {
		partNumber := int32(ctx.QueryInt("partNumber", -1))
		if partNumber < 1 || partNumber > 10000 {
			if c.debug {
				log.Printf("invalid part number: %d", partNumber)
			}
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidPart),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:UploadPart",
					BucketOwner: parsedAcl.Owner,
				})
		}

		err := auth.VerifyAccess(ctx.Context(), c.be,
			auth.AccessOptions{
				Readonly:      c.readonly,
				Acl:           parsedAcl,
				AclPermission: types.PermissionWrite,
				IsRoot:        isRoot,
				Acc:           acct,
				Bucket:        bucket,
				Object:        keyStart,
				Action:        auth.PutObjectAction,
			})
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:UploadPart",
					BucketOwner: parsedAcl.Owner,
				})
		}

		contentLength, err := strconv.ParseInt(contentLengthStr, 10, 64)
		if err != nil {
			if c.debug {
				log.Printf("error parsing content length %q: %v",
					contentLengthStr, err)
			}
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:UploadPart",
					BucketOwner: parsedAcl.Owner,
				})
		}

		var body io.Reader
		bodyi := ctx.Locals("body-reader")
		if bodyi != nil {
			body = bodyi.(io.Reader)
		} else {
			body = bytes.NewReader([]byte{})
		}

		ctx.Locals("logReqBody", false)
		etag, err := c.be.UploadPart(ctx.Context(),
			&s3.UploadPartInput{
				Bucket:        &bucket,
				Key:           &keyStart,
				UploadId:      &uploadId,
				PartNumber:    &partNumber,
				ContentLength: &contentLength,
				Body:          body,
			})
		ctx.Response().Header.Set("Etag", etag)
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:        c.logger,
				MetricsMng:    c.mm,
				ContentLength: contentLength,
				Action:        "s3:UploadPart",
				BucketOwner:   parsedAcl.Owner,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("acl") {
		var input *s3.PutObjectAclInput

		if len(ctx.Body()) > 0 {
			if grants+acl != "" {
				if c.debug {
					log.Printf("invalid request: %q (grants) %q (acl)",
						grants, acl)
				}
				return SendResponse(ctx,
					s3err.GetAPIError(s3err.ErrInvalidRequest),
					&MetaOpts{
						Logger:      c.logger,
						MetricsMng:  c.mm,
						Action:      "s3:PutObjectAcl",
						BucketOwner: parsedAcl.Owner,
					})
			}

			var accessControlPolicy auth.AccessControlPolicy
			err := xml.Unmarshal(ctx.Body(), &accessControlPolicy)
			if err != nil {
				if c.debug {
					log.Printf("error unmarshalling access control policy: %v",
						err)
				}
				return SendResponse(ctx,
					s3err.GetAPIError(s3err.ErrInvalidRequest),
					&MetaOpts{
						Logger:      c.logger,
						MetricsMng:  c.mm,
						Action:      "s3:PutObjectAcl",
						BucketOwner: parsedAcl.Owner,
					})
			}

			input = &s3.PutObjectAclInput{
				Bucket: &bucket,
				Key:    &keyStart,
				ACL:    "",
				AccessControlPolicy: &types.AccessControlPolicy{
					Owner:  &accessControlPolicy.Owner,
					Grants: accessControlPolicy.AccessControlList.Grants,
				},
			}
		}
		if acl != "" {
			if acl != "private" && acl != "public-read" && acl != "public-read-write" {
				if c.debug {
					log.Printf("invalid acl: %q", acl)
				}
				return SendResponse(ctx,
					s3err.GetAPIError(s3err.ErrInvalidRequest),
					&MetaOpts{
						Logger:      c.logger,
						MetricsMng:  c.mm,
						Action:      "s3:PutObjectAcl",
						BucketOwner: parsedAcl.Owner,
					})
			}
			if len(ctx.Body()) > 0 || grants != "" {
				if c.debug {
					log.Printf("invalid request: %q (grants) %q (acl) %v (body len)",
						grants, acl, len(ctx.Body()))
				}
				return SendResponse(ctx,
					s3err.GetAPIError(s3err.ErrInvalidRequest),
					&MetaOpts{
						Logger:      c.logger,
						MetricsMng:  c.mm,
						Action:      "s3:PutObjectAcl",
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
				Action:      "s3:PutObjectAcl",
				BucketOwner: parsedAcl.Owner,
				EventName:   s3event.EventObjectAclPut,
			})
	}

	if copySource != "" {
		err := auth.VerifyObjectCopyAccess(ctx.Context(), c.be, copySource,
			auth.AccessOptions{
				Acl:           parsedAcl,
				AclPermission: types.PermissionWrite,
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
					Action:      "s3:CopyObject",
					BucketOwner: parsedAcl.Owner,
				})
		}

		var mtime *time.Time
		var umtime *time.Time
		if copySrcModifSince != "" {
			tm, err := time.Parse(iso8601Format, copySrcModifSince)
			if err != nil {
				if c.debug {
					log.Printf("error parsing copy source modified since %q: %v",
						copySrcModifSince, err)
				}
				return SendXMLResponse(ctx, nil,
					s3err.GetAPIError(s3err.ErrInvalidCopySource),
					&MetaOpts{
						Logger:      c.logger,
						MetricsMng:  c.mm,
						Action:      "s3:CopyObject",
						BucketOwner: parsedAcl.Owner,
					})
			}
			mtime = &tm
		}
		if copySrcUnmodifSince != "" {
			tm, err := time.Parse(iso8601Format, copySrcUnmodifSince)
			if err != nil {
				if c.debug {
					log.Printf("error parsing copy source unmodified since %q: %v",
						copySrcUnmodifSince, err)
				}
				return SendXMLResponse(ctx, nil,
					s3err.GetAPIError(s3err.ErrInvalidCopySource),
					&MetaOpts{
						Logger:      c.logger,
						MetricsMng:  c.mm,
						Action:      "s3:CopyObject",
						BucketOwner: parsedAcl.Owner,
					})
			}
			umtime = &tm
		}

		metadata := utils.GetUserMetaData(&ctx.Request().Header)

		res, err := c.be.CopyObject(ctx.Context(),
			&s3.CopyObjectInput{
				Bucket:                      &bucket,
				Key:                         &keyStart,
				CopySource:                  &copySource,
				CopySourceIfMatch:           &copySrcIfMatch,
				CopySourceIfNoneMatch:       &copySrcIfNoneMatch,
				CopySourceIfModifiedSince:   mtime,
				CopySourceIfUnmodifiedSince: umtime,
				ExpectedBucketOwner:         &acct.Access,
				Metadata:                    metadata,
			})
		if err == nil {
			return SendXMLResponse(ctx, res.CopyObjectResult, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					EvSender:    c.evSender,
					Action:      "s3:CopyObject",
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
					Action:      "s3:CopyObject",
					BucketOwner: parsedAcl.Owner,
				})
		}
	}

	metadata := utils.GetUserMetaData(&ctx.Request().Header)

	err := auth.VerifyAccess(ctx.Context(), c.be,
		auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: types.PermissionWrite,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Object:        keyStart,
			Action:        auth.PutObjectAction,
		})
	if err != nil {
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:PutObject",
				BucketOwner: parsedAcl.Owner,
			})
	}

	err = auth.CheckObjectAccess(ctx.Context(), bucket, acct.Access, []string{keyStart}, true, c.be)
	if err != nil {
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:PutObject",
				BucketOwner: parsedAcl.Owner,
			})
	}

	contentLength, err := strconv.ParseInt(contentLengthStr, 10, 64)
	if err != nil {
		if c.debug {
			log.Printf("error parsing content length %q: %v",
				contentLengthStr, err)
		}
		return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest),
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:PutObject",
				BucketOwner: parsedAcl.Owner,
			})
	}

	objLock, err := utils.ParsObjectLockHdrs(ctx)
	if err != nil {
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:PutObject",
				BucketOwner: parsedAcl.Owner,
			})
	}

	var body io.Reader
	bodyi := ctx.Locals("body-reader")
	if bodyi != nil {
		body = bodyi.(io.Reader)
	} else {
		body = bytes.NewReader([]byte{})
	}

	ctx.Locals("logReqBody", false)
	etag, err := c.be.PutObject(ctx.Context(),
		&s3.PutObjectInput{
			Bucket:                    &bucket,
			Key:                       &keyStart,
			ContentLength:             &contentLength,
			Metadata:                  metadata,
			Body:                      body,
			Tagging:                   &tagging,
			ObjectLockRetainUntilDate: &objLock.RetainUntilDate,
			ObjectLockMode:            objLock.ObjectLockMode,
			ObjectLockLegalHoldStatus: objLock.LegalHoldStatus,
		})
	ctx.Response().Header.Set("ETag", etag)
	return SendResponse(ctx, err,
		&MetaOpts{
			Logger:        c.logger,
			MetricsMng:    c.mm,
			ContentLength: contentLength,
			EvSender:      c.evSender,
			Action:        "s3:PutObject",
			BucketOwner:   parsedAcl.Owner,
			ObjectETag:    &etag,
			ObjectSize:    contentLength,
			EventName:     s3event.EventObjectCreatedPut,
		})
}

func (c S3ApiController) DeleteBucket(ctx *fiber.Ctx) error {
	bucket := ctx.Params("bucket")
	acct := ctx.Locals("account").(auth.Account)
	isRoot := ctx.Locals("isRoot").(bool)
	parsedAcl := ctx.Locals("parsedAcl").(auth.ACL)

	if ctx.Request().URI().QueryArgs().Has("tagging") {
		err := auth.VerifyAccess(ctx.Context(), c.be,
			auth.AccessOptions{
				Readonly:      c.readonly,
				Acl:           parsedAcl,
				AclPermission: types.PermissionWrite,
				IsRoot:        isRoot,
				Acc:           acct,
				Bucket:        bucket,
				Action:        auth.PutBucketTaggingAction,
			})
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:DeleteBucketTagging",
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = c.be.DeleteBucketTagging(ctx.Context(), bucket)
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:DeleteBucketTagging",
				BucketOwner: parsedAcl.Owner,
				Status:      http.StatusNoContent,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("policy") {
		err := auth.VerifyAccess(ctx.Context(), c.be,
			auth.AccessOptions{
				Readonly:      c.readonly,
				Acl:           parsedAcl,
				AclPermission: types.PermissionWrite,
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
					Action:      "s3:DeleteBucketPolicy",
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = c.be.DeleteBucketPolicy(ctx.Context(), bucket)
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:DeleteBucketPolicy",
				BucketOwner: parsedAcl.Owner,
				Status:      http.StatusNoContent,
			})
	}

	err := auth.VerifyAccess(ctx.Context(), c.be,
		auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: types.PermissionWrite,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Action:        auth.DeleteBucketAction,
		})
	if err != nil {
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:DeleteBucket",
				BucketOwner: parsedAcl.Owner,
			})
	}

	err = c.be.DeleteBucket(ctx.Context(),
		&s3.DeleteBucketInput{
			Bucket: &bucket,
		})
	return SendResponse(ctx, err,
		&MetaOpts{
			Logger:      c.logger,
			MetricsMng:  c.mm,
			Action:      "s3:DeleteBucket",
			BucketOwner: parsedAcl.Owner,
			Status:      http.StatusNoContent,
		})
}

func (c S3ApiController) DeleteObjects(ctx *fiber.Ctx) error {
	bucket := ctx.Params("bucket")
	acct := ctx.Locals("account").(auth.Account)
	isRoot := ctx.Locals("isRoot").(bool)
	parsedAcl := ctx.Locals("parsedAcl").(auth.ACL)
	bypass := ctx.Get("X-Amz-Bypass-Governance-Retention")
	var dObj s3response.DeleteObjects

	err := xml.Unmarshal(ctx.Body(), &dObj)
	if err != nil {
		if c.debug {
			log.Printf("error unmarshalling delete objects: %v", err)
		}
		return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest),
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:DeleteObjects",
				BucketOwner: parsedAcl.Owner,
			})
	}

	err = auth.VerifyAccess(ctx.Context(), c.be,
		auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: types.PermissionWrite,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Action:        auth.DeleteObjectAction,
		})
	if err != nil {
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:DeleteObjects",
				BucketOwner: parsedAcl.Owner,
			})
	}

	err = auth.CheckObjectAccess(ctx.Context(), bucket, acct.Access, utils.ParseDeleteObjects(dObj.Objects), bypass == "true", c.be)
	if err != nil {
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:DeleteObjects",
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
			Action:      "s3:DeleteObjects",
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
	acct := ctx.Locals("account").(auth.Account)
	isRoot := ctx.Locals("isRoot").(bool)
	parsedAcl := ctx.Locals("parsedAcl").(auth.ACL)
	bypass := ctx.Get("X-Amz-Bypass-Governance-Retention")

	if keyEnd != "" {
		key = strings.Join([]string{key, keyEnd}, "/")
	}

	if ctx.Request().URI().QueryArgs().Has("tagging") {
		err := auth.VerifyAccess(ctx.Context(), c.be,
			auth.AccessOptions{
				Readonly:      c.readonly,
				Acl:           parsedAcl,
				AclPermission: types.PermissionWrite,
				IsRoot:        isRoot,
				Acc:           acct,
				Bucket:        bucket,
				Object:        key,
				Action:        auth.DeleteObjectTaggingAction,
			})
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:DeleteObjectTagging",
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
				Action:      "s3:DeleteObjectTagging",
				BucketOwner: parsedAcl.Owner,
				EventName:   s3event.EventObjectTaggingDelete,
			})
	}

	if uploadId != "" {
		expectedBucketOwner := ctx.Get("X-Amz-Expected-Bucket-Owner")
		requestPayer := ctx.Get("X-Amz-Request-Payer")

		err := auth.VerifyAccess(ctx.Context(), c.be,
			auth.AccessOptions{
				Readonly:      c.readonly,
				Acl:           parsedAcl,
				AclPermission: types.PermissionWrite,
				IsRoot:        isRoot,
				Acc:           acct,
				Bucket:        bucket,
				Object:        key,
				Action:        auth.AbortMultipartUploadAction,
			})
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:AbortMultipartUpload",
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
				Action:      "s3:AbortMultipartUpload",
				BucketOwner: parsedAcl.Owner,
				Status:      http.StatusNoContent,
			})
	}

	err := auth.VerifyAccess(ctx.Context(), c.be,
		auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: types.PermissionWrite,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Object:        key,
			Action:        auth.DeleteObjectAction,
		})
	if err != nil {
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:DeleteObject",
				BucketOwner: parsedAcl.Owner,
			})
	}

	err = auth.CheckObjectAccess(ctx.Context(), bucket, acct.Access, []string{key}, bypass == "true", c.be)
	if err != nil {
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:DeleteObject",
				BucketOwner: parsedAcl.Owner,
			})
	}

	err = c.be.DeleteObject(ctx.Context(),
		&s3.DeleteObjectInput{
			Bucket:    &bucket,
			Key:       &key,
			VersionId: &versionId,
		})
	return SendResponse(ctx, err,
		&MetaOpts{
			Logger:      c.logger,
			MetricsMng:  c.mm,
			EvSender:    c.evSender,
			Action:      "s3:DeleteObject",
			BucketOwner: parsedAcl.Owner,
			EventName:   s3event.EventObjectRemovedDelete,
			Status:      http.StatusNoContent,
		})
}

func (c S3ApiController) HeadBucket(ctx *fiber.Ctx) error {
	bucket := ctx.Params("bucket")
	acct := ctx.Locals("account").(auth.Account)
	isRoot := ctx.Locals("isRoot").(bool)
	region := ctx.Locals("region").(string)
	parsedAcl := ctx.Locals("parsedAcl").(auth.ACL)

	err := auth.VerifyAccess(ctx.Context(), c.be,
		auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: types.PermissionRead,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Action:        auth.ListBucketAction,
		})
	if err != nil {
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:HeadBucket",
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
			Action:      "s3:HeadBucket",
			BucketOwner: parsedAcl.Owner,
		})
}

const (
	timefmt = "Mon, 02 Jan 2006 15:04:05 GMT"
)

func (c S3ApiController) HeadObject(ctx *fiber.Ctx) error {
	bucket := ctx.Params("bucket")
	acct := ctx.Locals("account").(auth.Account)
	isRoot := ctx.Locals("isRoot").(bool)
	parsedAcl := ctx.Locals("parsedAcl").(auth.ACL)
	partNumberQuery := int32(ctx.QueryInt("partNumber", -1))
	key := ctx.Params("key")
	keyEnd := ctx.Params("*1")
	if keyEnd != "" {
		key = strings.Join([]string{key, keyEnd}, "/")
	}

	var partNumber *int32
	if ctx.Request().URI().QueryArgs().Has("partNumber") {
		if partNumberQuery < 1 || partNumberQuery > 10000 {
			if c.debug {
				log.Printf("invalid part number: %d", partNumberQuery)
			}
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidPartNumber),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:HeadObject",
					BucketOwner: parsedAcl.Owner,
				})
		}

		partNumber = &partNumberQuery
	}

	err := auth.VerifyAccess(ctx.Context(), c.be,
		auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: types.PermissionRead,
			IsRoot:        isRoot,
			Acc:           acct,
			Bucket:        bucket,
			Object:        key,
			Action:        auth.GetObjectAction,
		})
	if err != nil {
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:HeadObject",
				BucketOwner: parsedAcl.Owner,
			})
	}

	res, err := c.be.HeadObject(ctx.Context(),
		&s3.HeadObjectInput{
			Bucket:     &bucket,
			Key:        &key,
			PartNumber: partNumber,
		})
	if err != nil {
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:HeadObject",
				BucketOwner: parsedAcl.Owner,
			})
	}
	if res == nil {
		return SendResponse(ctx, fmt.Errorf("head object nil response"),
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:HeadObject",
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
			Key:   "x-amz-storage-class",
			Value: string(res.StorageClass),
		},
		{
			Key:   "x-amz-restore",
			Value: getstring(res.Restore),
		},
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
		lastmod := res.LastModified.Format(timefmt)
		headers = append(headers, utils.CustomHeader{
			Key:   "Last-Modified",
			Value: lastmod,
		})
	}
	if res.ContentEncoding != nil {
		headers = append(headers, utils.CustomHeader{
			Key:   "Content-Encoding",
			Value: getstring(res.ContentEncoding),
		})
	}
	if res.ContentType != nil {
		headers = append(headers, utils.CustomHeader{
			Key:   "Content-Type",
			Value: getstring(res.ContentType),
		})
	}
	utils.SetResponseHeaders(ctx, headers)

	return SendResponse(ctx, nil,
		&MetaOpts{
			Logger:      c.logger,
			MetricsMng:  c.mm,
			Action:      "s3:HeadObject",
			BucketOwner: parsedAcl.Owner,
		})
}

func (c S3ApiController) CreateActions(ctx *fiber.Ctx) error {
	bucket := ctx.Params("bucket")
	key := ctx.Params("key")
	keyEnd := ctx.Params("*1")
	uploadId := ctx.Query("uploadId")
	acct := ctx.Locals("account").(auth.Account)
	isRoot := ctx.Locals("isRoot").(bool)
	parsedAcl := ctx.Locals("parsedAcl").(auth.ACL)
	contentType := ctx.Get("Content-Type")
	tagging := ctx.Get("X-Amz-Tagging")

	if keyEnd != "" {
		key = strings.Join([]string{key, keyEnd}, "/")
	}

	path := ctx.Path()
	if path[len(path)-1:] == "/" && key[len(key)-1:] != "/" {
		key = key + "/"
	}

	var restoreRequest s3.RestoreObjectInput
	if ctx.Request().URI().QueryArgs().Has("restore") {
		err := xml.Unmarshal(ctx.Body(), &restoreRequest)
		if err != nil {
			if c.debug {
				log.Printf("error unmarshalling restore object: %v", err)
			}
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:RestoreObject",
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = auth.VerifyAccess(ctx.Context(), c.be,
			auth.AccessOptions{
				Readonly:      c.readonly,
				Acl:           parsedAcl,
				AclPermission: types.PermissionWrite,
				IsRoot:        isRoot,
				Acc:           acct,
				Bucket:        bucket,
				Object:        key,
				Action:        auth.RestoreObjectAction,
			})
		if err != nil {
			return SendResponse(ctx, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:RestoreObject",
					BucketOwner: parsedAcl.Owner,
				})
		}

		restoreRequest.Bucket = &bucket
		restoreRequest.Key = &key

		err = c.be.RestoreObject(ctx.Context(), &restoreRequest)
		return SendResponse(ctx, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				EvSender:    c.evSender,
				Action:      "s3:RestoreObject",
				BucketOwner: parsedAcl.Owner,
				EventName:   s3event.EventObjectRestoreCompleted,
			})
	}

	if ctx.Request().URI().QueryArgs().Has("select") && ctx.Query("select-type") == "2" {
		var payload s3response.SelectObjectContentPayload

		err := xml.Unmarshal(ctx.Body(), &payload)
		if err != nil {
			if c.debug {
				log.Printf("error unmarshalling select object content: %v", err)
			}
			return SendXMLResponse(ctx, nil,
				s3err.GetAPIError(s3err.ErrMalformedXML),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:SelectObjectContent",
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = auth.VerifyAccess(ctx.Context(), c.be,
			auth.AccessOptions{
				Readonly:      c.readonly,
				Acl:           parsedAcl,
				AclPermission: types.PermissionRead,
				IsRoot:        isRoot,
				Acc:           acct,
				Bucket:        bucket,
				Object:        key,
				Action:        auth.GetObjectAction,
			})
		if err != nil {
			return SendXMLResponse(ctx, nil, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:SelectObjectContent",
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
				log.Printf("error unmarshalling complete multipart upload: %v", err)
			}
			return SendXMLResponse(ctx, nil,
				s3err.GetAPIError(s3err.ErrMalformedXML),
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					Action:      "s3:CompleteMultipartUpload",
					BucketOwner: parsedAcl.Owner,
				})
		}

		err = auth.VerifyAccess(ctx.Context(), c.be,
			auth.AccessOptions{
				Readonly:      c.readonly,
				Acl:           parsedAcl,
				AclPermission: types.PermissionWrite,
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
					Action:      "s3:CompleteMultipartUpload",
					BucketOwner: parsedAcl.Owner,
				})
		}

		res, err := c.be.CompleteMultipartUpload(ctx.Context(),
			&s3.CompleteMultipartUploadInput{
				Bucket:   &bucket,
				Key:      &key,
				UploadId: &uploadId,
				MultipartUpload: &types.CompletedMultipartUpload{
					Parts: data.Parts,
				},
			})
		if err == nil {
			return SendXMLResponse(ctx, res, err,
				&MetaOpts{
					Logger:      c.logger,
					MetricsMng:  c.mm,
					EvSender:    c.evSender,
					Action:      "s3:CompleteMultipartUpload",
					BucketOwner: parsedAcl.Owner,
					ObjectETag:  res.ETag,
					EventName:   s3event.EventCompleteMultipartUpload,
					VersionId:   res.VersionId,
				})
		}
		return SendXMLResponse(ctx, res, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "s3:CompleteMultipartUpload",
				BucketOwner: parsedAcl.Owner,
			})
	}

	err := auth.VerifyAccess(ctx.Context(), c.be,
		auth.AccessOptions{
			Readonly:      c.readonly,
			Acl:           parsedAcl,
			AclPermission: types.PermissionWrite,
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
				Action:      "s3:CreateMultipartUpload",
				BucketOwner: parsedAcl.Owner,
			})
	}

	objLockState, err := utils.ParsObjectLockHdrs(ctx)
	if err != nil {
		return SendXMLResponse(ctx, nil, err,
			&MetaOpts{
				Logger:      c.logger,
				MetricsMng:  c.mm,
				Action:      "CreateMultipartUpload",
				BucketOwner: parsedAcl.Owner,
			})
	}

	metadata := utils.GetUserMetaData(&ctx.Request().Header)

	res, err := c.be.CreateMultipartUpload(ctx.Context(),
		&s3.CreateMultipartUploadInput{
			Bucket:                    &bucket,
			Key:                       &key,
			Tagging:                   &tagging,
			ContentType:               &contentType,
			ObjectLockRetainUntilDate: &objLockState.RetainUntilDate,
			ObjectLockMode:            objLockState.ObjectLockMode,
			ObjectLockLegalHoldStatus: objLockState.LegalHoldStatus,
			Metadata:                  metadata,
		})
	return SendXMLResponse(ctx, res, err,
		&MetaOpts{
			Logger:      c.logger,
			MetricsMng:  c.mm,
			Action:      "s3:CreateMultipartUpload",
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
		l.MetricsMng.Send(err, l.Action, l.ContentLength, l.ObjectCount)
	}
	if err != nil {
		var apierr s3err.APIError
		if errors.As(err, &apierr) {
			ctx.Status(apierr.HTTPStatusCode)
			return ctx.Send(s3err.GetAPIErrorResponse(apierr, "", "", ""))
		}

		log.Printf("Internal Error, %v", err)
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

	utils.LogCtxDetails(ctx, []byte{})

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
		l.MetricsMng.Send(err, l.Action, l.ContentLength, l.ObjectCount)
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

		log.Printf("Internal Error, %v", err)
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

	utils.LogCtxDetails(ctx, b)
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
		log.Printf("XML encoded body len %v exceeds max len %v",
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
