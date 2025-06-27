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
	"errors"
	"fmt"
	"io"
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
	timefmt                   = "Mon, 02 Jan 2006 15:04:05 GMT"
	maxXMLBodyLen             = 4 * 1024 * 1024
)

var (
	xmlhdr = []byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
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

// Returns MethodNotAllowed for unmatched routes
func (c S3ApiController) HandleUnmatch(ctx *fiber.Ctx) (*Response, error) {
	return &Response{}, s3err.GetAPIError(s3err.ErrMethodNotAllowed)
}

func getint64(i *int64) int64 {
	if i == nil {
		return 0
	}
	return *i
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
			body = ctx.Request().BodyStream()
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
		body = ctx.Request().BodyStream()
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

func (c S3ApiController) HeadBuckets(ctx *fiber.Ctx) error {
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

type MetaOpts struct {
	Logger        s3log.AuditLogger
	EvSender      s3event.S3EventSender
	MetricsMng    *metrics.Manager
	ContentLength int64
	BucketOwner   string
	ObjectSize    int64
	ObjectCount   int64
	EventName     s3event.EventType
	ObjectETag    *string
	VersionId     *string
	Status        int
}

// Response is the type definition for a controller response
// Data - Response body
// Headers - Resposne headers
// MetaOpts - Meta options for metrics, audit logs and s3 events
type Response struct {
	Data     any
	Headers  map[string]*string
	MetaOpts *MetaOptions
}

// Services groups the metrics manager, s3 event sender and audit logger
type Services struct {
	Logger         s3log.AuditLogger
	EventSender    s3event.S3EventSender
	MetricsManager *metrics.Manager
}

// Controller is the type definition for an s3api controller
type Controller func(ctx *fiber.Ctx) (*Response, error)

// ProcessHandlers groups a controller and multiple middlewares into a single fiber handler
func ProcessHandlers(controller Controller, s3action string, svc *Services, handlers ...fiber.Handler) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		// if skip locals is set, skip to the next rout handler
		if utils.ContextKeySkip.IsSet(ctx) {
			utils.ContextKeySkip.Delete(ctx)
			return ctx.Next()
		}

		for _, handler := range handlers {
			err := handler(ctx)
			if err != nil {
				return ProcessController(ctx, func(ctx *fiber.Ctx) (*Response, error) {
					return &Response{
						MetaOpts: &MetaOptions{},
					}, err
				}, s3action, svc)
			}
		}

		return ProcessController(ctx, controller, s3action, svc)
	}
}

// WrapMiddleware executes the given middleware and handles sending the audit logs
// and metrics. It also handles the error parsing
func WrapMiddleware(handler fiber.Handler, logger s3log.AuditLogger, mm *metrics.Manager) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		err := handler(ctx)
		if mm != nil {
			mm.Send(ctx, err, metrics.ActionUndetected, 0, 0)
		}
		if logger != nil {
			logger.Log(ctx, err, ctx.Body(), s3log.LogMeta{
				Action: metrics.ActionUndetected,
			})
		}

		if err != nil {
			serr, ok := err.(s3err.APIError)
			if ok {
				ctx.Status(serr.HTTPStatusCode)
				return ctx.Send(s3err.GetAPIErrorResponse(serr, "", "", ""))
			}

			debuglogger.Logf("Internal Error, %v", err)
			ctx.Status(http.StatusInternalServerError)

			// If the error is not 's3err.APIError' return 'InternalError'
			return ctx.Send(s3err.GetAPIErrorResponse(
				s3err.GetAPIError(s3err.ErrInternalError), "", "", ""))
		}

		return ctx.Next()
	}
}

// ProcessController executes the given s3api controller and handles the metrics
// access logs and s3 events
func ProcessController(ctx *fiber.Ctx, controller Controller, s3action string, svc *Services) error {
	response, err := controller(ctx)

	// Set the response headers
	SetResponseHeaders(ctx, response.Headers)

	opts := response.MetaOpts
	// Send the metrics
	if svc.MetricsManager != nil {
		if opts.ObjectCount > 0 {
			svc.MetricsManager.Send(ctx, err, s3action, opts.ObjectCount, opts.Status)
		} else {
			svc.MetricsManager.Send(ctx, err, s3action, opts.ContentLength, opts.Status)
		}
	}
	// Handle the error case
	if err != nil {
		// Audit the error log
		if svc.Logger != nil {
			svc.Logger.Log(ctx, err, nil, s3log.LogMeta{
				Action:      s3action,
				BucketOwner: opts.BucketOwner,
				ObjectSize:  opts.ObjectSize,
			})
		}
		serr, ok := err.(s3err.APIError)
		if ok {
			ctx.Status(serr.HTTPStatusCode)
			return ctx.Send(s3err.GetAPIErrorResponse(serr, "", "", ""))
		}

		fmt.Fprintf(os.Stderr, "Internal Error, %v\n", err)
		ctx.Status(http.StatusInternalServerError)

		// If the error is not 's3err.APIError' return 'InternalError'
		return ctx.Send(s3err.GetAPIErrorResponse(
			s3err.GetAPIError(s3err.ErrInternalError), "", "", ""))
	}

	if opts.Status == 0 {
		opts.Status = http.StatusOK
	}

	// if no data payload is provided, send the response status
	if response.Data == nil {
		ctx.Status(opts.Status)
		return nil
	}

	var responseBytes []byte

	// Handle already encoded responses(text, json...)
	encodedResp, ok := response.Data.([]byte)
	if ok {
		responseBytes = encodedResp
	} else {
		if responseBytes, err = xml.Marshal(response.Data); err != nil {
			return err
		}

		if len(responseBytes) > 0 {
			ctx.Response().Header.Set("Content-Length", fmt.Sprint(len(responseBytes)))
			ctx.Response().Header.SetContentType(fiber.MIMEApplicationXML)
		}
	}

	if svc.Logger != nil {
		svc.Logger.Log(ctx, nil, responseBytes, s3log.LogMeta{
			Action:      s3action,
			BucketOwner: opts.BucketOwner,
			ObjectSize:  opts.ObjectSize,
		})
	}

	if svc.EventSender != nil {
		svc.EventSender.SendEvent(ctx, s3event.EventMeta{
			BucketOwner: opts.BucketOwner,
			ObjectSize:  opts.ObjectSize,
			ObjectETag:  opts.ObjectETag,
			VersionId:   opts.VersionId,
			EventName:   opts.EventName,
		})
	}

	if ok {
		if len(responseBytes) > 0 {
			ctx.Response().Header.Set("Content-Length", fmt.Sprint(len(responseBytes)))
		}

		return ctx.Send(responseBytes)
	}

	msglen := len(xmlhdr) + len(responseBytes)
	if msglen > maxXMLBodyLen {
		debuglogger.Logf("XML encoded body len %v exceeds max len %v",
			msglen, maxXMLBodyLen)
		ctx.Status(http.StatusInternalServerError)

		return ctx.Send(s3err.GetAPIErrorResponse(
			s3err.GetAPIError(s3err.ErrInternalError), "", "", ""))
	}
	res := make([]byte, 0, msglen)
	res = append(res, xmlhdr...)
	res = append(res, responseBytes...)

	return ctx.Send(res)
}

// Sets the response headers
func SetResponseHeaders(ctx *fiber.Ctx, headers map[string]*string) {
	if headers == nil {
		return
	}
	for key, val := range headers {
		if val == nil || *val == "" {
			continue
		}
		ctx.Response().Header.Add(key, *val)
	}
}
