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

package middlewares

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3log"
)

func AuthorizePublicBucketAccess(be backend.Backend, l s3log.AuditLogger, mm *metrics.Manager) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		// skip for auhtneicated requests
		if ctx.Query("X-Amz-Algorithm") != "" || ctx.Get("Authorization") != "" {
			return ctx.Next()
		}

		if ctx.Method() != fiber.MethodGet && ctx.Method() != fiber.MethodHead {
			//FIXME: fix the error type
			return sendResponse(ctx, s3err.GetAPIError(s3err.ErrAccessDenied), l, mm)
		}

		bucket, object := parsePath(ctx.Path())

		action, err := detectS3Action(ctx, object == "")
		if err != nil {
			return sendResponse(ctx, s3err.GetAPIError(s3err.ErrAccessDenied), l, mm)
		}

		policy, err := be.GetBucketPolicy(ctx.Context(), bucket)
		if err != nil {
			if !errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchBucketPolicy)) {
				return sendResponse(ctx, err, l, mm)
			}
		} else {
			err := auth.VerifyPublicBucketPolicy(policy, bucket, object, action)
			if err == nil {
				utils.ContextKeyPublicBucket.Set(ctx, true)
				return ctx.Next()
			}
			return sendResponse(ctx, s3err.GetAPIError(s3err.ErrAccessDenied), l, mm)
		}

		err = auth.VerifyPublicBucketACL(ctx.Context(), be, bucket, action)
		if err != nil {
			return sendResponse(ctx, s3err.GetAPIError(s3err.ErrAccessDenied), l, mm)
		}

		utils.ContextKeyPublicBucket.Set(ctx, true)

		return ctx.Next()
	}
}

func detectS3Action(ctx *fiber.Ctx, isBucketAction bool) (auth.Action, error) {
	path := ctx.Path()
	// ListBuckets is not publically available
	if path == "/" {
		return "", s3err.GetAPIError(s3err.ErrAccessDenied)
	}

	if ctx.Method() == fiber.MethodHead {
		// HeadBucket
		if isBucketAction {
			return auth.ListBucketAction, nil
		}

		// HeadObject
		return auth.GetObjectAction, nil
	}

	queryArgs := ctx.Context().QueryArgs()

	if isBucketAction {
		if queryArgs.Has("tagging") {
			// GetBucketTagging
			return auth.GetBucketTaggingAction, nil
		} else if queryArgs.Has("ownershipControls") {
			//FIXME: fix the error type
			// GetBucketOwnershipControls
			return auth.GetBucketOwnershipControlsAction, s3err.GetAPIError(s3err.ErrAccessDenied)
		} else if queryArgs.Has("versioning") {
			// GetBucketVersioning
			return auth.GetBucketVersioningAction, nil
		} else if queryArgs.Has("policy") {
			// GetBucketPolicy
			return auth.GetBucketPolicyAction, s3err.GetAPIError(s3err.ErrAccessDenied)
		} else if queryArgs.Has("cors") {
			// GetBucketCors
			return auth.GetBucketCorsAction, nil
		} else if queryArgs.Has("versions") {
			// ListObjectVersions
			return auth.GetObjectVersionAction, nil
		} else if queryArgs.Has("object-lock") {
			// GetObjectLockConfiguration
			return auth.GetBucketObjectLockConfigurationAction, nil
		} else if queryArgs.Has("acl") {
			// GetBucketAcl
			return auth.GetBucketAclAction, nil
		} else if queryArgs.Has("uploads") {
			// ListMultipartUploads
			return auth.ListBucketMultipartUploadsAction, nil
		} else if queryArgs.GetUintOrZero("list-type") == 2 {
			// ListObjectsV2
			return auth.ListBucketAction, nil
		}
		// All the other requests are considerd as ListObjects in the router
		// no matter what kind of query arguments are provided apart from the ones above

		return auth.ListBucketAction, nil
	}

	if queryArgs.Has("tagging") {
		// GetObjectTagging
		return auth.GetObjectTaggingAction, nil
	} else if queryArgs.Has("retention") {
		// GetObjectRetention
		return auth.GetObjectRetentionAction, nil
	} else if queryArgs.Has("legal-hold") {
		// GetObjectLegalHold
		return auth.GetObjectLegalHoldAction, nil
	} else if queryArgs.Has("acl") {
		// GetObjectAcl
		return auth.GetObjectAclAction, nil
	} else if queryArgs.Has("attributes") {
		// GetObjectAttributes
		return auth.GetObjectAttributesAction, nil
	} else if queryArgs.Has("uploadId") {
		// ListParts
		return auth.ListMultipartUploadPartsAction, nil
	}

	// All the other requests are considerd as GetObject in the router
	// no matter what kind of query arguments are provided apart from the ones above
	if queryArgs.Has("versionId") {
		return auth.GetObjectVersionAction, nil
	}
	return auth.GetObjectAction, nil
}

// parsePath extracts the bucket and object names from the path
func parsePath(path string) (string, string) {
	p := strings.TrimPrefix(path, "/")
	bucket, object, _ := strings.Cut(p, "/")

	return bucket, object
}
