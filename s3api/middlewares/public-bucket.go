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
	"io"
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

		bucket, object := parsePath(ctx.Path())

		action, permission, err := detectS3Action(ctx, object == "")
		if err != nil {
			return sendResponse(ctx, err, l, mm)
		}

		err = auth.VerifyPublicAccess(ctx.Context(), be, action, permission, bucket, object)
		if err != nil {
			return sendResponse(ctx, err, l, mm)
		}

		if utils.IsBigDataAction(ctx) {
			payloadType := ctx.Get("X-Amz-Content-Sha256")
			if utils.IsUnsignedStreamingPayload(payloadType) {
				checksumType, err := utils.ExtractChecksumType(ctx)
				if err != nil {
					return sendResponse(ctx, err, l, mm)
				}

				wrapBodyReader(ctx, func(r io.Reader) io.Reader {
					var cr io.Reader
					cr, err = utils.NewUnsignedChunkReader(r, checksumType)
					return cr
				})
				if err != nil {
					return sendResponse(ctx, err, l, mm)
				}
			}
		}

		utils.ContextKeyPublicBucket.Set(ctx, true)

		return ctx.Next()
	}
}

func detectS3Action(ctx *fiber.Ctx, isBucketAction bool) (auth.Action, auth.Permission, error) {
	path := ctx.Path()
	// ListBuckets is not publically available
	if path == "/" {
		//TODO: Still not clear what kind of error should be returned in this case(ListBuckets)
		return "", auth.PermissionRead, s3err.GetAPIError(s3err.ErrAccessDenied)
	}

	queryArgs := ctx.Context().QueryArgs()

	switch ctx.Method() {
	case fiber.MethodPatch:
		// Admin apis should always be protected
		return "", "", s3err.GetAPIError(s3err.ErrAccessDenied)
	case fiber.MethodHead:
		// HeadBucket
		if isBucketAction {
			return auth.ListBucketAction, auth.PermissionRead, nil
		}

		// HeadObject
		return auth.GetObjectAction, auth.PermissionRead, nil
	case fiber.MethodGet:
		if isBucketAction {
			if queryArgs.Has("tagging") {
				// GetBucketTagging
				return auth.GetBucketTaggingAction, auth.PermissionRead, nil
			} else if queryArgs.Has("ownershipControls") {
				// GetBucketOwnershipControls
				return auth.GetBucketOwnershipControlsAction, auth.PermissionRead, s3err.GetAPIError(s3err.ErrAnonymousGetBucketOwnership)
			} else if queryArgs.Has("versioning") {
				// GetBucketVersioning
				return auth.GetBucketVersioningAction, auth.PermissionRead, nil
			} else if queryArgs.Has("policy") {
				// GetBucketPolicy
				return auth.GetBucketPolicyAction, auth.PermissionRead, nil
			} else if queryArgs.Has("cors") {
				// GetBucketCors
				return auth.GetBucketCorsAction, auth.PermissionRead, nil
			} else if queryArgs.Has("versions") {
				// ListObjectVersions
				return auth.ListBucketVersionsAction, auth.PermissionRead, nil
			} else if queryArgs.Has("object-lock") {
				// GetObjectLockConfiguration
				return auth.GetBucketObjectLockConfigurationAction, auth.PermissionReadAcp, nil
			} else if queryArgs.Has("acl") {
				// GetBucketAcl
				return auth.GetBucketAclAction, auth.PermissionRead, nil
			} else if queryArgs.Has("uploads") {
				// ListMultipartUploads
				return auth.ListBucketMultipartUploadsAction, auth.PermissionRead, nil
			} else if queryArgs.GetUintOrZero("list-type") == 2 {
				// ListObjectsV2
				return auth.ListBucketAction, auth.PermissionRead, nil
			}
			// All the other requests are considerd as ListObjects in the router
			// no matter what kind of query arguments are provided apart from the ones above

			return auth.ListBucketAction, auth.PermissionRead, nil
		}

		if queryArgs.Has("tagging") {
			// GetObjectTagging
			return auth.GetObjectTaggingAction, auth.PermissionRead, nil
		} else if queryArgs.Has("retention") {
			// GetObjectRetention
			return auth.GetObjectRetentionAction, auth.PermissionRead, nil
		} else if queryArgs.Has("legal-hold") {
			// GetObjectLegalHold
			return auth.GetObjectLegalHoldAction, auth.PermissionReadAcp, nil
		} else if queryArgs.Has("acl") {
			// GetObjectAcl
			return auth.GetObjectAclAction, auth.PermissionRead, nil
		} else if queryArgs.Has("attributes") {
			// GetObjectAttributes
			return auth.GetObjectAttributesAction, auth.PermissionRead, nil
		} else if queryArgs.Has("uploadId") {
			// ListParts
			return auth.ListMultipartUploadPartsAction, auth.PermissionRead, nil
		}

		// All the other requests are considerd as GetObject in the router
		// no matter what kind of query arguments are provided apart from the ones above
		if queryArgs.Has("versionId") {
			return auth.GetObjectVersionAction, auth.PermissionRead, nil
		}
		return auth.GetObjectAction, auth.PermissionRead, nil
	case fiber.MethodPut:
		if isBucketAction {
			if queryArgs.Has("tagging") {
				// PutBucketTagging
				return auth.PutBucketTaggingAction, auth.PermissionWrite, nil
			}
			if queryArgs.Has("ownershipControls") {
				// PutBucketOwnershipControls
				return auth.PutBucketOwnershipControlsAction, auth.PermissionWrite, s3err.GetAPIError(s3err.ErrAnonymousPutBucketOwnership)
			}
			if queryArgs.Has("versioning") {
				// PutBucketVersioning
				return auth.PutBucketVersioningAction, auth.PermissionWrite, nil
			}
			if queryArgs.Has("object-lock") {
				// PutObjectLockConfiguration
				return auth.PutBucketObjectLockConfigurationAction, auth.PermissionWrite, nil
			}
			if queryArgs.Has("cors") {
				// PutBucketCors
				return auth.PutBucketCorsAction, auth.PermissionWrite, nil
			}
			if queryArgs.Has("policy") {
				// PutBucketPolicy
				return auth.PutBucketPolicyAction, auth.PermissionWrite, nil
			}
			if queryArgs.Has("acl") {
				// PutBucketAcl
				return auth.PutBucketAclAction, auth.PermissionWrite, s3err.GetAPIError(s3err.ErrAnonymousRequest)
			}

			// All the other rquestes are considered as 'CreateBucket' in the router
			return "", "", s3err.GetAPIError(s3err.ErrAnonymousRequest)
		}

		if queryArgs.Has("tagging") {
			// PutObjectTagging
			return auth.PutObjectTaggingAction, auth.PermissionWrite, nil
		}
		if queryArgs.Has("retention") {
			// PutObjectRetention
			return auth.PutObjectRetentionAction, auth.PermissionWrite, nil
		}
		if queryArgs.Has("legal-hold") {
			// PutObjectLegalHold
			return auth.PutObjectLegalHoldAction, auth.PermissionWrite, nil
		}
		if queryArgs.Has("acl") {
			// PutObjectAcl
			return auth.PutObjectAclAction, auth.PermissionWriteAcp, s3err.GetAPIError(s3err.ErrAnonymousRequest)
		}
		if queryArgs.Has("uploadId") && queryArgs.Has("partNumber") {
			if ctx.Get("X-Amz-Copy-Source") != "" {
				// UploadPartCopy
				//TODO: Add public access check for copy-source
				// Return AccessDenied for now
				return auth.PutObjectAction, auth.PermissionWrite, s3err.GetAPIError(s3err.ErrAccessDenied)
			}

			utils.ContextKeyBodyReader.Set(ctx, ctx.Request().BodyStream())
			// UploadPart
			return auth.PutObjectAction, auth.PermissionWrite, nil
		}
		if ctx.Get("X-Amz-Copy-Source") != "" {
			return auth.PutObjectAction, auth.PermissionWrite, s3err.GetAPIError(s3err.ErrAnonymousCopyObject)
		}

		utils.ContextKeyBodyReader.Set(ctx, ctx.Request().BodyStream())
		// All the other requests are considered as 'PutObject' in the router
		return auth.PutObjectAction, auth.PermissionWrite, nil
	case fiber.MethodPost:
		if isBucketAction {
			// DeleteObjects
			// FIXME: should be fixed with https://github.com/versity/versitygw/issues/1327
			// Return AccessDenied for now
			return auth.DeleteObjectAction, auth.PermissionWrite, s3err.GetAPIError(s3err.ErrAccessDenied)
		}

		if queryArgs.Has("restore") {
			return auth.RestoreObjectAction, auth.PermissionWrite, nil
		}
		if queryArgs.Has("select") && ctx.Query("select-type") == "2" {
			// SelectObjectContent
			return auth.GetObjectAction, auth.PermissionRead, s3err.GetAPIError(s3err.ErrAnonymousRequest)
		}
		if queryArgs.Has("uploadId") {
			// CompleteMultipartUpload
			return auth.PutObjectAction, auth.PermissionWrite, nil
		}

		// All the other requests are considered as 'CreateMultipartUpload' in the router
		return "", "", s3err.GetAPIError(s3err.ErrAnonymousCreateMp)
	case fiber.MethodDelete:
		if isBucketAction {
			if queryArgs.Has("tagging") {
				// DeleteBucketTagging
				return auth.PutBucketTaggingAction, auth.PermissionWrite, nil
			}
			if queryArgs.Has("ownershipControls") {
				// DeleteBucketOwnershipControls
				return auth.PutBucketOwnershipControlsAction, auth.PermissionWrite, s3err.GetAPIError(s3err.ErrAnonymousPutBucketOwnership)
			}
			if queryArgs.Has("policy") {
				// DeleteBucketPolicy
				return auth.PutBucketPolicyAction, auth.PermissionWrite, nil
			}
			if queryArgs.Has("cors") {
				// DeleteBucketCors
				return auth.PutBucketCorsAction, auth.PermissionWrite, nil
			}

			// All the other requests are considered as 'DeleteBucket' in the router
			return auth.DeleteBucketAction, auth.PermissionWrite, nil
		}

		if queryArgs.Has("tagging") {
			// DeleteObjectTagging
			return auth.PutObjectTaggingAction, auth.PermissionWrite, nil
		}
		if queryArgs.Has("uploadId") {
			// AbortMultipartUpload
			return auth.AbortMultipartUploadAction, auth.PermissionWrite, nil
		}
		// All the other requests are considered as 'DeleteObject' in the router
		return auth.DeleteObjectAction, auth.PermissionWrite, nil
	default:
		// In no action is detected, return AccessDenied ?
		return "", "", s3err.GetAPIError(s3err.ErrAccessDenied)
	}
}

// parsePath extracts the bucket and object names from the path
func parsePath(path string) (string, string) {
	p := strings.TrimPrefix(path, "/")
	bucket, object, _ := strings.Cut(p, "/")

	return bucket, object
}
