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
)

// AuthorizePublicBucketAccess checks if the bucket grants public
// access to anonymous requesters
func AuthorizePublicBucketAccess(be backend.Backend, s3action string, policyPermission auth.Action, permission auth.Permission) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		// skip for auhtneicated requests
		if ctx.Query("X-Amz-Algorithm") != "" || ctx.Get("Authorization") != "" {
			return nil
		}

		switch s3action {
		case metrics.ActionListAllMyBuckets:
			return s3err.GetAPIError(s3err.ErrAccessDenied)
		case metrics.ActionGetBucketOwnershipControls:
			return s3err.GetAPIError(s3err.ErrAnonymousGetBucketOwnership)
		case metrics.ActionPutBucketOwnershipControls, metrics.ActionDeleteBucketOwnershipControls:
			return s3err.GetAPIError(s3err.ErrAnonymousPutBucketOwnership)
		case metrics.ActionPutBucketAcl, metrics.ActionPutObjectAcl, metrics.ActionSelectObjectContent, metrics.ActionCreateBucket:
			return s3err.GetAPIError(s3err.ErrAnonymousRequest)
		case metrics.ActionCopyObject:
			return s3err.GetAPIError(s3err.ErrAnonymousCopyObject)
		case metrics.ActionCreateMultipartUpload:
			return s3err.GetAPIError(s3err.ErrAnonymousCreateMp)
		case metrics.ActionUploadPartCopy, metrics.ActionDeleteObjects:
			// TODO: should be fixed with https://github.com/versity/versitygw/issues/1327
			// TODO: should be fixed with https://github.com/versity/versitygw/issues/1338
			return s3err.GetAPIError(s3err.ErrAccessDenied)
		}

		bucket, object := parsePath(ctx.Path())
		err := auth.VerifyPublicAccess(ctx.Context(), be, policyPermission, permission, bucket, object)
		if err != nil {
			return err
		}

		if utils.IsBigDataAction(ctx) {
			payloadType := ctx.Get("X-Amz-Content-Sha256")
			if utils.IsUnsignedStreamingPayload(payloadType) {
				checksumType, err := utils.ExtractChecksumType(ctx)
				if err != nil {
					return err
				}

				wrapBodyReader(ctx, func(r io.Reader) io.Reader {
					var cr io.Reader
					cr, err = utils.NewUnsignedChunkReader(r, checksumType)
					return cr
				})
				if err != nil {
					return err
				}
			}
		}

		if utils.IsBigDataAction(ctx) {
			payloadType := ctx.Get("X-Amz-Content-Sha256")
			if utils.IsUnsignedStreamingPayload(payloadType) {
				checksumType, err := utils.ExtractChecksumType(ctx)
				if err != nil {
					return err
				}

				wrapBodyReader(ctx, func(r io.Reader) io.Reader {
					var cr io.Reader
					cr, err = utils.NewUnsignedChunkReader(r, checksumType)
					return cr
				})
				if err != nil {
					return err
				}
			}
		}

		utils.ContextKeyPublicBucket.Set(ctx, true)

		return nil
	}
}

// parsePath extracts the bucket and object names from the path
func parsePath(path string) (string, string) {
	p := strings.TrimPrefix(path, "/")
	bucket, object, _ := strings.Cut(p, "/")

	return bucket, object
}
