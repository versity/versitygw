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
	"crypto/sha256"
	"encoding/hex"
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
func AuthorizePublicBucketAccess(be backend.Backend, s3action string, policyPermission auth.Action, permission auth.Permission, region string, streamBody bool) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		// skip for authenticated requests
		if utils.IsPresignedURLAuth(ctx) || ctx.Get("Authorization") != "" {
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
			if s3action == metrics.ActionHeadBucket {
				// add the bucket region header for HeadBucket
				// if anonymous access is denied
				ctx.Response().Header.Add("x-amz-bucket-region", region)
			}
			return err
		}

		// at this point the bucket is considered as public
		// as public access is granted
		utils.ContextKeyPublicBucket.Set(ctx, true)

		payloadHash := ctx.Get("X-Amz-Content-Sha256")
		err = utils.IsAnonymousPayloadHashSupported(payloadHash)
		if err != nil {
			return err
		}

		if streamBody {
			if utils.IsUnsignedStreamingPayload(payloadHash) {
				cLength, err := utils.ParseDecodedContentLength(ctx)
				if err != nil {
					return err
				}
				// stack an unsigned streaming payload reader
				checksumType, err := utils.ExtractChecksumType(ctx)
				if err != nil {
					return err
				}

				wrapBodyReader(ctx, func(r io.Reader) io.Reader {
					var cr io.Reader
					cr, err = utils.NewUnsignedChunkReader(r, checksumType, cLength)
					return cr
				})

				return err
			} else if utils.IsUnsignedPaylod(payloadHash) {
				// for UNSIGNED-PAYLOD simply store the body reader in context locals
				utils.ContextKeyBodyReader.Set(ctx, ctx.Request().BodyStream())
				return nil
			} else {
				// stack a hash reader to calculated the payload sha256 hash
				wrapBodyReader(ctx, func(r io.Reader) io.Reader {
					var cr io.Reader
					cr, err = utils.NewHashReader(r, payloadHash, utils.HashTypeSha256Hex)
					return cr
				})

				return err
			}
		}

		if payloadHash != "" {
			// Calculate the hash of the request payload
			hashedPayload := sha256.Sum256(ctx.Body())
			hexPayload := hex.EncodeToString(hashedPayload[:])

			// Compare the calculated hash with the hash provided
			if payloadHash != hexPayload {
				return s3err.GetAPIError(s3err.ErrContentSHA256Mismatch)
			}
		}

		return nil
	}
}

// parsePath extracts the bucket and object names from the path
func parsePath(path string) (string, string) {
	p := strings.TrimPrefix(path, "/")
	bucket, object, _ := strings.Cut(p, "/")

	return bucket, object
}
