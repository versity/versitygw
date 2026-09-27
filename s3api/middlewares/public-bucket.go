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

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
)

// objectVersionActions maps an object action to the one a request naming a
// specific object version with versionId is authorized as instead.
var objectVersionActions = map[auth.Action]auth.Action{
	auth.GetObjectAction:           auth.GetObjectVersionAction,
	auth.DeleteObjectAction:        auth.DeleteObjectVersionAction,
	auth.GetObjectTaggingAction:    auth.GetObjectVersionTaggingAction,
	auth.PutObjectTaggingAction:    auth.PutObjectVersionTaggingAction,
	auth.DeleteObjectTaggingAction: auth.DeleteObjectVersionTaggingAction,
	auth.GetObjectAttributesAction: auth.GetObjectVersionAttributesAction,
}

// AuthorizePublicBucketAccess checks if the bucket grants public
// access to anonymous requesters
func AuthorizePublicBucketAccess(be backend.Backend, s3action string, policyPermission auth.Action, permission auth.Permission, region string, streamBody bool) fiber.Handler {
	return func(ctx fiber.Ctx) error {
		// skip for authenticated requests
		if utils.IsPresignedURLAuth(ctx) || ctx.Get("Authorization") != "" || utils.ContextKeyAuthenticated.IsSet(ctx) {
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

		// A request naming an object version is authorized as that
		// version's own action, s3:GetObjectVersion rather than
		// s3:GetObject and so on, which a grant of the plain action
		// doesn't cover. An empty versionId is left to the handler to
		// reject.
		action := policyPermission
		if ctx.Query("versionId") != "" {
			if versionAction, ok := objectVersionActions[action]; ok {
				action = versionAction
			}
		}
		actions := []auth.Action{action}

		// An upload is authorized as s3:PutObject plus an action for each
		// attribute it sets on the object, and the bucket has to grant
		// every one of them publicly.
		switch s3action {
		case metrics.ActionPutObject:
			if err := verifyAnonymousUploadLock(ctx, be, bucket); err != nil {
				return err
			}
			actions = auth.ObjectUploadActions(ctx.Get("X-Amz-Tagging"), "", "", "")
		case metrics.ActionPostObject:
			// A POST upload is addressed to the bucket; the object it writes
			// is named by the form's key field instead, which
			// AuthorizePostObject has already parsed. Authorize against that
			// object's ARN, as PutObject is.
			if parsed, ok := utils.ContextKeyObjectPostResult.Get(ctx).(PostObjectResult); ok {
				object = parsed.Fields["key"]

				// Only a non-empty tag set takes s3:PutObjectTagging, so the
				// form's tagging has to be parsed to tell, and a malformed
				// one is rejected before any permission is checked.
				var tagging string
				if taggingXML, ok := parsed.Fields["tagging"]; ok {
					var err error
					tagging, err = utils.ConvertTaggingXMLToQueryString([]byte(taggingXML))
					if err != nil {
						return err
					}
				}
				actions = auth.ObjectUploadActions(tagging, "", "", "")
			}
		}

		err := auth.VerifyPublicAccess(ctx, be, actions, permission, bucket, object)
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
				utils.ContextKeyBodyReader.Set(ctx, requestBodyStream(ctx))
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
			hashedPayload := sha256.Sum256(ctx.BodyRaw())
			hexPayload := hex.EncodeToString(hashedPayload[:])

			// Compare the calculated hash with the hash provided
			if payloadHash != hexPayload {
				return s3err.GetContentSHA256MismatchErr(payloadHash, hexPayload)
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

// verifyAnonymousUploadLock refuses an anonymous PutObject that carries
// Object Lock parameters: only a signed upload may lock the object it
// writes. The parameters are those its lock headers set and those the
// bucket's default retention rule gives every object written to it, so a
// plain upload to such a bucket is refused as well, even when the bucket
// grants no public access at all. This runs before the upload itself is
// authorized, and the lock actions it would take are never checked.
func verifyAnonymousUploadLock(ctx fiber.Ctx, be backend.Backend, bucket string) error {
	objLock, err := utils.ParsObjectLockHdrs(ctx)
	if err != nil {
		return err
	}

	explicit := objLock.LegalHoldStatus != "" || objLock.ObjectLockMode != ""
	locked, err := auth.VerifyWriteObjectLock(ctx.RequestCtx(), be, bucket, explicit)
	if err != nil || !locked {
		return err
	}

	if !utils.HasPayloadIntegrityCheck(ctx) {
		return s3err.GetAPIError(s3err.ErrObjectLockChecksumRequired)
	}
	return s3err.GetInvalidArgumentErr(s3err.InvalidArgAnonymousObjectLock, "")
}
