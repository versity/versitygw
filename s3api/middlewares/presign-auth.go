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
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3log"
)

func VerifyPresignedV4Signature(root RootUserConfig, iam auth.IAMService, logger s3log.AuditLogger, mm *metrics.Manager, region string, debug bool) fiber.Handler {
	acct := accounts{root: root, iam: iam}

	return func(ctx *fiber.Ctx) error {
		// The bucket is public, no need to check this signature
		if utils.ContextKeyPublicBucket.IsSet(ctx) {
			return ctx.Next()
		}
		if ctx.Query("X-Amz-Signature") == "" {
			return ctx.Next()
		}

		// Set in the context the "authenticated" key, in case the authentication succeeds,
		// otherwise the middleware will return the caucht error
		utils.ContextKeyAuthenticated.Set(ctx, true)

		authData, err := utils.ParsePresignedURIParts(ctx)
		if err != nil {
			return sendResponse(ctx, err, logger, mm)
		}

		utils.ContextKeyIsRoot.Set(ctx, authData.Access == root.Access)

		account, err := acct.getAccount(authData.Access)
		if err == auth.ErrNoSuchUser {
			return sendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidAccessKeyID), logger, mm)
		}
		if err != nil {
			return sendResponse(ctx, err, logger, mm)
		}
		utils.ContextKeyAccount.Set(ctx, account)

		var contentLength int64
		contentLengthStr := ctx.Get("Content-Length")
		if contentLengthStr != "" {
			contentLength, err = strconv.ParseInt(contentLengthStr, 10, 64)
			//TODO: not sure if InvalidRequest should be returned in this case
			if err != nil {
				return sendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest), logger, mm)
			}
		}

		if utils.IsBigDataAction(ctx) {
			// Content-Length has to be set for data uploads: PutObject, UploadPart
			if contentLengthStr == "" {
				return sendResponse(ctx, s3err.GetAPIError(s3err.ErrMissingContentLength), logger, mm)
			}
			// the upload limit for big data actions: PutObject, UploadPart
			// is 5gb. If the size exceeds the limit, return 'EntityTooLarge' err
			if contentLength > maxObjSizeLimit {
				return sendResponse(ctx, s3err.GetAPIError(s3err.ErrEntityTooLarge), logger, mm)
			}
			wrapBodyReader(ctx, func(r io.Reader) io.Reader {
				return utils.NewPresignedAuthReader(ctx, r, authData, account.Secret, debug)
			})

			return ctx.Next()
		}

		err = utils.CheckPresignedSignature(ctx, authData, account.Secret, debug)
		if err != nil {
			return sendResponse(ctx, err, logger, mm)
		}

		return ctx.Next()
	}
}
