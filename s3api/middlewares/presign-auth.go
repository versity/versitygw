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
	"io"
	"strconv"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/internal/sigv4auth"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
)

func VerifyPresignedV4Signature(root RootUserConfig, iam auth.IAMService, region string, streamBody bool) fiber.Handler {
	rootAccount := auth.Account{Access: root.Access, Secret: root.Secret, Role: auth.RoleAdmin}

	return func(ctx fiber.Ctx) error {
		// The bucket is public, no need to check this signature
		if utils.ContextKeyPublicBucket.IsSet(ctx) {
			return nil
		}
		if !utils.IsPresignedURLAuth(ctx) {
			return nil
		}
		if utils.IsPresignedURLAuthV2(ctx) {
			// SigV2 authorization is not supported by the gateway
			return s3err.GetAPIError(s3err.ErrUnsupportedAuthorizationMechanism)
		}

		// Set in the context the "authenticated" key, in case the authentication succeeds,
		// otherwise the middleware will return the caucht error
		utils.ContextKeyAuthenticated.Set(ctx, true)

		authData, err := utils.ParsePresignedURIParts(ctx, region)
		if err != nil {
			return err
		}

		utils.ContextKeyIsRoot.Set(ctx, authData.Access == root.Access)

		sessionToken := ctx.Query(sigv4auth.QuerySecurityToken)

		derivedKey, account, err := auth.ResolveDerivedKey(iam, rootAccount, authData.Access, sessionToken, authData.Date[:8], authData.Region, sigv4auth.ServiceS3)
		if err == auth.ErrNoSuchUser {
			return s3err.GetInvalidAccessKeyIdErr(authData.Access)
		}
		if errors.Is(err, auth.ErrInvalidSessionToken) {
			return s3err.GetAPIError(s3err.ErrInvalidToken)
		}
		if err != nil {
			return err
		}
		utils.ContextKeyAccount.Set(ctx, account)

		var contentLength int64
		contentLengthStr := ctx.Get("Content-Length")
		if contentLengthStr != "" {
			contentLength, err = strconv.ParseInt(contentLengthStr, 10, 64)
			//TODO: not sure if InvalidRequest should be returned in this case
			if err != nil {
				return err
			}
		}

		err = utils.CheckPresignedSignature(ctx, authData, derivedKey)
		if err != nil {
			return err
		}

		if streamBody {
			wrapBodyReader(ctx, func(r io.Reader) io.Reader {
				return r
			})
			// Content-Length has to be set for data uploads: PutObject, UploadPart
			if contentLengthStr == "" {
				return s3err.GetAPIError(s3err.ErrMissingContentLength)
			}
			// the upload limit for big data actions: PutObject, UploadPart
			// is 5gb. If the size exceeds the limit, return 'EntityTooLarge' err
			if contentLength > maxObjSizeLimit {
				return s3err.GetEntityTooLargeErr(contentLength, maxObjSizeLimit)
			}
		}

		return nil
	}
}
