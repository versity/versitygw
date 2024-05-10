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
	"time"

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
		if ctx.Query("X-Amz-Signature") == "" {
			return ctx.Next()
		}

		ctx.Locals("region", region)
		ctx.Locals("startTime", time.Now())

		authData, err := utils.ParsePresignedURIParts(ctx)
		if err != nil {
			return sendResponse(ctx, err, logger, mm)
		}

		ctx.Locals("isRoot", authData.Access == root.Access)
		account, err := acct.getAccount(authData.Access)
		if err == auth.ErrNoSuchUser {
			return sendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidAccessKeyID), logger, mm)
		}
		if err != nil {
			return sendResponse(ctx, err, logger, mm)
		}
		ctx.Locals("account", account)

		if utils.IsBigDataAction(ctx) {
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
