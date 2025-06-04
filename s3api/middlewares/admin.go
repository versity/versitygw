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
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/s3api/controllers"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3log"
)

func IsAdmin(logger s3log.AuditLogger) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
		if acct.Role != auth.RoleAdmin {
			path := ctx.Path()
			return controllers.SendResponse(ctx, s3err.GetAPIError(s3err.ErrAdminAccessDenied),
				&controllers.MetaOpts{
					Logger: logger,
					Action: detectAction(path),
				})
		}

		return ctx.Next()
	}
}

func detectAction(path string) (action string) {
	if strings.Contains(path, "create-user") {
		action = metrics.ActionAdminCreateUser
	} else if strings.Contains(path, "update-user") {
		action = metrics.ActionAdminUpdateUser
	} else if strings.Contains(path, "delete-user") {
		action = metrics.ActionAdminDeleteUser
	} else if strings.Contains(path, "list-user") {
		action = metrics.ActionAdminListUsers
	} else if strings.Contains(path, "list-buckets") {
		action = metrics.ActionAdminListBuckets
	} else if strings.Contains(path, "change-bucket-owner") {
		action = metrics.ActionAdminChangeBucketOwner
	}
	return action
}
