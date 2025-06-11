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
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/s3api/utils"
)

func SetDefaultValues(root RootUserConfig, region string) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		// These are necessary for the server access logs
		utils.ContextKeyRegion.Set(ctx, region)
		utils.ContextKeyStartTime.Set(ctx, time.Now())
		utils.ContextKeyRootAccessKey.Set(ctx, root.Access)
		// Set the account and isRoot to some defulat values, to avoid panics
		// in case of public buckets
		utils.ContextKeyAccount.Set(ctx, auth.Account{})
		utils.ContextKeyIsRoot.Set(ctx, false)
		return ctx.Next()
	}
}
