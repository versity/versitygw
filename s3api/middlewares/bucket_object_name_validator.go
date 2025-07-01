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
	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3log"
)

func ValidateBucketObjectNames(l s3log.AuditLogger, mm *metrics.Manager) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		bucket, object := parsePath(ctx.Path())
		if bucket != "" && !utils.IsValidBucketName(bucket) {
			return sendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidBucketName), l, mm)
		}
		if object != "" && !utils.IsObjectNameValid(object) {
			return sendResponse(ctx, s3err.GetAPIError(s3err.ErrBadRequest), l, mm)
		}
		return ctx.Next()
	}
}
