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
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3log"
)

// BucketObjectNameValidator extracts and validates
// the bucket and object names from the request URI.
func BucketObjectNameValidator(l s3log.AuditLogger, mm *metrics.Manager) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		// skip the check for admin apis
		if ctx.Method() == http.MethodPatch {
			return ctx.Next()
		}

		path := ctx.Path()
		// skip the check if the operation isn't bucket/object scoped
		// e.g ListBuckets
		if path == "/" {
			return ctx.Next()
		}

		bucket, object := parsePath(path)

		// check if the provided bucket name is valid
		if !utils.IsValidBucketName(bucket) {
			return sendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidBucketName), l, mm)
		}

		// check if the provided object name is valid
		// skip for empty objects: e.g bucket operations: HeadBucket...
		if object != "" && !utils.IsObjectNameValid(object) {
			return sendResponse(ctx, s3err.GetAPIError(s3err.ErrBadRequest), l, mm)
		}

		return ctx.Next()
	}
}
