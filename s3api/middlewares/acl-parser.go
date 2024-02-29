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
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3api/controllers"
	"github.com/versity/versitygw/s3log"
)

var (
	singlePath = regexp.MustCompile(`^/[^/]+/?$`)
)

func AclParser(be backend.Backend, logger s3log.AuditLogger) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		isRoot, acct := ctx.Locals("isRoot").(bool), ctx.Locals("account").(auth.Account)
		path := ctx.Path()
		pathParts := strings.Split(path, "/")
		bucket := pathParts[1]
		if path == "/" && ctx.Method() == http.MethodGet {
			return ctx.Next()
		}
		if ctx.Method() == http.MethodPatch {
			return ctx.Next()
		}
		if singlePath.MatchString(path) &&
			ctx.Method() == http.MethodPut &&
			!ctx.Request().URI().QueryArgs().Has("acl") &&
			!ctx.Request().URI().QueryArgs().Has("tagging") &&
			!ctx.Request().URI().QueryArgs().Has("versioning") {
			if err := auth.MayCreateBucket(acct, isRoot); err != nil {
				return controllers.SendXMLResponse(ctx, nil, err, &controllers.MetaOpts{Logger: logger, Action: "CreateBucket"})
			}
			return ctx.Next()
		}
		//TODO: provide correct action names for the logger, after implementing DetectAction middleware
		data, err := be.GetBucketAcl(ctx.Context(), &s3.GetBucketAclInput{Bucket: &bucket})
		if err != nil {
			return controllers.SendResponse(ctx, err, &controllers.MetaOpts{Logger: logger})
		}

		parsedAcl, err := auth.ParseACL(data)
		if err != nil {
			return controllers.SendResponse(ctx, err, &controllers.MetaOpts{Logger: logger})
		}

		ctx.Locals("parsedAcl", parsedAcl)
		return ctx.Next()
	}
}
