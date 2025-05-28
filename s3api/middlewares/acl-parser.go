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
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3log"
)

var (
	singlePath = regexp.MustCompile(`^/[^/]+/?$`)
)

func AclParser(be backend.Backend, logger s3log.AuditLogger, readonly bool) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
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
			!ctx.Request().URI().QueryArgs().Has("versioning") &&
			!ctx.Request().URI().QueryArgs().Has("policy") &&
			!ctx.Request().URI().QueryArgs().Has("object-lock") &&
			!ctx.Request().URI().QueryArgs().Has("ownershipControls") &&
			!ctx.Request().URI().QueryArgs().Has("cors") {
			isRoot, acct := utils.ContextKeyIsRoot.Get(ctx).(bool), utils.ContextKeyAccount.Get(ctx).(auth.Account)
			if err := auth.MayCreateBucket(acct, isRoot); err != nil {
				return controllers.SendXMLResponse(ctx, nil, err, &controllers.MetaOpts{Logger: logger, Action: "CreateBucket"})
			}
			if readonly {
				return controllers.SendXMLResponse(ctx, nil, s3err.GetAPIError(s3err.ErrAccessDenied),
					&controllers.MetaOpts{
						Logger: logger,
						Action: "CreateBucket",
					})
			}
			return ctx.Next()
		}
		data, err := be.GetBucketAcl(ctx.Context(), &s3.GetBucketAclInput{Bucket: &bucket})
		if err != nil {
			return controllers.SendResponse(ctx, err, &controllers.MetaOpts{Logger: logger})
		}

		parsedAcl, err := auth.ParseACL(data)
		if err != nil {
			return controllers.SendResponse(ctx, err, &controllers.MetaOpts{Logger: logger})
		}

		// if owner is not set, set default owner to root account
		if parsedAcl.Owner == "" {
			parsedAcl.Owner = utils.ContextKeyRootAccessKey.Get(ctx).(string)
		}

		utils.ContextKeyParsedAcl.Set(ctx, parsedAcl)
		return ctx.Next()
	}
}
