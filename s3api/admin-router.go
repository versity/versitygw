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

package s3api

import (
	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/s3api/controllers"
	"github.com/versity/versitygw/s3api/middlewares"
	"github.com/versity/versitygw/s3log"
)

type S3AdminRouter struct {
	s3api controllers.S3ApiController
}

func (ar *S3AdminRouter) Init(app *fiber.App, be backend.Backend, iam auth.IAMService, logger s3log.AuditLogger, root middlewares.RootUserConfig, region string, debug bool, corsAllowOrigin string) {
	ctrl := controllers.NewAdminController(iam, be, logger, ar.s3api)
	services := &controllers.Services{
		Logger: logger,
	}

	// CreateUser admin api
	app.Patch("/create-user",
		controllers.ProcessHandlers(ctrl.CreateUser, metrics.ActionAdminCreateUser, services,
			middlewares.VerifyV4Signature(root, iam, region, false, true),
			middlewares.IsAdmin(metrics.ActionAdminCreateUser),
			middlewares.ApplyDefaultCORS(corsAllowOrigin),
		))
	app.Options("/create-user",
		middlewares.ApplyDefaultCORSPreflight(corsAllowOrigin),
		middlewares.ApplyDefaultCORS(corsAllowOrigin),
	)

	// DeleteUsers admin api
	app.Patch("/delete-user",
		controllers.ProcessHandlers(ctrl.DeleteUser, metrics.ActionAdminDeleteUser, services,
			middlewares.VerifyV4Signature(root, iam, region, false, true),
			middlewares.IsAdmin(metrics.ActionAdminDeleteUser),
			middlewares.ApplyDefaultCORS(corsAllowOrigin),
		))
	app.Options("/delete-user",
		middlewares.ApplyDefaultCORSPreflight(corsAllowOrigin),
		middlewares.ApplyDefaultCORS(corsAllowOrigin),
	)

	// UpdateUser admin api
	app.Patch("/update-user",
		controllers.ProcessHandlers(ctrl.UpdateUser, metrics.ActionAdminUpdateUser, services,
			middlewares.VerifyV4Signature(root, iam, region, false, true),
			middlewares.IsAdmin(metrics.ActionAdminUpdateUser),
			middlewares.ApplyDefaultCORS(corsAllowOrigin),
		))
	app.Options("/update-user",
		middlewares.ApplyDefaultCORSPreflight(corsAllowOrigin),
		middlewares.ApplyDefaultCORS(corsAllowOrigin),
	)

	// ListUsers admin api
	app.Patch("/list-users",
		controllers.ProcessHandlers(ctrl.ListUsers, metrics.ActionAdminListUsers, services,
			middlewares.VerifyV4Signature(root, iam, region, false, true),
			middlewares.IsAdmin(metrics.ActionAdminListUsers),
			middlewares.ApplyDefaultCORS(corsAllowOrigin),
		))
	app.Options("/list-users",
		middlewares.ApplyDefaultCORSPreflight(corsAllowOrigin),
		middlewares.ApplyDefaultCORS(corsAllowOrigin),
	)

	// ChangeBucketOwner admin api
	app.Patch("/change-bucket-owner",
		controllers.ProcessHandlers(ctrl.ChangeBucketOwner, metrics.ActionAdminChangeBucketOwner, services,
			middlewares.VerifyV4Signature(root, iam, region, false, true),
			middlewares.IsAdmin(metrics.ActionAdminChangeBucketOwner),
			middlewares.ApplyDefaultCORS(corsAllowOrigin),
		))
	app.Options("/change-bucket-owner",
		middlewares.ApplyDefaultCORSPreflight(corsAllowOrigin),
		middlewares.ApplyDefaultCORS(corsAllowOrigin),
	)

	// ListBucketsAndOwners admin api
	app.Patch("/list-buckets",
		controllers.ProcessHandlers(ctrl.ListBuckets, metrics.ActionAdminListBuckets, services,
			middlewares.VerifyV4Signature(root, iam, region, false, true),
			middlewares.IsAdmin(metrics.ActionAdminListBuckets),
			middlewares.ApplyDefaultCORS(corsAllowOrigin),
		))
	app.Options("/list-buckets",
		middlewares.ApplyDefaultCORSPreflight(corsAllowOrigin),
		middlewares.ApplyDefaultCORS(corsAllowOrigin),
	)

	app.Patch("/:bucket/create",
		controllers.ProcessHandlers(ctrl.CreateBucket, metrics.ActionAdminListBuckets, services,
			middlewares.VerifyV4Signature(root, iam, region, false, true),
			middlewares.IsAdmin(metrics.ActionAdminCreateBucket),
		))
	app.Options("/:bucket/create",
		middlewares.ApplyDefaultCORSPreflight(corsAllowOrigin),
		middlewares.ApplyDefaultCORS(corsAllowOrigin),
	)
}
