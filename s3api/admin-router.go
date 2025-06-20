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
	"github.com/versity/versitygw/s3api/controllers"
	"github.com/versity/versitygw/s3log"
)

type S3AdminRouter struct{}

func (ar *S3AdminRouter) Init(app *fiber.App, be backend.Backend, iam auth.IAMService, logger s3log.AuditLogger) {
	ctrl := controllers.NewAdminController(iam, be, logger)

	// CreateUser admin api
	app.Patch("/create-user", controllers.ProcessResponse(ctrl.CreateUser, logger, nil, nil))

	// DeleteUsers admin api
	app.Patch("/delete-user", controllers.ProcessResponse(ctrl.DeleteUser, logger, nil, nil))

	// UpdateUser admin api
	app.Patch("/update-user", controllers.ProcessResponse(ctrl.UpdateUser, logger, nil, nil))

	// ListUsers admin api
	app.Patch("/list-users", controllers.ProcessResponse(ctrl.ListUsers, logger, nil, nil))

	// ChangeBucketOwner admin api
	app.Patch("/change-bucket-owner", controllers.ProcessResponse(ctrl.ChangeBucketOwner, logger, nil, nil))

	// ListBucketsAndOwners admin api
	app.Patch("/list-buckets", controllers.ProcessResponse(ctrl.ListBuckets, logger, nil, nil))
}
