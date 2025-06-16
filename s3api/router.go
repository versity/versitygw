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
	"github.com/versity/versitygw/s3event"
	"github.com/versity/versitygw/s3log"
)

type S3ApiRouter struct {
	WithAdmSrv bool
}

func (sa *S3ApiRouter) Init(app *fiber.App, be backend.Backend, iam auth.IAMService, logger s3log.AuditLogger, aLogger s3log.AuditLogger, evs s3event.S3EventSender, mm *metrics.Manager, debug bool, readonly bool) {
	ctrl := controllers.New(be, iam, logger, evs, mm, debug, readonly)

	if sa.WithAdmSrv {
		adminController := controllers.NewAdminController(iam, be, aLogger)

		// CreateUser admin api
		app.Patch("/create-user", middlewares.IsAdmin(logger), adminController.CreateUser)

		// DeleteUsers admin api
		app.Patch("/delete-user", middlewares.IsAdmin(logger), adminController.DeleteUser)

		// UpdateUser admin api
		app.Patch("/update-user", middlewares.IsAdmin(logger), adminController.UpdateUser)

		// ListUsers admin api
		app.Patch("/list-users", middlewares.IsAdmin(logger), adminController.ListUsers)

		// ChangeBucketOwner admin api
		app.Patch("/change-bucket-owner", middlewares.IsAdmin(logger), adminController.ChangeBucketOwner)

		// ListBucketsAndOwners admin api
		app.Patch("/list-buckets", middlewares.IsAdmin(logger), adminController.ListBuckets)
	}

	app.Get("/", controllers.ProcessResponse(ctrl.ListBuckets, logger, evs, mm))

	// Put bucket operations
	app.Put("/:bucket", middlewares.MatchQueryArgs("tagging"), controllers.ProcessResponse(ctrl.PutBucketTagging, logger, evs, mm))
	app.Put("/:bucket", middlewares.MatchQueryArgs("ownershipControls"), controllers.ProcessResponse(ctrl.PutBucketOwnershipControls, logger, evs, mm))
	app.Put("/:bucket", middlewares.MatchQueryArgs("versioning"), controllers.ProcessResponse(ctrl.PutBucketVersioning, logger, evs, mm))
	app.Put("/:bucket", middlewares.MatchQueryArgs("object-lock"), controllers.ProcessResponse(ctrl.PutObjectLockConfiguration, logger, evs, mm))
	app.Put("/:bucket", middlewares.MatchQueryArgs("cors"), controllers.ProcessResponse(ctrl.PutBucketCors, logger, evs, mm))
	app.Put("/:bucket", middlewares.MatchQueryArgs("policy"), controllers.ProcessResponse(ctrl.PutBucketPolicy, logger, evs, mm))
	app.Put("/:bucket", middlewares.MatchQueryArgs("acl"), controllers.ProcessResponse(ctrl.PutBucketAcl, logger, evs, mm))
	app.Put("/:bucket", controllers.ProcessResponse(ctrl.CreateBucket, logger, evs, mm))

	// HeadBucket
	app.Head("/:bucket", controllers.ProcessResponse(ctrl.HeadBucket, logger, evs, mm))

	// Delete bucket operations
	app.Delete("/:bucket", middlewares.MatchQueryArgs("tagging"), controllers.ProcessResponse(ctrl.DeleteBucketTagging, logger, evs, mm))
	app.Delete("/:bucket", middlewares.MatchQueryArgs("ownershipControls"), controllers.ProcessResponse(ctrl.DeleteBucketOwnershipControls, logger, evs, mm))
	app.Delete("/:bucket", middlewares.MatchQueryArgs("policy"), controllers.ProcessResponse(ctrl.DeleteBucketPolicy, logger, evs, mm))
	app.Delete("/:bucket", middlewares.MatchQueryArgs("cors"), controllers.ProcessResponse(ctrl.DeleteBucketCors, logger, evs, mm))
	app.Delete("/:bucket", controllers.ProcessResponse(ctrl.DeleteBucket, logger, evs, mm))

	// Get bucket operations
	app.Get("/:bucket", middlewares.MatchQueryArgs("tagging"), controllers.ProcessResponse(ctrl.GetBucketTagging, logger, evs, mm))
	app.Get("/:bucket", middlewares.MatchQueryArgs("ownershipControls"), controllers.ProcessResponse(ctrl.GetBucketOwnershipControls, logger, evs, mm))
	app.Get("/:bucket", middlewares.MatchQueryArgs("versioning"), controllers.ProcessResponse(ctrl.GetBucketVersioning, logger, evs, mm))
	app.Get("/:bucket", middlewares.MatchQueryArgs("policy"), controllers.ProcessResponse(ctrl.GetBucketPolicy, logger, evs, mm))
	app.Get("/:bucket", middlewares.MatchQueryArgs("cors"), controllers.ProcessResponse(ctrl.GetBucketCors, logger, evs, mm))
	app.Get("/:bucket", middlewares.MatchQueryArgs("object-lock"), controllers.ProcessResponse(ctrl.GetObjectLockConfiguration, logger, evs, mm))
	app.Get("/:bucket", middlewares.MatchQueryArgs("acl"), controllers.ProcessResponse(ctrl.GetBucketAcl, logger, evs, mm))
	app.Get("/:bucket", middlewares.MatchQueryArgs("uploads"), controllers.ProcessResponse(ctrl.ListMultipartUploads, logger, evs, mm))
	app.Get("/:bucket", middlewares.MatchQueryArgs("versions"), controllers.ProcessResponse(ctrl.ListObjectVersions, logger, evs, mm))
	app.Get("/:bucket", middlewares.MatchQueryArgWithValue("list-type", "2"), controllers.ProcessResponse(ctrl.ListObjectsV2, logger, evs, mm))
	app.Get("/:bucket", controllers.ProcessResponse(ctrl.ListObjects, logger, evs, mm))

	// HeadObject
	app.Head("/:bucket/:key/*", controllers.ProcessResponse(ctrl.HeadObject, logger, evs, mm))

	// GetObjectAcl action
	// GetObject action
	// ListObjectParts action
	// GetObjectTagging action
	// ListParts action
	// GetObjectAttributes action
	app.Get("/:bucket/:key/*", ctrl.GetActions)

	// DeleteObject action
	// AbortMultipartUpload action
	// DeleteObjectTagging action
	app.Delete("/:bucket/:key/*", ctrl.DeleteActions)

	// DeleteObjects action
	app.Post("/:bucket", ctrl.DeleteObjects)

	// CompleteMultipartUpload action
	// CreateMultipartUpload
	// RestoreObject action
	// SelectObjectContent action
	app.Post("/:bucket/:key/*", ctrl.CreateActions)

	// CopyObject action
	// PutObject action
	// UploadPart action
	// UploadPartCopy action
	// PutObjectTagging action
	// PutObjectAcl action
	app.Put("/:bucket/:key/*", ctrl.PutActions)
}
