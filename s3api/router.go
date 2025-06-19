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

	// ListBuckets action
	app.Get("/", controllers.ProcessResponse(ctrl.ListBuckets, logger, evs, mm))

	bucketRouter := app.Group("/:bucket")
	objectRouter := app.Group("/:bucket/*")

	// PUT bucket operations
	bucketRouter.Put("", middlewares.MatchQueryArgs("tagging"), controllers.ProcessResponse(ctrl.PutBucketTagging, logger, evs, mm))
	bucketRouter.Put("", middlewares.MatchQueryArgs("ownershipControls"), controllers.ProcessResponse(ctrl.PutBucketOwnershipControls, logger, evs, mm))
	bucketRouter.Put("", middlewares.MatchQueryArgs("versioning"), controllers.ProcessResponse(ctrl.PutBucketVersioning, logger, evs, mm))
	bucketRouter.Put("", middlewares.MatchQueryArgs("object-lock"), controllers.ProcessResponse(ctrl.PutObjectLockConfiguration, logger, evs, mm))
	bucketRouter.Put("", middlewares.MatchQueryArgs("cors"), controllers.ProcessResponse(ctrl.PutBucketCors, logger, evs, mm))
	bucketRouter.Put("", middlewares.MatchQueryArgs("policy"), controllers.ProcessResponse(ctrl.PutBucketPolicy, logger, evs, mm))
	bucketRouter.Put("", middlewares.MatchQueryArgs("acl"), controllers.ProcessResponse(ctrl.PutBucketAcl, logger, evs, mm))
	bucketRouter.Put("", controllers.ProcessResponse(ctrl.CreateBucket, logger, evs, mm))

	// HeadBucket action
	bucketRouter.Head("", controllers.ProcessResponse(ctrl.HeadBucket, logger, evs, mm))

	// DELETE bucket operations
	bucketRouter.Delete("", middlewares.MatchQueryArgs("tagging"), controllers.ProcessResponse(ctrl.DeleteBucketTagging, logger, evs, mm))
	bucketRouter.Delete("", middlewares.MatchQueryArgs("ownershipControls"), controllers.ProcessResponse(ctrl.DeleteBucketOwnershipControls, logger, evs, mm))
	bucketRouter.Delete("", middlewares.MatchQueryArgs("policy"), controllers.ProcessResponse(ctrl.DeleteBucketPolicy, logger, evs, mm))
	bucketRouter.Delete("", middlewares.MatchQueryArgs("cors"), controllers.ProcessResponse(ctrl.DeleteBucketCors, logger, evs, mm))
	bucketRouter.Delete("", controllers.ProcessResponse(ctrl.DeleteBucket, logger, evs, mm))

	// GET bucket operations
	bucketRouter.Get("", middlewares.MatchQueryArgs("tagging"), controllers.ProcessResponse(ctrl.GetBucketTagging, logger, evs, mm))
	bucketRouter.Get("", middlewares.MatchQueryArgs("ownershipControls"), controllers.ProcessResponse(ctrl.GetBucketOwnershipControls, logger, evs, mm))
	bucketRouter.Get("", middlewares.MatchQueryArgs("versioning"), controllers.ProcessResponse(ctrl.GetBucketVersioning, logger, evs, mm))
	bucketRouter.Get("", middlewares.MatchQueryArgs("policy"), controllers.ProcessResponse(ctrl.GetBucketPolicy, logger, evs, mm))
	bucketRouter.Get("", middlewares.MatchQueryArgs("cors"), controllers.ProcessResponse(ctrl.GetBucketCors, logger, evs, mm))
	bucketRouter.Get("", middlewares.MatchQueryArgs("object-lock"), controllers.ProcessResponse(ctrl.GetObjectLockConfiguration, logger, evs, mm))
	bucketRouter.Get("", middlewares.MatchQueryArgs("acl"), controllers.ProcessResponse(ctrl.GetBucketAcl, logger, evs, mm))
	bucketRouter.Get("", middlewares.MatchQueryArgs("uploads"), controllers.ProcessResponse(ctrl.ListMultipartUploads, logger, evs, mm))
	bucketRouter.Get("", middlewares.MatchQueryArgs("versions"), controllers.ProcessResponse(ctrl.ListObjectVersions, logger, evs, mm))
	bucketRouter.Get("", middlewares.MatchQueryArgWithValue("list-type", "2"), controllers.ProcessResponse(ctrl.ListObjectsV2, logger, evs, mm))
	bucketRouter.Get("", controllers.ProcessResponse(ctrl.ListObjects, logger, evs, mm))

	// DeleteObjects action
	bucketRouter.Post("", middlewares.MatchQueryArgs("delete"), controllers.ProcessResponse(ctrl.DeleteObjects, logger, evs, mm))

	// HeadObject
	objectRouter.Head("", controllers.ProcessResponse(ctrl.HeadObject, logger, evs, mm))

	// GET object operations
	objectRouter.Get("", middlewares.MatchQueryArgs("tagging"), controllers.ProcessResponse(ctrl.GetObjectTagging, logger, evs, mm))
	objectRouter.Get("", middlewares.MatchQueryArgs("retention"), controllers.ProcessResponse(ctrl.GetObjectRetention, logger, evs, mm))
	objectRouter.Get("", middlewares.MatchQueryArgs("legal-hold"), controllers.ProcessResponse(ctrl.GetObjectLegalHold, logger, evs, mm))
	objectRouter.Get("", middlewares.MatchQueryArgs("acl"), controllers.ProcessResponse(ctrl.GetObjectAcl, logger, evs, mm))
	objectRouter.Get("", middlewares.MatchQueryArgs("attributes"), controllers.ProcessResponse(ctrl.GetObjectAttributes, logger, evs, mm))
	objectRouter.Get("", middlewares.MatchQueryArgs("uploadId"), controllers.ProcessResponse(ctrl.ListParts, logger, evs, mm))
	objectRouter.Get("", controllers.ProcessResponse(ctrl.GetObject, logger, evs, mm))

	// DELETE object operations
	objectRouter.Delete("", middlewares.MatchQueryArgs("tagging"), controllers.ProcessResponse(ctrl.DeleteObjectTagging, logger, evs, mm))
	objectRouter.Delete("", middlewares.MatchQueryArgs("uploadId"), controllers.ProcessResponse(ctrl.AbortMultipartUplaod, logger, evs, mm))
	objectRouter.Delete("", controllers.ProcessResponse(ctrl.DeleteObject, logger, evs, mm))

	objectRouter.Post("", middlewares.MatchQueryArgs("restore"), controllers.ProcessResponse(ctrl.RestoreObject, logger, evs, mm))
	objectRouter.Post("", middlewares.MatchQueryArgs("list-type"), middlewares.MatchQueryArgWithValue("list-type", "2"), controllers.ProcessResponse(ctrl.RestoreObject, logger, evs, mm))
	objectRouter.Post("", middlewares.MatchQueryArgs("uploadId"), controllers.ProcessResponse(ctrl.CompleteMultipartUpload, logger, evs, mm))
	objectRouter.Post("", middlewares.MatchQueryArgs("uploads"), controllers.ProcessResponse(ctrl.CreateMultipartUpload, logger, evs, mm))

	// PUT object operations
	objectRouter.Put("", middlewares.MatchQueryArgs("tagging"), controllers.ProcessResponse(ctrl.PutObjectTagging, logger, evs, mm))
	objectRouter.Put("", middlewares.MatchQueryArgs("retention"), controllers.ProcessResponse(ctrl.PutObjectRetention, logger, evs, mm))
	objectRouter.Put("", middlewares.MatchQueryArgs("legal-hold"), controllers.ProcessResponse(ctrl.PutObjectLegalHold, logger, evs, mm))
	objectRouter.Put("", middlewares.MatchQueryArgs("acl"), controllers.ProcessResponse(ctrl.PutObjectAcl, logger, evs, mm))
	objectRouter.Put("", middlewares.MatchQueryArgs("uploadId", "partNumber"), middlewares.MatchHeader("X-Amz-Copy-Source"), controllers.ProcessResponse(ctrl.UploadPartCopy, logger, evs, mm))
	objectRouter.Put("", middlewares.MatchQueryArgs("uploadId", "partNumber"), controllers.ProcessResponse(ctrl.UploadPart, logger, evs, mm))
	objectRouter.Put("", middlewares.MatchHeader("X-Amz-Copy-Source"), controllers.ProcessResponse(ctrl.CopyObject, logger, evs, mm))
	objectRouter.Put("", controllers.ProcessResponse(ctrl.PutObject, logger, evs, mm))

	// Return MethodNotAllowed for all the unmatched routes
	app.All("*", controllers.ProcessResponse(ctrl.HandleUnmatch, logger, evs, mm))
}
