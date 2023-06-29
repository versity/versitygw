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
)

type S3ApiRouter struct{}

func (sa *S3ApiRouter) Init(app *fiber.App, be backend.Backend, iam auth.IAMService) {
	s3ApiController := controllers.New(be, iam)
	adminController := controllers.AdminController{IAMService: iam}

	// TODO: think of better routing system
	app.Post("/create-user", adminController.CreateUser)

	// Admin Delete api
	app.Delete("/delete-user", adminController.DeleteUser)
	// ListBuckets action
	app.Get("/", s3ApiController.ListBuckets)

	// PutBucket action
	// PutBucketAcl action
	app.Put("/:bucket", s3ApiController.PutBucketActions)

	// DeleteBucket action
	app.Delete("/:bucket", s3ApiController.DeleteBucket)

	// HeadBucket
	app.Head("/:bucket", s3ApiController.HeadBucket)
	// GetBucketAcl action
	// ListMultipartUploads action
	// ListObjects action
	// ListObjectsV2 action
	app.Get("/:bucket", s3ApiController.ListActions)

	// HeadObject action
	app.Head("/:bucket/:key/*", s3ApiController.HeadObject)
	// GetObjectAcl action
	// GetObject action
	// ListObjectParts action
	app.Get("/:bucket/:key/*", s3ApiController.GetActions)
	// DeleteObject action
	// AbortMultipartUpload action
	app.Delete("/:bucket/:key/*", s3ApiController.DeleteActions)
	// DeleteObjects action
	app.Post("/:bucket", s3ApiController.DeleteObjects)
	// CompleteMultipartUpload action
	// CreateMultipartUpload
	// RestoreObject action
	app.Post("/:bucket/:key/*", s3ApiController.CreateActions)
	// CopyObject action
	// PutObject action
	// UploadPart action
	// UploadPartCopy action
	app.Put("/:bucket/:key/*", s3ApiController.PutActions)
}
