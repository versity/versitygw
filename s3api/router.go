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
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3event"
	"github.com/versity/versitygw/s3log"
)

type S3ApiRouter struct {
	WithAdmSrv bool
}

func (sa *S3ApiRouter) Init(app *fiber.App, be backend.Backend, iam auth.IAMService, logger s3log.AuditLogger, aLogger s3log.AuditLogger, evs s3event.S3EventSender, mm metrics.Manager, debug bool, readonly bool, region string, root middlewares.RootUserConfig) {
	ctrl := controllers.New(be, iam, logger, evs, mm, debug, readonly)
	adminServices := &controllers.Services{
		Logger: aLogger,
	}

	if sa.WithAdmSrv {
		adminController := controllers.NewAdminController(iam, be, aLogger)

		// CreateUser admin api
		app.Patch("/create-user",
			controllers.ProcessHandlers(adminController.CreateUser, metrics.ActionAdminCreateUser, adminServices,
				middlewares.VerifyV4Signature(root, iam, region, debug),
				middlewares.IsAdmin(metrics.ActionAdminCreateUser),
			))

		// DeleteUsers admin api
		app.Patch("/delete-user",
			controllers.ProcessHandlers(adminController.DeleteUser, metrics.ActionAdminDeleteUser, adminServices,
				middlewares.VerifyV4Signature(root, iam, region, debug),
				middlewares.IsAdmin(metrics.ActionAdminDeleteUser),
			))

		// UpdateUser admin api
		app.Patch("/update-user",
			controllers.ProcessHandlers(adminController.UpdateUser, metrics.ActionAdminUpdateUser, adminServices,
				middlewares.VerifyV4Signature(root, iam, region, debug),
				middlewares.IsAdmin(metrics.ActionAdminUpdateUser),
			))

		// ListUsers admin api
		app.Patch("/list-users",
			controllers.ProcessHandlers(adminController.ListUsers, metrics.ActionAdminListUsers, adminServices,
				middlewares.VerifyV4Signature(root, iam, region, debug),
				middlewares.IsAdmin(metrics.ActionAdminListUsers),
			))

		// ChangeBucketOwner admin api
		app.Patch("/change-bucket-owner",
			controllers.ProcessHandlers(adminController.ChangeBucketOwner, metrics.ActionAdminChangeBucketOwner, adminServices,
				middlewares.VerifyV4Signature(root, iam, region, debug),
				middlewares.IsAdmin(metrics.ActionAdminChangeBucketOwner),
			))

		// ListBucketsAndOwners admin api
		app.Patch("/list-buckets",
			controllers.ProcessHandlers(adminController.ListBuckets, metrics.ActionAdminListBuckets, adminServices,
				middlewares.VerifyV4Signature(root, iam, region, debug),
				middlewares.IsAdmin(metrics.ActionAdminListBuckets),
			))
	}

	services := &controllers.Services{
		Logger:         logger,
		EventSender:    evs,
		MetricsManager: mm,
	}

	// ListBuckets action
	app.Get("/",
		controllers.ProcessHandlers(
			ctrl.ListBuckets,
			metrics.ActionListAllMyBuckets,
			services,
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionListAllMyBuckets, "", auth.PermissionRead),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
		))

	bucketRouter := app.Group("/:bucket")
	objectRouter := app.Group("/:bucket/*")

	// PUT bucket operations
	bucketRouter.Put("",
		middlewares.MatchQueryArgs("tagging"),
		controllers.ProcessHandlers(
			ctrl.PutBucketTagging,
			metrics.ActionPutBucketTagging,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionPutBucketTagging, auth.PutBucketTaggingAction, auth.PermissionWrite),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	bucketRouter.Put("",
		middlewares.MatchQueryArgs("ownershipControls"),
		controllers.ProcessHandlers(
			ctrl.PutBucketOwnershipControls,
			metrics.ActionPutBucketOwnershipControls,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionPutBucketOwnershipControls, auth.PutBucketOwnershipControlsAction, auth.PermissionWrite),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	bucketRouter.Put("",
		middlewares.MatchQueryArgs("versioning"),
		controllers.ProcessHandlers(
			ctrl.PutBucketVersioning,
			metrics.ActionPutBucketVersioning,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionPutBucketVersioning, auth.PutBucketVersioningAction, auth.PermissionWrite),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	bucketRouter.Put("",
		middlewares.MatchQueryArgs("object-lock"),
		controllers.ProcessHandlers(
			ctrl.PutObjectLockConfiguration,
			metrics.ActionPutObjectLockConfiguration,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionPutObjectLockConfiguration, auth.PutBucketObjectLockConfigurationAction, auth.PermissionWrite),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	bucketRouter.Put("",
		middlewares.MatchQueryArgs("cors"),
		controllers.ProcessHandlers(
			ctrl.PutBucketCors,
			metrics.ActionPutBucketCors,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionPutBucketCors, auth.PutBucketCorsAction, auth.PermissionWrite),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	bucketRouter.Put("",
		middlewares.MatchQueryArgs("policy"),
		controllers.ProcessHandlers(
			ctrl.PutBucketPolicy,
			metrics.ActionPutBucketPolicy,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionPutBucketPolicy, auth.PutBucketPolicyAction, auth.PermissionWrite),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	bucketRouter.Put("",
		middlewares.MatchQueryArgs("acl"),
		controllers.ProcessHandlers(
			ctrl.PutBucketAcl,
			metrics.ActionPutBucketAcl,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionPutBucketAcl, auth.PutBucketAclAction, auth.PermissionWriteAcp),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	bucketRouter.Put("",
		controllers.ProcessHandlers(
			ctrl.CreateBucket,
			metrics.ActionCreateBucket,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionCreateBucket, auth.CreateBucketAction, auth.PermissionWrite),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
		))

	// HeadBucket action
	bucketRouter.Head("",
		controllers.ProcessHandlers(
			ctrl.HeadBucket,
			metrics.ActionHeadBucket,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionHeadBucket, auth.ListBucketAction, auth.PermissionRead),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))

	// DELETE bucket operations
	bucketRouter.Delete("",
		middlewares.MatchQueryArgs("tagging"),
		controllers.ProcessHandlers(
			ctrl.DeleteBucketTagging,
			metrics.ActionDeleteBucketTagging,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionDeleteBucketTagging, auth.PutBucketTaggingAction, auth.PermissionWrite),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	bucketRouter.Delete("",
		middlewares.MatchQueryArgs("ownershipControls"),
		controllers.ProcessHandlers(
			ctrl.DeleteBucketOwnershipControls,
			metrics.ActionDeleteBucketOwnershipControls,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionDeleteBucketOwnershipControls, auth.PutBucketOwnershipControlsAction, auth.PermissionWrite),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	bucketRouter.Delete("",
		middlewares.MatchQueryArgs("policy"),
		controllers.ProcessHandlers(
			ctrl.DeleteBucketPolicy,
			metrics.ActionDeleteBucketPolicy,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionDeleteBucketPolicy, auth.PutBucketPolicyAction, auth.PermissionWrite),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	bucketRouter.Delete("",
		middlewares.MatchQueryArgs("cors"),
		controllers.ProcessHandlers(
			ctrl.DeleteBucketCors,
			metrics.ActionDeleteBucketCors,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionDeleteBucketCors, auth.PutBucketCorsAction, auth.PermissionWrite),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	bucketRouter.Delete("",
		controllers.ProcessHandlers(
			ctrl.DeleteBucket,
			metrics.ActionDeleteBucket,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionDeleteBucket, auth.DeleteBucketAction, auth.PermissionWrite),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))

	// GET bucket operations
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("tagging"),
		controllers.ProcessHandlers(
			ctrl.GetBucketTagging,
			metrics.ActionGetBucketTagging,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionGetBucketTagging, auth.GetBucketTaggingAction, auth.PermissionRead),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("ownershipControls"),
		controllers.ProcessHandlers(
			ctrl.GetBucketOwnershipControls,
			metrics.ActionGetBucketOwnershipControls,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionGetBucketOwnershipControls, auth.GetBucketOwnershipControlsAction, auth.PermissionRead),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("versioning"),
		controllers.ProcessHandlers(
			ctrl.GetBucketVersioning,
			metrics.ActionGetBucketVersioning,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionGetBucketVersioning, auth.GetBucketVersioningAction, auth.PermissionRead),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("policy"),
		controllers.ProcessHandlers(
			ctrl.GetBucketPolicy,
			metrics.ActionGetBucketPolicy,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionGetBucketPolicy, auth.GetBucketPolicyAction, auth.PermissionRead),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("cors"),
		controllers.ProcessHandlers(
			ctrl.GetBucketCors,
			metrics.ActionGetBucketCors,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionGetBucketCors, auth.GetBucketCorsAction, auth.PermissionRead),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("object-lock"),
		controllers.ProcessHandlers(
			ctrl.GetObjectLockConfiguration,
			metrics.ActionGetObjectLockConfiguration,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionGetObjectLockConfiguration, auth.GetBucketObjectLockConfigurationAction, auth.PermissionRead),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("acl"),
		controllers.ProcessHandlers(
			ctrl.GetBucketAcl,
			metrics.ActionGetBucketAcl,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionGetBucketAcl, auth.GetBucketAclAction, auth.PermissionReadAcp),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("uploads"),
		controllers.ProcessHandlers(
			ctrl.ListMultipartUploads,
			metrics.ActionListMultipartUploads,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionListMultipartUploads, auth.ListBucketMultipartUploadsAction, auth.PermissionRead),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("versions"),
		controllers.ProcessHandlers(
			ctrl.ListObjectVersions,
			metrics.ActionListObjectVersions,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionListObjectVersions, auth.ListBucketVersionsAction, auth.PermissionRead),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	bucketRouter.Get("",
		middlewares.MatchQueryArgWithValue("list-type", "2"),
		controllers.ProcessHandlers(
			ctrl.ListObjectsV2,
			metrics.ActionListObjectsV2,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionListObjectsV2, auth.ListBucketAction, auth.PermissionRead),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	bucketRouter.Get("",
		controllers.ProcessHandlers(
			ctrl.ListObjects,
			metrics.ActionListObjects,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionListObjects, auth.ListBucketAction, auth.PermissionRead),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))

	// DeleteObjects action
	bucketRouter.Post("",
		middlewares.MatchQueryArgs("delete"),
		controllers.ProcessHandlers(
			ctrl.DeleteObjects,
			metrics.ActionDeleteObjects,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionDeleteObjects, auth.DeleteObjectAction, auth.PermissionWrite),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))

	// HeadObject
	objectRouter.Head("",
		controllers.ProcessHandlers(
			ctrl.HeadObject,
			metrics.ActionHeadObject,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionHeadObject, auth.GetObjectAction, auth.PermissionRead),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))

	// GET object operations
	objectRouter.Get("",
		middlewares.MatchQueryArgs("tagging"),
		controllers.ProcessHandlers(
			ctrl.GetObjectTagging,
			metrics.ActionGetObjectTagging,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionGetObjectTagging, auth.GetObjectTaggingAction, auth.PermissionRead),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	objectRouter.Get("",
		middlewares.MatchQueryArgs("retention"),
		controllers.ProcessHandlers(
			ctrl.GetObjectRetention,
			metrics.ActionGetObjectRetention,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionGetObjectRetention, auth.GetObjectRetentionAction, auth.PermissionRead),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	objectRouter.Get("",
		middlewares.MatchQueryArgs("legal-hold"),
		controllers.ProcessHandlers(
			ctrl.GetObjectLegalHold,
			metrics.ActionGetObjectLegalHold,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionGetObjectLegalHold, auth.GetObjectLegalHoldAction, auth.PermissionRead),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	objectRouter.Get("",
		middlewares.MatchQueryArgs("acl"),
		controllers.ProcessHandlers(
			ctrl.GetObjectAcl,
			metrics.ActionGetObjectAcl,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionGetObjectAcl, auth.GetObjectAclAction, auth.PermissionReadAcp),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	objectRouter.Get("",
		middlewares.MatchQueryArgs("attributes"),
		controllers.ProcessHandlers(
			ctrl.GetObjectAttributes,
			metrics.ActionGetObjectAttributes,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionGetObjectAttributes, auth.GetObjectAttributesAction, auth.PermissionRead),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	objectRouter.Get("",
		middlewares.MatchQueryArgs("uploadId"),
		controllers.ProcessHandlers(
			ctrl.ListParts,
			metrics.ActionListParts,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionListParts, auth.ListMultipartUploadPartsAction, auth.PermissionRead),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	objectRouter.Get("",
		controllers.ProcessHandlers(
			ctrl.GetObject,
			metrics.ActionGetObject,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionGetObject, auth.GetObjectAction, auth.PermissionRead),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))

	// DELETE object operations
	objectRouter.Delete("",
		middlewares.MatchQueryArgs("tagging"),
		controllers.ProcessHandlers(
			ctrl.DeleteObjectTagging,
			metrics.ActionDeleteObjectTagging,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionDeleteObjectTagging, auth.DeleteObjectTaggingAction, auth.PermissionWrite),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	objectRouter.Delete("",
		middlewares.MatchQueryArgs("uploadId"),
		controllers.ProcessHandlers(
			ctrl.AbortMultipartUpload,
			metrics.ActionAbortMultipartUpload,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionAbortMultipartUpload, auth.AbortMultipartUploadAction, auth.PermissionWrite),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	objectRouter.Delete("",
		controllers.ProcessHandlers(
			ctrl.DeleteObject,
			metrics.ActionDeleteObject,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionDeleteObject, auth.DeleteObjectAction, auth.PermissionWrite),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))

	objectRouter.Post("",
		middlewares.MatchQueryArgs("restore"),
		controllers.ProcessHandlers(
			ctrl.RestoreObject,
			metrics.ActionRestoreObject,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionRestoreObject, auth.RestoreObjectAction, auth.PermissionWrite),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	objectRouter.Post("",
		middlewares.MatchQueryArgs("select"),
		middlewares.MatchQueryArgWithValue("select-type", "2"),
		controllers.ProcessHandlers(
			ctrl.SelectObjectContent,
			metrics.ActionSelectObjectContent,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionSelectObjectContent, auth.GetObjectAction, auth.PermissionRead),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	objectRouter.Post("",
		middlewares.MatchQueryArgs("uploadId"),
		controllers.ProcessHandlers(
			ctrl.CompleteMultipartUpload,
			metrics.ActionCompleteMultipartUpload,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionCompleteMultipartUpload, auth.PutObjectAction, auth.PermissionWrite),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	objectRouter.Post("",
		middlewares.MatchQueryArgs("uploads"),
		controllers.ProcessHandlers(
			ctrl.CreateMultipartUpload,
			metrics.ActionCreateMultipartUpload,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionCreateMultipartUpload, auth.PutObjectAction, auth.PermissionWrite),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))

	// PUT object operations
	objectRouter.Put("",
		middlewares.MatchQueryArgs("tagging"),
		controllers.ProcessHandlers(
			ctrl.PutObjectTagging,
			metrics.ActionPutObjectTagging,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionPutObjectTagging, auth.PutObjectTaggingAction, auth.PermissionWrite),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	objectRouter.Put("",
		middlewares.MatchQueryArgs("retention"),
		controllers.ProcessHandlers(
			ctrl.PutObjectRetention,
			metrics.ActionPutObjectRetention,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionPutObjectRetention, auth.PutObjectRetentionAction, auth.PermissionWrite),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	objectRouter.Put("",
		middlewares.MatchQueryArgs("legal-hold"),
		controllers.ProcessHandlers(
			ctrl.PutObjectLegalHold,
			metrics.ActionPutObjectLegalHold,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionPutObjectLegalHold, auth.PutObjectLegalHoldAction, auth.PermissionWrite),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	objectRouter.Put("",
		middlewares.MatchQueryArgs("acl"),
		controllers.ProcessHandlers(
			ctrl.PutObjectAcl,
			metrics.ActionPutObjectAcl,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionPutObjectAcl, auth.PutObjectAclAction, auth.PermissionWriteAcp),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	objectRouter.Put("",
		middlewares.MatchQueryArgs("uploadId", "partNumber"),
		middlewares.MatchHeader("X-Amz-Copy-Source"),
		controllers.ProcessHandlers(
			ctrl.UploadPartCopy,
			metrics.ActionUploadPartCopy,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionUploadPartCopy, auth.PutObjectAction, auth.PermissionWrite),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	objectRouter.Put("",
		middlewares.MatchQueryArgs("uploadId", "partNumber"),
		controllers.ProcessHandlers(
			ctrl.UploadPart,
			metrics.ActionUploadPart,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionUploadPart, auth.PutObjectAction, auth.PermissionWrite),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))

	// return error if partNumber is used without uploadId
	objectRouter.Put("",
		middlewares.MatchQueryArgs("partNumber"),
		controllers.ProcessHandlers(ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrMissingUploadId)), metrics.ActionUndetected, services))

	// return 'MethodNotAllowed' if uploadId is provided without partNumber
	// before the router reaches to 'PutObject'
	objectRouter.Put("",
		middlewares.MatchQueryArgs("uploadId"),
		controllers.ProcessHandlers(ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrMethodNotAllowed)), metrics.ActionUndetected, services))

	objectRouter.Put("",
		middlewares.MatchHeader("X-Amz-Copy-Source"),
		controllers.ProcessHandlers(
			ctrl.CopyObject,
			metrics.ActionCopyObject,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionCopyObject, auth.PutObjectAction, auth.PermissionWrite),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))
	objectRouter.Put("",
		controllers.ProcessHandlers(
			ctrl.PutObject,
			metrics.ActionPutObject,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(be, metrics.ActionPutObject, auth.PutObjectAction, auth.PermissionWrite),
			middlewares.VerifyPresignedV4Signature(root, iam, region, debug),
			middlewares.VerifyV4Signature(root, iam, region, debug),
			middlewares.VerifyMD5Body(),
			middlewares.ParseAcl(be),
		))

	// Return MethodNotAllowed for all the unmatched routes
	app.All("*", controllers.ProcessHandlers(ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrMethodNotAllowed)), metrics.ActionUndetected, services))
}
