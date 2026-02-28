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
	WithAdmSrv      bool
	app             *fiber.App
	be              backend.Backend
	iam             auth.IAMService
	logger          s3log.AuditLogger
	aLogger         s3log.AuditLogger
	evs             s3event.S3EventSender
	mm              metrics.Manager
	root            middlewares.RootUserConfig
	Ctrl            controllers.S3ApiController
	readonly        bool
	disableACL      bool
	region          string
	virtualDomain   string
	corsAllowOrigin string
}

func (sa *S3ApiRouter) Init() {
	ctrl := controllers.New(sa.be, sa.iam, sa.logger, sa.evs, sa.mm, sa.readonly, sa.disableACL, sa.virtualDomain)
	sa.Ctrl = ctrl
	adminServices := &controllers.Services{
		Logger: sa.aLogger,
	}

	// initialize global host-style parser middleware if virtual domain is specified
	if sa.virtualDomain != "" {
		sa.app.Use(middlewares.HostStyleParser(sa.virtualDomain))
	}

	if sa.WithAdmSrv {
		adminController := controllers.NewAdminController(sa.iam, sa.be, sa.aLogger, ctrl)

		// CreateUser admin api
		sa.app.Patch("/create-user",
			controllers.ProcessHandlers(adminController.CreateUser, metrics.ActionAdminCreateUser, adminServices,
				middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
				middlewares.IsAdmin(metrics.ActionAdminCreateUser),
				middlewares.ApplyDefaultCORS(sa.corsAllowOrigin),
			))
		sa.app.Options("/create-user",
			middlewares.ApplyDefaultCORSPreflight(sa.corsAllowOrigin),
			middlewares.ApplyDefaultCORS(sa.corsAllowOrigin),
		)

		// DeleteUsers admin api
		sa.app.Patch("/delete-user",
			controllers.ProcessHandlers(adminController.DeleteUser, metrics.ActionAdminDeleteUser, adminServices,
				middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
				middlewares.IsAdmin(metrics.ActionAdminDeleteUser),
				middlewares.ApplyDefaultCORS(sa.corsAllowOrigin),
			))
		sa.app.Options("/delete-user",
			middlewares.ApplyDefaultCORSPreflight(sa.corsAllowOrigin),
			middlewares.ApplyDefaultCORS(sa.corsAllowOrigin),
		)

		// UpdateUser admin api
		sa.app.Patch("/update-user",
			controllers.ProcessHandlers(adminController.UpdateUser, metrics.ActionAdminUpdateUser, adminServices,
				middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
				middlewares.IsAdmin(metrics.ActionAdminUpdateUser),
				middlewares.ApplyDefaultCORS(sa.corsAllowOrigin),
			))
		sa.app.Options("/update-user",
			middlewares.ApplyDefaultCORSPreflight(sa.corsAllowOrigin),
			middlewares.ApplyDefaultCORS(sa.corsAllowOrigin),
		)

		// ListUsers admin api
		sa.app.Patch("/list-users",
			controllers.ProcessHandlers(adminController.ListUsers, metrics.ActionAdminListUsers, adminServices,
				middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
				middlewares.IsAdmin(metrics.ActionAdminListUsers),
				middlewares.ApplyDefaultCORS(sa.corsAllowOrigin),
			))
		sa.app.Options("/list-users",
			middlewares.ApplyDefaultCORSPreflight(sa.corsAllowOrigin),
			middlewares.ApplyDefaultCORS(sa.corsAllowOrigin),
		)

		// ChangeBucketOwner admin api
		sa.app.Patch("/change-bucket-owner",
			controllers.ProcessHandlers(adminController.ChangeBucketOwner, metrics.ActionAdminChangeBucketOwner, adminServices,
				middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
				middlewares.IsAdmin(metrics.ActionAdminChangeBucketOwner),
				middlewares.ApplyDefaultCORS(sa.corsAllowOrigin),
			))
		sa.app.Options("/change-bucket-owner",
			middlewares.ApplyDefaultCORSPreflight(sa.corsAllowOrigin),
			middlewares.ApplyDefaultCORS(sa.corsAllowOrigin),
		)

		// ListBucketsAndOwners admin api
		sa.app.Patch("/list-buckets",
			controllers.ProcessHandlers(adminController.ListBuckets, metrics.ActionAdminListBuckets, adminServices,
				middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
				middlewares.IsAdmin(metrics.ActionAdminListBuckets),
				middlewares.ApplyDefaultCORS(sa.corsAllowOrigin),
			))
		sa.app.Options("/list-buckets",
			middlewares.ApplyDefaultCORSPreflight(sa.corsAllowOrigin),
			middlewares.ApplyDefaultCORS(sa.corsAllowOrigin),
		)

		// CreateBucket admin api
		sa.app.Patch("/:bucket/create",
			controllers.ProcessHandlers(adminController.CreateBucket, metrics.ActionAdminCreateBucket, adminServices,
				middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
				middlewares.IsAdmin(metrics.ActionAdminCreateBucket),
				middlewares.ApplyDefaultCORS(sa.corsAllowOrigin),
			))
		sa.app.Options("/:bucket/create",
			middlewares.ApplyDefaultCORSPreflight(sa.corsAllowOrigin),
			middlewares.ApplyDefaultCORS(sa.corsAllowOrigin),
		)
	}

	services := &controllers.Services{
		Logger:         sa.logger,
		EventSender:    sa.evs,
		MetricsManager: sa.mm,
	}

	// ListBuckets action

	// copy source is not allowed on '/'
	sa.app.Get("/", middlewares.MatchHeader("X-Amz-Copy-Source"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrCopySourceNotAllowed)),
			metrics.ActionUndetected,
			services,
			middlewares.ApplyDefaultCORS(sa.corsAllowOrigin),
		),
	)

	sa.app.Get("/",
		controllers.ProcessHandlers(
			ctrl.ListBuckets,
			metrics.ActionListAllMyBuckets,
			services,
			middlewares.ApplyDefaultCORS(sa.corsAllowOrigin),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionListAllMyBuckets, "", auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
		))

	sa.app.Options("/",
		middlewares.ApplyDefaultCORSPreflight(sa.corsAllowOrigin),
		middlewares.ApplyDefaultCORS(sa.corsAllowOrigin),
	)

	bucketRouter := sa.app.Group("/:bucket")
	objectRouter := sa.app.Group("/:bucket/*")

	// PUT bucket operations
	bucketRouter.Put("",
		middlewares.MatchQueryArgs("tagging"),
		controllers.ProcessHandlers(
			ctrl.PutBucketTagging,
			metrics.ActionPutBucketTagging,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionPutBucketTagging, auth.PutBucketTaggingAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.VerifyChecksums(false, true, true),
			middlewares.ParseAcl(sa.be),
		))
	bucketRouter.Put("",
		middlewares.MatchQueryArgs("ownershipControls"),
		controllers.ProcessHandlers(
			ctrl.PutBucketOwnershipControls,
			metrics.ActionPutBucketOwnershipControls,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionPutBucketOwnershipControls, auth.PutBucketOwnershipControlsAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.VerifyChecksums(false, true, false),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	bucketRouter.Put("",
		middlewares.MatchQueryArgs("versioning"),
		controllers.ProcessHandlers(
			ctrl.PutBucketVersioning,
			metrics.ActionPutBucketVersioning,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionPutBucketVersioning, auth.PutBucketVersioningAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.VerifyChecksums(false, true, false),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	bucketRouter.Put("",
		middlewares.MatchQueryArgs("object-lock"),
		controllers.ProcessHandlers(
			ctrl.PutObjectLockConfiguration,
			metrics.ActionPutObjectLockConfiguration,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionPutObjectLockConfiguration, auth.PutBucketObjectLockConfigurationAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.VerifyChecksums(false, true, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	bucketRouter.Put("",
		middlewares.MatchQueryArgs("cors"),
		controllers.ProcessHandlers(
			ctrl.PutBucketCors,
			metrics.ActionPutBucketCors,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionPutBucketCors, auth.PutBucketCorsAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.VerifyChecksums(false, true, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	bucketRouter.Put("",
		middlewares.MatchQueryArgs("policy"),
		controllers.ProcessHandlers(
			ctrl.PutBucketPolicy,
			metrics.ActionPutBucketPolicy,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionPutBucketPolicy, auth.PutBucketPolicyAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.VerifyChecksums(false, false, false),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	bucketRouter.Put("",
		middlewares.MatchQueryArgs("acl"),
		controllers.ProcessHandlers(
			ctrl.PutBucketAcl,
			metrics.ActionPutBucketAcl,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionPutBucketAcl, auth.PutBucketAclAction, auth.PermissionWriteAcp, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.VerifyChecksums(false, false, false),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	bucketRouter.Put("",
		middlewares.MatchQueryArgs("analytics"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionPutBucketAnalyticsConfiguration,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionPutBucketAnalyticsConfiguration, auth.PutAnalyticsConfigurationAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Put("",
		middlewares.MatchQueryArgs("encryption"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionPutBucketEncryption,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionPutBucketEncryption, auth.PutEncryptionConfigurationAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Put("",
		middlewares.MatchQueryArgs("intelligent-tiering"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionPutBucketIntelligentTieringConfiguration,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionPutBucketIntelligentTieringConfiguration, auth.PutIntelligentTieringConfigurationAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Put("",
		middlewares.MatchQueryArgs("inventory"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionPutBucketInventoryConfiguration,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionPutBucketInventoryConfiguration, auth.PutInventoryConfigurationAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Put("",
		middlewares.MatchQueryArgs("lifecycle"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionPutBucketLifecycleConfiguration,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionPutBucketLifecycleConfiguration, auth.PutLifecycleConfigurationAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Put("",
		middlewares.MatchQueryArgs("logging"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionPutBucketLogging,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionPutBucketLogging, auth.PutBucketLoggingAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Put("",
		middlewares.MatchQueryArgs("requestPayment"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionPutBucketRequestPayment,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionPutBucketRequestPayment, auth.PutBucketRequestPaymentAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Put("",
		middlewares.MatchQueryArgs("metrics"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionPutBucketMetricsConfiguration,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionPutBucketMetricsConfiguration, auth.PutMetricsConfigurationAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Put("",
		middlewares.MatchQueryArgs("replication"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionPutBucketReplication,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionPutBucketReplication, auth.PutReplicationConfigurationAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Put("",
		middlewares.MatchQueryArgs("publicAccessBlock"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionPutPublicAccessBlock,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionPutPublicAccessBlock, auth.PutBucketPublicAccessBlockAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Put("",
		middlewares.MatchQueryArgs("notification"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionPutBucketNotificationConfiguration,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionPutBucketNotificationConfiguration, auth.PutBucketNotificationAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Put("",
		middlewares.MatchQueryArgs("accelerate"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionPutBucketAccelerateConfiguration,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionPutBucketAccelerateConfiguration, auth.PutAccelerateConfigurationAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Put("",
		middlewares.MatchQueryArgs("website"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionPutBucketWebsite,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionPutBucketWebsite, auth.PutBucketWebsiteAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Put("",
		controllers.ProcessHandlers(
			ctrl.CreateBucket,
			metrics.ActionCreateBucket,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionCreateBucket, auth.CreateBucketAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.VerifyChecksums(false, false, false),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
		))

	// HeadBucket action

	// copy source is not allowed on bucket HEAD operation
	bucketRouter.Head("/", middlewares.MatchHeader("X-Amz-Copy-Source"),
		controllers.ProcessHandlers(ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrCopySourceNotAllowed)), metrics.ActionUndetected, services),
	)

	bucketRouter.Head("",
		controllers.ProcessHandlers(
			ctrl.HeadBucket,
			metrics.ActionHeadBucket,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionHeadBucket, auth.ListBucketAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, false),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))

	// DELETE bucket operations

	// copy source is not allowed on bucket DELETE operation
	bucketRouter.Delete("/", middlewares.MatchHeader("X-Amz-Copy-Source"),
		controllers.ProcessHandlers(ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrCopySourceNotAllowed)), metrics.ActionUndetected, services),
	)

	bucketRouter.Delete("",
		middlewares.MatchQueryArgs("tagging"),
		controllers.ProcessHandlers(
			ctrl.DeleteBucketTagging,
			metrics.ActionDeleteBucketTagging,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionDeleteBucketTagging, auth.PutBucketTaggingAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	bucketRouter.Delete("",
		middlewares.MatchQueryArgs("ownershipControls"),
		controllers.ProcessHandlers(
			ctrl.DeleteBucketOwnershipControls,
			metrics.ActionDeleteBucketOwnershipControls,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionDeleteBucketOwnershipControls, auth.PutBucketOwnershipControlsAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	bucketRouter.Delete("",
		middlewares.MatchQueryArgs("policy"),
		controllers.ProcessHandlers(
			ctrl.DeleteBucketPolicy,
			metrics.ActionDeleteBucketPolicy,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionDeleteBucketPolicy, auth.PutBucketPolicyAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	bucketRouter.Delete("",
		middlewares.MatchQueryArgs("cors"),
		controllers.ProcessHandlers(
			ctrl.DeleteBucketCors,
			metrics.ActionDeleteBucketCors,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionDeleteBucketCors, auth.PutBucketCorsAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	bucketRouter.Delete("",
		middlewares.MatchQueryArgs("analytics"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionDeleteBucketAnalyticsConfiguration,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionDeleteBucketAnalyticsConfiguration, auth.PutAnalyticsConfigurationAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Delete("",
		middlewares.MatchQueryArgs("encryption"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionDeleteBucketEncryption,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionDeleteBucketEncryption, auth.PutEncryptionConfigurationAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Delete("",
		middlewares.MatchQueryArgs("intelligent-tiering"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionDeleteBucketIntelligentTieringConfiguration,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionDeleteBucketIntelligentTieringConfiguration, auth.PutIntelligentTieringConfigurationAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Delete("",
		middlewares.MatchQueryArgs("inventory"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionDeleteBucketInventoryConfiguration,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionDeleteBucketInventoryConfiguration, auth.PutInventoryConfigurationAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Delete("",
		middlewares.MatchQueryArgs("lifecycle"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionDeleteBucketLifecycle,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionDeleteBucketLifecycle, auth.PutLifecycleConfigurationAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Delete("",
		middlewares.MatchQueryArgs("metrics"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionDeleteBucketMetricsConfiguration,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionDeleteBucketMetricsConfiguration, auth.PutMetricsConfigurationAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Delete("",
		middlewares.MatchQueryArgs("replication"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionDeleteBucketReplication,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionDeleteBucketReplication, auth.PutReplicationConfigurationAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Delete("",
		middlewares.MatchQueryArgs("publicAccessBlock"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionDeletePublicAccessBlock,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionDeletePublicAccessBlock, auth.PutBucketPublicAccessBlockAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Delete("",
		middlewares.MatchQueryArgs("website"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionDeleteBucketWebsite,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionDeleteBucketWebsite, auth.PutBucketWebsiteAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Delete("",
		controllers.ProcessHandlers(
			ctrl.DeleteBucket,
			metrics.ActionDeleteBucket,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionDeleteBucket, auth.DeleteBucketAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))

	// GET bucket operations

	// copy source is not allowed on bucket GET operation
	bucketRouter.Get("/", middlewares.MatchHeader("X-Amz-Copy-Source"),
		controllers.ProcessHandlers(ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrCopySourceNotAllowed)), metrics.ActionUndetected, services),
	)

	bucketRouter.Get("",
		middlewares.MatchQueryArgs("location"),
		controllers.ProcessHandlers(
			ctrl.GetBucketLocation,
			metrics.ActionGetBucketLocation,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionGetBucketLocation, auth.GetBucketLocationAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("tagging"),
		controllers.ProcessHandlers(
			ctrl.GetBucketTagging,
			metrics.ActionGetBucketTagging,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionGetBucketTagging, auth.GetBucketTaggingAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("ownershipControls"),
		controllers.ProcessHandlers(
			ctrl.GetBucketOwnershipControls,
			metrics.ActionGetBucketOwnershipControls,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionGetBucketOwnershipControls, auth.GetBucketOwnershipControlsAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("versioning"),
		controllers.ProcessHandlers(
			ctrl.GetBucketVersioning,
			metrics.ActionGetBucketVersioning,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionGetBucketVersioning, auth.GetBucketVersioningAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("policy"),
		controllers.ProcessHandlers(
			ctrl.GetBucketPolicy,
			metrics.ActionGetBucketPolicy,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionGetBucketPolicy, auth.GetBucketPolicyAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("cors"),
		controllers.ProcessHandlers(
			ctrl.GetBucketCors,
			metrics.ActionGetBucketCors,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionGetBucketCors, auth.GetBucketCorsAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("object-lock"),
		controllers.ProcessHandlers(
			ctrl.GetObjectLockConfiguration,
			metrics.ActionGetObjectLockConfiguration,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionGetObjectLockConfiguration, auth.GetBucketObjectLockConfigurationAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("acl"),
		controllers.ProcessHandlers(
			ctrl.GetBucketAcl,
			metrics.ActionGetBucketAcl,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionGetBucketAcl, auth.GetBucketAclAction, auth.PermissionReadAcp, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, false),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("uploads"),
		controllers.ProcessHandlers(
			ctrl.ListMultipartUploads,
			metrics.ActionListMultipartUploads,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionListMultipartUploads, auth.ListBucketMultipartUploadsAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("versions"),
		controllers.ProcessHandlers(
			ctrl.ListObjectVersions,
			metrics.ActionListObjectVersions,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionListObjectVersions, auth.ListBucketVersionsAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("policyStatus"),
		controllers.ProcessHandlers(
			ctrl.GetBucketPolicyStatus,
			metrics.ActionGetBucketPolicyStatus,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionGetBucketPolicyStatus, auth.GetBucketPolicyStatusAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("analytics", "id"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionGetBucketAnalyticsConfiguration,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionGetBucketAnalyticsConfiguration, auth.GetAnalyticsConfigurationAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("analytics"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionListBucketAnalyticsConfigurations,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionListBucketAnalyticsConfigurations, auth.GetAnalyticsConfigurationAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("encryption"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionGetBucketEncryption,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionGetBucketEncryption, auth.GetEncryptionConfigurationAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("intelligent-tiering", "id"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionGetBucketIntelligentTieringConfiguration,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionGetBucketIntelligentTieringConfiguration, auth.GetIntelligentTieringConfigurationAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("intelligent-tiering"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionListBucketIntelligentTieringConfigurations,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionListBucketIntelligentTieringConfigurations, auth.GetIntelligentTieringConfigurationAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("inventory", "id"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionGetBucketInventoryConfiguration,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionGetBucketInventoryConfiguration, auth.GetInventoryConfigurationAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("inventory"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionListBucketInventoryConfigurations,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionListBucketInventoryConfigurations, auth.GetInventoryConfigurationAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("lifecycle"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionGetBucketLifecycleConfiguration,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionGetBucketLifecycleConfiguration, auth.GetLifecycleConfigurationAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("logging"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionGetBucketLogging,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionGetBucketLogging, auth.GetBucketLoggingAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("requestPayment"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionGetBucketRequestPayment,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionGetBucketRequestPayment, auth.GetBucketRequestPaymentAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("metrics", "id"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionGetBucketMetricsConfiguration,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionGetBucketMetricsConfiguration, auth.GetMetricsConfigurationAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("metrics"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionListBucketMetricsConfigurations,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionListBucketMetricsConfigurations, auth.GetMetricsConfigurationAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("replication"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionGetBucketReplication,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionGetBucketReplication, auth.GetReplicationConfigurationAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("publicAccessBlock"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionGetPublicAccessBlock,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionGetPublicAccessBlock, auth.GetBucketPublicAccessBlockAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("notification"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionGetBucketNotificationConfiguration,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionGetBucketNotificationConfiguration, auth.GetBucketNotificationAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("accelerate"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionGetBucketAccelerateConfiguration,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionGetBucketAccelerateConfiguration, auth.GetAccelerateConfigurationAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Get("",
		middlewares.MatchQueryArgs("website"),
		controllers.ProcessHandlers(
			ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrNotImplemented)),
			metrics.ActionGetBucketWebsite,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionGetBucketWebsite, auth.GetBucketWebsiteAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		),
	)
	bucketRouter.Get("",
		middlewares.MatchQueryArgWithValue("list-type", "2"),
		controllers.ProcessHandlers(
			ctrl.ListObjectsV2,
			metrics.ActionListObjectsV2,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionListObjectsV2, auth.ListBucketAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	bucketRouter.Get("",
		controllers.ProcessHandlers(
			ctrl.ListObjects,
			metrics.ActionListObjects,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionListObjects, auth.ListBucketAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))

	// bucket POST operation is not allowed with uploadId and copy source
	bucketRouter.Post("/",
		middlewares.MatchHeader("X-Amz-Copy-Source"),
		middlewares.MatchQueryArgs("uploadId"),
		controllers.ProcessHandlers(ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrCopySourceNotAllowed)), metrics.ActionUndetected, services),
	)

	// DeleteObjects action
	bucketRouter.Post("",
		middlewares.MatchQueryArgs("delete"),
		controllers.ProcessHandlers(
			ctrl.DeleteObjects,
			metrics.ActionDeleteObjects,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionDeleteObjects, auth.DeleteObjectAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.VerifyChecksums(false, true, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))

	// object HEAD operation is not allowed with copy source
	objectRouter.Head("/",
		middlewares.MatchHeader("X-Amz-Copy-Source"),
		controllers.ProcessHandlers(ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrCopySourceNotAllowed)), metrics.ActionUndetected, services),
	)

	// HeadObject
	objectRouter.Head("",
		controllers.ProcessHandlers(
			ctrl.HeadObject,
			metrics.ActionHeadObject,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionHeadObject, auth.GetObjectAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, false),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))

	// GET object operations

	// object operation with '?uploads' is rejected with a specific error
	objectRouter.Get("",
		middlewares.MatchQueryArgs("uploads"),
		controllers.ProcessHandlers(ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrGetUploadsWithKey)), metrics.ActionUndetected, services),
	)

	// object operation with '?versions' is rejected with a specific error
	objectRouter.Get("",
		middlewares.MatchQueryArgs("versions"),
		controllers.ProcessHandlers(ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrVersionsWithKey)), metrics.ActionUndetected, services),
	)

	// object GET operation is not allowed with copy source
	objectRouter.Get("/",
		middlewares.MatchHeader("X-Amz-Copy-Source"),
		controllers.ProcessHandlers(ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrCopySourceNotAllowed)), metrics.ActionUndetected, services),
	)

	objectRouter.Get("",
		middlewares.MatchQueryArgs("tagging"),
		controllers.ProcessHandlers(
			ctrl.GetObjectTagging,
			metrics.ActionGetObjectTagging,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionGetObjectTagging, auth.GetObjectTaggingAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	objectRouter.Get("",
		middlewares.MatchQueryArgs("retention"),
		controllers.ProcessHandlers(
			ctrl.GetObjectRetention,
			metrics.ActionGetObjectRetention,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionGetObjectRetention, auth.GetObjectRetentionAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	objectRouter.Get("",
		middlewares.MatchQueryArgs("legal-hold"),
		controllers.ProcessHandlers(
			ctrl.GetObjectLegalHold,
			metrics.ActionGetObjectLegalHold,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionGetObjectLegalHold, auth.GetObjectLegalHoldAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	objectRouter.Get("",
		middlewares.MatchQueryArgs("acl"),
		controllers.ProcessHandlers(
			ctrl.GetObjectAcl,
			metrics.ActionGetObjectAcl,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionGetObjectAcl, auth.GetObjectAclAction, auth.PermissionReadAcp, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	objectRouter.Get("",
		middlewares.MatchQueryArgs("attributes"),
		controllers.ProcessHandlers(
			ctrl.GetObjectAttributes,
			metrics.ActionGetObjectAttributes,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionGetObjectAttributes, auth.GetObjectAttributesAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	objectRouter.Get("",
		middlewares.MatchQueryArgs("uploadId"),
		controllers.ProcessHandlers(
			ctrl.ListParts,
			metrics.ActionListParts,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionListParts, auth.ListMultipartUploadPartsAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	objectRouter.Get("",
		controllers.ProcessHandlers(
			ctrl.GetObject,
			metrics.ActionGetObject,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionGetObject, auth.GetObjectAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))

	// DELETE object operations

	// object DELETE operation is not allowed with copy source
	objectRouter.Delete("/",
		middlewares.MatchHeader("X-Amz-Copy-Source"),
		controllers.ProcessHandlers(ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrCopySourceNotAllowed)), metrics.ActionUndetected, services),
	)

	objectRouter.Delete("",
		middlewares.MatchQueryArgs("tagging"),
		controllers.ProcessHandlers(
			ctrl.DeleteObjectTagging,
			metrics.ActionDeleteObjectTagging,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionDeleteObjectTagging, auth.DeleteObjectTaggingAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	objectRouter.Delete("",
		middlewares.MatchQueryArgs("uploadId"),
		controllers.ProcessHandlers(
			ctrl.AbortMultipartUpload,
			metrics.ActionAbortMultipartUpload,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionAbortMultipartUpload, auth.AbortMultipartUploadAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	objectRouter.Delete("",
		controllers.ProcessHandlers(
			ctrl.DeleteObject,
			metrics.ActionDeleteObject,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionDeleteObject, auth.DeleteObjectAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))

	// object POST operations

	// object POST operation is not allowed with copy source and uploadId
	objectRouter.Post("/",
		middlewares.MatchHeader("X-Amz-Copy-Source"),
		middlewares.MatchQueryArgs("uploadId"),
		controllers.ProcessHandlers(ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrCopySourceNotAllowed)), metrics.ActionUndetected, services),
	)

	objectRouter.Post("",
		middlewares.MatchQueryArgs("restore"),
		controllers.ProcessHandlers(
			ctrl.RestoreObject,
			metrics.ActionRestoreObject,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionRestoreObject, auth.RestoreObjectAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.VerifyChecksums(false, false, false),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	objectRouter.Post("",
		middlewares.MatchQueryArgs("select"),
		middlewares.MatchQueryArgWithValue("select-type", "2"),
		controllers.ProcessHandlers(
			ctrl.SelectObjectContent,
			metrics.ActionSelectObjectContent,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionSelectObjectContent, auth.GetObjectAction, auth.PermissionRead, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.VerifyChecksums(false, false, false),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	objectRouter.Post("",
		middlewares.MatchQueryArgs("uploadId"),
		controllers.ProcessHandlers(
			ctrl.CompleteMultipartUpload,
			metrics.ActionCompleteMultipartUpload,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionCompleteMultipartUpload, auth.PutObjectAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	objectRouter.Post("",
		middlewares.MatchQueryArgs("uploads"),
		controllers.ProcessHandlers(
			ctrl.CreateMultipartUpload,
			metrics.ActionCreateMultipartUpload,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionCreateMultipartUpload, auth.PutObjectAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))

	// PUT object operations
	objectRouter.Put("",
		middlewares.MatchQueryArgs("tagging"),
		controllers.ProcessHandlers(
			ctrl.PutObjectTagging,
			metrics.ActionPutObjectTagging,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionPutObjectTagging, auth.PutObjectTaggingAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.VerifyChecksums(false, true, false),
			middlewares.ParseAcl(sa.be),
		))
	objectRouter.Put("",
		middlewares.MatchQueryArgs("retention"),
		controllers.ProcessHandlers(
			ctrl.PutObjectRetention,
			metrics.ActionPutObjectRetention,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionPutObjectRetention, auth.PutObjectRetentionAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.VerifyChecksums(false, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	objectRouter.Put("",
		middlewares.MatchQueryArgs("legal-hold"),
		controllers.ProcessHandlers(
			ctrl.PutObjectLegalHold,
			metrics.ActionPutObjectLegalHold,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionPutObjectLegalHold, auth.PutObjectLegalHoldAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.VerifyChecksums(false, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	objectRouter.Put("",
		middlewares.MatchQueryArgs("acl"),
		controllers.ProcessHandlers(
			ctrl.PutObjectAcl,
			metrics.ActionPutObjectAcl,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionPutObjectAcl, auth.PutObjectAclAction, auth.PermissionWriteAcp, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.VerifyChecksums(false, false, false),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	objectRouter.Put("",
		middlewares.MatchQueryArgs("uploadId", "partNumber"),
		middlewares.MatchHeader("X-Amz-Copy-Source"),
		controllers.ProcessHandlers(
			ctrl.UploadPartCopy,
			metrics.ActionUploadPartCopy,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionUploadPartCopy, auth.PutObjectAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
		))
	objectRouter.Put("",
		middlewares.MatchQueryArgs("uploadId", "partNumber"),
		controllers.ProcessHandlers(
			ctrl.UploadPart,
			metrics.ActionUploadPart,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionUploadPart, auth.PutObjectAction, auth.PermissionWrite, sa.region, true),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, true),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, true, true),
			middlewares.VerifyChecksums(true, false, false),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.ParseAcl(sa.be),
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
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionCopyObject, auth.PutObjectAction, auth.PermissionWrite, sa.region, false),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, false),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, false, true),
			middlewares.ParseAcl(sa.be),
		))
	objectRouter.Put("",
		controllers.ProcessHandlers(
			ctrl.PutObject,
			metrics.ActionPutObject,
			services,
			middlewares.BucketObjectNameValidator(),
			middlewares.ApplyBucketCORS(sa.be, sa.corsAllowOrigin),
			middlewares.AuthorizePublicBucketAccess(sa.be, metrics.ActionPutObject, auth.PutObjectAction, auth.PermissionWrite, sa.region, true),
			middlewares.VerifyPresignedV4Signature(sa.root, sa.iam, sa.region, true),
			middlewares.VerifyV4Signature(sa.root, sa.iam, sa.region, true, true),
			middlewares.VerifyChecksums(true, false, false),
			middlewares.ParseAcl(sa.be),
		))

	sa.app.Options("/:bucket",
		middlewares.ApplyBucketCORSPreflightFallback(sa.be, sa.corsAllowOrigin),
		controllers.ProcessHandlers(ctrl.CORSOptions, metrics.ActionOptions, services,
			middlewares.BucketObjectNameValidator(),
			middlewares.ParseAcl(sa.be),
		),
	)

	sa.app.Options("/:bucket/*",
		middlewares.ApplyBucketCORSPreflightFallback(sa.be, sa.corsAllowOrigin),
		controllers.ProcessHandlers(ctrl.CORSOptions, metrics.ActionOptions, services,
			middlewares.BucketObjectNameValidator(),
			middlewares.ParseAcl(sa.be),
		),
	)

	// Return MethodNotAllowed for all the unmatched routes
	sa.app.All("*", controllers.ProcessHandlers(ctrl.HandleErrorRoute(s3err.GetAPIError(s3err.ErrMethodNotAllowed)), metrics.ActionUndetected, services))
}
