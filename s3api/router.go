package s3api

import (
	"github.com/gofiber/fiber/v2"
	"github.com/versity/scoutgw/backend"
	"github.com/versity/scoutgw/s3api/controllers"
)

type S3ApiRouter struct{}

func (sa *S3ApiRouter) Init(app *fiber.App, be backend.Backend) {
	s3ApiController := controllers.New(be)
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
