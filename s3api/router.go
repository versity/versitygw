package s3api

import (
	"encoding/xml"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/scoutgw/backend"
	"github.com/versity/scoutgw/internal"
	"github.com/versity/scoutgw/s3err"
)

type S3ApiRouter struct {
	app *fiber.App
	api fiber.Router
}

func (sa *S3ApiRouter) Init(app *fiber.App, be backend.Backend) {
	// ListBuckets action
	app.Get("/", func(ctx *fiber.Ctx) error {
		res, code := be.ListBuckets()
		return responce[*s3.ListBucketsOutput](ctx, res, code)
	})

	// PutBucket action
	app.Put("/:bucket", func(ctx *fiber.Ctx) error {
		code := be.PutBucket(ctx.Params("bucket"))
		return responce[internal.Any](ctx, nil, code)
	})
	// DeleteBucket action
	app.Delete("/:bucket", func(ctx *fiber.Ctx) error {
		code := be.DeleteBucket(ctx.Params("bucket"))
		return responce[internal.Any](ctx, nil, code)
	})

	// HeadBucket
	app.Head("/:bucket", func(ctx *fiber.Ctx) error {
		res, code := be.HeadBucket(ctx.Params("bucket"))
		return responce[*s3.HeadBucketOutput](ctx, res, code)
	})
	// GetBucketAcl action
	// ListMultipartUploads action
	// ListObjects action
	// ListObjectsV2 action
	app.Get("/:bucket", func(ctx *fiber.Ctx) error {
		if ctx.Request().URI().QueryArgs().Has("acl") {
			res, code := be.GetBucketAcl(ctx.Params("bucket"))
			return responce[*s3.GetBucketAclOutput](ctx, res, code)
		}

		if ctx.Request().URI().QueryArgs().Has("uploads") {
			res, code := be.ListMultipartUploads(&s3.ListMultipartUploadsInput{Bucket: aws.String(ctx.Params("bucket"))})
			return responce[*s3.ListMultipartUploadsOutput](ctx, res, code)
		}

		if ctx.QueryInt("list-type") == 2 {
			res, code := be.ListObjectsV2(ctx.Params("bucket"), "", "", "", 1)
			return responce[*s3.ListBucketsOutput](ctx, res, code)
		}

		res, code := be.ListObjects(ctx.Params("bucket"), "", "", "", 1)
		return responce[*s3.ListBucketsOutput](ctx, res, code)
	})

	// HeadObject action
	app.Head("/:bucket/:key/*", func(ctx *fiber.Ctx) error {
		bucket, key, keyEnd := ctx.Params("bucket"), ctx.Params("key"), ctx.Params("*1")
		if keyEnd != "" {
			key = strings.Join([]string{key, keyEnd}, "/")
		}

		res, code := be.HeadObject(bucket, key, "")
		return responce[*s3.HeadObjectOutput](ctx, res, code)
	})
	// GetObjectAcl action
	// GetObject action
	// ListObjectParts action
	app.Get("/:bucket/:key/*", func(ctx *fiber.Ctx) error {
		bucket, key, keyEnd, uploadId, maxPartsStr, partNumberMarkerStr := ctx.Params("bucket"), ctx.Params("key"), ctx.Params("*1"), ctx.Query("uploadId"), ctx.Query("max-parts"), ctx.Query("part-number-marker")
		if keyEnd != "" {
			key = strings.Join([]string{key, keyEnd}, "/")
		}

		if uploadId != "" {
			maxParts, err := strconv.Atoi(maxPartsStr)
			if err != nil && maxPartsStr != "" {
				return errors.New("wrong api call")
			}

			partNumberMarker, err := strconv.Atoi(partNumberMarkerStr)
			if err != nil && partNumberMarkerStr != "" {
				return errors.New("wrong api call")
			}

			res, code := be.ListObjectParts(bucket, "", uploadId, partNumberMarker, maxParts)
			return responce[*s3.ListPartsOutput](ctx, res, code)
		}

		if ctx.Request().URI().QueryArgs().Has("acl") {
			res, code := be.GetObjectAcl(bucket, key)
			return responce[*s3.GetObjectAclOutput](ctx, res, code)
		}

		if attrs := ctx.Get("X-Amz-Object-Attributes"); attrs != "" {
			res, code := be.GetObjectAttributes(bucket, key, strings.Split(attrs, ","))
			return responce[*s3.GetObjectAttributesOutput](ctx, res, code)
		}

		bRangeSl := strings.Split(ctx.Get("Range"), "=")
		if len(bRangeSl) < 2 {
			return errors.New("wrong api call")
		}

		bRange := strings.Split(bRangeSl[1], "-")
		if len(bRange) < 2 {
			return errors.New("wrong api call")
		}

		startOffset, err := strconv.Atoi(bRange[0])
		if err != nil {
			return errors.New("wrong api call")
		}

		length, err := strconv.Atoi(bRange[1])
		if err != nil {
			return errors.New("wrong api call")
		}

		res, code := be.GetObject(bucket, key, int64(startOffset), int64(length), ctx.Response().BodyWriter(), "")
		return responce[*s3.GetObjectOutput](ctx, res, code)
	})
	// DeleteObject action
	// AbortMultipartUpload action
	app.Delete("/:bucket/:key/*", func(ctx *fiber.Ctx) error {
		bucket, key, keyEnd, uploadId := ctx.Params("bucket"), ctx.Params("key"), ctx.Params("*1"), ctx.Query("uploadId")

		if keyEnd != "" {
			key = strings.Join([]string{key, keyEnd}, "/")
		}

		if uploadId != "" {
			expectedBucketOwner, requestPayer := ctx.Get("X-Amz-Expected-Bucket-Owner"), ctx.Get("X-Amz-Request-Payer")

			code := be.AbortMultipartUpload(&s3.AbortMultipartUploadInput{
				UploadId:            &uploadId,
				Bucket:              &bucket,
				Key:                 &key,
				ExpectedBucketOwner: &expectedBucketOwner,
				RequestPayer:        types.RequestPayer(requestPayer),
			})
			return responce[internal.Any](ctx, nil, code)
		}

		code := be.DeleteObject(bucket, key)
		return responce[internal.Any](ctx, nil, code)
	})
	// DeleteObjects action
	app.Post("/:bucket", func(ctx *fiber.Ctx) error {
		var dObj types.Delete
		if err := xml.Unmarshal(ctx.Body(), &dObj); err != nil {
			return errors.New("wrong api call")
		}

		code := be.DeleteObjects(ctx.Params("bucket"), &s3.DeleteObjectsInput{Delete: &dObj})
		return responce[internal.Any](ctx, nil, code)
	})
	// CompleteMultipartUpload action
	// CreateMultipartUpload
	app.Post("/:bucket/:key/*", func(ctx *fiber.Ctx) error {
		bucket, key, keyEnd, uploadId := ctx.Params("bucket"), ctx.Params("key"), ctx.Params("*1"), ctx.Query("uploadId")

		if keyEnd != "" {
			key = strings.Join([]string{key, keyEnd}, "/")
		}

		if uploadId != "" {
			var parts []types.Part

			if err := xml.Unmarshal(ctx.Body(), &parts); err != nil {
				return errors.New("wrong api call")
			}

			res, code := be.CompleteMultipartUpload(bucket, "", uploadId, parts)
			return responce[*s3.CompleteMultipartUploadOutput](ctx, res, code)
		}
		res, code := be.CreateMultipartUpload(&s3.CreateMultipartUploadInput{Bucket: &bucket, Key: &key})
		return responce[*s3.CreateMultipartUploadOutput](ctx, res, code)
	})
	// CopyObject action
	app.Put("/:bucket/:key/*", func(ctx *fiber.Ctx) error {
		copySource := strings.Split(ctx.Get("X-Amz-Copy-Source"), "/")
		if len(copySource) < 2 {
			return errors.New("wrong api call")
		}

		srcBucket, srcObject := copySource[0], copySource[1:]
		dstBucket, dstKeyStart, dstKeyEnd := ctx.Params("bucket"), ctx.Params("key"), ctx.Params("*1")
		if dstKeyEnd != "" {
			dstKeyStart = strings.Join([]string{dstKeyStart, dstKeyEnd}, "/")
		}

		res, code := be.CopyObject(srcBucket, strings.Join(srcObject, "/"), dstBucket, dstKeyStart)
		return responce[*s3.CopyObjectOutput](ctx, res, code)
	})
}

func responce[R comparable](ctx *fiber.Ctx, resp R, code s3err.ErrorCode) error {
	if code != 0 {
		err := s3err.GetAPIError(code)
		ctx.Status(err.HTTPStatusCode)
		return ctx.Send(s3err.GetAPIErrorResponse(err, "", "", ""))
	} else if b, err := xml.Marshal(resp); err != nil {
		return err
	} else {
		return ctx.Send(b)
	}
}
