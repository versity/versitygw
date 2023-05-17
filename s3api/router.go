package s3api

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/gofiber/fiber/v2"
	"github.com/versity/scoutgw/backend"
	"github.com/versity/scoutgw/internal"
	"github.com/versity/scoutgw/s3err"
	"github.com/versity/scoutgw/s3response"
)

type S3ApiRouter struct{}

func (sa *S3ApiRouter) Init(app *fiber.App, be backend.Backend) {
	// ListBuckets action
	app.Get("/", func(ctx *fiber.Ctx) error {
		res, code := be.ListBuckets()
		return responce[*s3response.ListAllMyBucketsList](ctx, res, code)
	})

	// PutBucket action
	// PutBucketAcl action
	app.Put("/:bucket", func(ctx *fiber.Ctx) error {
		bucket, acl, grantFullControl, grantRead, grantReadACP, granWrite, grantWriteACP :=
			ctx.Params("bucket"),
			ctx.Get("X-Amz-Acl"),
			ctx.Get("X-Amz-Grant-Full-Control"),
			ctx.Get("X-Amz-Grant-Read"),
			ctx.Get("X-Amz-Grant-Read-Acp"),
			ctx.Get("X-Amz-Grant-Write"),
			ctx.Get("X-Amz-Grant-Write-Acp")

		grants := grantFullControl + grantRead + grantReadACP + granWrite + grantWriteACP

		if grants != "" || acl != "" {
			if grants != "" && acl != "" {
				return errors.New("wrong api call")
			}
			code := be.PutBucketAcl(&s3.PutBucketAclInput{
				Bucket:           &bucket,
				ACL:              &acl,
				GrantFullControl: &grantFullControl,
				GrantRead:        &grantRead,
				GrantReadACP:     &grantReadACP,
				GrantWrite:       &granWrite,
				GrantWriteACP:    &grantWriteACP,
			})

			return responce[internal.Any](ctx, nil, code)
		}

		code := be.PutBucket(bucket)
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
		return responce[*s3response.HeadBucketResponse](ctx, res, code)
	})
	// GetBucketAcl action
	// ListMultipartUploads action
	// ListObjects action
	// ListObjectsV2 action
	app.Get("/:bucket", func(ctx *fiber.Ctx) error {
		if ctx.Request().URI().QueryArgs().Has("acl") {
			res, code := be.GetBucketAcl(ctx.Params("bucket"))
			return responce[*s3response.GetBucketAclResponse](ctx, res, code)
		}

		if ctx.Request().URI().QueryArgs().Has("uploads") {
			res, code := be.ListMultipartUploads(&s3response.ListMultipartUploads{Bucket: ctx.Params("bucket")})
			return responce[*s3response.ListMultipartUploadsResponse](ctx, res, code)
		}

		if ctx.QueryInt("list-type") == 2 {
			res, code := be.ListObjectsV2(ctx.Params("bucket"), "", "", "", 1)
			return responce[*s3response.ListBucketResultV2](ctx, res, code)
		}

		res, code := be.ListObjects(ctx.Params("bucket"), "", "", "", 1)
		return responce[*s3response.ListBucketResult](ctx, res, code)
	})

	// HeadObject action
	app.Head("/:bucket/:key/*", func(ctx *fiber.Ctx) error {
		bucket, key, keyEnd := ctx.Params("bucket"), ctx.Params("key"), ctx.Params("*1")
		if keyEnd != "" {
			key = strings.Join([]string{key, keyEnd}, "/")
		}

		res, code := be.HeadObject(bucket, key, "")
		return responce[*s3response.HeadObjectResponse](ctx, res, code)
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
			return responce[*s3response.ListPartsResponse](ctx, res, code)
		}

		if ctx.Request().URI().QueryArgs().Has("acl") {
			res, code := be.GetObjectAcl(bucket, key)
			return responce[*s3response.GetObjectAccessControlPolicyResponse](ctx, res, code)
		}

		if attrs := ctx.Get("X-Amz-Object-Attributes"); attrs != "" {
			res, code := be.GetObjectAttributes(bucket, key, strings.Split(attrs, ","))
			return responce[*s3response.GetObjectAttributesResponse](ctx, res, code)
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
		return responce[*s3response.GetObjectResponse](ctx, res, code)
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
				RequestPayer:        &requestPayer,
			})
			return responce[internal.Any](ctx, nil, code)
		}

		code := be.DeleteObject(bucket, key)
		return responce[internal.Any](ctx, nil, code)
	})
	// DeleteObjects action
	app.Post("/:bucket", func(ctx *fiber.Ctx) error {
		var dObj s3response.DeleteObjectEntry
		if err := xml.Unmarshal(ctx.Body(), &dObj); err != nil {
			return errors.New("wrong api call")
		}

		code := be.DeleteObjects(ctx.Params("bucket"), &s3response.DeleteObjectsInput{Delete: dObj})
		return responce[internal.Any](ctx, nil, code)
	})
	// CompleteMultipartUpload action
	// CreateMultipartUpload
	// RestoreObject action
	app.Post("/:bucket/:key/*", func(ctx *fiber.Ctx) error {
		bucket, key, keyEnd, uploadId := ctx.Params("bucket"), ctx.Params("key"), ctx.Params("*1"), ctx.Query("uploadId")
		var restoreRequest s3.RestoreRequest

		if keyEnd != "" {
			key = strings.Join([]string{key, keyEnd}, "/")
		}

		if err := xml.Unmarshal(ctx.Body(), &restoreRequest); err == nil {
			code := be.RestoreObject(bucket, key, &restoreRequest)
			return responce[internal.Any](ctx, nil, code)
		}

		if uploadId != "" {
			var parts []s3response.Part

			if err := xml.Unmarshal(ctx.Body(), &parts); err != nil {
				return errors.New("wrong api call")
			}

			res, code := be.CompleteMultipartUpload(bucket, "", uploadId, parts)
			return responce[*s3response.CompleteMultipartUploadResponse](ctx, res, code)
		}
		res, code := be.CreateMultipartUpload(&s3.CreateMultipartUploadInput{Bucket: &bucket, Key: &key})
		return responce[*s3response.InitiateMultipartUploadResponse](ctx, res, code)
	})
	// CopyObject action
	// PutObject action
	// UploadPart action
	// UploadPartCopy action
	app.Put("/:bucket/:key/*", func(ctx *fiber.Ctx) error {
		dstBucket, dstKeyStart, dstKeyEnd, uploadId, partNumberStr := ctx.Params("bucket"), ctx.Params("key"), ctx.Params("*1"), ctx.Query("uploadId"), ctx.Query("partNumber")
		copySource, copySrcIfMatch, copySrcIfNoneMatch,
			copySrcModifSince, copySrcUnmodifSince, acl,
			grantFullControl, grantRead, grantReadACP,
			granWrite, grantWriteACP :=
			// Copy source headers
			ctx.Get("X-Amz-Copy-Source"),
			ctx.Get("X-Amz-Copy-Source-If-Match"),
			ctx.Get("X-Amz-Copy-Source-If-None-Match"),
			ctx.Get("X-Amz-Copy-Source-If-Modified-Since"),
			ctx.Get("X-Amz-Copy-Source-If-Unmodified-Since"),
			// Permission headers
			ctx.Get("X-Amz-Acl"),
			ctx.Get("X-Amz-Grant-Full-Control"),
			ctx.Get("X-Amz-Grant-Read"),
			ctx.Get("X-Amz-Grant-Read-Acp"),
			ctx.Get("X-Amz-Grant-Write"),
			ctx.Get("X-Amz-Grant-Write-Acp")

		grants := grantFullControl + grantRead + grantReadACP + granWrite + grantWriteACP

		if dstKeyEnd != "" {
			dstKeyStart = strings.Join([]string{dstKeyStart, dstKeyEnd}, "/")
		}

		if partNumberStr != "" {
			copySrcModifSinceDate, err := time.Parse(time.RFC3339, copySrcModifSince)
			if err != nil && copySrcModifSince != "" {
				return errors.New("wrong api call")
			}

			copySrcUnmodifSinceDate, err := time.Parse(time.RFC3339, copySrcUnmodifSince)
			if err != nil && copySrcUnmodifSince != "" {
				return errors.New("wrong api call")
			}

			partNumber, err := strconv.ParseInt(partNumberStr, 10, 64)
			if err != nil {
				return errors.New("wrong api call")
			}

			res, code := be.UploadPartCopy(&s3.UploadPartCopyInput{
				Bucket:                      &dstBucket,
				Key:                         &dstKeyStart,
				PartNumber:                  &partNumber,
				UploadId:                    &uploadId,
				CopySource:                  &copySource,
				CopySourceIfMatch:           &copySrcIfMatch,
				CopySourceIfNoneMatch:       &copySrcIfNoneMatch,
				CopySourceIfModifiedSince:   &copySrcModifSinceDate,
				CopySourceIfUnmodifiedSince: &copySrcUnmodifSinceDate,
			})

			return responce[*s3.UploadPartCopyOutput](ctx, res, code)
		}

		if uploadId != "" {
			body := io.ReadSeeker(bytes.NewReader([]byte(ctx.Body())))
			res, code := be.UploadPart(dstBucket, dstKeyStart, uploadId, body)
			return responce[*s3.UploadPartOutput](ctx, res, code)
		}

		if grants != "" || acl != "" {
			if grants != "" && acl != "" {
				return errors.New("wrong api call")
			}

			code := be.PutObjectAcl(&s3.PutObjectAclInput{
				Bucket:           &dstBucket,
				Key:              &dstKeyStart,
				ACL:              &acl,
				GrantFullControl: &grantFullControl,
				GrantRead:        &grantRead,
				GrantReadACP:     &grantReadACP,
				GrantWrite:       &granWrite,
				GrantWriteACP:    &grantWriteACP,
			})
			return responce[internal.Any](ctx, nil, code)
		}

		if copySource != "" {
			copySourceSplit := strings.Split(copySource, "/")
			srcBucket, srcObject := copySourceSplit[0], copySourceSplit[1:]

			res, code := be.CopyObject(srcBucket, strings.Join(srcObject, "/"), dstBucket, dstKeyStart)
			return responce[*s3response.CopyObjectResponse](ctx, res, code)
		}

		res, code := be.PutObject(dstBucket, dstKeyStart, bytes.NewReader(ctx.Request().Body()))
		return responce[string](ctx, res, code)
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
