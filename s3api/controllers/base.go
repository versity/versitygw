package controllers

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v2"
	"github.com/versity/scoutgw/backend"
	"github.com/versity/scoutgw/internal"
	"github.com/versity/scoutgw/s3err"
)

type S3ApiController struct {
	be backend.Backend
}

func New(be backend.Backend) S3ApiController {
	return S3ApiController{be: be}
}

func (c S3ApiController) ListBuckets(ctx *fiber.Ctx) error {
	res, code := c.be.ListBuckets()
	return responce[*s3.ListBucketsOutput](ctx, res, code)
}

func (c S3ApiController) GetActions(ctx *fiber.Ctx) error {
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

		res, code := c.be.ListObjectParts(bucket, "", uploadId, partNumberMarker, maxParts)
		return responce[*s3.ListPartsOutput](ctx, res, code)
	}

	if ctx.Request().URI().QueryArgs().Has("acl") {
		res, code := c.be.GetObjectAcl(bucket, key)
		return responce[*s3.GetObjectAclOutput](ctx, res, code)
	}

	if attrs := ctx.Get("X-Amz-Object-Attributes"); attrs != "" {
		res, code := c.be.GetObjectAttributes(bucket, key, strings.Split(attrs, ","))
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

	res, code := c.be.GetObject(bucket, key, int64(startOffset), int64(length), ctx.Response().BodyWriter(), "")
	return responce[*s3.GetObjectOutput](ctx, res, code)
}

func (c S3ApiController) ListActions(ctx *fiber.Ctx) error {
	if ctx.Request().URI().QueryArgs().Has("acl") {
		res, code := c.be.GetBucketAcl(ctx.Params("bucket"))
		return responce[*s3.GetBucketAclOutput](ctx, res, code)
	}

	if ctx.Request().URI().QueryArgs().Has("uploads") {
		res, code := c.be.ListMultipartUploads(&s3.ListMultipartUploadsInput{Bucket: aws.String(ctx.Params("bucket"))})
		return responce[*s3.ListMultipartUploadsOutput](ctx, res, code)
	}

	if ctx.QueryInt("list-type") == 2 {
		res, code := c.be.ListObjectsV2(ctx.Params("bucket"), "", "", "", 1)
		return responce[*s3.ListBucketsOutput](ctx, res, code)
	}

	res, code := c.be.ListObjects(ctx.Params("bucket"), "", "", "", 1)
	return responce[*s3.ListBucketsOutput](ctx, res, code)
}

func (c S3ApiController) PutBucketActions(ctx *fiber.Ctx) error {
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
		code := c.be.PutBucketAcl(&s3.PutBucketAclInput{
			Bucket:           &bucket,
			ACL:              types.BucketCannedACL(acl),
			GrantFullControl: &grantFullControl,
			GrantRead:        &grantRead,
			GrantReadACP:     &grantReadACP,
			GrantWrite:       &granWrite,
			GrantWriteACP:    &grantWriteACP,
		})

		return responce[internal.Any](ctx, nil, code)
	}

	code := c.be.PutBucket(bucket)
	return responce[internal.Any](ctx, nil, code)
}

func (c S3ApiController) PutActions(ctx *fiber.Ctx) error {
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

		res, code := c.be.UploadPartCopy(&s3.UploadPartCopyInput{
			Bucket:                      &dstBucket,
			Key:                         &dstKeyStart,
			PartNumber:                  int32(partNumber),
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
		res, code := c.be.UploadPart(dstBucket, dstKeyStart, uploadId, body)
		return responce[*s3.UploadPartOutput](ctx, res, code)
	}

	if grants != "" || acl != "" {
		if grants != "" && acl != "" {
			return errors.New("wrong api call")
		}

		code := c.be.PutObjectAcl(&s3.PutObjectAclInput{
			Bucket:           &dstBucket,
			Key:              &dstKeyStart,
			ACL:              types.ObjectCannedACL(acl),
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

		res, code := c.be.CopyObject(srcBucket, strings.Join(srcObject, "/"), dstBucket, dstKeyStart)
		return responce[*s3.CopyObjectOutput](ctx, res, code)
	}

	res, code := c.be.PutObject(dstBucket, dstKeyStart, bytes.NewReader(ctx.Request().Body()))
	return responce[string](ctx, res, code)
}

func (c S3ApiController) DeleteBucket(ctx *fiber.Ctx) error {
	code := c.be.DeleteBucket(ctx.Params("bucket"))
	return responce[internal.Any](ctx, nil, code)
}

func (c S3ApiController) DeleteObjects(ctx *fiber.Ctx) error {
	var dObj types.Delete
	if err := xml.Unmarshal(ctx.Body(), &dObj); err != nil {
		return errors.New("wrong api call")
	}

	code := c.be.DeleteObjects(ctx.Params("bucket"), &s3.DeleteObjectsInput{Delete: &dObj})
	return responce[internal.Any](ctx, nil, code)
}

func (c S3ApiController) DeleteActions(ctx *fiber.Ctx) error {
	bucket, key, keyEnd, uploadId := ctx.Params("bucket"), ctx.Params("key"), ctx.Params("*1"), ctx.Query("uploadId")

	if keyEnd != "" {
		key = strings.Join([]string{key, keyEnd}, "/")
	}

	if uploadId != "" {
		expectedBucketOwner, requestPayer := ctx.Get("X-Amz-Expected-Bucket-Owner"), ctx.Get("X-Amz-Request-Payer")

		code := c.be.AbortMultipartUpload(&s3.AbortMultipartUploadInput{
			UploadId:            &uploadId,
			Bucket:              &bucket,
			Key:                 &key,
			ExpectedBucketOwner: &expectedBucketOwner,
			RequestPayer:        types.RequestPayer(requestPayer),
		})
		return responce[internal.Any](ctx, nil, code)
	}

	code := c.be.DeleteObject(bucket, key)
	return responce[internal.Any](ctx, nil, code)
}

func (c S3ApiController) HeadBucket(ctx *fiber.Ctx) error {
	res, code := c.be.HeadBucket(ctx.Params("bucket"))
	return responce[*s3.HeadBucketOutput](ctx, res, code)
}

func (c S3ApiController) HeadObject(ctx *fiber.Ctx) error {
	bucket, key, keyEnd := ctx.Params("bucket"), ctx.Params("key"), ctx.Params("*1")
	if keyEnd != "" {
		key = strings.Join([]string{key, keyEnd}, "/")
	}

	res, code := c.be.HeadObject(bucket, key, "")
	return responce[*s3.HeadObjectOutput](ctx, res, code)
}

func (c S3ApiController) CreateActions(ctx *fiber.Ctx) error {
	bucket, key, keyEnd, uploadId := ctx.Params("bucket"), ctx.Params("key"), ctx.Params("*1"), ctx.Query("uploadId")
	var restoreRequest s3.RestoreObjectInput

	if keyEnd != "" {
		key = strings.Join([]string{key, keyEnd}, "/")
	}

	if err := xml.Unmarshal(ctx.Body(), &restoreRequest); err == nil {
		code := c.be.RestoreObject(bucket, key, &restoreRequest)
		return responce[internal.Any](ctx, nil, code)
	}

	if uploadId != "" {
		var parts []types.Part

		if err := xml.Unmarshal(ctx.Body(), &parts); err != nil {
			return errors.New("wrong api call")
		}

		res, code := c.be.CompleteMultipartUpload(bucket, "", uploadId, parts)
		return responce[*s3.CompleteMultipartUploadOutput](ctx, res, code)
	}
	res, code := c.be.CreateMultipartUpload(&s3.CreateMultipartUploadInput{Bucket: &bucket, Key: &key})
	return responce[*s3.CreateMultipartUploadOutput](ctx, res, code)
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
