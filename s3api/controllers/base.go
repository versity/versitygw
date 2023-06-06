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

package controllers

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
)

type S3ApiController struct {
	be backend.Backend
}

func New(be backend.Backend) S3ApiController {
	return S3ApiController{be: be}
}

func (c S3ApiController) ListBuckets(ctx *fiber.Ctx) error {
	res, err := c.be.ListBuckets()
	return Responce(ctx, res, err)
}

func (c S3ApiController) GetActions(ctx *fiber.Ctx) error {
	bucket, key, keyEnd, uploadId, maxPartsStr, partNumberMarkerStr, acceptRange := ctx.Params("bucket"), ctx.Params("key"), ctx.Params("*1"), ctx.Query("uploadId"), ctx.Query("max-parts"), ctx.Query("part-number-marker"), ctx.Get("Range")
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

		res, err := c.be.ListObjectParts(bucket, "", uploadId, partNumberMarker, maxParts)
		return Responce(ctx, res, err)
	}

	if ctx.Request().URI().QueryArgs().Has("acl") {
		res, err := c.be.GetObjectAcl(bucket, key)
		return Responce(ctx, res, err)
	}

	if attrs := ctx.Get("X-Amz-Object-Attributes"); attrs != "" {
		res, err := c.be.GetObjectAttributes(bucket, key, strings.Split(attrs, ","))
		return Responce(ctx, res, err)
	}

	res, err := c.be.GetObject(bucket, key, acceptRange, ctx.Response().BodyWriter())
	return Responce(ctx, res, err)
}

func (c S3ApiController) ListActions(ctx *fiber.Ctx) error {
	if ctx.Request().URI().QueryArgs().Has("acl") {
		res, err := c.be.GetBucketAcl(ctx.Params("bucket"))
		return Responce(ctx, res, err)
	}

	if ctx.Request().URI().QueryArgs().Has("uploads") {
		res, err := c.be.ListMultipartUploads(&s3.ListMultipartUploadsInput{Bucket: aws.String(ctx.Params("bucket"))})
		return Responce(ctx, res, err)
	}

	if ctx.QueryInt("list-type") == 2 {
		res, err := c.be.ListObjectsV2(ctx.Params("bucket"), "", "", "", 1)
		return Responce(ctx, res, err)
	}

	res, err := c.be.ListObjects(ctx.Params("bucket"), "", "", "", 1)
	return Responce(ctx, res, err)
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
		err := c.be.PutBucketAcl(&s3.PutBucketAclInput{
			Bucket:           &bucket,
			ACL:              types.BucketCannedACL(acl),
			GrantFullControl: &grantFullControl,
			GrantRead:        &grantRead,
			GrantReadACP:     &grantReadACP,
			GrantWrite:       &granWrite,
			GrantWriteACP:    &grantWriteACP,
		})

		return Responce[any](ctx, nil, err)
	}

	err := c.be.PutBucket(bucket)
	return Responce[any](ctx, nil, err)
}

func (c S3ApiController) PutActions(ctx *fiber.Ctx) error {
	dstBucket, dstKeyStart, dstKeyEnd, uploadId, partNumberStr := ctx.Params("bucket"), ctx.Params("key"), ctx.Params("*1"), ctx.Query("uploadId"), ctx.Query("partNumber")
	copySource, copySrcIfMatch, copySrcIfNoneMatch,
		copySrcModifSince, copySrcUnmodifSince, acl,
		grantFullControl, grantRead, grantReadACP,
		granWrite, grantWriteACP, contentLengthStr :=
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
		ctx.Get("X-Amz-Grant-Write-Acp"),
		// Other headers
		ctx.Get("Content-Length")

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

		res, err := c.be.UploadPartCopy(&s3.UploadPartCopyInput{
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

		return Responce(ctx, res, err)
	}

	if uploadId != "" {
		body := io.ReadSeeker(bytes.NewReader([]byte(ctx.Body())))
		res, err := c.be.UploadPart(dstBucket, dstKeyStart, uploadId, body)
		return Responce(ctx, res, err)
	}

	if grants != "" || acl != "" {
		if grants != "" && acl != "" {
			return errors.New("wrong api call")
		}

		err := c.be.PutObjectAcl(&s3.PutObjectAclInput{
			Bucket:           &dstBucket,
			Key:              &dstKeyStart,
			ACL:              types.ObjectCannedACL(acl),
			GrantFullControl: &grantFullControl,
			GrantRead:        &grantRead,
			GrantReadACP:     &grantReadACP,
			GrantWrite:       &granWrite,
			GrantWriteACP:    &grantWriteACP,
		})
		return Responce[any](ctx, nil, err)
	}

	if copySource != "" {
		copySourceSplit := strings.Split(copySource, "/")
		srcBucket, srcObject := copySourceSplit[0], copySourceSplit[1:]

		res, err := c.be.CopyObject(srcBucket, strings.Join(srcObject, "/"), dstBucket, dstKeyStart)
		return Responce(ctx, res, err)
	}

	contentLength, err := strconv.ParseInt(contentLengthStr, 10, 64)
	if err != nil {
		return errors.New("wrong api call")
	}

	metadata := utils.GetUserMetaData(&ctx.Request().Header)

	res, err := c.be.PutObject(&s3.PutObjectInput{
		Bucket:        &dstBucket,
		Key:           &dstKeyStart,
		ContentLength: contentLength,
		Metadata:      metadata,
		Body:          bytes.NewReader(ctx.Request().Body()),
	})
	return Responce(ctx, res, err)
}

func (c S3ApiController) DeleteBucket(ctx *fiber.Ctx) error {
	err := c.be.DeleteBucket(ctx.Params("bucket"))
	return Responce[any](ctx, nil, err)
}

func (c S3ApiController) DeleteObjects(ctx *fiber.Ctx) error {
	var dObj types.Delete
	if err := xml.Unmarshal(ctx.Body(), &dObj); err != nil {
		return errors.New("wrong api call")
	}

	err := c.be.DeleteObjects(ctx.Params("bucket"), &s3.DeleteObjectsInput{Delete: &dObj})
	return Responce[any](ctx, nil, err)
}

func (c S3ApiController) DeleteActions(ctx *fiber.Ctx) error {
	bucket, key, keyEnd, uploadId := ctx.Params("bucket"), ctx.Params("key"), ctx.Params("*1"), ctx.Query("uploadId")

	if keyEnd != "" {
		key = strings.Join([]string{key, keyEnd}, "/")
	}

	if uploadId != "" {
		expectedBucketOwner, requestPayer := ctx.Get("X-Amz-Expected-Bucket-Owner"), ctx.Get("X-Amz-Request-Payer")

		err := c.be.AbortMultipartUpload(&s3.AbortMultipartUploadInput{
			UploadId:            &uploadId,
			Bucket:              &bucket,
			Key:                 &key,
			ExpectedBucketOwner: &expectedBucketOwner,
			RequestPayer:        types.RequestPayer(requestPayer),
		})
		return Responce[any](ctx, nil, err)
	}

	err := c.be.DeleteObject(bucket, key)
	return Responce[any](ctx, nil, err)
}

func (c S3ApiController) HeadBucket(ctx *fiber.Ctx) error {
	res, err := c.be.HeadBucket(ctx.Params("bucket"))
	return Responce(ctx, res, err)
}

func (c S3ApiController) HeadObject(ctx *fiber.Ctx) error {
	bucket, key, keyEnd := ctx.Params("bucket"), ctx.Params("key"), ctx.Params("*1")
	if keyEnd != "" {
		key = strings.Join([]string{key, keyEnd}, "/")
	}

	res, err := c.be.HeadObject(bucket, key)
	if err != nil {
		return ErrorResponse(ctx, err)
	}

	utils.SetMetaHeaders(ctx, res.Metadata)
	utils.SetResponseHeaders(ctx, []utils.CustomHeader{
		{
			Key:   "Content-Length",
			Value: fmt.Sprint(res.ContentLength),
		},
		{
			Key:   "Content-Type",
			Value: *res.ContentType,
		},
		{
			Key:   "Content-Encoding",
			Value: *res.ContentEncoding,
		},
		{
			Key:   "ETag",
			Value: *res.ETag,
		},
		{
			Key:   "Last-Modified",
			Value: res.LastModified.Format("20060102T150405Z"),
		},
	})

	// https://github.com/gofiber/fiber/issues/2080
	// ctx.SendStatus() sets incorrect content length on HEAD request
	ctx.Status(http.StatusOK)
	return nil
}

func (c S3ApiController) CreateActions(ctx *fiber.Ctx) error {
	bucket, key, keyEnd, uploadId := ctx.Params("bucket"), ctx.Params("key"), ctx.Params("*1"), ctx.Query("uploadId")
	var restoreRequest s3.RestoreObjectInput

	if keyEnd != "" {
		key = strings.Join([]string{key, keyEnd}, "/")
	}

	if ctx.Request().URI().QueryArgs().Has("restore") {
		xmlErr := xml.Unmarshal(ctx.Body(), &restoreRequest)
		if xmlErr != nil {
			return errors.New("wrong api call")
		}
		err := c.be.RestoreObject(bucket, key, &restoreRequest)
		return Responce[any](ctx, nil, err)
	}

	if uploadId != "" {
		var parts []types.Part

		if err := xml.Unmarshal(ctx.Body(), &parts); err != nil {
			return errors.New("wrong api call")
		}

		res, err := c.be.CompleteMultipartUpload(bucket, "", uploadId, parts)
		return Responce(ctx, res, err)
	}
	res, err := c.be.CreateMultipartUpload(&s3.CreateMultipartUploadInput{Bucket: &bucket, Key: &key})
	return Responce(ctx, res, err)
}

func Responce[R comparable](ctx *fiber.Ctx, resp R, err error) error {
	if err != nil {
		serr, ok := err.(s3err.APIError)
		if ok {
			ctx.Status(serr.HTTPStatusCode)
			return ctx.Send(s3err.GetAPIErrorResponse(serr, "", "", ""))
		}
		return ctx.Send(s3err.GetAPIErrorResponse(
			s3err.GetAPIError(s3err.ErrInternalError), "", "", ""))
	}

	var b []byte
	if b, err = xml.Marshal(resp); err != nil {
		return err
	}

	return ctx.Send(b)
}

func ErrorResponse(ctx *fiber.Ctx, err error) error {
	serr, ok := err.(s3err.APIError)
	if ok {
		ctx.Status(serr.HTTPStatusCode)
		return ctx.Send(s3err.GetAPIErrorResponse(serr, "", "", ""))
	}
	return ctx.Send(s3err.GetAPIErrorResponse(
		s3err.GetAPIError(s3err.ErrInternalError), "", "", ""))
}
