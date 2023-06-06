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
	"os"
	"strconv"
	"strings"

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
	bucket := ctx.Params("bucket")
	key := ctx.Params("key")
	keyEnd := ctx.Params("*1")
	uploadId := ctx.Query("uploadId")
	maxParts := ctx.QueryInt("max-parts", 0)
	partNumberMarker := ctx.QueryInt("part-number-marker", 0)
	acceptRange := ctx.Get("Range")
	if keyEnd != "" {
		key = strings.Join([]string{key, keyEnd}, "/")
	}

	if uploadId != "" {
		if maxParts < 0 || (maxParts == 0 && ctx.Query("max-parts") != "") {
			return ErrorResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidMaxParts))
		}
		if partNumberMarker < 0 || (partNumberMarker == 0 && ctx.Query("part-number-marker") != "") {
			return ErrorResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidPartNumberMarker))
		}
		res, err := c.be.ListObjectParts(bucket, key, uploadId, partNumberMarker, maxParts)
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
	if err != nil {
		return Responce(ctx, res, err)
	}
	return nil
}

func (c S3ApiController) ListActions(ctx *fiber.Ctx) error {
	bucket := ctx.Params("bucket")
	prefix := ctx.Query("prefix")
	marker := ctx.Query("continuation-token")
	delimiter := ctx.Query("delimiter")
	maxkeys := ctx.QueryInt("max-keys")

	if ctx.Request().URI().QueryArgs().Has("acl") {
		res, err := c.be.GetBucketAcl(ctx.Params("bucket"))
		return Responce(ctx, res, err)
	}

	if ctx.Request().URI().QueryArgs().Has("uploads") {
		res, err := c.be.ListMultipartUploads(&s3.ListMultipartUploadsInput{Bucket: aws.String(ctx.Params("bucket"))})
		return Responce(ctx, res, err)
	}

	if ctx.QueryInt("list-type") == 2 {
		res, err := c.be.ListObjectsV2(bucket, prefix, marker, delimiter, maxkeys)
		return Responce(ctx, res, err)
	}

	res, err := c.be.ListObjects(bucket, prefix, marker, delimiter, maxkeys)
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
	bucket := ctx.Params("bucket")
	keyStart := ctx.Params("key")
	keyEnd := ctx.Params("*1")
	uploadId := ctx.Query("uploadId")
	partNumberStr := ctx.Query("partNumber")

	// Copy source headers
	copySource := ctx.Get("X-Amz-Copy-Source")
	copySrcIfMatch := ctx.Get("X-Amz-Copy-Source-If-Match")
	copySrcIfNoneMatch := ctx.Get("X-Amz-Copy-Source-If-None-Match")
	copySrcModifSince := ctx.Get("X-Amz-Copy-Source-If-Modified-Since")
	copySrcUnmodifSince := ctx.Get("X-Amz-Copy-Source-If-Unmodified-Since")

	// Permission headers
	acl := ctx.Get("X-Amz-Acl")
	grantFullControl := ctx.Get("X-Amz-Grant-Full-Control")
	grantRead := ctx.Get("X-Amz-Grant-Read")
	grantReadACP := ctx.Get("X-Amz-Grant-Read-Acp")
	granWrite := ctx.Get("X-Amz-Grant-Write")
	grantWriteACP := ctx.Get("X-Amz-Grant-Write-Acp")

	// Other headers
	contentLengthStr := ctx.Get("Content-Length")

	grants := grantFullControl + grantRead + grantReadACP + granWrite + grantWriteACP

	if keyEnd != "" {
		keyStart = strings.Join([]string{keyStart, keyEnd}, "/")
	}
	path := ctx.Path()
	if path[len(path)-1:] == "/" && keyStart[len(keyStart)-1:] != "/" {
		keyStart = keyStart + "/"
	}

	var contentLength int64
	if contentLengthStr != "" {
		var err error
		contentLength, err = strconv.ParseInt(contentLengthStr, 10, 64)
		if err != nil {
			return ErrorResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest))
		}
	}

	if uploadId != "" && partNumberStr != "" {
		partNumber := ctx.QueryInt("partNumber", -1)
		if partNumber < 1 {
			return ErrorResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidPart))
		}

		body := io.ReadSeeker(bytes.NewReader([]byte(ctx.Body())))
		res, err := c.be.PutObjectPart(bucket, keyStart, uploadId,
			partNumber, contentLength, body)
		return Responce(ctx, res, err)
	}

	if grants != "" || acl != "" {
		if grants != "" && acl != "" {
			return errors.New("wrong api call")
		}

		err := c.be.PutObjectAcl(&s3.PutObjectAclInput{
			Bucket:           &bucket,
			Key:              &keyStart,
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
		_, _, _, _ = copySrcIfMatch, copySrcIfNoneMatch,
			copySrcModifSince, copySrcUnmodifSince
		copySourceSplit := strings.Split(copySource, "/")
		srcBucket, srcObject := copySourceSplit[0], copySourceSplit[1:]

		res, err := c.be.CopyObject(srcBucket, strings.Join(srcObject, "/"), bucket, keyStart)
		return Responce(ctx, res, err)
	}

	metadata := utils.GetUserMetaData(&ctx.Request().Header)

	res, err := c.be.PutObject(&s3.PutObjectInput{
		Bucket:        &bucket,
		Key:           &keyStart,
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
	bucket := ctx.Params("bucket")
	key := ctx.Params("key")
	keyEnd := ctx.Params("*1")
	uploadId := ctx.Query("uploadId")

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

const (
	timefmt = "Mon, 02 Jan 2006 15:04:05 GMT"
)

func (c S3ApiController) HeadObject(ctx *fiber.Ctx) error {
	bucket := ctx.Params("bucket")
	key := ctx.Params("key")
	keyEnd := ctx.Params("*1")
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
			Value: res.LastModified.Format(timefmt),
		},
	})

	// https://github.com/gofiber/fiber/issues/2080
	// ctx.SendStatus() sets incorrect content length on HEAD request
	ctx.Status(http.StatusOK)
	return nil
}

func (c S3ApiController) CreateActions(ctx *fiber.Ctx) error {
	bucket := ctx.Params("bucket")
	key := ctx.Params("key")
	keyEnd := ctx.Params("*1")
	uploadId := ctx.Query("uploadId")

	if keyEnd != "" {
		key = strings.Join([]string{key, keyEnd}, "/")
	}

	var restoreRequest s3.RestoreObjectInput
	if ctx.Request().URI().QueryArgs().Has("restore") {
		xmlErr := xml.Unmarshal(ctx.Body(), &restoreRequest)
		if xmlErr != nil {
			return errors.New("wrong api call")
		}
		err := c.be.RestoreObject(bucket, key, &restoreRequest)
		return Responce[any](ctx, nil, err)
	}

	if uploadId != "" {
		data := struct {
			Parts []types.Part `xml:"Part"`
		}{}

		if err := xml.Unmarshal(ctx.Body(), &data); err != nil {
			return errors.New("wrong api call")
		}

		res, err := c.be.CompleteMultipartUpload(bucket, key, uploadId, data.Parts)
		return Responce(ctx, res, err)
	}
	res, err := c.be.CreateMultipartUpload(&s3.CreateMultipartUploadInput{Bucket: &bucket, Key: &key})
	return Responce(ctx, res, err)
}

func Responce[R any](ctx *fiber.Ctx, resp R, err error) error {
	if err != nil {
		serr, ok := err.(s3err.APIError)
		if ok {
			ctx.Status(serr.HTTPStatusCode)
			return ctx.Send(s3err.GetAPIErrorResponse(serr, "", "", ""))
		}

		fmt.Fprintf(os.Stderr, "Internal Error, req:\n%v\nerr:\n%v\n",
			ctx.Request(), err)

		return ctx.Send(s3err.GetAPIErrorResponse(
			s3err.GetAPIError(s3err.ErrInternalError), "", "", ""))
	}

	var b []byte
	if b, err = xml.Marshal(resp); err != nil {
		return err
	}

	if len(b) > 0 {
		ctx.Response().Header.SetContentType(fiber.MIMEApplicationXML)
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
