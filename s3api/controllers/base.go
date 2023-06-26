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
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

type S3ApiController struct {
	be  backend.Backend
	iam auth.IAMService
}

func New(be backend.Backend) S3ApiController {
	return S3ApiController{be: be}
}

func (c S3ApiController) ListBuckets(ctx *fiber.Ctx) error {
	access, isRoot := ctx.Locals("access").(string), ctx.Locals("isRoot").(bool)
	if err := auth.IsAdmin(access, isRoot); err != nil {
		return SendXMLResponse(ctx, nil, err)
	}
	res, err := c.be.ListBuckets()
	return SendXMLResponse(ctx, res, err)
}

func (c S3ApiController) GetActions(ctx *fiber.Ctx) error {
	bucket := ctx.Params("bucket")
	key := ctx.Params("key")
	keyEnd := ctx.Params("*1")
	uploadId := ctx.Query("uploadId")
	maxParts := ctx.QueryInt("max-parts", 0)
	partNumberMarker := ctx.QueryInt("part-number-marker", 0)
	acceptRange := ctx.Get("Range")
	access := ctx.Locals("access").(string)
	isRoot := ctx.Locals("isRoot").(bool)
	if keyEnd != "" {
		key = strings.Join([]string{key, keyEnd}, "/")
	}

	data, err := c.be.GetBucketAcl(bucket)
	if err != nil {
		return SendResponse(ctx, err)
	}

	parsedAcl, err := auth.ParseACL(data)
	if err != nil {
		return SendResponse(ctx, err)
	}

	if ctx.Request().URI().QueryArgs().Has("tagging") {
		if err := auth.VerifyACL(parsedAcl, bucket, access, "READ", isRoot); err != nil {
			return SendXMLResponse(ctx, nil, err)
		}

		tags, err := c.be.GetTags(bucket, key)
		if err != nil {
			return SendXMLResponse(ctx, nil, err)
		}
		resp := s3response.Tagging{TagSet: s3response.TagSet{Tags: []s3response.Tag{}}}

		for key, val := range tags {
			resp.TagSet.Tags = append(resp.TagSet.Tags, s3response.Tag{Key: key, Value: val})
		}

		return SendXMLResponse(ctx, resp, nil)
	}

	if uploadId != "" {
		if maxParts < 0 || (maxParts == 0 && ctx.Query("max-parts") != "") {
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidMaxParts))
		}
		if partNumberMarker < 0 || (partNumberMarker == 0 && ctx.Query("part-number-marker") != "") {
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidPartNumberMarker))
		}

		if err := auth.VerifyACL(parsedAcl, bucket, access, "READ", isRoot); err != nil {
			return SendXMLResponse(ctx, nil, err)
		}

		res, err := c.be.ListObjectParts(bucket, key, uploadId, partNumberMarker, maxParts)
		return SendXMLResponse(ctx, res, err)
	}

	if ctx.Request().URI().QueryArgs().Has("acl") {
		if err := auth.VerifyACL(parsedAcl, bucket, access, "READ_ACP", isRoot); err != nil {
			return SendXMLResponse(ctx, nil, err)
		}
		res, err := c.be.GetObjectAcl(bucket, key)
		return SendXMLResponse(ctx, res, err)
	}

	if attrs := ctx.Get("X-Amz-Object-Attributes"); attrs != "" {
		if err := auth.VerifyACL(parsedAcl, bucket, access, "READ", isRoot); err != nil {
			return SendXMLResponse(ctx, nil, err)
		}
		res, err := c.be.GetObjectAttributes(bucket, key, strings.Split(attrs, ","))
		return SendXMLResponse(ctx, res, err)
	}

	if err := auth.VerifyACL(parsedAcl, bucket, access, "READ_ACP", isRoot); err != nil {
		return SendResponse(ctx, err)
	}

	fmt.Println("Request is here")

	ctx.Locals("logResBody", false)
	res, err := c.be.GetObject(bucket, key, acceptRange, ctx.Response().BodyWriter())
	if err != nil {
		return SendResponse(ctx, err)
	}
	if res == nil {
		return SendResponse(ctx, fmt.Errorf("get object nil response"))
	}

	utils.SetMetaHeaders(ctx, res.Metadata)
	var lastmod string
	if res.LastModified != nil {
		lastmod = res.LastModified.Format(timefmt)
	}
	utils.SetResponseHeaders(ctx, []utils.CustomHeader{
		{
			Key:   "Content-Length",
			Value: fmt.Sprint(res.ContentLength),
		},
		{
			Key:   "Content-Type",
			Value: getstring(res.ContentType),
		},
		{
			Key:   "Content-Encoding",
			Value: getstring(res.ContentEncoding),
		},
		{
			Key:   "ETag",
			Value: getstring(res.ETag),
		},
		{
			Key:   "Last-Modified",
			Value: lastmod,
		},
		{
			Key:   "x-amz-storage-class",
			Value: string(res.StorageClass),
		},
	})
	return SendResponse(ctx, err)
}

func getstring(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (c S3ApiController) ListActions(ctx *fiber.Ctx) error {
	bucket := ctx.Params("bucket")
	prefix := ctx.Query("prefix")
	marker := ctx.Query("continuation-token")
	delimiter := ctx.Query("delimiter")
	maxkeys := ctx.QueryInt("max-keys")
	access := ctx.Locals("access").(string)
	isRoot := ctx.Locals("isRoot").(bool)

	data, err := c.be.GetBucketAcl(bucket)
	if err != nil {
		return SendResponse(ctx, err)
	}

	parsedAcl, err := auth.ParseACL(data)
	if err != nil {
		return SendResponse(ctx, err)
	}

	if ctx.Request().URI().QueryArgs().Has("acl") {
		if err := auth.VerifyACL(parsedAcl, bucket, access, "READ_ACP", isRoot); err != nil {
			return SendXMLResponse(ctx, nil, err)
		}

		res, err := auth.ParseACLOutput(data)
		return SendXMLResponse(ctx, res, err)
	}

	if ctx.Request().URI().QueryArgs().Has("uploads") {
		if err := auth.VerifyACL(parsedAcl, bucket, access, "READ", isRoot); err != nil {
			return SendXMLResponse(ctx, nil, err)
		}
		res, err := c.be.ListMultipartUploads(&s3.ListMultipartUploadsInput{Bucket: aws.String(ctx.Params("bucket"))})
		return SendXMLResponse(ctx, res, err)
	}

	if ctx.QueryInt("list-type") == 2 {
		if err := auth.VerifyACL(parsedAcl, bucket, access, "READ", isRoot); err != nil {
			return SendXMLResponse(ctx, nil, err)
		}
		res, err := c.be.ListObjectsV2(bucket, prefix, marker, delimiter, maxkeys)
		return SendXMLResponse(ctx, res, err)
	}

	if err := auth.VerifyACL(parsedAcl, bucket, access, "READ", isRoot); err != nil {
		return SendXMLResponse(ctx, nil, err)
	}

	res, err := c.be.ListObjects(bucket, prefix, marker, delimiter, maxkeys)
	return SendXMLResponse(ctx, res, err)
}

func (c S3ApiController) PutBucketActions(ctx *fiber.Ctx) error {
	bucket, acl, grantFullControl, grantRead, grantReadACP, granWrite, grantWriteACP, access, isRoot :=
		ctx.Params("bucket"),
		ctx.Get("X-Amz-Acl"),
		ctx.Get("X-Amz-Grant-Full-Control"),
		ctx.Get("X-Amz-Grant-Read"),
		ctx.Get("X-Amz-Grant-Read-Acp"),
		ctx.Get("X-Amz-Grant-Write"),
		ctx.Get("X-Amz-Grant-Write-Acp"),
		ctx.Locals("access").(string),
		ctx.Locals("isRoot").(bool)

	grants := grantFullControl + grantRead + grantReadACP + granWrite + grantWriteACP

	if grants != "" || acl != "" {
		if grants != "" && acl != "" {
			return errors.New("wrong api call")
		}

		if acl != "" && acl != "private" && acl != "public-read" && acl != "public-read-write" {
			return errors.New("wrong api call")
		}

		data, err := c.be.GetBucketAcl(bucket)
		if err != nil {
			return SendResponse(ctx, err)
		}

		parsedAcl, err := auth.ParseACL(data)
		if err != nil {
			return SendResponse(ctx, err)
		}

		if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE_ACP", isRoot); err != nil {
			return SendResponse(ctx, err)
		}

		input := &s3.PutBucketAclInput{
			Bucket:              &bucket,
			ACL:                 types.BucketCannedACL(acl),
			GrantFullControl:    &grantFullControl,
			GrantRead:           &grantRead,
			GrantReadACP:        &grantReadACP,
			GrantWrite:          &granWrite,
			GrantWriteACP:       &grantWriteACP,
			AccessControlPolicy: &types.AccessControlPolicy{Owner: &types.Owner{ID: &access}},
		}

		err = auth.UpdateACL(input, parsedAcl, c.iam)
		return SendResponse(ctx, err)
	}

	err := c.be.PutBucket(bucket, access)
	return SendResponse(ctx, err)
}

func (c S3ApiController) PutActions(ctx *fiber.Ctx) error {
	bucket := ctx.Params("bucket")
	keyStart := ctx.Params("key")
	keyEnd := ctx.Params("*1")
	uploadId := ctx.Query("uploadId")
	partNumberStr := ctx.Query("partNumber")
	access := ctx.Locals("access").(string)
	isRoot := ctx.Locals("isRoot").(bool)

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
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest))
		}
	}

	data, err := c.be.GetBucketAcl(bucket)
	if err != nil {
		return SendResponse(ctx, err)
	}

	parsedAcl, err := auth.ParseACL(data)
	if err != nil {
		return SendResponse(ctx, err)
	}

	if ctx.Request().URI().QueryArgs().Has("tagging") {
		var objTagging s3response.Tagging
		err := xml.Unmarshal(ctx.Body(), &objTagging)
		if err != nil {
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest))
		}

		tags := make(map[string]string, len(objTagging.TagSet.Tags))

		for _, tag := range objTagging.TagSet.Tags {
			tags[tag.Key] = tag.Value
		}

		if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
			return SendResponse(ctx, err)
		}

		err = c.be.SetTags(bucket, keyStart, tags)

		return SendResponse(ctx, err)
	}

	if uploadId != "" && partNumberStr != "" {
		partNumber := ctx.QueryInt("partNumber", -1)
		if partNumber < 1 {
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidPart))
		}

		if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
			return SendResponse(ctx, err)
		}

		body := io.ReadSeeker(bytes.NewReader([]byte(ctx.Body())))
		ctx.Locals("logReqBody", false)
		etag, err := c.be.PutObjectPart(bucket, keyStart, uploadId,
			partNumber, contentLength, body)
		ctx.Response().Header.Set("Etag", etag)
		return SendResponse(ctx, err)
	}

	if grants != "" || acl != "" {
		if grants != "" && acl != "" {
			return errors.New("wrong api call")
		}

		if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE_ACP", isRoot); err != nil {
			return SendResponse(ctx, err)
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
		return SendResponse(ctx, err)
	}

	if copySource != "" {
		_, _, _, _ = copySrcIfMatch, copySrcIfNoneMatch,
			copySrcModifSince, copySrcUnmodifSince
		copySourceSplit := strings.Split(copySource, "/")
		srcBucket, srcObject := copySourceSplit[0], copySourceSplit[1:]

		if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
			return SendXMLResponse(ctx, nil, err)
		}

		res, err := c.be.CopyObject(srcBucket, strings.Join(srcObject, "/"), bucket, keyStart)
		return SendXMLResponse(ctx, res, err)
	}

	metadata := utils.GetUserMetaData(&ctx.Request().Header)

	if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
		return SendResponse(ctx, err)
	}

	ctx.Locals("logReqBody", false)
	etag, err := c.be.PutObject(&s3.PutObjectInput{
		Bucket:        &bucket,
		Key:           &keyStart,
		ContentLength: contentLength,
		Metadata:      metadata,
		Body:          bytes.NewReader(ctx.Request().Body()),
	})
	ctx.Response().Header.Set("ETag", etag)
	return SendResponse(ctx, err)
}

func (c S3ApiController) DeleteBucket(ctx *fiber.Ctx) error {
	bucket, access, isRoot := ctx.Params("bucket"), ctx.Locals("access").(string), ctx.Locals("isRoot").(bool)

	data, err := c.be.GetBucketAcl(bucket)
	if err != nil {
		return SendResponse(ctx, err)
	}

	parsedAcl, err := auth.ParseACL(data)
	if err != nil {
		return SendResponse(ctx, err)
	}

	if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
		return SendResponse(ctx, err)
	}

	err = c.be.DeleteBucket(bucket)
	return SendResponse(ctx, err)
}

func (c S3ApiController) DeleteObjects(ctx *fiber.Ctx) error {
	bucket, access, isRoot := ctx.Params("bucket"), ctx.Locals("access").(string), ctx.Locals("isRoot").(bool)
	var dObj types.Delete

	if err := xml.Unmarshal(ctx.Body(), &dObj); err != nil {
		return errors.New("wrong api call")
	}

	data, err := c.be.GetBucketAcl(bucket)
	if err != nil {
		return SendResponse(ctx, err)
	}

	parsedAcl, err := auth.ParseACL(data)
	if err != nil {
		return SendResponse(ctx, err)
	}

	if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
		return SendResponse(ctx, err)
	}

	err = c.be.DeleteObjects(bucket, &s3.DeleteObjectsInput{Delete: &dObj})
	return SendResponse(ctx, err)
}

func (c S3ApiController) DeleteActions(ctx *fiber.Ctx) error {
	bucket := ctx.Params("bucket")
	key := ctx.Params("key")
	keyEnd := ctx.Params("*1")
	uploadId := ctx.Query("uploadId")
	access := ctx.Locals("access").(string)
	isRoot := ctx.Locals("isRoot").(bool)

	if keyEnd != "" {
		key = strings.Join([]string{key, keyEnd}, "/")
	}

	data, err := c.be.GetBucketAcl(bucket)
	if err != nil {
		return SendResponse(ctx, err)
	}

	parsedAcl, err := auth.ParseACL(data)
	if err != nil {
		return SendResponse(ctx, err)
	}

	if ctx.Request().URI().QueryArgs().Has("tagging") {
		if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
			return SendResponse(ctx, err)
		}

		err = c.be.RemoveTags(bucket, key)
		return SendResponse(ctx, err)
	}

	if uploadId != "" {
		expectedBucketOwner, requestPayer := ctx.Get("X-Amz-Expected-Bucket-Owner"), ctx.Get("X-Amz-Request-Payer")

		if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
			return SendResponse(ctx, err)
		}

		err := c.be.AbortMultipartUpload(&s3.AbortMultipartUploadInput{
			UploadId:            &uploadId,
			Bucket:              &bucket,
			Key:                 &key,
			ExpectedBucketOwner: &expectedBucketOwner,
			RequestPayer:        types.RequestPayer(requestPayer),
		})
		return SendResponse(ctx, err)
	}

	if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
		return SendResponse(ctx, err)
	}

	err = c.be.DeleteObject(bucket, key)
	return SendResponse(ctx, err)
}

func (c S3ApiController) HeadBucket(ctx *fiber.Ctx) error {
	bucket, access, isRoot := ctx.Params("bucket"), ctx.Locals("access").(string), ctx.Locals("isRoot").(bool)

	data, err := c.be.GetBucketAcl(bucket)
	if err != nil {
		return SendResponse(ctx, err)
	}

	parsedAcl, err := auth.ParseACL(data)
	if err != nil {
		return SendResponse(ctx, err)
	}

	if err := auth.VerifyACL(parsedAcl, bucket, access, "READ", isRoot); err != nil {
		return SendResponse(ctx, err)
	}

	_, err = c.be.HeadBucket(bucket)
	// TODO: set bucket response headers
	return SendResponse(ctx, err)
}

const (
	timefmt = "Mon, 02 Jan 2006 15:04:05 GMT"
)

func (c S3ApiController) HeadObject(ctx *fiber.Ctx) error {
	bucket, access, isRoot := ctx.Params("bucket"), ctx.Locals("access").(string), ctx.Locals("isRoot").(bool)
	key := ctx.Params("key")
	keyEnd := ctx.Params("*1")
	if keyEnd != "" {
		key = strings.Join([]string{key, keyEnd}, "/")
	}

	data, err := c.be.GetBucketAcl(bucket)
	if err != nil {
		return SendResponse(ctx, err)
	}

	parsedAcl, err := auth.ParseACL(data)
	if err != nil {
		return SendResponse(ctx, err)
	}

	if err := auth.VerifyACL(parsedAcl, bucket, access, "READ", isRoot); err != nil {
		return SendResponse(ctx, err)
	}

	res, err := c.be.HeadObject(bucket, key)
	if err != nil {
		return SendResponse(ctx, err)
	}
	if res == nil {
		return SendResponse(ctx, fmt.Errorf("head object nil response"))
	}

	utils.SetMetaHeaders(ctx, res.Metadata)
	var lastmod string
	if res.LastModified != nil {
		lastmod = res.LastModified.Format(timefmt)
	}
	utils.SetResponseHeaders(ctx, []utils.CustomHeader{
		{
			Key:   "Content-Length",
			Value: fmt.Sprint(res.ContentLength),
		},
		{
			Key:   "Content-Type",
			Value: getstring(res.ContentType),
		},
		{
			Key:   "Content-Encoding",
			Value: getstring(res.ContentEncoding),
		},
		{
			Key:   "ETag",
			Value: getstring(res.ETag),
		},
		{
			Key:   "Last-Modified",
			Value: lastmod,
		},
		{
			Key:   "x-amz-storage-class",
			Value: string(res.StorageClass),
		},
		{
			Key:   "x-amz-restore",
			Value: getstring(res.Restore),
		},
	})

	return SendResponse(ctx, nil)
}

func (c S3ApiController) CreateActions(ctx *fiber.Ctx) error {
	bucket := ctx.Params("bucket")
	key := ctx.Params("key")
	keyEnd := ctx.Params("*1")
	uploadId := ctx.Query("uploadId")
	access := ctx.Locals("access").(string)
	isRoot := ctx.Locals("isRoot").(bool)

	if keyEnd != "" {
		key = strings.Join([]string{key, keyEnd}, "/")
	}

	data, err := c.be.GetBucketAcl(bucket)
	if err != nil {
		return SendResponse(ctx, err)
	}

	parsedAcl, err := auth.ParseACL(data)
	if err != nil {
		return SendResponse(ctx, err)
	}

	var restoreRequest s3.RestoreObjectInput
	if ctx.Request().URI().QueryArgs().Has("restore") {
		xmlErr := xml.Unmarshal(ctx.Body(), &restoreRequest)
		if xmlErr != nil {
			return errors.New("wrong api call")
		}

		if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
			return SendResponse(ctx, err)
		}

		err := c.be.RestoreObject(bucket, key, &restoreRequest)
		return SendResponse(ctx, err)
	}

	if uploadId != "" {
		data := struct {
			Parts []types.Part `xml:"Part"`
		}{}

		if err := xml.Unmarshal(ctx.Body(), &data); err != nil {
			return errors.New("wrong api call")
		}

		if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
			return SendXMLResponse(ctx, nil, err)
		}

		res, err := c.be.CompleteMultipartUpload(bucket, key, uploadId, data.Parts)
		return SendXMLResponse(ctx, res, err)
	}

	if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
		return SendXMLResponse(ctx, nil, err)
	}

	res, err := c.be.CreateMultipartUpload(&s3.CreateMultipartUploadInput{Bucket: &bucket, Key: &key})
	return SendXMLResponse(ctx, res, err)
}

func SendResponse(ctx *fiber.Ctx, err error) error {
	if err != nil {
		serr, ok := err.(s3err.APIError)
		if ok {
			ctx.Status(serr.HTTPStatusCode)
			return ctx.Send(s3err.GetAPIErrorResponse(serr, "", "", ""))
		}

		log.Printf("Internal Error, %v", err)
		ctx.Status(http.StatusInternalServerError)
		return ctx.Send(s3err.GetAPIErrorResponse(
			s3err.GetAPIError(s3err.ErrInternalError), "", "", ""))
	}

	utils.LogCtxDetails(ctx, []byte{})

	// https://github.com/gofiber/fiber/issues/2080
	// ctx.SendStatus() sets incorrect content length on HEAD request
	ctx.Status(http.StatusOK)
	return nil
}

func SendXMLResponse(ctx *fiber.Ctx, resp any, err error) error {
	if err != nil {
		serr, ok := err.(s3err.APIError)
		if ok {
			ctx.Status(serr.HTTPStatusCode)
			return ctx.Send(s3err.GetAPIErrorResponse(serr, "", "", ""))
		}

		log.Printf("Internal Error, %v", err)
		ctx.Status(http.StatusInternalServerError)

		return ctx.Send(s3err.GetAPIErrorResponse(
			s3err.GetAPIError(s3err.ErrInternalError), "", "", ""))
	}

	var b []byte

	if resp != nil {
		if b, err = xml.Marshal(resp); err != nil {
			return err
		}

		if len(b) > 0 {
			ctx.Response().Header.SetContentType(fiber.MIMEApplicationXML)
		}
	}

	utils.LogCtxDetails(ctx, b)

	return ctx.Send(b)
}
