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
	"github.com/versity/versitygw/s3log"
	"github.com/versity/versitygw/s3response"
)

type S3ApiController struct {
	be     backend.Backend
	iam    auth.IAMService
	logger s3log.Logger
}

func New(be backend.Backend, iam auth.IAMService, logger s3log.Logger) S3ApiController {
	return S3ApiController{be: be, iam: iam, logger: logger}
}

func (c S3ApiController) ListBuckets(ctx *fiber.Ctx) error {
	access, isRoot := ctx.Locals("access").(string), ctx.Locals("isRoot").(bool)
	if err := auth.IsAdmin(access, isRoot); err != nil {
		return SendXMLResponse(ctx, nil, err, LogOptions{Logger: c.logger, Action: "ListBucket"})
	}
	res, err := c.be.ListBuckets()
	return SendXMLResponse(ctx, res, err, LogOptions{Logger: c.logger, Action: "ListBucket"})
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
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Bucket: &bucket, Object: &key})
	}

	parsedAcl, err := auth.ParseACL(data)
	if err != nil {
		return SendResponse(ctx, err, LogOptions{Logger: c.logger})
	}

	if ctx.Request().URI().QueryArgs().Has("tagging") {
		if err := auth.VerifyACL(parsedAcl, bucket, access, "READ", isRoot); err != nil {
			return SendXMLResponse(ctx, nil, err, LogOptions{Logger: c.logger, Action: "GetObjectTagging", Bucket: &bucket, Object: &key})
		}

		tags, err := c.be.GetTags(bucket, key)
		if err != nil {
			return SendXMLResponse(ctx, nil, err, LogOptions{Logger: c.logger, Action: "GetObjectTagging", Bucket: &bucket, Object: &key})
		}
		resp := s3response.Tagging{TagSet: s3response.TagSet{Tags: []s3response.Tag{}}}

		for key, val := range tags {
			resp.TagSet.Tags = append(resp.TagSet.Tags, s3response.Tag{Key: key, Value: val})
		}

		return SendXMLResponse(ctx, resp, nil, LogOptions{Logger: c.logger, Action: "GetObjectTagging", Bucket: &bucket, Object: &key})
	}

	if uploadId != "" {
		if maxParts < 0 || (maxParts == 0 && ctx.Query("max-parts") != "") {
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidMaxParts), LogOptions{
				Logger: c.logger,
				Action: "ListObjectParts",
				Bucket: &bucket,
				Object: &key,
			})
		}
		if partNumberMarker < 0 || (partNumberMarker == 0 && ctx.Query("part-number-marker") != "") {
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidPartNumberMarker), LogOptions{
				Logger: c.logger,
				Action: "ListObjectParts",
				Bucket: &bucket,
				Object: &key,
			})
		}

		if err := auth.VerifyACL(parsedAcl, bucket, access, "READ", isRoot); err != nil {
			return SendXMLResponse(ctx, nil, err, LogOptions{Logger: c.logger, Action: "ListObjectParts", Bucket: &bucket, Object: &key})
		}

		res, err := c.be.ListObjectParts(bucket, key, uploadId, partNumberMarker, maxParts)
		return SendXMLResponse(ctx, res, err, LogOptions{Logger: c.logger, Action: "ListObjectParts", Bucket: &bucket, Object: &key})
	}

	if ctx.Request().URI().QueryArgs().Has("acl") {
		if err := auth.VerifyACL(parsedAcl, bucket, access, "READ_ACP", isRoot); err != nil {
			return SendXMLResponse(ctx, nil, err, LogOptions{Logger: c.logger, Action: "GetObjectAcl", Bucket: &bucket, Object: &key})
		}
		res, err := c.be.GetObjectAcl(bucket, key)
		return SendXMLResponse(ctx, res, err, LogOptions{Logger: c.logger, Action: "GetObjectAcl", Bucket: &bucket, Object: &key})
	}

	if attrs := ctx.Get("X-Amz-Object-Attributes"); attrs != "" {
		if err := auth.VerifyACL(parsedAcl, bucket, access, "READ", isRoot); err != nil {
			return SendXMLResponse(ctx, nil, err, LogOptions{Logger: c.logger, Action: "GetObjectAttributes", Bucket: &bucket, Object: &key})
		}
		res, err := c.be.GetObjectAttributes(bucket, key, strings.Split(attrs, ","))
		return SendXMLResponse(ctx, res, err, LogOptions{Logger: c.logger, Action: "GetObjectAttributes", Bucket: &bucket, Object: &key})
	}

	if err := auth.VerifyACL(parsedAcl, bucket, access, "READ_ACP", isRoot); err != nil {
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Bucket: &bucket, Object: &key, Action: "GetObject"})
	}

	ctx.Locals("logResBody", false)
	res, err := c.be.GetObject(bucket, key, acceptRange, ctx.Response().BodyWriter())
	if err != nil {
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Bucket: &bucket, Object: &key, Action: "GetObject"})
	}
	if res == nil {
		return SendResponse(ctx, fmt.Errorf("get object nil response"), LogOptions{Logger: c.logger, Bucket: &bucket, Object: &key, Action: "GetObject"})
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
	return SendResponse(ctx, err, LogOptions{Logger: c.logger, Bucket: &bucket, Object: &key, Action: "GetObject"})
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
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Bucket: &bucket})
	}

	parsedAcl, err := auth.ParseACL(data)
	if err != nil {
		return SendResponse(ctx, err, LogOptions{Logger: c.logger})
	}

	if ctx.Request().URI().QueryArgs().Has("acl") {
		if err := auth.VerifyACL(parsedAcl, bucket, access, "READ_ACP", isRoot); err != nil {
			return SendXMLResponse(ctx, nil, err, LogOptions{Logger: c.logger, Action: "GetBucketAcl", Bucket: &bucket})
		}

		res, err := auth.ParseACLOutput(data)
		return SendXMLResponse(ctx, res, err, LogOptions{Logger: c.logger, Action: "GetBucketAcl", Bucket: &bucket})
	}

	if ctx.Request().URI().QueryArgs().Has("uploads") {
		if err := auth.VerifyACL(parsedAcl, bucket, access, "READ", isRoot); err != nil {
			return SendXMLResponse(ctx, nil, err, LogOptions{Logger: c.logger, Action: "ListMultipartUploads", Bucket: &bucket})
		}
		res, err := c.be.ListMultipartUploads(&s3.ListMultipartUploadsInput{Bucket: aws.String(ctx.Params("bucket"))})
		return SendXMLResponse(ctx, res, err, LogOptions{Logger: c.logger, Action: "ListMultipartUploads", Bucket: &bucket})
	}

	if ctx.QueryInt("list-type") == 2 {
		if err := auth.VerifyACL(parsedAcl, bucket, access, "READ", isRoot); err != nil {
			return SendXMLResponse(ctx, nil, err, LogOptions{Logger: c.logger, Action: "ListObjectsV2", Bucket: &bucket})
		}
		res, err := c.be.ListObjectsV2(bucket, prefix, marker, delimiter, maxkeys)
		return SendXMLResponse(ctx, res, err, LogOptions{Logger: c.logger, Action: "ListObjectsV2", Bucket: &bucket})
	}

	if err := auth.VerifyACL(parsedAcl, bucket, access, "READ", isRoot); err != nil {
		return SendXMLResponse(ctx, nil, err, LogOptions{Logger: c.logger, Action: "ListObjects", Bucket: &bucket})
	}

	res, err := c.be.ListObjects(bucket, prefix, marker, delimiter, maxkeys)
	return SendXMLResponse(ctx, res, err, LogOptions{Logger: c.logger, Action: "ListObjects", Bucket: &bucket})
}

func (c S3ApiController) PutBucketActions(ctx *fiber.Ctx) error {
	bucket, bucketOwner, acl, grantFullControl, grantRead, grantReadACP, granWrite, grantWriteACP, access, isRoot :=
		ctx.Params("bucket"),
		ctx.Get("X-Amz-Expected-Bucket-Owner"),
		ctx.Get("X-Amz-Acl"),
		ctx.Get("X-Amz-Grant-Full-Control"),
		ctx.Get("X-Amz-Grant-Read"),
		ctx.Get("X-Amz-Grant-Read-Acp"),
		ctx.Get("X-Amz-Grant-Write"),
		ctx.Get("X-Amz-Grant-Write-Acp"),
		ctx.Locals("access").(string),
		ctx.Locals("isRoot").(bool)

	grants := grantFullControl + grantRead + grantReadACP + granWrite + grantWriteACP

	if ctx.Request().URI().QueryArgs().Has("acl") {
		var input *s3.PutBucketAclInput

		if len(ctx.Body()) > 0 {
			if grants+acl != "" {
				return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest), LogOptions{Logger: c.logger, Action: "PutBucketAcl", Bucket: &bucket})
			}

			var accessControlPolicy auth.AccessControlPolicy
			err := xml.Unmarshal(ctx.Body(), &accessControlPolicy)
			if err != nil {
				return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest), LogOptions{Logger: c.logger, Action: "PutBucketAcl", Bucket: &bucket})
			}

			input = &s3.PutBucketAclInput{
				Bucket:              &bucket,
				ACL:                 "",
				AccessControlPolicy: &types.AccessControlPolicy{Owner: &accessControlPolicy.Owner, Grants: accessControlPolicy.AccessControlList.Grants},
			}
		}
		if acl != "" {
			if acl != "private" && acl != "public-read" && acl != "public-read-write" {
				return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest), LogOptions{Logger: c.logger, Action: "PutBucketAcl", Bucket: &bucket})
			}
			if len(ctx.Body()) > 0 || grants != "" {
				return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest), LogOptions{Logger: c.logger, Action: "PutBucketAcl", Bucket: &bucket})
			}

			input = &s3.PutBucketAclInput{
				Bucket:              &bucket,
				ACL:                 types.BucketCannedACL(acl),
				AccessControlPolicy: &types.AccessControlPolicy{Owner: &types.Owner{ID: &bucketOwner}},
			}
		}
		if grants != "" {
			input = &s3.PutBucketAclInput{
				Bucket:              &bucket,
				GrantFullControl:    &grantFullControl,
				GrantRead:           &grantRead,
				GrantReadACP:        &grantReadACP,
				GrantWrite:          &granWrite,
				GrantWriteACP:       &grantWriteACP,
				AccessControlPolicy: &types.AccessControlPolicy{Owner: &types.Owner{ID: &bucketOwner}},
				ACL:                 "",
			}
		}

		data, err := c.be.GetBucketAcl(bucket)
		if err != nil {
			return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "PutBucketAcl", Bucket: &bucket})
		}

		parsedAcl, err := auth.ParseACL(data)
		if err != nil {
			return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "PutBucketAcl", Bucket: &bucket})
		}

		if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE_ACP", isRoot); err != nil {
			return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "PutBucketAcl", Bucket: &bucket})
		}

		updAcl, err := auth.UpdateACL(input, parsedAcl, c.iam)
		if err != nil {
			return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "PutBucketAcl", Bucket: &bucket})
		}

		err = c.be.PutBucketAcl(bucket, updAcl)
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "PutBucketAcl", Bucket: &bucket})
	}

	err := c.be.PutBucket(bucket, access)
	return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "PutBucket", Bucket: &bucket})
}

func (c S3ApiController) PutActions(ctx *fiber.Ctx) error {
	bucket := ctx.Params("bucket")
	keyStart := ctx.Params("key")
	keyEnd := ctx.Params("*1")
	uploadId := ctx.Query("uploadId")
	access := ctx.Locals("access").(string)
	isRoot := ctx.Locals("isRoot").(bool)

	// Copy source headers
	copySource := ctx.Get("X-Amz-Copy-Source")
	copySrcIfMatch := ctx.Get("X-Amz-Copy-Source-If-Match")
	copySrcIfNoneMatch := ctx.Get("X-Amz-Copy-Source-If-None-Match")
	copySrcModifSince := ctx.Get("X-Amz-Copy-Source-If-Modified-Since")
	copySrcUnmodifSince := ctx.Get("X-Amz-Copy-Source-If-Unmodified-Since")
	copySrcRange := ctx.Get("X-Amz-Copy-Source-Range")

	// Permission headers
	acl := ctx.Get("X-Amz-Acl")
	grantFullControl := ctx.Get("X-Amz-Grant-Full-Control")
	grantRead := ctx.Get("X-Amz-Grant-Read")
	grantReadACP := ctx.Get("X-Amz-Grant-Read-Acp")
	granWrite := ctx.Get("X-Amz-Grant-Write")
	grantWriteACP := ctx.Get("X-Amz-Grant-Write-Acp")

	// Other headers
	contentLengthStr := ctx.Get("Content-Length")
	bucketOwner := ctx.Get("X-Amz-Expected-Bucket-Owner")

	grants := grantFullControl + grantRead + grantReadACP + granWrite + grantWriteACP

	if keyEnd != "" {
		keyStart = strings.Join([]string{keyStart, keyEnd}, "/")
	}
	path := ctx.Path()
	if path[len(path)-1:] == "/" && keyStart[len(keyStart)-1:] != "/" {
		keyStart = keyStart + "/"
	}

	data, err := c.be.GetBucketAcl(bucket)
	if err != nil {
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Bucket: &bucket, Object: &keyStart})
	}

	parsedAcl, err := auth.ParseACL(data)
	if err != nil {
		return SendResponse(ctx, err, LogOptions{Logger: c.logger})
	}

	if ctx.Request().URI().QueryArgs().Has("tagging") {
		var objTagging s3response.Tagging
		err := xml.Unmarshal(ctx.Body(), &objTagging)
		if err != nil {
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest), LogOptions{Logger: c.logger, Action: "PutObjectTagging", Bucket: &bucket, Object: &keyStart})
		}

		tags := make(map[string]string, len(objTagging.TagSet.Tags))

		for _, tag := range objTagging.TagSet.Tags {
			tags[tag.Key] = tag.Value
		}

		if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
			return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "PutObjectTagging", Bucket: &bucket, Object: &keyStart})
		}

		err = c.be.SetTags(bucket, keyStart, tags)

		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "PutObjectTagging", Bucket: &bucket, Object: &keyStart})
	}

	if ctx.Request().URI().QueryArgs().Has("uploadId") && ctx.Request().URI().QueryArgs().Has("partNumber") && copySource != "" {
		partNumber := ctx.QueryInt("partNumber", -1)
		if partNumber < 1 || partNumber > 10000 {
			return SendXMLResponse(ctx, nil, s3err.GetAPIError(s3err.ErrInvalidPart), LogOptions{Logger: c.logger, Action: "UploadPartCopy", Bucket: &bucket, Object: &keyStart})
		}

		resp, err := c.be.UploadPartCopy(&s3.UploadPartCopyInput{
			Bucket:              &bucket,
			Key:                 &keyStart,
			CopySource:          &copySource,
			PartNumber:          int32(partNumber),
			UploadId:            &uploadId,
			ExpectedBucketOwner: &bucketOwner,
			CopySourceRange:     &copySrcRange,
		})
		return SendXMLResponse(ctx, resp, err, LogOptions{Logger: c.logger, Action: "UploadPartCopy", Bucket: &bucket, Object: &keyStart})
	}

	if ctx.Request().URI().QueryArgs().Has("uploadId") && ctx.Request().URI().QueryArgs().Has("partNumber") {
		partNumber := ctx.QueryInt("partNumber", -1)
		if partNumber < 1 || partNumber > 10000 {
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidPart), LogOptions{Logger: c.logger, Action: "PutObjectPart", Bucket: &bucket, Object: &keyStart})
		}

		if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
			return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "PutObjectPart", Bucket: &bucket, Object: &keyStart})
		}

		contentLength, err := strconv.ParseInt(contentLengthStr, 10, 64)
		if err != nil {
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest), LogOptions{Logger: c.logger, Action: "PutObjectPart", Bucket: &bucket, Object: &keyStart})
		}

		body := io.ReadSeeker(bytes.NewReader([]byte(ctx.Body())))
		ctx.Locals("logReqBody", false)
		etag, err := c.be.PutObjectPart(bucket, keyStart, uploadId,
			partNumber, contentLength, body)
		ctx.Response().Header.Set("Etag", etag)
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "PutObjectPart", Bucket: &bucket, Object: &keyStart})
	}

	if ctx.Request().URI().QueryArgs().Has("acl") {
		var input *s3.PutObjectAclInput

		if len(ctx.Body()) > 0 {
			if grants+acl != "" {
				return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest), LogOptions{Logger: c.logger, Action: "PutObjectAcl", Bucket: &bucket, Object: &keyStart})
			}

			var accessControlPolicy auth.AccessControlPolicy
			err := xml.Unmarshal(ctx.Body(), &accessControlPolicy)
			if err != nil {
				return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest), LogOptions{Logger: c.logger, Action: "PutObjectAcl", Bucket: &bucket, Object: &keyStart})
			}

			input = &s3.PutObjectAclInput{
				Bucket:              &bucket,
				Key:                 &keyStart,
				ACL:                 "",
				AccessControlPolicy: &types.AccessControlPolicy{Owner: &accessControlPolicy.Owner, Grants: accessControlPolicy.AccessControlList.Grants},
			}
		}
		if acl != "" {
			if acl != "private" && acl != "public-read" && acl != "public-read-write" {
				return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest), LogOptions{Logger: c.logger, Action: "PutObjectAcl", Bucket: &bucket, Object: &keyStart})
			}
			if len(ctx.Body()) > 0 || grants != "" {
				return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest), LogOptions{Logger: c.logger, Action: "PutObjectAcl", Bucket: &bucket, Object: &keyStart})
			}

			input = &s3.PutObjectAclInput{
				Bucket:              &bucket,
				Key:                 &keyStart,
				ACL:                 types.ObjectCannedACL(acl),
				AccessControlPolicy: &types.AccessControlPolicy{Owner: &types.Owner{ID: &bucketOwner}},
			}
		}
		if grants != "" {
			input = &s3.PutObjectAclInput{
				Bucket:              &bucket,
				Key:                 &keyStart,
				GrantFullControl:    &grantFullControl,
				GrantRead:           &grantRead,
				GrantReadACP:        &grantReadACP,
				GrantWrite:          &granWrite,
				GrantWriteACP:       &grantWriteACP,
				AccessControlPolicy: &types.AccessControlPolicy{Owner: &types.Owner{ID: &bucketOwner}},
				ACL:                 "",
			}
		}

		err = c.be.PutObjectAcl(input)
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "PutObjectAcl", Bucket: &bucket, Object: &keyStart})
	}

	if copySource != "" {
		_, _, _, _ = copySrcIfMatch, copySrcIfNoneMatch,
			copySrcModifSince, copySrcUnmodifSince
		copySourceSplit := strings.Split(copySource, "/")
		srcBucket, srcObject := copySourceSplit[0], copySourceSplit[1:]

		if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
			return SendXMLResponse(ctx, nil, err, LogOptions{Logger: c.logger, Action: "CopyObject", Bucket: &bucket, Object: &keyStart})
		}

		res, err := c.be.CopyObject(srcBucket, strings.Join(srcObject, "/"), bucket, keyStart)
		return SendXMLResponse(ctx, res, err, LogOptions{Logger: c.logger, Action: "CopyObject", Bucket: &bucket, Object: &keyStart})
	}

	metadata := utils.GetUserMetaData(&ctx.Request().Header)

	if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "PutObject", Bucket: &bucket, Object: &keyStart})
	}

	contentLength, err := strconv.ParseInt(contentLengthStr, 10, 64)
	if err != nil {
		return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest), LogOptions{Logger: c.logger, Action: "PutObject", Bucket: &bucket, Object: &keyStart})
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
	return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "PutObject", Bucket: &bucket, Object: &keyStart})
}

func (c S3ApiController) DeleteBucket(ctx *fiber.Ctx) error {
	bucket, access, isRoot := ctx.Params("bucket"), ctx.Locals("access").(string), ctx.Locals("isRoot").(bool)

	data, err := c.be.GetBucketAcl(bucket)
	if err != nil {
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "DeleteBucket", Bucket: &bucket})
	}

	parsedAcl, err := auth.ParseACL(data)
	if err != nil {
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "DeleteBucket", Bucket: &bucket})
	}

	if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "DeleteBucket", Bucket: &bucket})
	}

	err = c.be.DeleteBucket(bucket)
	return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "DeleteBucket", Bucket: &bucket})
}

func (c S3ApiController) DeleteObjects(ctx *fiber.Ctx) error {
	bucket, access, isRoot := ctx.Params("bucket"), ctx.Locals("access").(string), ctx.Locals("isRoot").(bool)
	var dObj types.Delete

	if err := xml.Unmarshal(ctx.Body(), &dObj); err != nil {
		return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest), LogOptions{Logger: c.logger, Action: "DeleteObjects", Bucket: &bucket})
	}

	data, err := c.be.GetBucketAcl(bucket)
	if err != nil {
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "DeleteObjects", Bucket: &bucket})
	}

	parsedAcl, err := auth.ParseACL(data)
	if err != nil {
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "DeleteObjects", Bucket: &bucket})
	}

	if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "DeleteObjects", Bucket: &bucket})
	}

	err = c.be.DeleteObjects(bucket, &s3.DeleteObjectsInput{Delete: &dObj})
	return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "DeleteObjects", Bucket: &bucket})
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
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Bucket: &bucket, Object: &key})
	}

	parsedAcl, err := auth.ParseACL(data)
	if err != nil {
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Bucket: &bucket, Object: &key})
	}

	if ctx.Request().URI().QueryArgs().Has("tagging") {
		if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
			return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "RemoveObjectTagging", Bucket: &bucket, Object: &key})
		}

		err = c.be.RemoveTags(bucket, key)
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "RemoveObjectTagging", Bucket: &bucket, Object: &key})
	}

	if uploadId != "" {
		expectedBucketOwner, requestPayer := ctx.Get("X-Amz-Expected-Bucket-Owner"), ctx.Get("X-Amz-Request-Payer")

		if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
			return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "AbortMultipartUpload", Bucket: &bucket, Object: &key})
		}

		err := c.be.AbortMultipartUpload(&s3.AbortMultipartUploadInput{
			UploadId:            &uploadId,
			Bucket:              &bucket,
			Key:                 &key,
			ExpectedBucketOwner: &expectedBucketOwner,
			RequestPayer:        types.RequestPayer(requestPayer),
		})
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "AbortMultipartUpload", Bucket: &bucket, Object: &key})
	}

	if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "DeleteObject", Bucket: &bucket, Object: &key})
	}

	err = c.be.DeleteObject(bucket, key)
	return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "DeleteObject", Bucket: &bucket, Object: &key})
}

func (c S3ApiController) HeadBucket(ctx *fiber.Ctx) error {
	bucket, access, isRoot := ctx.Params("bucket"), ctx.Locals("access").(string), ctx.Locals("isRoot").(bool)

	data, err := c.be.GetBucketAcl(bucket)
	if err != nil {
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "HeadBucket", Bucket: &bucket})
	}

	parsedAcl, err := auth.ParseACL(data)
	if err != nil {
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "HeadBucket", Bucket: &bucket})
	}

	if err := auth.VerifyACL(parsedAcl, bucket, access, "READ", isRoot); err != nil {
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "HeadBucket", Bucket: &bucket})
	}

	_, err = c.be.HeadBucket(bucket)
	// TODO: set bucket response headers
	return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "HeadBucket", Bucket: &bucket})
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
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "HeadObject", Bucket: &bucket, Object: &key})
	}

	parsedAcl, err := auth.ParseACL(data)
	if err != nil {
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "HeadObject", Bucket: &bucket, Object: &key})
	}

	if err := auth.VerifyACL(parsedAcl, bucket, access, "READ", isRoot); err != nil {
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "HeadObject", Bucket: &bucket, Object: &key})
	}

	res, err := c.be.HeadObject(bucket, key)
	if err != nil {
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "HeadObject", Bucket: &bucket, Object: &key})
	}
	if res == nil {
		return SendResponse(ctx, fmt.Errorf("head object nil response"), LogOptions{Logger: c.logger, Action: "HeadObject", Bucket: &bucket, Object: &key})
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

	return SendResponse(ctx, nil, LogOptions{Logger: c.logger, Action: "HeadObject", Bucket: &bucket, Object: &key})
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
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Bucket: &bucket, Object: &key})
	}

	parsedAcl, err := auth.ParseACL(data)
	if err != nil {
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Bucket: &bucket, Object: &key})
	}

	var restoreRequest s3.RestoreObjectInput
	if ctx.Request().URI().QueryArgs().Has("restore") {
		err := xml.Unmarshal(ctx.Body(), &restoreRequest)
		if err != nil {
			return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "RestoreObject", Bucket: &bucket, Object: &key})
		}

		if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
			return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "RestoreObject", Bucket: &bucket, Object: &key})
		}

		err = c.be.RestoreObject(bucket, key, &restoreRequest)
		return SendResponse(ctx, err, LogOptions{Logger: c.logger, Action: "RestoreObject", Bucket: &bucket, Object: &key})
	}

	if uploadId != "" {
		data := struct {
			Parts []types.Part `xml:"Part"`
		}{}

		if err := xml.Unmarshal(ctx.Body(), &data); err != nil {
			return SendXMLResponse(ctx, nil, err, LogOptions{Logger: c.logger, Action: "CompleteMultipartUpload", Bucket: &bucket, Object: &key})
		}

		if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
			return SendXMLResponse(ctx, nil, err, LogOptions{Logger: c.logger, Action: "CompleteMultipartUpload", Bucket: &bucket, Object: &key})
		}

		res, err := c.be.CompleteMultipartUpload(bucket, key, uploadId, data.Parts)
		return SendXMLResponse(ctx, res, err, LogOptions{Logger: c.logger, Action: "CompleteMultipartUpload", Bucket: &bucket, Object: &key})
	}

	if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
		return SendXMLResponse(ctx, nil, err, LogOptions{Logger: c.logger, Action: "CreateMultipartUpload", Bucket: &bucket, Object: &key})
	}

	res, err := c.be.CreateMultipartUpload(&s3.CreateMultipartUploadInput{Bucket: &bucket, Key: &key})
	return SendXMLResponse(ctx, res, err, LogOptions{Logger: c.logger, Action: "CreateMultipartUpload", Bucket: &bucket, Object: &key})
}

type LogOptions struct {
	Logger  s3log.Logger
	Action  string
	Bucket  *string
	Object  *string
	LogType string
}

func SendResponse(ctx *fiber.Ctx, err error, lo LogOptions) error {
	if err != nil {
		if lo.Logger != nil {
			var access *string
			acc := ctx.Locals("access")
			switch tp := acc.(type) {
			case string:
				access = &tp
			}

			if lo.LogType == "auth" {
				lo.Logger.SendAuthLog(access, err)
			} else {
				lo.Logger.SendErrorLog(err, lo.Action, access, lo.Bucket, lo.Object)
			}
		}
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

	if lo.Logger != nil {
		var access *string
		acc := ctx.Locals("access")
		switch tp := acc.(type) {
		case string:
			access = &tp
		}

		if lo.LogType == "auth" {
			lo.Logger.SendAuthLog(access, nil)
		} else {
			lo.Logger.SendSuccessLog(nil, lo.Action, access, lo.Bucket, lo.Object)
		}
	}

	// https://github.com/gofiber/fiber/issues/2080
	// ctx.SendStatus() sets incorrect content length on HEAD request
	ctx.Status(http.StatusOK)
	return nil
}

func SendXMLResponse(ctx *fiber.Ctx, resp any, err error, lo LogOptions) error {
	if err != nil {
		if lo.Logger != nil {
			access := ctx.Locals("access").(string)
			lo.Logger.SendErrorLog(err, lo.Action, &access, lo.Bucket, lo.Object)
		}
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
	if lo.Logger != nil {
		access := ctx.Locals("access").(string)
		if lo.Logger != nil {
			lo.Logger.SendSuccessLog(resp, lo.Action, &access, lo.Bucket, lo.Object)
		}
	}

	return ctx.Send(b)
}
