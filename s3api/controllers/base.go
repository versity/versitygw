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
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3event"
	"github.com/versity/versitygw/s3log"
	"github.com/versity/versitygw/s3response"
)

type S3ApiController struct {
	be       backend.Backend
	iam      auth.IAMService
	logger   s3log.AuditLogger
	evSender s3event.S3EventSender
}

const (
	iso8601Format = "20060102T150405Z"
)

func New(be backend.Backend, iam auth.IAMService, logger s3log.AuditLogger, evs s3event.S3EventSender) S3ApiController {
	return S3ApiController{be: be, iam: iam, logger: logger, evSender: evs}
}

func (c S3ApiController) ListBuckets(ctx *fiber.Ctx) error {
	access, isRoot := ctx.Locals("access").(string), ctx.Locals("isRoot").(bool)
	if err := auth.IsAdmin(access, isRoot); err != nil {
		return SendXMLResponse(ctx, nil, err, &MetaOpts{Logger: c.logger, Action: "ListBucket"})
	}
	res, err := c.be.ListBuckets(access, isRoot)
	return SendXMLResponse(ctx, res, err, &MetaOpts{Logger: c.logger, Action: "ListBucket"})
}

func (c S3ApiController) GetActions(ctx *fiber.Ctx) error {
	bucket := ctx.Params("bucket")
	key := ctx.Params("key")
	keyEnd := ctx.Params("*1")
	uploadId := ctx.Query("uploadId")
	maxParts := ctx.QueryInt("max-parts", 0)
	partNumberMarker := ctx.Query("part-number-marker")
	acceptRange := ctx.Get("Range")
	access := ctx.Locals("access").(string)
	isRoot := ctx.Locals("isRoot").(bool)
	if keyEnd != "" {
		key = strings.Join([]string{key, keyEnd}, "/")
	}

	data, err := c.be.GetBucketAcl(&s3.GetBucketAclInput{Bucket: &bucket})
	if err != nil {
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger})
	}

	parsedAcl, err := auth.ParseACL(data)
	if err != nil {
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger})
	}

	if ctx.Request().URI().QueryArgs().Has("tagging") {
		if err := auth.VerifyACL(parsedAcl, bucket, access, "READ", isRoot); err != nil {
			return SendXMLResponse(ctx, nil, err, &MetaOpts{Logger: c.logger, Action: "GetObjectTagging", BucketOwner: parsedAcl.Owner})
		}

		tags, err := c.be.GetTags(bucket, key)
		if err != nil {
			return SendXMLResponse(ctx, nil, err, &MetaOpts{Logger: c.logger, Action: "GetObjectTagging", BucketOwner: parsedAcl.Owner})
		}
		resp := s3response.Tagging{TagSet: s3response.TagSet{Tags: []s3response.Tag{}}}

		for key, val := range tags {
			resp.TagSet.Tags = append(resp.TagSet.Tags, s3response.Tag{Key: key, Value: val})
		}

		return SendXMLResponse(ctx, resp, nil, &MetaOpts{Logger: c.logger, Action: "GetObjectTagging", BucketOwner: parsedAcl.Owner})
	}

	if uploadId != "" {
		if maxParts < 0 || (maxParts == 0 && ctx.Query("max-parts") != "") {
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidMaxParts), &MetaOpts{Logger: c.logger, Action: "ListParts", BucketOwner: parsedAcl.Owner})
		}
		if partNumberMarker != "" {
			n, err := strconv.Atoi(partNumberMarker)
			if err != nil || n < 0 {
				return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidPartNumberMarker), &MetaOpts{Logger: c.logger, Action: "ListParts", BucketOwner: parsedAcl.Owner})
			}
		}

		if err := auth.VerifyACL(parsedAcl, bucket, access, "READ", isRoot); err != nil {
			return SendXMLResponse(ctx, nil, err, &MetaOpts{Logger: c.logger, Action: "ListParts", BucketOwner: parsedAcl.Owner})
		}

		res, err := c.be.ListParts(&s3.ListPartsInput{
			Bucket:           &bucket,
			Key:              &key,
			UploadId:         &uploadId,
			PartNumberMarker: &partNumberMarker,
			MaxParts:         int32(maxParts),
		})
		return SendXMLResponse(ctx, res, err, &MetaOpts{Logger: c.logger, Action: "ListParts", BucketOwner: parsedAcl.Owner})
	}

	if ctx.Request().URI().QueryArgs().Has("acl") {
		if err := auth.VerifyACL(parsedAcl, bucket, access, "READ_ACP", isRoot); err != nil {
			return SendXMLResponse(ctx, nil, err, &MetaOpts{Logger: c.logger, Action: "GetObjectAcl", BucketOwner: parsedAcl.Owner})
		}
		res, err := c.be.GetObjectAcl(&s3.GetObjectAclInput{
			Bucket: &bucket,
			Key:    &key,
		})
		return SendXMLResponse(ctx, res, err, &MetaOpts{Logger: c.logger, Action: "GetObjectAcl", BucketOwner: parsedAcl.Owner})
	}

	if attrs := ctx.Get("X-Amz-Object-Attributes"); attrs != "" {
		if err := auth.VerifyACL(parsedAcl, bucket, access, "READ", isRoot); err != nil {
			return SendXMLResponse(ctx, nil, err, &MetaOpts{Logger: c.logger, Action: "GetObjectAttributes", BucketOwner: parsedAcl.Owner})
		}
		var oattrs []types.ObjectAttributes
		for _, a := range strings.Split(attrs, ",") {
			oattrs = append(oattrs, types.ObjectAttributes(a))
		}
		res, err := c.be.GetObjectAttributes(&s3.GetObjectAttributesInput{
			Bucket:           &bucket,
			Key:              &key,
			ObjectAttributes: oattrs,
		})
		return SendXMLResponse(ctx, res, err, &MetaOpts{Logger: c.logger, Action: "GetObjectAttributes", BucketOwner: parsedAcl.Owner})
	}

	if err := auth.VerifyACL(parsedAcl, bucket, access, "READ_ACP", isRoot); err != nil {
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "GetObject", BucketOwner: parsedAcl.Owner})
	}

	ctx.Locals("logResBody", false)
	res, err := c.be.GetObject(&s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
		Range:  &acceptRange,
	}, ctx.Response().BodyWriter())
	if err != nil {
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "GetObject", BucketOwner: parsedAcl.Owner})
	}
	if res == nil {
		return SendResponse(ctx, fmt.Errorf("get object nil response"), &MetaOpts{Logger: c.logger, Action: "GetObject", BucketOwner: parsedAcl.Owner})
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
	return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "GetObject", BucketOwner: parsedAcl.Owner})
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

	data, err := c.be.GetBucketAcl(&s3.GetBucketAclInput{Bucket: &bucket})
	if err != nil {
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger})
	}

	parsedAcl, err := auth.ParseACL(data)
	if err != nil {
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger})
	}

	if ctx.Request().URI().QueryArgs().Has("acl") {
		if err := auth.VerifyACL(parsedAcl, bucket, access, "READ_ACP", isRoot); err != nil {
			return SendXMLResponse(ctx, nil, err, &MetaOpts{Logger: c.logger, Action: "GetBucketAcl", BucketOwner: parsedAcl.Owner})
		}

		res, err := auth.ParseACLOutput(data)
		return SendXMLResponse(ctx, res, err, &MetaOpts{Logger: c.logger, Action: "GetBucketAcl", BucketOwner: parsedAcl.Owner})
	}

	if ctx.Request().URI().QueryArgs().Has("uploads") {
		if err := auth.VerifyACL(parsedAcl, bucket, access, "READ", isRoot); err != nil {
			return SendXMLResponse(ctx, nil, err, &MetaOpts{Logger: c.logger, Action: "ListMultipartUploads", BucketOwner: parsedAcl.Owner})
		}
		res, err := c.be.ListMultipartUploads(&s3.ListMultipartUploadsInput{Bucket: aws.String(ctx.Params("bucket"))})
		return SendXMLResponse(ctx, res, err, &MetaOpts{Logger: c.logger, Action: "ListMultipartUploads", BucketOwner: parsedAcl.Owner})
	}

	if ctx.QueryInt("list-type") == 2 {
		if err := auth.VerifyACL(parsedAcl, bucket, access, "READ", isRoot); err != nil {
			return SendXMLResponse(ctx, nil, err, &MetaOpts{Logger: c.logger, Action: "ListObjectsV2", BucketOwner: parsedAcl.Owner})
		}
		res, err := c.be.ListObjectsV2(&s3.ListObjectsV2Input{
			Bucket:            &bucket,
			Prefix:            &prefix,
			ContinuationToken: &marker,
			Delimiter:         &delimiter,
			MaxKeys:           int32(maxkeys),
		})
		return SendXMLResponse(ctx, res, err, &MetaOpts{Logger: c.logger, Action: "ListObjectsV2", BucketOwner: parsedAcl.Owner})
	}

	if err := auth.VerifyACL(parsedAcl, bucket, access, "READ", isRoot); err != nil {
		return SendXMLResponse(ctx, nil, err, &MetaOpts{Logger: c.logger, Action: "ListObjects", BucketOwner: parsedAcl.Owner})
	}

	res, err := c.be.ListObjects(&s3.ListObjectsInput{
		Bucket:    &bucket,
		Prefix:    &prefix,
		Marker:    &marker,
		Delimiter: &delimiter,
		MaxKeys:   int32(maxkeys),
	})
	return SendXMLResponse(ctx, res, err, &MetaOpts{Logger: c.logger, Action: "ListObjects", BucketOwner: parsedAcl.Owner})
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

		data, err := c.be.GetBucketAcl(&s3.GetBucketAclInput{Bucket: &bucket})
		if err != nil {
			return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "PutBucketAcl"})
		}

		parsedAcl, err := auth.ParseACL(data)
		if err != nil {
			return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "PutBucketAcl"})
		}

		if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE_ACP", isRoot); err != nil {
			return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "PutBucketAcl", BucketOwner: parsedAcl.Owner})
		}

		if len(ctx.Body()) > 0 {
			if grants+acl != "" {
				return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest), &MetaOpts{Logger: c.logger, Action: "PutBucketAcl", BucketOwner: parsedAcl.Owner})
			}

			var accessControlPolicy auth.AccessControlPolicy
			err := xml.Unmarshal(ctx.Body(), &accessControlPolicy)
			if err != nil {
				return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest), &MetaOpts{Logger: c.logger, Action: "PutBucketAcl", BucketOwner: parsedAcl.Owner})
			}

			input = &s3.PutBucketAclInput{
				Bucket:              &bucket,
				ACL:                 "",
				AccessControlPolicy: &types.AccessControlPolicy{Owner: &accessControlPolicy.Owner, Grants: accessControlPolicy.AccessControlList.Grants},
			}
		}
		if acl != "" {
			if acl != "private" && acl != "public-read" && acl != "public-read-write" {
				return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest), &MetaOpts{Logger: c.logger, Action: "PutBucketAcl", BucketOwner: parsedAcl.Owner})
			}
			if len(ctx.Body()) > 0 || grants != "" {
				return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest), &MetaOpts{Logger: c.logger, Action: "PutBucketAcl", BucketOwner: parsedAcl.Owner})
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

		updAcl, err := auth.UpdateACL(input, parsedAcl, c.iam)
		if err != nil {
			return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "PutBucketAcl", BucketOwner: parsedAcl.Owner})
		}

		err = c.be.PutBucketAcl(bucket, updAcl)
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "PutBucketAcl", BucketOwner: parsedAcl.Owner})
	}

	err := c.be.CreateBucket(&s3.CreateBucketInput{
		Bucket:          &bucket,
		ObjectOwnership: types.ObjectOwnership(access),
	})
	return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "PutBucket", BucketOwner: ctx.Locals("access").(string)})
}

func (c S3ApiController) PutActions(ctx *fiber.Ctx) error {
	bucket := ctx.Params("bucket")
	keyStart := ctx.Params("key")
	keyEnd := ctx.Params("*1")
	uploadId := ctx.Query("uploadId")
	access := ctx.Locals("access").(string)
	isRoot := ctx.Locals("isRoot").(bool)
	tagging := ctx.Get("x-amz-tagging")

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

	data, err := c.be.GetBucketAcl(&s3.GetBucketAclInput{Bucket: &bucket})
	if err != nil {
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger})
	}

	parsedAcl, err := auth.ParseACL(data)
	if err != nil {
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger})
	}

	if ctx.Request().URI().QueryArgs().Has("tagging") {
		var objTagging s3response.Tagging
		err := xml.Unmarshal(ctx.Body(), &objTagging)
		if err != nil {
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest), &MetaOpts{Logger: c.logger, Action: "PutObjectTagging", BucketOwner: parsedAcl.Owner})
		}

		tags := make(map[string]string, len(objTagging.TagSet.Tags))

		for _, tag := range objTagging.TagSet.Tags {
			tags[tag.Key] = tag.Value
		}

		if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
			return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "PutObjectTagging", BucketOwner: parsedAcl.Owner})
		}

		err = c.be.SetTags(bucket, keyStart, tags)
		return SendResponse(ctx, err, &MetaOpts{
			Logger:      c.logger,
			EvSender:    c.evSender,
			Action:      "PutObjectTagging",
			BucketOwner: parsedAcl.Owner,
			EventName:   s3event.EventObjectTaggingPut,
		})
	}

	if ctx.Request().URI().QueryArgs().Has("uploadId") && ctx.Request().URI().QueryArgs().Has("partNumber") && copySource != "" {
		partNumber := ctx.QueryInt("partNumber", -1)
		if partNumber < 1 || partNumber > 10000 {
			return SendXMLResponse(ctx, nil, s3err.GetAPIError(s3err.ErrInvalidPart), &MetaOpts{Logger: c.logger, Action: "UploadPartCopy", BucketOwner: parsedAcl.Owner})
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
		return SendXMLResponse(ctx, resp, err, &MetaOpts{Logger: c.logger, Action: "UploadPartCopy", BucketOwner: parsedAcl.Owner})
	}

	if ctx.Request().URI().QueryArgs().Has("uploadId") && ctx.Request().URI().QueryArgs().Has("partNumber") {
		partNumber := ctx.QueryInt("partNumber", -1)
		if partNumber < 1 || partNumber > 10000 {
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidPart), &MetaOpts{Logger: c.logger, Action: "UploadPart", BucketOwner: parsedAcl.Owner})
		}

		if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
			return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "UploadPart", BucketOwner: parsedAcl.Owner})
		}

		contentLength, err := strconv.ParseInt(contentLengthStr, 10, 64)
		if err != nil {
			return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest), &MetaOpts{Logger: c.logger, Action: "UploadPart", BucketOwner: parsedAcl.Owner})
		}

		body := io.ReadSeeker(bytes.NewReader([]byte(ctx.Body())))
		ctx.Locals("logReqBody", false)
		etag, err := c.be.UploadPart(&s3.UploadPartInput{
			Bucket:        &bucket,
			Key:           &keyStart,
			UploadId:      &uploadId,
			PartNumber:    int32(partNumber),
			ContentLength: contentLength,
			Body:          body,
		})
		ctx.Response().Header.Set("Etag", etag)
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "UploadPart", BucketOwner: parsedAcl.Owner})
	}

	if ctx.Request().URI().QueryArgs().Has("acl") {
		var input *s3.PutObjectAclInput

		if len(ctx.Body()) > 0 {
			if grants+acl != "" {
				return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest), &MetaOpts{Logger: c.logger, Action: "PutObjectAcl", BucketOwner: parsedAcl.Owner})
			}

			var accessControlPolicy auth.AccessControlPolicy
			err := xml.Unmarshal(ctx.Body(), &accessControlPolicy)
			if err != nil {
				return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest), &MetaOpts{Logger: c.logger, Action: "PutObjectAcl", BucketOwner: parsedAcl.Owner})
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
				return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest), &MetaOpts{Logger: c.logger, Action: "PutObjectAcl", BucketOwner: parsedAcl.Owner})
			}
			if len(ctx.Body()) > 0 || grants != "" {
				return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest), &MetaOpts{Logger: c.logger, Action: "PutObjectAcl", BucketOwner: parsedAcl.Owner})
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
		return SendResponse(ctx, err, &MetaOpts{
			Logger:      c.logger,
			EvSender:    c.evSender,
			Action:      "PutObjectAcl",
			BucketOwner: parsedAcl.Owner,
			EventName:   s3event.EventObjectAclPut,
		})
	}

	if copySource != "" {
		if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
			return SendXMLResponse(ctx, nil, err, &MetaOpts{Logger: c.logger, Action: "CopyObject", BucketOwner: parsedAcl.Owner})
		}

		var mtime time.Time
		if copySrcModifSince != "" {
			mtime, err = time.Parse(iso8601Format, copySrcModifSince)
			if err != nil {
				return SendXMLResponse(ctx, nil, s3err.GetAPIError(s3err.ErrInvalidCopySource), &MetaOpts{Logger: c.logger, Action: "CopyObject", BucketOwner: parsedAcl.Owner})
			}
		}
		var umtime time.Time
		if copySrcModifSince != "" {
			mtime, err = time.Parse(iso8601Format, copySrcUnmodifSince)
			if err != nil {
				return SendXMLResponse(ctx, nil, s3err.GetAPIError(s3err.ErrInvalidCopySource), &MetaOpts{Logger: c.logger, Action: "CopyObject", BucketOwner: parsedAcl.Owner})
			}
		}
		res, err := c.be.CopyObject(&s3.CopyObjectInput{
			Bucket:                      &bucket,
			Key:                         &keyStart,
			CopySource:                  &copySource,
			CopySourceIfMatch:           &copySrcIfMatch,
			CopySourceIfNoneMatch:       &copySrcIfNoneMatch,
			CopySourceIfModifiedSince:   &mtime,
			CopySourceIfUnmodifiedSince: &umtime,
		})
		if err == nil {
			return SendXMLResponse(ctx, res, err, &MetaOpts{
				Logger:      c.logger,
				EvSender:    c.evSender,
				Action:      "CopyObject",
				BucketOwner: parsedAcl.Owner,
				ObjectETag:  res.CopyObjectResult.ETag,
				VersionId:   res.VersionId,
				EventName:   s3event.EventObjectCopy,
			})
		} else {
			return SendXMLResponse(ctx, res, err, &MetaOpts{
				Logger:      c.logger,
				Action:      "CopyObject",
				BucketOwner: parsedAcl.Owner,
			})
		}
	}

	metadata := utils.GetUserMetaData(&ctx.Request().Header)

	if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "PutObject", BucketOwner: parsedAcl.Owner})
	}

	contentLength, err := strconv.ParseInt(contentLengthStr, 10, 64)
	if err != nil {
		return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest), &MetaOpts{Logger: c.logger, Action: "PutObject", BucketOwner: parsedAcl.Owner})
	}

	ctx.Locals("logReqBody", false)
	etag, err := c.be.PutObject(&s3.PutObjectInput{
		Bucket:        &bucket,
		Key:           &keyStart,
		ContentLength: contentLength,
		Metadata:      metadata,
		Body:          bytes.NewReader(ctx.Request().Body()),
		Tagging:       &tagging,
	})
	ctx.Response().Header.Set("ETag", etag)
	return SendResponse(ctx, err, &MetaOpts{
		Logger:      c.logger,
		EvSender:    c.evSender,
		Action:      "PutObject",
		BucketOwner: parsedAcl.Owner,
		ObjectETag:  &etag,
		ObjectSize:  contentLength,
		EventName:   s3event.EventObjectPut,
	})
}

func (c S3ApiController) DeleteBucket(ctx *fiber.Ctx) error {
	bucket, access, isRoot := ctx.Params("bucket"), ctx.Locals("access").(string), ctx.Locals("isRoot").(bool)

	data, err := c.be.GetBucketAcl(&s3.GetBucketAclInput{Bucket: &bucket})
	if err != nil {
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "DeleteBuckets"})
	}

	parsedAcl, err := auth.ParseACL(data)
	if err != nil {
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "DeleteBuckets"})
	}

	if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "DeleteBucket", BucketOwner: parsedAcl.Owner})
	}

	err = c.be.DeleteBucket(&s3.DeleteBucketInput{
		Bucket: &bucket,
	})
	return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "DeleteBucket", BucketOwner: parsedAcl.Owner})
}

func (c S3ApiController) DeleteObjects(ctx *fiber.Ctx) error {
	bucket, access, isRoot := ctx.Params("bucket"), ctx.Locals("access").(string), ctx.Locals("isRoot").(bool)
	var dObj types.Delete

	data, err := c.be.GetBucketAcl(&s3.GetBucketAclInput{Bucket: &bucket})
	if err != nil {
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "DeleteObjects"})
	}

	parsedAcl, err := auth.ParseACL(data)
	if err != nil {
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "DeleteObjects"})
	}

	if err := xml.Unmarshal(ctx.Body(), &dObj); err != nil {
		return SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest), &MetaOpts{Logger: c.logger, Action: "DeleteObjects", BucketOwner: parsedAcl.Owner})
	}

	if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "DeleteObjects", BucketOwner: parsedAcl.Owner})
	}

	err = c.be.DeleteObjects(&s3.DeleteObjectsInput{
		Bucket: &bucket,
		Delete: &dObj,
	})
	return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "DeleteObjects", BucketOwner: parsedAcl.Owner})
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

	data, err := c.be.GetBucketAcl(&s3.GetBucketAclInput{Bucket: &bucket})
	if err != nil {
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger})
	}

	parsedAcl, err := auth.ParseACL(data)
	if err != nil {
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger})
	}

	if ctx.Request().URI().QueryArgs().Has("tagging") {
		if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
			return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "RemoveObjectTagging", BucketOwner: parsedAcl.Owner})
		}

		err = c.be.RemoveTags(bucket, key)
		return SendResponse(ctx, err, &MetaOpts{
			Logger:      c.logger,
			EvSender:    c.evSender,
			Action:      "RemoveObjectTagging",
			BucketOwner: parsedAcl.Owner,
			EventName:   s3event.EventObjectTaggingDelete,
		})
	}

	if uploadId != "" {
		expectedBucketOwner, requestPayer := ctx.Get("X-Amz-Expected-Bucket-Owner"), ctx.Get("X-Amz-Request-Payer")

		if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
			return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "AbortMultipartUpload", BucketOwner: parsedAcl.Owner})
		}

		err := c.be.AbortMultipartUpload(&s3.AbortMultipartUploadInput{
			UploadId:            &uploadId,
			Bucket:              &bucket,
			Key:                 &key,
			ExpectedBucketOwner: &expectedBucketOwner,
			RequestPayer:        types.RequestPayer(requestPayer),
		})
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "AbortMultipartUpload", BucketOwner: parsedAcl.Owner})
	}

	if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "DeleteObject", BucketOwner: parsedAcl.Owner})
	}

	err = c.be.DeleteObject(&s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	return SendResponse(ctx, err, &MetaOpts{
		Logger:      c.logger,
		EvSender:    c.evSender,
		Action:      "DeleteObject",
		BucketOwner: parsedAcl.Owner,
		EventName:   s3event.EventObjectDelete,
	})
}

func (c S3ApiController) HeadBucket(ctx *fiber.Ctx) error {
	bucket, access, isRoot := ctx.Params("bucket"), ctx.Locals("access").(string), ctx.Locals("isRoot").(bool)

	data, err := c.be.GetBucketAcl(&s3.GetBucketAclInput{Bucket: &bucket})
	if err != nil {
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "HeadBucket"})
	}

	parsedAcl, err := auth.ParseACL(data)
	if err != nil {
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "HeadBucket"})
	}

	if err := auth.VerifyACL(parsedAcl, bucket, access, "READ", isRoot); err != nil {
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "HeadBucket", BucketOwner: parsedAcl.Owner})
	}

	_, err = c.be.HeadBucket(&s3.HeadBucketInput{
		Bucket: &bucket,
	})
	// TODO: set bucket response headers
	return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "HeadBucket", BucketOwner: parsedAcl.Owner})
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

	data, err := c.be.GetBucketAcl(&s3.GetBucketAclInput{
		Bucket: &bucket,
	})
	if err != nil {
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "HeadObject"})
	}

	parsedAcl, err := auth.ParseACL(data)
	if err != nil {
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "HeadObject"})
	}

	if err := auth.VerifyACL(parsedAcl, bucket, access, "READ", isRoot); err != nil {
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "HeadObject", BucketOwner: parsedAcl.Owner})
	}

	res, err := c.be.HeadObject(&s3.HeadObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "HeadObject", BucketOwner: parsedAcl.Owner})
	}
	if res == nil {
		return SendResponse(ctx, fmt.Errorf("head object nil response"), &MetaOpts{Logger: c.logger, Action: "HeadObject", BucketOwner: parsedAcl.Owner})
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

	return SendResponse(ctx, nil, &MetaOpts{Logger: c.logger, Action: "HeadObject", BucketOwner: parsedAcl.Owner})
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

	data, err := c.be.GetBucketAcl(&s3.GetBucketAclInput{Bucket: &bucket})
	if err != nil {
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger})
	}

	parsedAcl, err := auth.ParseACL(data)
	if err != nil {
		return SendResponse(ctx, err, &MetaOpts{Logger: c.logger})
	}

	var restoreRequest s3.RestoreObjectInput
	if ctx.Request().URI().QueryArgs().Has("restore") {
		err := xml.Unmarshal(ctx.Body(), &restoreRequest)
		if err != nil {
			return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "RestoreObject", BucketOwner: parsedAcl.Owner})
		}

		if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
			return SendResponse(ctx, err, &MetaOpts{Logger: c.logger, Action: "RestoreObject", BucketOwner: parsedAcl.Owner})
		}

		restoreRequest.Bucket = &bucket
		restoreRequest.Key = &key

		err = c.be.RestoreObject(&restoreRequest)
		return SendResponse(ctx, err, &MetaOpts{
			Logger:      c.logger,
			EvSender:    c.evSender,
			Action:      "RestoreObject",
			BucketOwner: parsedAcl.Owner,
			EventName:   s3event.EventObjectRestoreCompleted,
		})
	}

	if uploadId != "" {
		data := struct {
			Parts []types.CompletedPart `xml:"Part"`
		}{}

		if err := xml.Unmarshal(ctx.Body(), &data); err != nil {
			return SendXMLResponse(ctx, nil, err, &MetaOpts{Logger: c.logger, Action: "CompleteMultipartUpload", BucketOwner: parsedAcl.Owner})
		}

		if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
			return SendXMLResponse(ctx, nil, err, &MetaOpts{Logger: c.logger, Action: "CompleteMultipartUpload", BucketOwner: parsedAcl.Owner})
		}

		res, err := c.be.CompleteMultipartUpload(&s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &key,
			UploadId: &uploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: data.Parts,
			},
		})
		if err == nil {
			return SendXMLResponse(ctx, res, err, &MetaOpts{
				Logger:      c.logger,
				EvSender:    c.evSender,
				Action:      "CompleteMultipartUpload",
				BucketOwner: parsedAcl.Owner,
				ObjectETag:  res.ETag,
				EventName:   s3event.EventCompleteMultipartUpload,
				VersionId:   res.VersionId,
			})
		} else {
			return SendXMLResponse(ctx, res, err, &MetaOpts{
				Logger:      c.logger,
				Action:      "CompleteMultipartUpload",
				BucketOwner: parsedAcl.Owner,
			})
		}
	}

	if err := auth.VerifyACL(parsedAcl, bucket, access, "WRITE", isRoot); err != nil {
		return SendXMLResponse(ctx, nil, err, &MetaOpts{Logger: c.logger, Action: "CreateMultipartUpload", BucketOwner: parsedAcl.Owner})
	}

	res, err := c.be.CreateMultipartUpload(&s3.CreateMultipartUploadInput{Bucket: &bucket, Key: &key})
	return SendXMLResponse(ctx, res, err, &MetaOpts{Logger: c.logger, Action: "CreateMultipartUpload", BucketOwner: parsedAcl.Owner})
}

type MetaOpts struct {
	Logger      s3log.AuditLogger
	EvSender    s3event.S3EventSender
	Action      string
	BucketOwner string
	ObjectSize  int64
	EventName   s3event.EventType
	ObjectETag  *string
	VersionId   *string
}

func SendResponse(ctx *fiber.Ctx, err error, l *MetaOpts) error {
	if l.Logger != nil {
		l.Logger.Log(ctx, err, nil, s3log.LogMeta{
			Action:      l.Action,
			BucketOwner: l.BucketOwner,
			ObjectSize:  l.ObjectSize,
		})
	}
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
	if l.EvSender != nil {
		l.EvSender.SendEvent(ctx, s3event.EventMeta{
			ObjectSize:  l.ObjectSize,
			ObjectETag:  l.ObjectETag,
			EventName:   l.EventName,
			BucketOwner: l.BucketOwner,
			VersionId:   l.VersionId,
		})
	}

	utils.LogCtxDetails(ctx, []byte{})

	// https://github.com/gofiber/fiber/issues/2080
	// ctx.SendStatus() sets incorrect content length on HEAD request
	ctx.Status(http.StatusOK)
	return nil
}

func SendXMLResponse(ctx *fiber.Ctx, resp any, err error, l *MetaOpts) error {
	if err != nil {
		if l.Logger != nil {
			l.Logger.Log(ctx, err, nil, s3log.LogMeta{
				Action:      l.Action,
				BucketOwner: l.BucketOwner,
				ObjectSize:  l.ObjectSize,
			})
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
	if l.Logger != nil {
		l.Logger.Log(ctx, nil, b, s3log.LogMeta{
			Action:      l.Action,
			BucketOwner: l.BucketOwner,
			ObjectSize:  l.ObjectSize,
		})
	}

	if l.EvSender != nil {
		l.EvSender.SendEvent(ctx, s3event.EventMeta{
			BucketOwner: l.BucketOwner,
			ObjectSize:  l.ObjectSize,
			ObjectETag:  l.ObjectETag,
			VersionId:   l.VersionId,
			EventName:   l.EventName,
		})
	}

	return ctx.Send(b)
}
