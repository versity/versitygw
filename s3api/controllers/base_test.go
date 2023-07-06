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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

var (
	acl     auth.ACL
	acldata []byte
)

func init() {
	var err error
	acldata, err = json.Marshal(acl)
	if err != nil {
		panic(err)
	}
}

func TestNew(t *testing.T) {
	type args struct {
		be  backend.Backend
		iam auth.IAMService
	}

	be := backend.BackendUnsupported{}

	tests := []struct {
		name string
		args args
		want S3ApiController
	}{
		{
			name: "Initialize S3 api controller",
			args: args{
				be:  be,
				iam: &auth.IAMServiceInternal{},
			},
			want: S3ApiController{
				be:  be,
				iam: &auth.IAMServiceInternal{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(tt.args.be, tt.args.iam); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestS3ApiController_ListBuckets(t *testing.T) {
	type args struct {
		req *http.Request
	}

	app := fiber.New()
	s3ApiController := S3ApiController{
		be: &BackendMock{
			GetBucketAclFunc: func(bucket string) ([]byte, error) {
				return acldata, nil
			},
			ListBucketsFunc: func() (s3response.ListAllMyBucketsResult, error) {
				return s3response.ListAllMyBucketsResult{}, nil
			},
		},
	}

	app.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("access", "valid access")
		ctx.Locals("isRoot", true)
		ctx.Locals("isDebug", false)
		return ctx.Next()
	})
	app.Get("/", s3ApiController.ListBuckets)

	// Error case
	appErr := fiber.New()
	s3ApiControllerErr := S3ApiController{
		be: &BackendMock{
			GetBucketAclFunc: func(bucket string) ([]byte, error) {
				return acldata, nil
			},
			ListBucketsFunc: func() (s3response.ListAllMyBucketsResult, error) {
				return s3response.ListAllMyBucketsResult{}, s3err.GetAPIError(s3err.ErrMethodNotAllowed)
			},
		},
	}

	appErr.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("access", "valid access")
		ctx.Locals("isRoot", true)
		ctx.Locals("isDebug", false)
		return ctx.Next()
	})
	appErr.Get("/", s3ApiControllerErr.ListBuckets)

	//Admin error case
	admErr := fiber.New()
	admErr.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("access", "valid access")
		ctx.Locals("isRoot", false)
		ctx.Locals("isDebug", false)
		return ctx.Next()
	})
	admErr.Get("/", s3ApiController.ListBuckets)

	tests := []struct {
		name       string
		args       args
		app        *fiber.App
		wantErr    bool
		statusCode int
	}{
		{
			name: "List-bucket-method-not-allowed",
			args: args{
				req: httptest.NewRequest(http.MethodGet, "/", nil),
			},
			app:        appErr,
			wantErr:    false,
			statusCode: 405,
		},
		{
			name: "list-bucket-success",
			args: args{
				req: httptest.NewRequest(http.MethodGet, "/", nil),
			},
			app:        app,
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "admin-error-case",
			args: args{
				req: httptest.NewRequest(http.MethodGet, "/", nil),
			},
			app:        admErr,
			wantErr:    false,
			statusCode: 500,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := tt.app.Test(tt.args.req)

			if (err != nil) != tt.wantErr {
				t.Errorf("S3ApiController.ListBuckets() error = %v, wantErr %v", err, tt.wantErr)
			}

			if resp.StatusCode != tt.statusCode {
				t.Errorf("S3ApiController.ListBuckets() statusCode = %v, wantStatusCode = %v", resp.StatusCode, tt.statusCode)
			}
		})
	}
}

func TestS3ApiController_GetActions(t *testing.T) {
	type args struct {
		req *http.Request
	}

	getPtr := func(val string) *string {
		return &val
	}
	now := time.Now()

	app := fiber.New()
	s3ApiController := S3ApiController{
		be: &BackendMock{
			GetBucketAclFunc: func(bucket string) ([]byte, error) {
				return acldata, nil
			},
			ListObjectPartsFunc: func(bucket, object, uploadID string, partNumberMarker int, maxParts int) (s3response.ListPartsResponse, error) {
				return s3response.ListPartsResponse{}, nil
			},
			GetObjectAclFunc: func(bucket, object string) (*s3.GetObjectAclOutput, error) {
				return &s3.GetObjectAclOutput{}, nil
			},
			GetObjectAttributesFunc: func(bucket, object string, attributes []string) (*s3.GetObjectAttributesOutput, error) {
				return &s3.GetObjectAttributesOutput{}, nil
			},
			GetObjectFunc: func(bucket, object, acceptRange string, writer io.Writer) (*s3.GetObjectOutput, error) {
				return &s3.GetObjectOutput{
					Metadata:        map[string]string{"hello": "world"},
					ContentType:     getPtr("application/xml"),
					ContentEncoding: getPtr("gzip"),
					ETag:            getPtr("98sda7f97sa9df798sd79f8as9df"),
					ContentLength:   1000,
					LastModified:    &now,
					StorageClass:    "storage class",
				}, nil
			},
			GetTagsFunc: func(bucket, object string) (map[string]string, error) {
				return map[string]string{"hello": "world"}, nil
			},
		},
	}
	app.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("access", "valid access")
		ctx.Locals("isRoot", true)
		ctx.Locals("isDebug", false)
		return ctx.Next()
	})
	app.Get("/:bucket/:key/*", s3ApiController.GetActions)

	// GetObjectAttributes success case
	getObjAttrs := httptest.NewRequest(http.MethodGet, "/my-bucket/key", nil)
	getObjAttrs.Header.Set("X-Amz-Object-Attributes", "hello")

	tests := []struct {
		name       string
		app        *fiber.App
		args       args
		wantErr    bool
		statusCode int
	}{
		{
			name: "Get-actions-get-tags-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodGet, "/my-bucket/key/key.json?tagging", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Get-actions-invalid-max-parts-string",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodGet, "/my-bucket/key?uploadId=hello&max-parts=invalid", nil),
			},
			wantErr:    false,
			statusCode: 400,
		},
		{
			name: "Get-actions-invalid-max-parts-negative",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodGet, "/my-bucket/key?uploadId=hello&max-parts=-8", nil),
			},
			wantErr:    false,
			statusCode: 400,
		},
		{
			name: "Get-actions-invalid-part-number-marker-string",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodGet, "/my-bucket/key?uploadId=hello&max-parts=200&part-number-marker=invalid", nil),
			},
			wantErr:    false,
			statusCode: 400,
		},
		{
			name: "Get-actions-invalid-part-number-marker-negative",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodGet, "/my-bucket/key?uploadId=hello&max-parts=200&part-number-marker=-8", nil),
			},
			wantErr:    false,
			statusCode: 400,
		},
		{
			name: "Get-actions-list-object-parts-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodGet, "/my-bucket/key?uploadId=hello&max-parts=200&part-number-marker=23", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Get-actions-get-object-acl-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodGet, "/my-bucket/key?acl", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Get-actions-get-object-attributes-success",
			app:  app,
			args: args{
				req: getObjAttrs,
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Get-actions-get-object-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodGet, "/my-bucket/key", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := tt.app.Test(tt.args.req)

			if (err != nil) != tt.wantErr {
				t.Errorf("S3ApiController.GetActions() error = %v, wantErr %v", err, tt.wantErr)
			}

			if resp.StatusCode != tt.statusCode {
				t.Errorf("S3ApiController.GetActions() statusCode = %v, wantStatusCode = %v", resp.StatusCode, tt.statusCode)
			}
		})
	}
}

func TestS3ApiController_ListActions(t *testing.T) {
	type args struct {
		req *http.Request
	}

	app := fiber.New()
	s3ApiController := S3ApiController{
		be: &BackendMock{
			GetBucketAclFunc: func(bucket string) ([]byte, error) {
				return acldata, nil
			},
			ListMultipartUploadsFunc: func(output *s3.ListMultipartUploadsInput) (s3response.ListMultipartUploadsResponse, error) {
				return s3response.ListMultipartUploadsResponse{}, nil
			},
			ListObjectsV2Func: func(bucket, prefix, marker, delim string, maxkeys int) (*s3.ListObjectsV2Output, error) {
				return &s3.ListObjectsV2Output{}, nil
			},
			ListObjectsFunc: func(bucket, prefix, marker, delim string, maxkeys int) (*s3.ListObjectsOutput, error) {
				return &s3.ListObjectsOutput{}, nil
			},
		},
	}

	app.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("access", "valid access")
		ctx.Locals("isRoot", true)
		ctx.Locals("isDebug", false)
		return ctx.Next()
	})

	app.Get("/:bucket", s3ApiController.ListActions)

	//Error case
	s3ApiControllerError := S3ApiController{
		be: &BackendMock{
			GetBucketAclFunc: func(bucket string) ([]byte, error) {
				return acldata, nil
			},
			ListObjectsFunc: func(bucket, prefix, marker, delim string, maxkeys int) (*s3.ListObjectsOutput, error) {
				return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
			},
		},
	}
	appError := fiber.New()
	appError.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("access", "valid access")
		ctx.Locals("isRoot", true)
		ctx.Locals("isDebug", false)
		return ctx.Next()
	})
	appError.Get("/:bucket", s3ApiControllerError.ListActions)

	tests := []struct {
		name       string
		app        *fiber.App
		args       args
		wantErr    bool
		statusCode int
	}{
		{
			name: "Get-bucket-acl-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodGet, "/my-bucket?acl=acl", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "List-Multipart-Upload-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodGet, "/my-bucket?uploads=uploads", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "List-Objects-V2-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodGet, "/my-bucket?list-type=2", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "List-Objects-V1-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodGet, "/my-bucket", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "List-actions-error-case",
			app:  appError,
			args: args{
				req: httptest.NewRequest(http.MethodGet, "/my-bucket", nil),
			},
			wantErr:    false,
			statusCode: 501,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := tt.app.Test(tt.args.req)

			if (err != nil) != tt.wantErr {
				t.Errorf("S3ApiController.ListActions() error = %v, wantErr %v", err, tt.wantErr)
			}

			if resp.StatusCode != tt.statusCode {
				t.Errorf("S3ApiController.ListActions() statusCode = %v, wantStatusCode = %v", resp.StatusCode, tt.statusCode)
			}
		})
	}
}

func TestS3ApiController_PutBucketActions(t *testing.T) {
	type args struct {
		req *http.Request
	}

	app := fiber.New()

	// Mock valid acl
	acl := auth.ACL{Owner: "valid access", ACL: "public-read-write"}
	acldata, err := json.Marshal(acl)
	if err != nil {
		t.Errorf("Failed to parse the params: %v", err.Error())
		return
	}

	body := `
	<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
		<AccessControlList>
			<Grant>
				<Grantee>
					<ID>hell</ID>
				</Grantee>
				<Permission>string</Permission>
			</Grant>
		</AccessControlList>
		<Owner>
			<ID>hello</ID>
		</Owner>
	</AccessControlPolicy>
	`

	s3ApiController := S3ApiController{
		be: &BackendMock{
			GetBucketAclFunc: func(bucket string) ([]byte, error) {
				return acldata, nil
			},
			PutBucketAclFunc: func(string, []byte) error {
				return nil
			},
			PutBucketFunc: func(bucket, owner string) error {
				return nil
			},
		},
	}
	// Mock ctx.Locals
	app.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("access", "valid access")
		ctx.Locals("isRoot", true)
		ctx.Locals("isDebug", false)
		return ctx.Next()
	})
	app.Put("/:bucket", s3ApiController.PutBucketActions)

	// invalid acl case
	invAclReq := httptest.NewRequest(http.MethodPut, "/my-bucket?acl", nil)
	invAclReq.Header.Set("X-Amz-Acl", "invalid")

	// invalid acl case 2
	errAclReq := httptest.NewRequest(http.MethodPut, "/my-bucket?acl", nil)
	errAclReq.Header.Set("X-Amz-Acl", "private")
	errAclReq.Header.Set("X-Amz-Grant-Read", "hello")

	// PutBucketAcl incorrect bucket owner case
	incorrectBucketOwner := httptest.NewRequest(http.MethodPut, "/my-bucket?acl", nil)
	incorrectBucketOwner.Header.Set("X-Amz-Acl", "private")
	incorrectBucketOwner.Header.Set("X-Amz-Expected-Bucket-Owner", "invalid access")

	// PutBucketAcl acl success
	aclSuccReq := httptest.NewRequest(http.MethodPut, "/my-bucket?acl", nil)
	aclSuccReq.Header.Set("X-Amz-Acl", "private")
	aclSuccReq.Header.Set("X-Amz-Expected-Bucket-Owner", "valid access")

	// Invalid acl body case
	errAclBodyReq := httptest.NewRequest(http.MethodPut, "/my-bucket?acl", strings.NewReader(body))
	errAclBodyReq.Header.Set("X-Amz-Grant-Read", "hello")

	tests := []struct {
		name       string
		app        *fiber.App
		args       args
		wantErr    bool
		statusCode int
	}{
		{
			name: "Put-bucket-acl-invalid-acl",
			app:  app,
			args: args{
				req: invAclReq,
			},
			wantErr:    false,
			statusCode: 400,
		},
		{
			name: "Put-bucket-acl-incorrect-acl",
			app:  app,
			args: args{
				req: errAclReq,
			},
			wantErr:    false,
			statusCode: 400,
		},
		{
			name: "Put-bucket-acl-incorrect-acl-body",
			app:  app,
			args: args{
				req: errAclBodyReq,
			},
			wantErr:    false,
			statusCode: 400,
		},
		{
			name: "Put-bucket-acl-incorrect-bucket-owner",
			app:  app,
			args: args{
				req: incorrectBucketOwner,
			},
			wantErr:    false,
			statusCode: 403,
		},
		{
			name: "Put-bucket-acl-success",
			app:  app,
			args: args{
				req: aclSuccReq,
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Put-bucket-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPut, "/my-bucket", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
	}
	for _, tt := range tests {
		resp, err := tt.app.Test(tt.args.req)

		if (err != nil) != tt.wantErr {
			t.Errorf("S3ApiController.PutBucketActions() error = %v, wantErr %v", err, tt.wantErr)
		}

		if resp.StatusCode != tt.statusCode {
			t.Errorf("S3ApiController.PutBucketActions() statusCode = %v, wantStatusCode = %v", resp.StatusCode, tt.statusCode)
		}
	}
}

func TestS3ApiController_PutActions(t *testing.T) {
	type args struct {
		req *http.Request
	}

	body := `
	<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
		<AccessControlList>
			<Grant>
				<Grantee>
					<ID>hell</ID>
				</Grantee>
				<Permission>string</Permission>
			</Grant>
		</AccessControlList>
		<Owner>
			<ID>hello</ID>
		</Owner>
	</AccessControlPolicy>
	`
	tagBody := `
	<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
		<TagSet>
			<Tag>
				<Key>string</Key>
				<Value>string</Value>
			</Tag>
		</TagSet>
	</Tagging>
	`

	app := fiber.New()
	s3ApiController := S3ApiController{
		be: &BackendMock{
			GetBucketAclFunc: func(bucket string) ([]byte, error) {
				return acldata, nil
			},
			PutObjectAclFunc: func(*s3.PutObjectAclInput) error {
				return nil
			},
			CopyObjectFunc: func(srcBucket, srcObject, DstBucket, dstObject string) (*s3.CopyObjectOutput, error) {
				return &s3.CopyObjectOutput{}, nil
			},
			PutObjectFunc: func(*s3.PutObjectInput) (string, error) {
				return "Hey", nil
			},
			PutObjectPartFunc: func(bucket, object, uploadID string, part int, length int64, r io.Reader) (string, error) {
				return "hello", nil
			},
			SetTagsFunc: func(bucket, object string, tags map[string]string) error {
				return nil
			},
			UploadPartCopyFunc: func(uploadPartCopyInput *s3.UploadPartCopyInput) (s3response.CopyObjectResult, error) {
				return s3response.CopyObjectResult{}, nil
			},
		},
	}
	app.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("access", "valid access")
		ctx.Locals("isRoot", true)
		ctx.Locals("isDebug", false)
		return ctx.Next()
	})
	app.Put("/:bucket/:key/*", s3ApiController.PutActions)

	// UploadPartCopy success
	uploadPartCpyReq := httptest.NewRequest(http.MethodPut, "/my-bucket/my-key?uploadId=12asd32&partNumber=3", nil)
	uploadPartCpyReq.Header.Set("X-Amz-Copy-Source", "srcBucket/srcObject")

	// UploadPartCopy error case
	uploadPartCpyErrReq := httptest.NewRequest(http.MethodPut, "/my-bucket/my-key?uploadId=12asd32&partNumber=invalid", nil)
	uploadPartCpyErrReq.Header.Set("X-Amz-Copy-Source", "srcBucket/srcObject")

	// CopyObject success
	cpySrcReq := httptest.NewRequest(http.MethodPut, "/my-bucket/my-key", nil)
	cpySrcReq.Header.Set("X-Amz-Copy-Source", "srcBucket/srcObject")

	// PutObjectAcl success
	aclReq := httptest.NewRequest(http.MethodPut, "/my-bucket/my-key", nil)
	aclReq.Header.Set("X-Amz-Acl", "private")

	// PutObjectAcl success grt case
	aclGrtReq := httptest.NewRequest(http.MethodPut, "/my-bucket/my-key", nil)
	aclGrtReq.Header.Set("X-Amz-Grant-Read", "private")

	// invalid acl case 1
	invAclReq := httptest.NewRequest(http.MethodPut, "/my-bucket/my-key?acl", nil)
	invAclReq.Header.Set("X-Amz-Acl", "invalid")

	// invalid acl case 2
	errAclReq := httptest.NewRequest(http.MethodPut, "/my-bucket/my-key?acl", nil)
	errAclReq.Header.Set("X-Amz-Acl", "private")
	errAclReq.Header.Set("X-Amz-Grant-Read", "hello")

	// invalid body & grt case
	invAclBodyGrtReq := httptest.NewRequest(http.MethodPut, "/my-bucket/my-key?acl", strings.NewReader(body))
	invAclBodyGrtReq.Header.Set("X-Amz-Grant-Read", "hello")

	tests := []struct {
		name       string
		app        *fiber.App
		args       args
		wantErr    bool
		statusCode int
	}{
		{
			name: "Put-object-part-error-case",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPut, "/my-bucket/my-key?uploadId=abc&partNumber=invalid", nil),
			},
			wantErr:    false,
			statusCode: 400,
		},
		{
			name: "Put-object-part-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPut, "/my-bucket/my-key?uploadId=4&partNumber=3", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Set-tags-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPut, "/my-bucket/my-key?tagging", strings.NewReader(tagBody)),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Put-object-acl-invalid-acl",
			app:  app,
			args: args{
				req: invAclReq,
			},
			wantErr:    false,
			statusCode: 400,
		},
		{
			name: "Put-object-acl-incorrect-acl",
			app:  app,
			args: args{
				req: errAclReq,
			},
			wantErr:    false,
			statusCode: 400,
		},
		{
			name: "Put-object-acl-incorrect-acl-body-case",
			app:  app,
			args: args{
				req: invAclBodyGrtReq,
			},
			wantErr:    false,
			statusCode: 400,
		},
		{
			name: "Put-object-acl-success",
			app:  app,
			args: args{
				req: aclReq,
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Put-object-acl-success-body-case",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPut, "/my-bucket/my-key?acl", strings.NewReader(body)),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Put-object-acl-success-grt-case",
			app:  app,
			args: args{
				req: aclGrtReq,
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Upload-part-copy-invalid-part-number",
			app:  app,
			args: args{
				req: uploadPartCpyErrReq,
			},
			wantErr:    false,
			statusCode: 400,
		},
		{
			name: "Upload-part-copy-success",
			app:  app,
			args: args{
				req: uploadPartCpyReq,
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Copy-object-success",
			app:  app,
			args: args{
				req: cpySrcReq,
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Put-object-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPut, "/my-bucket/my-key/key2", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
	}
	for _, tt := range tests {
		resp, err := tt.app.Test(tt.args.req)

		if (err != nil) != tt.wantErr {
			t.Errorf("S3ApiController.GetActions() %v error = %v, wantErr %v",
				tt.name, err, tt.wantErr)
		}

		if resp.StatusCode != tt.statusCode {
			t.Errorf("S3ApiController.GetActions() %v statusCode = %v, wantStatusCode = %v",
				tt.name, resp.StatusCode, tt.statusCode)
		}
	}
}

func TestS3ApiController_DeleteBucket(t *testing.T) {
	type args struct {
		req *http.Request
	}

	app := fiber.New()
	s3ApiController := S3ApiController{
		be: &BackendMock{
			GetBucketAclFunc: func(bucket string) ([]byte, error) {
				return acldata, nil
			},
			DeleteBucketFunc: func(bucket string) error {
				return nil
			},
		},
	}

	app.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("access", "valid access")
		ctx.Locals("isRoot", true)
		ctx.Locals("isDebug", false)
		return ctx.Next()
	})

	app.Delete("/:bucket", s3ApiController.DeleteBucket)

	tests := []struct {
		name       string
		app        *fiber.App
		args       args
		wantErr    bool
		statusCode int
	}{
		{
			name: "Delete-bucket-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodDelete, "/my-bucket", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
	}
	for _, tt := range tests {
		resp, err := tt.app.Test(tt.args.req)

		if (err != nil) != tt.wantErr {
			t.Errorf("S3ApiController.DeleteBucket() error = %v, wantErr %v", err, tt.wantErr)
		}

		if resp.StatusCode != tt.statusCode {
			t.Errorf("S3ApiController.DeleteBucket() statusCode = %v, wantStatusCode = %v", resp.StatusCode, tt.statusCode)
		}
	}
}

func TestS3ApiController_DeleteObjects(t *testing.T) {
	type args struct {
		req *http.Request
	}

	app := fiber.New()
	s3ApiController := S3ApiController{
		be: &BackendMock{
			GetBucketAclFunc: func(bucket string) ([]byte, error) {
				return acldata, nil
			},
			DeleteObjectsFunc: func(bucket string, objects *s3.DeleteObjectsInput) error {
				return nil
			},
		},
	}

	app.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("access", "valid access")
		ctx.Locals("isRoot", true)
		ctx.Locals("isDebug", false)
		return ctx.Next()
	})
	app.Post("/:bucket", s3ApiController.DeleteObjects)

	// Valid request body
	xmlBody := `<root><key>body</key></root>`

	request := httptest.NewRequest(http.MethodPost, "/my-bucket", strings.NewReader(xmlBody))
	request.Header.Set("Content-Type", "application/xml")

	tests := []struct {
		name       string
		app        *fiber.App
		args       args
		wantErr    bool
		statusCode int
	}{
		{
			name: "Delete-Objects-success",
			app:  app,
			args: args{
				req: request,
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Delete-Objects-error",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPost, "/my-bucket", nil),
			},
			wantErr:    false,
			statusCode: 400,
		},
	}
	for _, tt := range tests {
		resp, err := tt.app.Test(tt.args.req)

		if (err != nil) != tt.wantErr {
			t.Errorf("S3ApiController.DeleteObjects() error = %v, wantErr %v", err, tt.wantErr)
		}

		if resp.StatusCode != tt.statusCode {
			t.Errorf("S3ApiController.DeleteObjects() statusCode = %v, wantStatusCode = %v", resp.StatusCode, tt.statusCode)
		}
	}
}

func TestS3ApiController_DeleteActions(t *testing.T) {
	type args struct {
		req *http.Request
	}

	app := fiber.New()
	s3ApiController := S3ApiController{
		be: &BackendMock{
			GetBucketAclFunc: func(bucket string) ([]byte, error) {
				return acldata, nil
			},
			DeleteObjectFunc: func(bucket, object string) error {
				return nil
			},
			AbortMultipartUploadFunc: func(*s3.AbortMultipartUploadInput) error {
				return nil
			},
			RemoveTagsFunc: func(bucket, object string) error {
				return nil
			},
		},
	}

	app.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("access", "valid access")
		ctx.Locals("isRoot", true)
		ctx.Locals("isDebug", false)
		return ctx.Next()
	})
	app.Delete("/:bucket/:key/*", s3ApiController.DeleteActions)

	// Error case
	appErr := fiber.New()

	s3ApiControllerErr := S3ApiController{be: &BackendMock{
		GetBucketAclFunc: func(bucket string) ([]byte, error) {
			return acldata, nil
		},
		DeleteObjectFunc: func(bucket, object string) error {
			return s3err.GetAPIError(7)
		},
	}}

	appErr.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("access", "valid access")
		ctx.Locals("isRoot", true)
		ctx.Locals("isDebug", false)
		return ctx.Next()
	})
	appErr.Delete("/:bucket/:key/*", s3ApiControllerErr.DeleteActions)

	tests := []struct {
		name       string
		app        *fiber.App
		args       args
		wantErr    bool
		statusCode int
	}{
		{
			name: "Abort-multipart-upload-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodDelete, "/my-bucket/my-key?uploadId=324234", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Remove-object-tagging-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodDelete, "/my-bucket/my-key/key2?tagging", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Delete-object-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodDelete, "/my-bucket/my-key", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Delete-object-error",
			app:  appErr,
			args: args{
				req: httptest.NewRequest(http.MethodDelete, "/my-bucket/invalid-key", nil),
			},
			wantErr:    false,
			statusCode: 404,
		},
	}
	for _, tt := range tests {
		resp, err := tt.app.Test(tt.args.req)

		if (err != nil) != tt.wantErr {
			t.Errorf("S3ApiController.DeleteActions() error = %v, wantErr %v", err, tt.wantErr)
		}

		if resp.StatusCode != tt.statusCode {
			t.Errorf("S3ApiController.DeleteActions() statusCode = %v, wantStatusCode = %v", resp.StatusCode, tt.statusCode)
		}
	}
}

func TestS3ApiController_HeadBucket(t *testing.T) {
	type args struct {
		req *http.Request
	}

	app := fiber.New()
	s3ApiController := S3ApiController{
		be: &BackendMock{
			GetBucketAclFunc: func(bucket string) ([]byte, error) {
				return acldata, nil
			},
			HeadBucketFunc: func(bucket string) (*s3.HeadBucketOutput, error) {
				return &s3.HeadBucketOutput{}, nil
			},
		},
	}

	app.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("access", "valid access")
		ctx.Locals("isRoot", true)
		ctx.Locals("isDebug", false)
		return ctx.Next()
	})

	app.Head("/:bucket", s3ApiController.HeadBucket)

	// Error case
	appErr := fiber.New()

	s3ApiControllerErr := S3ApiController{be: &BackendMock{
		GetBucketAclFunc: func(bucket string) ([]byte, error) {
			return acldata, nil
		},
		HeadBucketFunc: func(bucket string) (*s3.HeadBucketOutput, error) {
			return nil, s3err.GetAPIError(3)
		},
	},
	}

	appErr.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("access", "valid access")
		ctx.Locals("isRoot", true)
		ctx.Locals("isDebug", false)
		return ctx.Next()
	})

	appErr.Head("/:bucket", s3ApiControllerErr.HeadBucket)

	tests := []struct {
		name       string
		app        *fiber.App
		args       args
		wantErr    bool
		statusCode int
	}{
		{
			name: "Head-bucket-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodHead, "/my-bucket", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Head-bucket-error",
			app:  appErr,
			args: args{
				req: httptest.NewRequest(http.MethodHead, "/my-bucket", nil),
			},
			wantErr:    false,
			statusCode: 409,
		},
	}
	for _, tt := range tests {
		resp, err := tt.app.Test(tt.args.req)

		if (err != nil) != tt.wantErr {
			t.Errorf("S3ApiController.HeadBucket() error = %v, wantErr %v", err, tt.wantErr)
		}

		if resp.StatusCode != tt.statusCode {
			t.Errorf("S3ApiController.HeadBucket() statusCode = %v, wantStatusCode = %v", resp.StatusCode, tt.statusCode)
		}
	}
}

func TestS3ApiController_HeadObject(t *testing.T) {
	type args struct {
		req *http.Request
	}

	app := fiber.New()

	// Mock values
	contentEncoding := "gzip"
	contentType := "application/xml"
	eTag := "Valid etag"
	lastModifie := time.Now()

	s3ApiController := S3ApiController{
		be: &BackendMock{
			GetBucketAclFunc: func(bucket string) ([]byte, error) {
				return acldata, nil
			},
			HeadObjectFunc: func(bucket, object string) (*s3.HeadObjectOutput, error) {
				return &s3.HeadObjectOutput{
					ContentEncoding: &contentEncoding,
					ContentLength:   64,
					ContentType:     &contentType,
					LastModified:    &lastModifie,
					ETag:            &eTag,
				}, nil
			},
		},
	}

	app.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("access", "valid access")
		ctx.Locals("isRoot", true)
		ctx.Locals("isDebug", false)
		return ctx.Next()
	})
	app.Head("/:bucket/:key/*", s3ApiController.HeadObject)

	//Error case
	appErr := fiber.New()

	s3ApiControllerErr := S3ApiController{
		be: &BackendMock{
			GetBucketAclFunc: func(bucket string) ([]byte, error) {
				return acldata, nil
			},
			HeadObjectFunc: func(bucket, object string) (*s3.HeadObjectOutput, error) {
				return nil, s3err.GetAPIError(42)
			},
		},
	}

	appErr.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("access", "valid access")
		ctx.Locals("isRoot", true)
		ctx.Locals("isDebug", false)
		return ctx.Next()
	})
	appErr.Head("/:bucket/:key/*", s3ApiControllerErr.HeadObject)

	tests := []struct {
		name       string
		app        *fiber.App
		args       args
		wantErr    bool
		statusCode int
	}{
		{
			name: "Head-object-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodHead, "/my-bucket/my-key", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Head-object-error",
			app:  appErr,
			args: args{
				req: httptest.NewRequest(http.MethodHead, "/my-bucket/my-key", nil),
			},
			wantErr:    false,
			statusCode: 400,
		},
	}
	for _, tt := range tests {
		resp, err := tt.app.Test(tt.args.req)

		if (err != nil) != tt.wantErr {
			t.Errorf("S3ApiController.HeadObject() error = %v, wantErr %v", err, tt.wantErr)
		}

		if resp.StatusCode != tt.statusCode {
			t.Errorf("S3ApiController.HeadObject() statusCode = %v, wantStatusCode = %v", resp.StatusCode, tt.statusCode)
		}
	}
}

func TestS3ApiController_CreateActions(t *testing.T) {
	type args struct {
		req *http.Request
	}
	app := fiber.New()
	s3ApiController := S3ApiController{
		be: &BackendMock{
			GetBucketAclFunc: func(bucket string) ([]byte, error) {
				return acldata, nil
			},
			RestoreObjectFunc: func(bucket, object string, restoreRequest *s3.RestoreObjectInput) error {
				return nil
			},
			CompleteMultipartUploadFunc: func(bucket, object, uploadID string, parts []types.Part) (*s3.CompleteMultipartUploadOutput, error) {
				return &s3.CompleteMultipartUploadOutput{}, nil
			},
			CreateMultipartUploadFunc: func(*s3.CreateMultipartUploadInput) (*s3.CreateMultipartUploadOutput, error) {
				return &s3.CreateMultipartUploadOutput{}, nil
			},
		},
	}

	app.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("access", "valid access")
		ctx.Locals("isRoot", true)
		ctx.Locals("isDebug", false)
		return ctx.Next()
	})
	app.Post("/:bucket/:key/*", s3ApiController.CreateActions)

	tests := []struct {
		name       string
		app        *fiber.App
		args       args
		wantErr    bool
		statusCode int
	}{
		{
			name: "Restore-object-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPost, "/my-bucket/my-key?restore", strings.NewReader(`<root><key>body</key></root>`)),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Restore-object-error",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPost, "/my-bucket/my-key?restore", nil),
			},
			wantErr:    false,
			statusCode: 500,
		},
		{
			name: "Complete-multipart-upload-error",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPost, "/my-bucket/my-key?uploadId=23423", nil),
			},
			wantErr:    false,
			statusCode: 500,
		},
		{
			name: "Complete-multipart-upload-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPost, "/my-bucket/my-key?uploadId=23423", strings.NewReader(`<root><key>body</key></root>`)),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Create-multipart-upload-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPost, "/my-bucket/my-key", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
	}
	for _, tt := range tests {
		resp, err := tt.app.Test(tt.args.req)

		if (err != nil) != tt.wantErr {
			t.Errorf("S3ApiController.CreateActions() error = %v, wantErr %v", err, tt.wantErr)
		}

		if resp.StatusCode != tt.statusCode {
			t.Errorf("S3ApiController.CreateActions() statusCode = %v, wantStatusCode = %v", resp.StatusCode, tt.statusCode)
		}
	}
}

func Test_XMLresponse(t *testing.T) {
	type args struct {
		ctx  *fiber.Ctx
		resp any
		err  error
	}
	app := fiber.New()

	var ctx fiber.Ctx
	// Mocking the fiber ctx
	app.Get("/:bucket/:key", func(c *fiber.Ctx) error {
		ctx = *c
		return nil
	})

	app.Test(httptest.NewRequest(http.MethodGet, "/my-bucket/my-key", nil))

	tests := []struct {
		name       string
		args       args
		wantErr    bool
		statusCode int
	}{
		{
			name: "Internal-server-error",
			args: args{
				ctx:  &ctx,
				resp: nil,
				err:  s3err.GetAPIError(16),
			},
			wantErr:    false,
			statusCode: 500,
		},
		{
			name: "Error-not-implemented",
			args: args{
				ctx:  &ctx,
				resp: nil,
				err:  s3err.GetAPIError(50),
			},
			wantErr:    false,
			statusCode: 501,
		},
		{
			name: "Invalid-request-body",
			args: args{
				ctx:  &ctx,
				resp: make(chan int),
				err:  nil,
			},
			wantErr:    true,
			statusCode: 200,
		},
		{
			name: "Successful-response",
			args: args{
				ctx:  &ctx,
				resp: "Valid response",
				err:  nil,
			},
			wantErr:    false,
			statusCode: 200,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := SendXMLResponse(tt.args.ctx, tt.args.resp, tt.args.err); (err != nil) != tt.wantErr {
				t.Errorf("response() %v error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}

			statusCode := tt.args.ctx.Response().StatusCode()

			if statusCode != tt.statusCode {
				t.Errorf("response() %v code = %v, wantErr %v", tt.name, statusCode, tt.wantErr)
			}

			tt.args.ctx.Status(http.StatusOK)
		})
	}
}

func Test_response(t *testing.T) {
	type args struct {
		ctx  *fiber.Ctx
		resp any
		err  error
	}
	app := fiber.New()
	var ctx fiber.Ctx
	// Mocking the fiber ctx
	app.Get("/:bucket/:key", func(c *fiber.Ctx) error {
		ctx = *c
		return nil
	})

	app.Test(httptest.NewRequest(http.MethodGet, "/my-bucket/my-key", nil))

	tests := []struct {
		name       string
		args       args
		wantErr    bool
		statusCode int
	}{
		{
			name: "Internal-server-error",
			args: args{
				ctx:  &ctx,
				resp: nil,
				err:  s3err.GetAPIError(16),
			},
			wantErr:    false,
			statusCode: 500,
		},
		{
			name: "Internal-server-error-not-api",
			args: args{
				ctx:  &ctx,
				resp: nil,
				err:  fmt.Errorf("custom error"),
			},
			wantErr:    false,
			statusCode: 500,
		},
		{
			name: "Error-not-implemented",
			args: args{
				ctx:  &ctx,
				resp: nil,
				err:  s3err.GetAPIError(50),
			},
			wantErr:    false,
			statusCode: 501,
		},
		{
			name: "Successful-response",
			args: args{
				ctx:  &ctx,
				resp: "Valid response",
				err:  nil,
			},
			wantErr:    false,
			statusCode: 200,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := SendResponse(tt.args.ctx, tt.args.err); (err != nil) != tt.wantErr {
				t.Errorf("response() %v error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}

			statusCode := tt.args.ctx.Response().StatusCode()

			if statusCode != tt.statusCode {
				t.Errorf("response() %v code = %v, wantErr %v", tt.name, statusCode, tt.wantErr)
			}
		})
	}
}
