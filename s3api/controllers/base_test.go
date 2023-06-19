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
	"github.com/valyala/fasthttp"
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
		be backend.Backend
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
				be: be,
			},
			want: S3ApiController{
				be: be,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(tt.args.be); !reflect.DeepEqual(got, tt.want) {
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
		return ctx.Next()
	})
	appErr.Get("/", s3ApiControllerErr.ListBuckets)

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
				return &s3.GetObjectOutput{Metadata: nil}, nil
			},
		},
	}
	app.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("access", "valid access")
		ctx.Locals("isRoot", true)
		return ctx.Next()
	})
	app.Get("/:bucket/:key/*", s3ApiController.GetActions)

	// GetObjectACL
	getObjectACLReq := httptest.NewRequest(http.MethodGet, "/my-bucket/key", nil)
	getObjectACLReq.Header.Set("X-Amz-Object-Attributes", "attrs")

	// GetObject error case
	getObjectReq := httptest.NewRequest(http.MethodGet, "/my-bucket/key", nil)
	getObjectReq.Header.Set("Range", "hello=")

	// GetObject success case
	getObjectSuccessReq := httptest.NewRequest(http.MethodGet, "/my-bucket/key", nil)
	getObjectReq.Header.Set("Range", "range=13-invalid")

	tests := []struct {
		name       string
		app        *fiber.App
		args       args
		wantErr    bool
		statusCode int
	}{
		{
			name: "Get-actions-invalid-max-parts",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodGet, "/my-bucket/key?uploadId=hello&max-parts=InvalidMaxParts", nil),
			},
			wantErr:    false,
			statusCode: 400,
		},
		{
			name: "Get-actions-invalid-part-number-marker",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodGet, "/my-bucket/key?uploadId=hello&max-parts=200&part-number-marker=InvalidPartNumber", nil),
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
				req: getObjectACLReq,
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Get-actions-get-object-success",
			app:  app,
			args: args{
				req: getObjectSuccessReq,
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
				t.Errorf("S3ApiController.GetActions() error = %v, wantErr %v", err, tt.wantErr)
			}

			if resp.StatusCode != tt.statusCode {
				t.Errorf("S3ApiController.GetActions() statusCode = %v, wantStatusCode = %v", resp.StatusCode, tt.statusCode)
			}
		})
	}
}

func TestS3ApiController_PutBucketActions(t *testing.T) {
	type args struct {
		req *http.Request
	}

	app := fiber.New()
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
		return ctx.Next()
	})
	app.Put("/:bucket", s3ApiController.PutBucketActions)

	// Error case
	errorReq := httptest.NewRequest(http.MethodPut, "/my-bucket", nil)
	errorReq.Header.Set("X-Amz-Acl", "restricted")
	errorReq.Header.Set("X-Amz-Grant-Read", "read")

	// PutBucketAcl success
	aclReq := httptest.NewRequest(http.MethodPut, "/my-bucket", nil)
	errorReq.Header.Set("X-Amz-Acl", "full")

	tests := []struct {
		name       string
		app        *fiber.App
		args       args
		wantErr    bool
		statusCode int
	}{
		{
			name: "Put-bucket-acl-error",
			app:  app,
			args: args{
				req: errorReq,
			},
			wantErr:    false,
			statusCode: 500,
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
			t.Errorf("S3ApiController.GetActions() error = %v, wantErr %v", err, tt.wantErr)
		}

		if resp.StatusCode != tt.statusCode {
			t.Errorf("S3ApiController.GetActions() statusCode = %v, wantStatusCode = %v", resp.StatusCode, tt.statusCode)
		}
	}
}

func TestS3ApiController_PutActions(t *testing.T) {
	type args struct {
		req *http.Request
	}

	app := fiber.New()
	s3ApiController := S3ApiController{
		be: &BackendMock{
			GetBucketAclFunc: func(bucket string) ([]byte, error) {
				return acldata, nil
			},
			UploadPartCopyFunc: func(*s3.UploadPartCopyInput) (*s3.UploadPartCopyOutput, error) {
				return &s3.UploadPartCopyOutput{}, nil
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
		},
	}
	app.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("access", "valid access")
		ctx.Locals("isRoot", true)
		return ctx.Next()
	})
	app.Put("/:bucket/:key/*", s3ApiController.PutActions)

	//PutObjectAcl error
	aclReqErr := httptest.NewRequest(http.MethodPut, "/my-bucket/my-key", nil)
	aclReqErr.Header.Set("X-Amz-Acl", "acl")
	aclReqErr.Header.Set("X-Amz-Grant-Write", "write")

	//PutObjectAcl success
	aclReq := httptest.NewRequest(http.MethodPut, "/my-bucket/my-key", nil)
	aclReq.Header.Set("X-Amz-Acl", "acl")

	//CopyObject success
	cpySrcReq := httptest.NewRequest(http.MethodPut, "/my-bucket/my-key", nil)
	cpySrcReq.Header.Set("X-Amz-Copy-Source", "srcBucket/srcObject")

	tests := []struct {
		name       string
		app        *fiber.App
		args       args
		wantErr    bool
		statusCode int
	}{
		{
			name: "Upload-put-part-error-case",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPut, "/my-bucket/my-key?uploadId=abc&partNumber=invalid", nil),
			},
			wantErr:    false,
			statusCode: 400,
		},
		{
			name: "Upload-copy-part-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPut, "/my-bucket/my-key?partNumber=3", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Upload-part-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPut, "/my-bucket/my-key?uploadId=234234", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Put-object-acl-error",
			app:  app,
			args: args{
				req: aclReqErr,
			},
			wantErr:    false,
			statusCode: 500,
		},
		{
			name: "Put-object-acl-error",
			app:  app,
			args: args{
				req: aclReqErr,
			},
			wantErr:    false,
			statusCode: 500,
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
				req: httptest.NewRequest(http.MethodPut, "/my-bucket/my-key", nil),
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
		return ctx.Next()
	})

	app.Delete("/:bucket", s3ApiController.DeleteBucket)

	// error case
	appErr := fiber.New()

	s3ApiControllerErr := S3ApiController{
		be: &BackendMock{
			GetBucketAclFunc: func(bucket string) ([]byte, error) {
				return acldata, nil
			},
			DeleteBucketFunc: func(bucket string) error {
				return s3err.GetAPIError(48)
			},
		},
	}

	appErr.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("access", "valid access")
		ctx.Locals("isRoot", true)
		return ctx.Next()
	})
	appErr.Delete("/:bucket", s3ApiControllerErr.DeleteBucket)

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
		{
			name: "Delete-bucket-error",
			app:  appErr,
			args: args{
				req: httptest.NewRequest(http.MethodDelete, "/my-bucket", nil),
			},
			wantErr:    false,
			statusCode: 400,
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
			statusCode: 500,
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
		},
	}

	app.Use(func(ctx *fiber.Ctx) error {
		ctx.Locals("access", "valid access")
		ctx.Locals("isRoot", true)
		return ctx.Next()
	})
	app.Delete("/:bucket/:key/*", s3ApiController.DeleteActions)

	//Error case
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
		return ctx.Next()
	})
	appErr.Delete("/:bucket", s3ApiControllerErr.DeleteBucket)

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

	tests := []struct {
		name       string
		args       args
		wantErr    bool
		statusCode int
	}{
		{
			name: "Internal-server-error",
			args: args{
				ctx:  app.AcquireCtx(&fasthttp.RequestCtx{}),
				resp: nil,
				err:  s3err.GetAPIError(16),
			},
			wantErr:    false,
			statusCode: 500,
		},
		{
			name: "Error-not-implemented",
			args: args{
				ctx:  app.AcquireCtx(&fasthttp.RequestCtx{}),
				resp: nil,
				err:  s3err.GetAPIError(50),
			},
			wantErr:    false,
			statusCode: 501,
		},
		{
			name: "Invalid-request-body",
			args: args{
				ctx:  app.AcquireCtx(&fasthttp.RequestCtx{}),
				resp: make(chan int),
				err:  nil,
			},
			wantErr:    true,
			statusCode: 200,
		},
		{
			name: "Successful-response",
			args: args{
				ctx:  app.AcquireCtx(&fasthttp.RequestCtx{}),
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

	tests := []struct {
		name       string
		args       args
		wantErr    bool
		statusCode int
	}{
		{
			name: "Internal-server-error",
			args: args{
				ctx:  app.AcquireCtx(&fasthttp.RequestCtx{}),
				resp: nil,
				err:  s3err.GetAPIError(16),
			},
			wantErr:    false,
			statusCode: 500,
		},
		{
			name: "Error-not-implemented",
			args: args{
				ctx:  app.AcquireCtx(&fasthttp.RequestCtx{}),
				resp: nil,
				err:  s3err.GetAPIError(50),
			},
			wantErr:    false,
			statusCode: 501,
		},
		{
			name: "Successful-response",
			args: args{
				ctx:  app.AcquireCtx(&fasthttp.RequestCtx{}),
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
