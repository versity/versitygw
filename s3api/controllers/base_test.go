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
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
)

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
		ctx *fiber.Ctx
	}

	app := fiber.New()

	tests := []struct {
		name       string
		c          S3ApiController
		args       args
		wantErr    bool
		statusCode int
	}{
		{
			name: "List-bucket-not-implemented",
			c: S3ApiController{
				be: backend.BackendUnsupported{},
			},
			args: args{
				ctx: app.AcquireCtx(&fasthttp.RequestCtx{}),
			},
			wantErr:    false,
			statusCode: 501,
		},
		{
			name: "list-bucket-success",
			c: S3ApiController{
				be: &BackendMock{
					ListBucketsFunc: func() (*s3.ListBucketsOutput, error) {
						return &s3.ListBucketsOutput{}, nil
					},
				},
			},
			args: args{
				ctx: app.AcquireCtx(&fasthttp.RequestCtx{}),
			},
			wantErr:    false,
			statusCode: 200,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.c.ListBuckets(tt.args.ctx)

			if (err != nil) != tt.wantErr {
				t.Errorf("S3ApiController.ListBuckets() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			statusCode := tt.args.ctx.Response().StatusCode()

			if statusCode != tt.statusCode {
				t.Errorf("S3ApiController.ListBuckets() code = %v, wantErr %v", statusCode, tt.wantErr)
			}
		})
	}
}

func TestS3ApiController_GetActions(t *testing.T) {
	type args struct {
		req *http.Request
	}

	app := fiber.New()
	s3ApiController := S3ApiController{be: &BackendMock{
		ListObjectPartsFunc: func(bucket, object, uploadID string, partNumberMarker int, maxParts int) (*s3.ListPartsOutput, error) {
			return &s3.ListPartsOutput{}, nil
		},
		GetObjectAclFunc: func(bucket, object string) (*s3.GetObjectAclOutput, error) {
			return &s3.GetObjectAclOutput{}, nil
		},
		GetObjectAttributesFunc: func(bucket, object string, attributes []string) (*s3.GetObjectAttributesOutput, error) {
			return &s3.GetObjectAttributesOutput{}, nil
		},
		GetObjectFunc: func(bucket, object, acceptRange string, startOffset, length int64, writer io.Writer) (*s3.GetObjectOutput, error) {
			return &s3.GetObjectOutput{Metadata: nil}, nil
		},
	}}
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
			statusCode: 500,
		},
		{
			name: "Get-actions-invalid-part-number",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodGet, "/my-bucket/key?uploadId=hello&max-parts=200&part-number-marker=InvalidPartNumber", nil),
			},
			wantErr:    false,
			statusCode: 500,
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
			name: "Get-actions-invalid-range-header",
			app:  app,
			args: args{
				req: getObjectReq,
			},
			wantErr:    false,
			statusCode: 500,
		},
		{
			name: "Get-actions-get-object-error",
			app:  app,
			args: args{
				req: getObjectSuccessReq,
			},
			wantErr:    false,
			statusCode: 500,
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
	s3ApiController := S3ApiController{be: &BackendMock{
		GetBucketAclFunc: func(bucket string) (*s3.GetBucketAclOutput, error) {
			return &s3.GetBucketAclOutput{}, nil
		},
		ListMultipartUploadsFunc: func(output *s3.ListMultipartUploadsInput) (*s3.ListMultipartUploadsOutput, error) {
			return &s3.ListMultipartUploadsOutput{}, nil
		},
		ListObjectsV2Func: func(bucket, prefix, marker, delim string, maxkeys int) (*s3.ListObjectsV2Output, error) {
			return &s3.ListObjectsV2Output{}, nil
		},
		ListObjectsFunc: func(bucket, prefix, marker, delim string, maxkeys int) (*s3.ListObjectsOutput, error) {
			return &s3.ListObjectsOutput{}, nil
		},
	}}
	app.Get("/:bucket", s3ApiController.ListActions)

	//Error case
	s3ApiControllerError := S3ApiController{be: &BackendMock{
		ListObjectsFunc: func(bucket, prefix, marker, delim string, maxkeys int) (*s3.ListObjectsOutput, error) {
			return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
		},
	}}
	appError := fiber.New()
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
	s3ApiController := S3ApiController{be: &BackendMock{
		PutBucketAclFunc: func(*s3.PutBucketAclInput) error {
			return nil
		},
		PutBucketFunc: func(bucket string) error {
			return nil
		},
	}}
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
	s3ApiController := S3ApiController{be: &BackendMock{
		UploadPartCopyFunc: func(*s3.UploadPartCopyInput) (*s3.UploadPartCopyOutput, error) {
			return &s3.UploadPartCopyOutput{}, nil
		},
		UploadPartFunc: func(bucket, object, uploadId string, Body io.ReadSeeker) (*s3.UploadPartOutput, error) {
			return &s3.UploadPartOutput{}, nil
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
	}}
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
			name: "Upload-copy-part-error-case",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPut, "/my-bucket/my-key?partNumber=invalid", nil),
			},
			wantErr:    false,
			statusCode: 500,
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
			t.Errorf("S3ApiController.GetActions() error = %v, wantErr %v", err, tt.wantErr)
		}

		if resp.StatusCode != tt.statusCode {
			t.Errorf("S3ApiController.GetActions() statusCode = %v, wantStatusCode = %v", resp.StatusCode, tt.statusCode)
		}
	}
}

func TestS3ApiController_DeleteBucket(t *testing.T) {
	type args struct {
		ctx *fiber.Ctx
	}
	tests := []struct {
		name    string
		c       S3ApiController
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.c.DeleteBucket(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("S3ApiController.DeleteBucket() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestS3ApiController_DeleteObjects(t *testing.T) {
	type args struct {
		ctx *fiber.Ctx
	}
	tests := []struct {
		name    string
		c       S3ApiController
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.c.DeleteObjects(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("S3ApiController.DeleteObjects() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestS3ApiController_DeleteActions(t *testing.T) {
	type args struct {
		ctx *fiber.Ctx
	}
	tests := []struct {
		name    string
		c       S3ApiController
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.c.DeleteActions(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("S3ApiController.DeleteActions() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestS3ApiController_HeadBucket(t *testing.T) {
	type args struct {
		ctx *fiber.Ctx
	}
	tests := []struct {
		name    string
		c       S3ApiController
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.c.HeadBucket(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("S3ApiController.HeadBucket() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestS3ApiController_HeadObject(t *testing.T) {
	type args struct {
		ctx *fiber.Ctx
	}
	tests := []struct {
		name    string
		c       S3ApiController
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.c.HeadObject(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("S3ApiController.HeadObject() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestS3ApiController_CreateActions(t *testing.T) {
	type args struct {
		ctx *fiber.Ctx
	}
	tests := []struct {
		name    string
		c       S3ApiController
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.c.CreateActions(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("S3ApiController.CreateActions() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_responce(t *testing.T) {
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
			if err := responce(tt.args.ctx, tt.args.resp, tt.args.err); (err != nil) != tt.wantErr {
				t.Errorf("responce() error = %v, wantErr %v", err, tt.wantErr)
			}

			statusCode := tt.args.ctx.Response().StatusCode()

			if statusCode != tt.statusCode {
				t.Errorf("responce() code = %v, wantErr %v", statusCode, tt.wantErr)
			}
		})
	}
}
