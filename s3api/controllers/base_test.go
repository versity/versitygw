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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
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
	"github.com/versity/versitygw/s3api/utils"
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
			got := New(tt.args.be, tt.args.iam, nil, nil, nil, false, false)
			if !reflect.DeepEqual(got, tt.want) {
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
			ListBucketsFunc: func(contextMoqParam context.Context, listBucketsInput s3response.ListBucketsInput) (s3response.ListAllMyBucketsResult, error) {
				return s3response.ListAllMyBucketsResult{}, nil
			},
		},
	}

	app.Use(func(ctx *fiber.Ctx) error {
		utils.ContextKeyAccount.Set(ctx, auth.Account{Access: "valid access", Role: "admin:"})
		return ctx.Next()
	})
	app.Get("/", s3ApiController.ListBuckets)

	// Error case
	appErr := fiber.New()
	s3ApiControllerErr := S3ApiController{
		be: &BackendMock{
			ListBucketsFunc: func(contextMoqParam context.Context, listBucketsInput s3response.ListBucketsInput) (s3response.ListAllMyBucketsResult, error) {
				return s3response.ListAllMyBucketsResult{}, s3err.GetAPIError(s3err.ErrMethodNotAllowed)
			},
		},
	}

	appErr.Use(func(ctx *fiber.Ctx) error {
		utils.ContextKeyAccount.Set(ctx, auth.Account{Access: "valid access", Role: "admin:"})
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

func getPtr(val string) *string {
	return &val
}

func TestS3ApiController_GetActions(t *testing.T) {
	type args struct {
		req *http.Request
	}

	now := time.Now()

	app := fiber.New()
	contentLength := int64(1000)
	s3ApiController := S3ApiController{
		be: &BackendMock{
			GetBucketAclFunc: func(context.Context, *s3.GetBucketAclInput) ([]byte, error) {
				return acldata, nil
			},
			ListPartsFunc: func(context.Context, *s3.ListPartsInput) (s3response.ListPartsResult, error) {
				return s3response.ListPartsResult{}, nil
			},
			GetObjectAclFunc: func(context.Context, *s3.GetObjectAclInput) (*s3.GetObjectAclOutput, error) {
				return &s3.GetObjectAclOutput{}, nil
			},
			GetObjectAttributesFunc: func(context.Context, *s3.GetObjectAttributesInput) (s3response.GetObjectAttributesResponse, error) {
				return s3response.GetObjectAttributesResponse{}, nil
			},
			GetObjectFunc: func(context.Context, *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
				return &s3.GetObjectOutput{
					Metadata:        map[string]string{"hello": "world"},
					ContentType:     getPtr("application/xml"),
					ContentEncoding: getPtr("gzip"),
					ETag:            getPtr("98sda7f97sa9df798sd79f8as9df"),
					ContentLength:   &contentLength,
					LastModified:    &now,
					StorageClass:    "storage class",
				}, nil
			},
			GetObjectTaggingFunc: func(_ context.Context, bucket, object string) (map[string]string, error) {
				return map[string]string{"hello": "world"}, nil
			},
			GetObjectRetentionFunc: func(contextMoqParam context.Context, bucket, object, versionId string) ([]byte, error) {
				result, err := json.Marshal(types.ObjectLockRetention{
					Mode: types.ObjectLockRetentionModeCompliance,
				})
				if err != nil {
					return nil, err
				}
				return result, nil
			},
			GetObjectLegalHoldFunc: func(contextMoqParam context.Context, bucket, object, versionId string) (*bool, error) {
				result := true
				return &result, nil
			},
		},
	}
	app.Use(func(ctx *fiber.Ctx) error {
		utils.ContextKeyAccount.Set(ctx, auth.Account{Access: "valid access"})
		utils.ContextKeyIsRoot.Set(ctx, true)
		utils.ContextKeyParsedAcl.Set(ctx, auth.ACL{})
		return ctx.Next()
	})
	app.Get("/:bucket/:key/*", s3ApiController.GetActions)

	// GetObjectAttributes success case
	getObjAttrs := httptest.NewRequest(http.MethodGet, "/my-bucket/key", nil)
	getObjAttrs.Header.Set("X-Amz-Object-Attributes", "hello")

	invalidChecksumMode := httptest.NewRequest(http.MethodGet, "/my-bucket/key", nil)
	invalidChecksumMode.Header.Set("x-amz-checksum-mode", "invalid_checksum_mode")

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
			name: "Get-actions-get-object-retention-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodGet, "/my-bucket/my-obj?retention", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Get-actions-get-object-legal-hold-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodGet, "/my-bucket/my-obj?legal-hold", nil),
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
			name: "Get-actions-get-object-invalid-checksum-mode",
			app:  app,
			args: args{
				req: invalidChecksumMode,
			},
			wantErr:    false,
			statusCode: 400,
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

	objectLockResult, err := json.Marshal(auth.BucketLockConfig{})
	if err != nil {
		t.Errorf("failed to parse object lock result %v", err)
	}

	app := fiber.New()
	s3ApiController := S3ApiController{
		be: &BackendMock{
			GetBucketAclFunc: func(context.Context, *s3.GetBucketAclInput) ([]byte, error) {
				return acldata, nil
			},
			ListMultipartUploadsFunc: func(_ context.Context, output *s3.ListMultipartUploadsInput) (s3response.ListMultipartUploadsResult, error) {
				return s3response.ListMultipartUploadsResult{}, nil
			},
			ListObjectsV2Func: func(context.Context, *s3.ListObjectsV2Input) (s3response.ListObjectsV2Result, error) {
				return s3response.ListObjectsV2Result{}, nil
			},
			ListObjectsFunc: func(context.Context, *s3.ListObjectsInput) (s3response.ListObjectsResult, error) {
				return s3response.ListObjectsResult{}, nil
			},
			GetBucketTaggingFunc: func(contextMoqParam context.Context, bucket string) (map[string]string, error) {
				return map[string]string{}, nil
			},
			GetBucketVersioningFunc: func(contextMoqParam context.Context, bucket string) (s3response.GetBucketVersioningOutput, error) {
				return s3response.GetBucketVersioningOutput{}, nil
			},
			ListObjectVersionsFunc: func(contextMoqParam context.Context, listObjectVersionsInput *s3.ListObjectVersionsInput) (s3response.ListVersionsResult, error) {
				return s3response.ListVersionsResult{}, nil
			},
			GetBucketPolicyFunc: func(contextMoqParam context.Context, bucket string) ([]byte, error) {
				return []byte{}, nil
			},
			GetObjectLockConfigurationFunc: func(contextMoqParam context.Context, bucket string) ([]byte, error) {
				return objectLockResult, nil
			},
			GetBucketOwnershipControlsFunc: func(contextMoqParam context.Context, bucket string) (types.ObjectOwnership, error) {
				return types.ObjectOwnershipBucketOwnerEnforced, nil
			},
		},
	}

	app.Use(func(ctx *fiber.Ctx) error {
		utils.ContextKeyAccount.Set(ctx, auth.Account{Access: "valid access"})
		utils.ContextKeyIsRoot.Set(ctx, true)
		utils.ContextKeyParsedAcl.Set(ctx, auth.ACL{})
		return ctx.Next()
	})

	app.Get("/:bucket", s3ApiController.ListActions)

	// Error case
	s3ApiControllerError := S3ApiController{
		be: &BackendMock{
			GetBucketAclFunc: func(context.Context, *s3.GetBucketAclInput) ([]byte, error) {
				return acldata, nil
			},
			ListObjectsFunc: func(context.Context, *s3.ListObjectsInput) (s3response.ListObjectsResult, error) {
				return s3response.ListObjectsResult{}, s3err.GetAPIError(s3err.ErrNotImplemented)
			},
			GetBucketTaggingFunc: func(contextMoqParam context.Context, bucket string) (map[string]string, error) {
				return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
			},
		},
	}
	appError := fiber.New()
	appError.Use(func(ctx *fiber.Ctx) error {
		utils.ContextKeyAccount.Set(ctx, auth.Account{Access: "valid access"})
		utils.ContextKeyIsRoot.Set(ctx, true)
		utils.ContextKeyParsedAcl.Set(ctx, auth.ACL{})
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
			name: "Get-bucket-tagging-non-existing-bucket",
			app:  appError,
			args: args{
				req: httptest.NewRequest(http.MethodGet, "/my-bucket?tagging", nil),
			},
			wantErr:    false,
			statusCode: 404,
		},
		{
			name: "Get-bucket-ownership-control-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodGet, "/my-bucket?ownershipControls", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Get-bucket-tagging-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodGet, "/my-bucket?tagging", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Get-object-lock-configuration-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodGet, "/my-bucket?object-lock", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
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
		{
			name: "List-actions-get-bucket-versioning-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodGet, "/my-bucket?versioning", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "List-actions-get-bucket-policy-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodGet, "/my-bucket?policy", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "List-actions-list-object-versions-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodGet, "/my-bucket?versions", nil),
			},
			wantErr:    false,
			statusCode: 200,
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
	acl := auth.ACL{Owner: "valid access"}
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

	invOwnerBody := `
	<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
		<Owner>
			<ID>hello</ID>
		</Owner>
	</AccessControlPolicy>
	`

	tagBody := `
	<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
		<TagSet>
			<Tag>
				<Key>organization</Key>
				<Value>marketing</Value>
			</Tag>
		</TagSet>
	</Tagging>
	`

	versioningBody := `
	<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"> 
		<Status>Enabled</Status> 
		<MfaDelete>Enabled</MfaDelete>
	</VersioningConfiguration>
	`

	policyBody := `{
		"Statement": [
			{
				"Effect": "Allow",
				"Principal": "*",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::my-bucket/*"
			}
		]
	}
	`

	objectLockBody := `
	<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
		<ObjectLockEnabled>Enabled</ObjectLockEnabled>
		<Rule>
			<DefaultRetention>
				<Mode>GOVERNANCE</Mode>
				<Years>2</Years>
			</DefaultRetention>
		</Rule>
	</ObjectLockConfiguration>
	`

	ownershipBody := `
	<OwnershipControls xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
		<Rule>
			<ObjectOwnership>BucketOwnerEnforced</ObjectOwnership>
		</Rule>
	</OwnershipControls>
	`

	invalidOwnershipBody := `
	<OwnershipControls xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
		<Rule>
			<ObjectOwnership>invalid_value</ObjectOwnership>
		</Rule>
	</OwnershipControls>
	`

	s3ApiController := S3ApiController{
		be: &BackendMock{
			GetBucketAclFunc: func(context.Context, *s3.GetBucketAclInput) ([]byte, error) {
				return acldata, nil
			},
			PutBucketAclFunc: func(context.Context, string, []byte) error {
				return nil
			},
			CreateBucketFunc: func(context.Context, *s3.CreateBucketInput, []byte) error {
				return nil
			},
			PutBucketTaggingFunc: func(contextMoqParam context.Context, bucket string, tags map[string]string) error {
				return nil
			},
			PutBucketVersioningFunc: func(contextMoqParam context.Context, bucket string, status types.BucketVersioningStatus) error {
				return nil
			},
			PutBucketPolicyFunc: func(contextMoqParam context.Context, bucket string, policy []byte) error {
				return nil
			},
			PutObjectLockConfigurationFunc: func(contextMoqParam context.Context, bucket string, config []byte) error {
				return nil
			},
			PutBucketOwnershipControlsFunc: func(contextMoqParam context.Context, bucket string, ownership types.ObjectOwnership) error {
				return nil
			},
			GetBucketOwnershipControlsFunc: func(contextMoqParam context.Context, bucket string) (types.ObjectOwnership, error) {
				return types.ObjectOwnershipBucketOwnerPreferred, nil
			},
		},
	}
	// Mock ctx.Locals
	app.Use(func(ctx *fiber.Ctx) error {
		utils.ContextKeyAccount.Set(ctx, auth.Account{Access: "valid access"})
		utils.ContextKeyIsRoot.Set(ctx, true)
		utils.ContextKeyParsedAcl.Set(ctx, auth.ACL{Owner: "valid access"})
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
	incorrectBucketOwner := httptest.NewRequest(http.MethodPut, "/my-bucket?acl", strings.NewReader(invOwnerBody))

	// PutBucketAcl acl success
	aclSuccReq := httptest.NewRequest(http.MethodPut, "/my-bucket?acl", nil)
	aclSuccReq.Header.Set("X-Amz-Acl", "private")

	// Invalid acl body case
	errAclBodyReq := httptest.NewRequest(http.MethodPut, "/my-bucket?acl", strings.NewReader(body))
	errAclBodyReq.Header.Set("X-Amz-Grant-Read", "hello")

	invAclOwnershipReq := httptest.NewRequest(http.MethodPut, "/my-bucket", nil)
	invAclOwnershipReq.Header.Set("X-Amz-Grant-Read", "hello")

	tests := []struct {
		name       string
		app        *fiber.App
		args       args
		wantErr    bool
		statusCode int
	}{
		{
			name: "Put-bucket-tagging-invalid-body",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPut, "/my-bucket?tagging", nil),
			},
			wantErr:    false,
			statusCode: 400,
		},
		{
			name: "Put-bucket-tagging-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPut, "/my-bucket?tagging", strings.NewReader(tagBody)),
			},
			wantErr:    false,
			statusCode: 204,
		},
		{
			name: "Put-bucket-ownership-controls-invalid-ownership",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPut, "/my-bucket?ownershipControls", strings.NewReader(invalidOwnershipBody)),
			},
			wantErr:    false,
			statusCode: 400,
		},
		{
			name: "Put-bucket-ownership-controls-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPut, "/my-bucket?ownershipControls", strings.NewReader(ownershipBody)),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Put-object-lock-configuration-invalid-body",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPut, "/my-bucket?object-lock", nil),
			},
			wantErr:    false,
			statusCode: 400,
		},
		{
			name: "Put-object-lock-configuration-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPut, "/my-bucket?object-lock", strings.NewReader(objectLockBody)),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Put-bucket-versioning-invalid-body",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPut, "/my-bucket?versioning", nil),
			},
			wantErr:    false,
			statusCode: 400,
		},
		{
			name: "Put-bucket-versioning-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPut, "/my-bucket?versioning", strings.NewReader(versioningBody)),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Put-bucket-policy-invalid-body",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPut, "/my-bucket?policy", nil),
			},
			wantErr:    false,
			statusCode: 400,
		},
		{
			name: "Put-bucket-policy-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPut, "/my-bucket?policy", strings.NewReader(policyBody)),
			},
			wantErr:    false,
			statusCode: 200,
		},
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
			statusCode: 400,
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
			name: "Create-bucket-invalid-acl-ownership-combination",
			app:  app,
			args: args{
				req: invAclOwnershipReq,
			},
			wantErr:    false,
			statusCode: 400,
		},
		{
			name: "Create-bucket-success",
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

	//retentionBody := `
	//<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
	//	<Mode>GOVERNANCE</Mode>
	//	<RetainUntilDate>2025-01-01T00:00:00Z</RetainUntilDate>
	//</Retention>
	//`

	legalHoldBody := `
	<LegalHold xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
		<Status>ON</Status>
	</LegalHold>
	`

	app := fiber.New()
	s3ApiController := S3ApiController{
		be: &BackendMock{
			GetBucketAclFunc: func(context.Context, *s3.GetBucketAclInput) ([]byte, error) {
				return acldata, nil
			},
			PutObjectAclFunc: func(context.Context, *s3.PutObjectAclInput) error {
				return nil
			},
			CopyObjectFunc: func(context.Context, s3response.CopyObjectInput) (s3response.CopyObjectOutput, error) {
				return s3response.CopyObjectOutput{
					CopyObjectResult: &s3response.CopyObjectResult{},
				}, nil
			},
			PutObjectFunc: func(context.Context, s3response.PutObjectInput) (s3response.PutObjectOutput, error) {
				return s3response.PutObjectOutput{}, nil
			},
			UploadPartFunc: func(context.Context, *s3.UploadPartInput) (*s3.UploadPartOutput, error) {
				return &s3.UploadPartOutput{}, nil
			},
			PutObjectTaggingFunc: func(_ context.Context, bucket, object string, tags map[string]string) error {
				return nil
			},
			UploadPartCopyFunc: func(context.Context, *s3.UploadPartCopyInput) (s3response.CopyPartResult, error) {
				return s3response.CopyPartResult{}, nil
			},
			PutObjectLegalHoldFunc: func(contextMoqParam context.Context, bucket, object, versionId string, status bool) error {
				return nil
			},
			PutObjectRetentionFunc: func(contextMoqParam context.Context, bucket, object, versionId string, bypass bool, retention []byte) error {
				return nil
			},
			GetObjectLockConfigurationFunc: func(contextMoqParam context.Context, bucket string) ([]byte, error) {
				return nil, s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound)
			},
		},
	}
	app.Use(func(ctx *fiber.Ctx) error {
		utils.ContextKeyAccount.Set(ctx, auth.Account{Access: "valid access"})
		utils.ContextKeyIsRoot.Set(ctx, true)
		utils.ContextKeyParsedAcl.Set(ctx, auth.ACL{})
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

	// CopyObject invalid checksum algorithm
	cpyInvChecksumAlgo := httptest.NewRequest(http.MethodPut, "/my-bucket/my-key", nil)
	cpyInvChecksumAlgo.Header.Set("X-Amz-Copy-Source", "srcBucket/srcObject")
	cpyInvChecksumAlgo.Header.Set("X-Amz-Checksum-Algorithm", "invalid_checksum_algorithm")

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

	// PutObject invalid checksum algorithm
	invChecksumAlgo := httptest.NewRequest(http.MethodPut, "/my-bucket/my-key", nil)
	invChecksumAlgo.Header.Set("X-Amz-Checksum-Algorithm", "invalid_checksum_algorithm")

	// PutObject invalid base64 checksum
	invBase64Checksum := httptest.NewRequest(http.MethodPut, "/my-bucket/my-key", nil)
	invBase64Checksum.Header.Set("X-Amz-Checksum-Crc32", "invalid_base64")

	// PutObject invalid crc32
	invCrc32 := httptest.NewRequest(http.MethodPut, "/my-bucket/my-key", nil)
	invCrc32.Header.Set("X-Amz-Checksum-Crc32", "YXNkZmFkc2Zhc2Rm")

	// PutObject invalid crc32c
	invCrc32c := httptest.NewRequest(http.MethodPut, "/my-bucket/my-key", nil)
	invCrc32c.Header.Set("X-Amz-Checksum-Crc32c", "YXNkZmFkc2Zhc2RmYXNkZg==")

	// PutObject invalid sha1
	invSha1 := httptest.NewRequest(http.MethodPut, "/my-bucket/my-key", nil)
	invSha1.Header.Set("X-Amz-Checksum-Sha1", "YXNkZmFkc2Zhc2RmYXNkZnNkYWZkYXNmZGFzZg==")

	// PutObject invalid sha256
	invSha256 := httptest.NewRequest(http.MethodPut, "/my-bucket/my-key", nil)
	invSha256.Header.Set("X-Amz-Checksum-Sha256", "YXNkZmFkc2Zhc2RmYXNkZnNkYWZkYXNmZGFzZmFkc2Zhc2Rm")

	// PutObject multiple checksum headers
	mulChecksumHdrs := httptest.NewRequest(http.MethodPut, "/my-bucket/my-key", nil)
	mulChecksumHdrs.Header.Set("X-Amz-Checksum-Sha256", "d1SPCd/kZ2rAzbbLUC0n/bEaOSx70FNbXbIqoIxKuPY=")
	mulChecksumHdrs.Header.Set("X-Amz-Checksum-Crc32c", "ww2FVQ==")

	// PutObject checksum algorithm and header mismatch
	checksumHdrMismatch := httptest.NewRequest(http.MethodPut, "/my-bucket/my-key", nil)
	checksumHdrMismatch.Header.Set("X-Amz-Checksum-Algorithm", "SHA1")
	checksumHdrMismatch.Header.Set("X-Amz-Checksum-Crc32c", "ww2FVQ==")

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
			name: "put-object-retention-invalid-request",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPut, "/my-bucket/my-key?retention", nil),
			},
			wantErr:    false,
			statusCode: 400,
		},
		//{
		//	name: "put-object-retention-success",
		//	app:  app,
		//	args: args{
		//		req: httptest.NewRequest(http.MethodPut, "/my-bucket/my-key?retention", strings.NewReader(retentionBody)),
		//	},
		//	wantErr:    false,
		//	statusCode: 200,
		//},
		{
			name: "put-legal-hold-invalid-request",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPut, "/my-bucket/my-key?legal-hold", nil),
			},
			wantErr:    false,
			statusCode: 400,
		},
		{
			name: "put-legal-hold-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPut, "/my-bucket/my-key?legal-hold", strings.NewReader(legalHoldBody)),
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
			name: "Copy-object-invalid-checksum-algorithm",
			app:  app,
			args: args{
				req: cpyInvChecksumAlgo,
			},
			wantErr:    false,
			statusCode: 400,
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
			t.Errorf("S3ApiController.PutActions() %v error = %v, wantErr %v",
				tt.name, err, tt.wantErr)
		}

		if resp.StatusCode != tt.statusCode {
			t.Errorf("S3ApiController.PutActions() %v statusCode = %v, wantStatusCode = %v",
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
			DeleteBucketFunc: func(_ context.Context, bucket string) error {
				return nil
			},
			DeleteBucketTaggingFunc: func(contextMoqParam context.Context, bucket string) error {
				return nil
			},
			DeleteBucketPolicyFunc: func(contextMoqParam context.Context, bucket string) error {
				return nil
			},
			DeleteBucketOwnershipControlsFunc: func(contextMoqParam context.Context, bucket string) error {
				return nil
			},
		},
	}

	app.Use(func(ctx *fiber.Ctx) error {
		utils.ContextKeyAccount.Set(ctx, auth.Account{Access: "valid access"})
		utils.ContextKeyIsRoot.Set(ctx, true)
		utils.ContextKeyParsedAcl.Set(ctx, auth.ACL{})
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
			statusCode: 204,
		},
		{
			name: "Delete-bucket-tagging-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodDelete, "/my-bucket?tagging", nil),
			},
			wantErr:    false,
			statusCode: 204,
		},
		{
			name: "Delete-bucket-ownership-controls-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodDelete, "/my-bucket?ownershipControls", nil),
			},
			wantErr:    false,
			statusCode: 204,
		}, {
			name: "Delete-bucket-policy-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodDelete, "/my-bucket?policy", nil),
			},
			wantErr:    false,
			statusCode: 204,
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
			GetBucketAclFunc: func(context.Context, *s3.GetBucketAclInput) ([]byte, error) {
				return acldata, nil
			},
			DeleteObjectsFunc: func(context.Context, *s3.DeleteObjectsInput) (s3response.DeleteResult, error) {
				return s3response.DeleteResult{}, nil
			},
			GetObjectLockConfigurationFunc: func(contextMoqParam context.Context, bucket string) ([]byte, error) {
				return nil, s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound)
			},
		},
	}

	app.Use(func(ctx *fiber.Ctx) error {
		utils.ContextKeyAccount.Set(ctx, auth.Account{Access: "valid access"})
		utils.ContextKeyIsRoot.Set(ctx, true)
		utils.ContextKeyParsedAcl.Set(ctx, auth.ACL{})
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
			GetBucketAclFunc: func(context.Context, *s3.GetBucketAclInput) ([]byte, error) {
				return acldata, nil
			},
			DeleteObjectFunc: func(contextMoqParam context.Context, deleteObjectInput *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error) {
				return &s3.DeleteObjectOutput{}, nil
			},
			AbortMultipartUploadFunc: func(context.Context, *s3.AbortMultipartUploadInput) error {
				return nil
			},
			DeleteObjectTaggingFunc: func(_ context.Context, bucket, object string) error {
				return nil
			},
			GetObjectLockConfigurationFunc: func(contextMoqParam context.Context, bucket string) ([]byte, error) {
				return nil, s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound)
			},
		},
	}

	app.Use(func(ctx *fiber.Ctx) error {
		utils.ContextKeyAccount.Set(ctx, auth.Account{Access: "valid access"})
		utils.ContextKeyIsRoot.Set(ctx, true)
		utils.ContextKeyParsedAcl.Set(ctx, auth.ACL{})
		return ctx.Next()
	})
	app.Delete("/:bucket/:key/*", s3ApiController.DeleteActions)

	// Error case
	appErr := fiber.New()

	s3ApiControllerErr := S3ApiController{be: &BackendMock{
		GetBucketAclFunc: func(context.Context, *s3.GetBucketAclInput) ([]byte, error) {
			return acldata, nil
		},
		DeleteObjectFunc: func(contextMoqParam context.Context, deleteObjectInput *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error) {
			return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
		},
		GetObjectLockConfigurationFunc: func(contextMoqParam context.Context, bucket string) ([]byte, error) {
			return nil, s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound)
		},
	}}

	appErr.Use(func(ctx *fiber.Ctx) error {
		utils.ContextKeyAccount.Set(ctx, auth.Account{Access: "valid access"})
		utils.ContextKeyIsRoot.Set(ctx, true)
		utils.ContextKeyParsedAcl.Set(ctx, auth.ACL{})
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
			statusCode: 204,
		},
		{
			name: "Remove-object-tagging-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodDelete, "/my-bucket/my-key/key2?tagging", nil),
			},
			wantErr:    false,
			statusCode: 204,
		},
		{
			name: "Delete-object-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodDelete, "/my-bucket/my-key", nil),
			},
			wantErr:    false,
			statusCode: 204,
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
			GetBucketAclFunc: func(context.Context, *s3.GetBucketAclInput) ([]byte, error) {
				return acldata, nil
			},
			HeadBucketFunc: func(context.Context, *s3.HeadBucketInput) (*s3.HeadBucketOutput, error) {
				return &s3.HeadBucketOutput{}, nil
			},
		},
	}

	app.Use(func(ctx *fiber.Ctx) error {
		utils.ContextKeyAccount.Set(ctx, auth.Account{Access: "valid access"})
		utils.ContextKeyIsRoot.Set(ctx, true)
		utils.ContextKeyParsedAcl.Set(ctx, auth.ACL{})
		utils.ContextKeyRegion.Set(ctx, "us-east-1")
		return ctx.Next()
	})

	app.Head("/:bucket", s3ApiController.HeadBucket)

	// Error case
	appErr := fiber.New()

	s3ApiControllerErr := S3ApiController{be: &BackendMock{
		GetBucketAclFunc: func(context.Context, *s3.GetBucketAclInput) ([]byte, error) {
			return acldata, nil
		},
		HeadBucketFunc: func(context.Context, *s3.HeadBucketInput) (*s3.HeadBucketOutput, error) {
			return nil, s3err.GetAPIError(s3err.ErrBucketNotEmpty)
		},
	},
	}

	appErr.Use(func(ctx *fiber.Ctx) error {
		utils.ContextKeyAccount.Set(ctx, auth.Account{Access: "valid access"})
		utils.ContextKeyIsRoot.Set(ctx, true)
		utils.ContextKeyParsedAcl.Set(ctx, auth.ACL{})
		utils.ContextKeyRegion.Set(ctx, "us-east-1")
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
	contentLength := int64(64)

	s3ApiController := S3ApiController{
		be: &BackendMock{
			GetBucketAclFunc: func(context.Context, *s3.GetBucketAclInput) ([]byte, error) {
				return acldata, nil
			},
			HeadObjectFunc: func(context.Context, *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
				return &s3.HeadObjectOutput{
					ContentEncoding: &contentEncoding,
					ContentLength:   &contentLength,
					ContentType:     &contentType,
					LastModified:    &lastModifie,
					ETag:            &eTag,
				}, nil
			},
		},
	}

	app.Use(func(ctx *fiber.Ctx) error {
		utils.ContextKeyAccount.Set(ctx, auth.Account{Access: "valid access"})
		utils.ContextKeyIsRoot.Set(ctx, true)
		utils.ContextKeyParsedAcl.Set(ctx, auth.ACL{})
		return ctx.Next()
	})
	app.Head("/:bucket/:key/*", s3ApiController.HeadObject)

	//Error case
	appErr := fiber.New()

	s3ApiControllerErr := S3ApiController{
		be: &BackendMock{
			GetBucketAclFunc: func(context.Context, *s3.GetBucketAclInput) ([]byte, error) {
				return acldata, nil
			},
			HeadObjectFunc: func(context.Context, *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
				return nil, s3err.GetAPIError(s3err.ErrInvalidRequest)
			},
		},
	}

	appErr.Use(func(ctx *fiber.Ctx) error {
		utils.ContextKeyAccount.Set(ctx, auth.Account{Access: "valid access"})
		utils.ContextKeyIsRoot.Set(ctx, true)
		utils.ContextKeyParsedAcl.Set(ctx, auth.ACL{})
		return ctx.Next()
	})
	appErr.Head("/:bucket/:key/*", s3ApiControllerErr.HeadObject)

	invChecksumMode := httptest.NewRequest(http.MethodHead, "/my-bucket/my-key", nil)
	invChecksumMode.Header.Set("X-Amz-Checksum-Mode", "invalid_checksum_mode")

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
			name: "Head-object-invalid-checksum-mode",
			app:  app,
			args: args{
				req: invChecksumMode,
			},
			wantErr:    false,
			statusCode: 400,
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
			GetBucketAclFunc: func(context.Context, *s3.GetBucketAclInput) ([]byte, error) {
				return acldata, nil
			},
			RestoreObjectFunc: func(context.Context, *s3.RestoreObjectInput) error {
				return nil
			},
			CompleteMultipartUploadFunc: func(context.Context, *s3.CompleteMultipartUploadInput) (s3response.CompleteMultipartUploadResult, string, error) {
				return s3response.CompleteMultipartUploadResult{}, "", nil
			},
			CreateMultipartUploadFunc: func(context.Context, s3response.CreateMultipartUploadInput) (s3response.InitiateMultipartUploadResult, error) {
				return s3response.InitiateMultipartUploadResult{}, nil
			},
			SelectObjectContentFunc: func(context.Context, *s3.SelectObjectContentInput) func(w *bufio.Writer) {
				return func(w *bufio.Writer) {}
			},
		},
	}

	bdy := `
		<SelectObjectContentRequest>
			<Expression>string</Expression>
			<ExpressionType>string</ExpressionType>
		</SelectObjectContentRequest>
	`

	completMpBody := `
		<CompleteMultipartUpload xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
			<Part>
				<ETag>etag</ETag>
				<PartNumber>1</PartNumber>
			</Part>
		</CompleteMultipartUpload>
	`

	completMpEmptyBody := `
		<CompleteMultipartUpload xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></CompleteMultipartUpload>
	`

	app.Use(func(ctx *fiber.Ctx) error {
		utils.ContextKeyAccount.Set(ctx, auth.Account{Access: "valid access"})
		utils.ContextKeyIsRoot.Set(ctx, true)
		utils.ContextKeyParsedAcl.Set(ctx, auth.ACL{})
		return ctx.Next()
	})
	app.Post("/:bucket/:key/*", s3ApiController.CreateActions)

	invChecksumAlgo := httptest.NewRequest(http.MethodPost, "/my-bucket/my-key", nil)
	invChecksumAlgo.Header.Set("X-Amz-Checksum-Algorithm", "invalid_checksum_algorithm")

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
				req: httptest.NewRequest(http.MethodPost, "/my-bucket/my-key?restore", nil),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Select-object-content-invalid-body",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPost, "/my-bucket/my-key?select&select-type=2", nil),
			},
			wantErr:    false,
			statusCode: 400,
		},
		{
			name: "Select-object-content-invalid-body",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPost, "/my-bucket/my-key?select&select-type=2", strings.NewReader(bdy)),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Complete-multipart-upload-error",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPost, "/my-bucket/my-key?uploadId=23423", nil),
			},
			wantErr:    false,
			statusCode: 400,
		},
		{
			name: "Complete-multipart-upload-empty-parts",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPost, "/my-bucket/my-key?uploadId=23423", strings.NewReader(completMpEmptyBody)),
			},
			wantErr:    false,
			statusCode: 400,
		},
		{
			name: "Complete-multipart-upload-success",
			app:  app,
			args: args{
				req: httptest.NewRequest(http.MethodPost, "/my-bucket/my-key?uploadId=23423", strings.NewReader(completMpBody)),
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Create-multipart-upload-invalid-checksum-algorithm",
			app:  app,
			args: args{
				req: invChecksumAlgo,
			},
			wantErr:    false,
			statusCode: 400,
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
	ctx := app.AcquireCtx(&fasthttp.RequestCtx{})

	tests := []struct {
		name       string
		args       args
		wantErr    bool
		statusCode int
	}{
		{
			name: "Internal-server-error",
			args: args{
				ctx:  ctx,
				resp: nil,
				err:  s3err.GetAPIError(s3err.ErrInternalError),
			},
			wantErr:    false,
			statusCode: 500,
		},
		{
			name: "Error-not-implemented",
			args: args{
				ctx:  ctx,
				resp: nil,
				err:  s3err.GetAPIError(s3err.ErrNotImplemented),
			},
			wantErr:    false,
			statusCode: 501,
		},
		{
			name: "Invalid-request-body",
			args: args{
				ctx:  ctx,
				resp: make(chan int),
				err:  nil,
			},
			wantErr:    true,
			statusCode: 200,
		},
		{
			name: "Successful-response",
			args: args{
				ctx:  ctx,
				resp: "Valid response",
				err:  nil,
			},
			wantErr:    false,
			statusCode: 200,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := SendXMLResponse(tt.args.ctx, tt.args.resp, tt.args.err, &MetaOpts{}); (err != nil) != tt.wantErr {
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
		opts *MetaOpts
	}

	app := fiber.New()
	ctx := app.AcquireCtx(&fasthttp.RequestCtx{})

	tests := []struct {
		name       string
		args       args
		wantErr    bool
		statusCode int
	}{
		{
			name: "Internal-server-error",
			args: args{
				ctx:  ctx,
				resp: nil,
				err:  s3err.GetAPIError(s3err.ErrInternalError),
				opts: &MetaOpts{},
			},
			wantErr:    false,
			statusCode: 500,
		},
		{
			name: "Internal-server-error-not-api",
			args: args{
				ctx:  ctx,
				resp: nil,
				err:  fmt.Errorf("custom error"),
				opts: &MetaOpts{},
			},
			wantErr:    false,
			statusCode: 500,
		},
		{
			name: "Error-not-implemented",
			args: args{
				ctx:  ctx,
				resp: nil,
				err:  s3err.GetAPIError(s3err.ErrNotImplemented),
				opts: &MetaOpts{},
			},
			wantErr:    false,
			statusCode: 501,
		},
		{
			name: "Successful-response",
			args: args{
				ctx:  ctx,
				resp: "Valid response",
				err:  nil,
				opts: &MetaOpts{},
			},
			wantErr:    false,
			statusCode: 200,
		},
		{
			name: "Successful-response-status-204",
			args: args{
				ctx:  ctx,
				resp: "Valid response",
				err:  nil,
				opts: &MetaOpts{
					Status: 204,
				},
			},
			wantErr:    false,
			statusCode: 204,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := SendResponse(tt.args.ctx, tt.args.err, tt.args.opts); (err != nil) != tt.wantErr {
				t.Errorf("response() %v error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}

			statusCode := tt.args.ctx.Response().StatusCode()

			if statusCode != tt.statusCode {
				t.Errorf("response() %v code = %v, wantErr %v", tt.name, statusCode, tt.wantErr)
			}
		})
	}
}
