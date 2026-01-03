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
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

func TestS3ApiController_PutBucketTagging(t *testing.T) {
	validTaggingBody, err := xml.Marshal(s3response.TaggingInput{
		TagSet: s3response.TagSet{
			Tags: []s3response.Tag{
				{
					Key:   "key",
					Value: "val",
				},
			},
		},
	})
	assert.NoError(t, err)

	tests := []struct {
		name   string
		input  testInput
		output testOutput
	}{
		{
			name: "verify access fails",
			input: testInput{
				locals: accessDeniedLocals,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
		},
		{
			name: "invalid request body",
			input: testInput{
				locals: defaultLocals,
				body:   []byte("invalid_body"),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrMalformedXML),
			},
		},
		{
			name: "backend returns error",
			input: testInput{
				locals: defaultLocals,
				beErr:  s3err.GetAPIError(s3err.ErrNoSuchBucket),
				body:   validTaggingBody,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
						Status:      http.StatusNoContent,
					},
				},
				err: s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
		},
		{
			name: "successful response",
			input: testInput{
				locals: defaultLocals,
				body:   validTaggingBody,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
						Status:      http.StatusNoContent,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := &BackendMock{
				PutBucketTaggingFunc: func(contextMoqParam context.Context, bucket string, tags map[string]string) error {
					return tt.input.beErr
				},
				GetBucketPolicyFunc: func(contextMoqParam context.Context, bucket string) ([]byte, error) {
					return nil, s3err.GetAPIError(s3err.ErrAccessDenied)
				},
			}

			ctrl := S3ApiController{
				be: be,
			}

			testController(
				t,
				ctrl.PutBucketTagging,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals: tt.input.locals,
					body:   tt.input.body,
				})
		})
	}
}

func TestS3ApiController_PutBucketOwnershipControls(t *testing.T) {
	validOwnershipBody, err := xml.Marshal(
		s3response.OwnershipControls{
			Rules: []types.OwnershipControlsRule{
				{ObjectOwnership: types.ObjectOwnershipBucketOwnerEnforced},
			},
		})
	assert.NoError(t, err)

	invalidRuleCountBody, err := xml.Marshal(
		s3response.OwnershipControls{
			Rules: []types.OwnershipControlsRule{
				{ObjectOwnership: types.ObjectOwnershipBucketOwnerEnforced},
				{ObjectOwnership: types.ObjectOwnershipBucketOwnerPreferred},
			},
		},
	)
	assert.NoError(t, err)

	tests := []struct {
		name   string
		input  testInput
		output testOutput
	}{
		{
			name: "verify access fails",
			input: testInput{
				locals: accessDeniedLocals,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
		},
		{
			name: "invalid request body",
			input: testInput{
				locals: defaultLocals,
				body:   []byte("invalid_body"),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{BucketOwner: "root"},
				},
				err: s3err.GetAPIError(s3err.ErrMalformedXML),
			},
		},
		{
			name: "invalid rules count",
			input: testInput{
				locals: defaultLocals,
				body:   invalidRuleCountBody,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{BucketOwner: "root"},
				},
				err: s3err.GetAPIError(s3err.ErrMalformedXML),
			},
		},
		{
			name: "backend error",
			input: testInput{
				locals: defaultLocals,
				body:   validOwnershipBody,
				beErr:  s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{BucketOwner: "root"},
				},
				err: s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
		},
		{
			name: "success",
			input: testInput{
				locals: defaultLocals,
				body:   validOwnershipBody,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := &BackendMock{
				PutBucketOwnershipControlsFunc: func(contextMoqParam context.Context, bucket string, ownership types.ObjectOwnership) error {
					return tt.input.beErr
				},
				GetBucketPolicyFunc: func(contextMoqParam context.Context, bucket string) ([]byte, error) {
					return nil, s3err.GetAPIError(s3err.ErrAccessDenied)
				},
			}

			ctrl := S3ApiController{
				be: be,
			}

			testController(t, ctrl.PutBucketOwnershipControls, tt.output.response, tt.output.err, ctxInputs{
				locals: tt.input.locals,
				body:   tt.input.body,
			})
		})
	}
}

func TestS3ApiController_PutBucketVersioning(t *testing.T) {
	validVersioningBody, err := xml.Marshal(
		types.VersioningConfiguration{
			Status: types.BucketVersioningStatusEnabled,
		},
	)
	assert.NoError(t, err)

	invalidVersioningStatusBody, err := xml.Marshal(
		types.VersioningConfiguration{
			Status: types.BucketVersioningStatus("invalid_status"),
		},
	)
	assert.NoError(t, err)

	tests := []struct {
		name   string
		input  testInput
		output testOutput
	}{
		{
			name: "verify access fails",
			input: testInput{
				locals: accessDeniedLocals,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
		},
		{
			name: "invalid request body",
			input: testInput{
				locals: defaultLocals,
				body:   []byte("invalid_body"),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{BucketOwner: "root"},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidRequest),
			},
		},
		{
			name: "invalid rules count",
			input: testInput{
				locals: defaultLocals,
				body:   invalidVersioningStatusBody,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{BucketOwner: "root"},
				},
				err: s3err.GetAPIError(s3err.ErrMalformedXML),
			},
		},
		{
			name: "backend error",
			input: testInput{
				locals: defaultLocals,
				body:   validVersioningBody,
				beErr:  s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{BucketOwner: "root"},
				},
				err: s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
		},
		{
			name: "success",
			input: testInput{
				locals: defaultLocals,
				body:   validVersioningBody,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := &BackendMock{
				PutBucketVersioningFunc: func(contextMoqParam context.Context, bucket string, status types.BucketVersioningStatus) error {
					return tt.input.beErr
				},
				GetBucketPolicyFunc: func(contextMoqParam context.Context, bucket string) ([]byte, error) {
					return nil, s3err.GetAPIError(s3err.ErrAccessDenied)
				},
			}

			ctrl := S3ApiController{
				be: be,
			}

			testController(t, ctrl.PutBucketVersioning, tt.output.response, tt.output.err, ctxInputs{
				locals: tt.input.locals,
				body:   tt.input.body,
			})
		})
	}
}

func TestS3ApiController_PutObjectLockConfiguration(t *testing.T) {
	validLockBody, err := xml.Marshal(
		types.ObjectLockConfiguration{
			ObjectLockEnabled: types.ObjectLockEnabledEnabled,
		},
	)
	assert.NoError(t, err)

	tests := []struct {
		name   string
		input  testInput
		output testOutput
	}{
		{
			name: "verify access fails",
			input: testInput{
				locals: accessDeniedLocals,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
		},
		{
			name: "invalid request body",
			input: testInput{
				locals: defaultLocals,
				body:   []byte("invalid_body"),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{BucketOwner: "root"},
				},
				err: s3err.GetAPIError(s3err.ErrMalformedXML),
			},
		},
		{
			name: "backend error",
			input: testInput{
				locals: defaultLocals,
				body:   validLockBody,
				beErr:  s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{BucketOwner: "root"},
				},
				err: s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
		},
		{
			name: "success",
			input: testInput{
				locals: defaultLocals,
				body:   validLockBody,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := &BackendMock{
				PutObjectLockConfigurationFunc: func(contextMoqParam context.Context, bucket string, config []byte) error {
					return tt.input.beErr
				},
				GetBucketPolicyFunc: func(contextMoqParam context.Context, bucket string) ([]byte, error) {
					return nil, s3err.GetAPIError(s3err.ErrAccessDenied)
				},
			}

			ctrl := S3ApiController{
				be: be,
			}

			testController(t, ctrl.PutObjectLockConfiguration, tt.output.response, tt.output.err, ctxInputs{
				locals: tt.input.locals,
				body:   tt.input.body,
			})
		})
	}
}

func TestS3ApiController_PutBucketCors(t *testing.T) {
	validBody, err := xml.Marshal(auth.CORSConfiguration{
		Rules: []auth.CORSRule{
			{
				AllowedOrigins: []string{"*"},
				AllowedMethods: []auth.CORSHTTPMethod{http.MethodPost},
			},
		},
	})
	assert.NoError(t, err)

	invalidCors, err := xml.Marshal(auth.CORSConfiguration{
		Rules: []auth.CORSRule{
			{
				AllowedOrigins: []string{"origin"},
				AllowedMethods: []auth.CORSHTTPMethod{"invalid_method"},
			},
		},
	})
	assert.NoError(t, err)

	tests := []struct {
		name   string
		input  testInput
		output testOutput
	}{
		{
			name: "verify access fails",
			input: testInput{
				locals: accessDeniedLocals,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
		},
		{
			name: "invalid request body",
			input: testInput{
				locals: defaultLocals,
				body:   []byte("invalid_body"),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{BucketOwner: "root"},
				},
				err: s3err.GetAPIError(s3err.ErrMalformedXML),
			},
		},
		{
			name: "invalid cors config",
			input: testInput{
				locals: defaultLocals,
				body:   invalidCors,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{BucketOwner: "root"},
				},
				err: s3err.GetUnsopportedCORSMethodErr("invalid_method"),
			},
		},
		{
			name: "backend error",
			input: testInput{
				locals: defaultLocals,
				beErr:  s3err.GetAPIError(s3err.ErrNotImplemented),
				body:   validBody,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{BucketOwner: "root"},
				},
				err: s3err.GetAPIError(s3err.ErrNotImplemented),
			},
		},
		{
			name: "success",
			input: testInput{
				locals: defaultLocals,
				body:   validBody,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := &BackendMock{
				PutBucketCorsFunc: func(contextMoqParam context.Context, bucket string, cors []byte) error {
					return tt.input.beErr
				},
				GetBucketPolicyFunc: func(contextMoqParam context.Context, bucket string) ([]byte, error) {
					return nil, s3err.GetAPIError(s3err.ErrAccessDenied)
				},
			}

			ctrl := S3ApiController{
				be: be,
			}

			testController(t, ctrl.PutBucketCors, tt.output.response, tt.output.err, ctxInputs{
				locals:  tt.input.locals,
				body:    tt.input.body,
				headers: tt.input.headers,
			})
		})
	}
}

func TestS3ApiController_PutBucketPolicy(t *testing.T) {
	validPolicyDocument :=
		`{
			"Version": "2012-10-17",
			"Statement": [
				{
				"Sid": "PublicReadGetObject",
				"Effect": "Allow",
				"Principal": "*",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::bucket/*"
				}
			]
		}`
	tests := []struct {
		name   string
		input  testInput
		output testOutput
	}{
		{
			name: "verify access fails",
			input: testInput{
				locals: accessDeniedLocals,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
		},
		{
			name: "invalid policy document",
			input: testInput{
				locals: defaultLocals,
				body:   []byte("invalid_body"),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{BucketOwner: "root"},
				},
				err: s3err.APIError{
					Code:           "MalformedPolicy",
					Description:    "Policies must be valid JSON and the first byte must be '{'",
					HTTPStatusCode: http.StatusBadRequest,
				},
			},
		},
		{
			name: "backend error",
			input: testInput{
				locals: defaultLocals,
				body:   []byte(validPolicyDocument),
				beErr:  s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
						Status:      http.StatusNoContent,
					},
				},
				err: s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
		},
		{
			name: "success",
			input: testInput{
				locals: defaultLocals,
				body:   []byte(validPolicyDocument),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
						Status:      http.StatusNoContent,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := &BackendMock{
				PutBucketPolicyFunc: func(contextMoqParam context.Context, bucket string, policy []byte) error {
					return tt.input.beErr
				},
				GetBucketPolicyFunc: func(contextMoqParam context.Context, bucket string) ([]byte, error) {
					return nil, s3err.GetAPIError(s3err.ErrAccessDenied)
				},
			}

			ctrl := S3ApiController{
				be: be,
			}

			testController(t, ctrl.PutBucketPolicy, tt.output.response, tt.output.err, ctxInputs{
				locals: tt.input.locals,
				body:   tt.input.body,
			})
		})
	}
}

func TestS3ApiController_CreateBucket(t *testing.T) {
	adminAcc := auth.Account{
		Access: "root",
		Role:   auth.RoleAdmin,
	}
	userAcc := auth.Account{
		Access: "user",
		Role:   auth.RoleUser,
	}

	invLocConstBody, err := xml.Marshal(s3response.CreateBucketConfiguration{
		LocationConstraint: utils.GetStringPtr("us-west-1"),
	})
	assert.NoError(t, err)

	tests := []struct {
		name   string
		input  testInput
		output testOutput
	}{
		{
			name: "access denied",
			input: testInput{
				locals: map[utils.ContextKey]any{
					utils.ContextKeyAccount: userAcc,
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
				err: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
		},
		{
			name: "invalid bucket name",
			input: testInput{
				locals: map[utils.ContextKey]any{
					utils.ContextKeyAccount: adminAcc,
				},
				bucket: "invalid_bucket_name",
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: adminAcc.Access,
					},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidBucketName),
			},
		},
		{
			name: "malformed body",
			input: testInput{
				locals: map[utils.ContextKey]any{
					utils.ContextKeyAccount: adminAcc,
				},
				body: []byte("invalid_body"),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{BucketOwner: adminAcc.Access},
				},
				err: s3err.GetAPIError(s3err.ErrMalformedXML),
			},
		},

		{
			name: "invalid canned acl",
			input: testInput{
				locals: map[utils.ContextKey]any{
					utils.ContextKeyAccount: adminAcc,
				},
				headers: map[string]string{
					"x-amz-acl": "invalid_acl",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{BucketOwner: adminAcc.Access},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidArgument),
			},
		},
		{
			name: "invalid location constraint",
			input: testInput{
				locals: map[utils.ContextKey]any{
					utils.ContextKeyAccount: adminAcc,
					utils.ContextKeyRegion:  "us-east-1",
				},
				body: invLocConstBody,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{BucketOwner: adminAcc.Access},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidLocationConstraint),
			},
		},
		{
			name: "invalid ownership",
			input: testInput{
				locals: map[utils.ContextKey]any{
					utils.ContextKeyAccount: adminAcc,
				},
				headers: map[string]string{
					"X-Amz-Object-Ownership": "invalid_ownership",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: adminAcc.Access,
					},
				},
				err: s3err.APIError{
					Code:           "InvalidArgument",
					Description:    "Invalid x-amz-object-ownership header: invalid_ownership",
					HTTPStatusCode: http.StatusBadRequest,
				},
			},
		},
		{
			name: "invalid ownership + acl",
			input: testInput{
				locals: map[utils.ContextKey]any{
					utils.ContextKeyAccount: adminAcc,
				},
				headers: map[string]string{
					"X-Amz-Object-Ownership": string(types.ObjectOwnershipBucketOwnerEnforced),
					"X-Amz-Acl":              string(types.BucketCannedACLPublicRead),
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{BucketOwner: adminAcc.Access},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidBucketAclWithObjectOwnership),
			},
		},
		{
			name: "both grants and canned acl",
			input: testInput{
				locals: map[utils.ContextKey]any{
					utils.ContextKeyAccount: adminAcc,
				},
				headers: map[string]string{
					"X-Amz-Acl":              string(types.BucketCannedACLPublicRead),
					"X-Amz-Grant-Read":       userAcc.Access,
					"X-Amz-Object-Ownership": string(types.ObjectOwnershipBucketOwnerPreferred),
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{BucketOwner: adminAcc.Access},
				},
				err: s3err.GetAPIError(s3err.ErrBothCannedAndHeaderGrants),
			},
		},
		{
			name: "fail to update the acl",
			input: testInput{
				locals: map[utils.ContextKey]any{
					utils.ContextKeyAccount: adminAcc,
				},
				headers: map[string]string{
					"X-Amz-Grant-Read":       userAcc.Access,
					"X-Amz-Object-Ownership": string(types.ObjectOwnershipBucketOwnerPreferred),
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{BucketOwner: adminAcc.Access},
				},
				err: fmt.Errorf("accounts does not exist: %s", userAcc.Access),
			},
		},
		{
			name: "backend error",
			input: testInput{
				locals: map[utils.ContextKey]any{
					utils.ContextKeyAccount: adminAcc,
				},
				beErr: s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{BucketOwner: adminAcc.Access},
				},
				err: s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
		},
		{
			name: "success",
			input: testInput{
				locals: map[utils.ContextKey]any{
					utils.ContextKeyAccount: adminAcc,
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: adminAcc.Access,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := &BackendMock{
				CreateBucketFunc: func(contextMoqParam context.Context, createBucketInput *s3.CreateBucketInput, defaultACL []byte) error {
					return tt.input.beErr
				},
			}

			ctrl := S3ApiController{
				be:  be,
				iam: auth.NewIAMServiceSingle(adminAcc),
			}

			testController(t, ctrl.CreateBucket, tt.output.response, tt.output.err,
				ctxInputs{
					locals:  tt.input.locals,
					body:    tt.input.body,
					bucket:  tt.input.bucket,
					headers: tt.input.headers,
				})
		})
	}
}

func TestS3ApiController_PutBucketAcl(t *testing.T) {
	invalidBody, err := xml.Marshal(auth.AccessControlPolicy{
		Owner: &types.Owner{
			ID: utils.GetStringPtr("root"),
		},
		AccessControlList: auth.AccessControlList{
			Grants: []auth.Grant{
				{
					Permission: auth.Permission("invalid_permission"),
				},
			},
		},
	})
	assert.NoError(t, err)

	incorrectOwnerBody, err := xml.Marshal(auth.AccessControlPolicy{
		Owner: &types.Owner{
			ID: utils.GetStringPtr("user"),
		},
		AccessControlList: auth.AccessControlList{},
	})
	assert.NoError(t, err)

	validAccessControlPolicy, err := xml.Marshal(auth.AccessControlPolicy{
		Owner: &types.Owner{
			ID: utils.GetStringPtr("root"),
		},
		AccessControlList: auth.AccessControlList{},
	})
	assert.NoError(t, err)

	tests := []struct {
		name   string
		input  testInput
		output testOutput
	}{
		{
			name: "access denied",
			input: testInput{
				locals: accessDeniedLocals,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
		},
		{
			name: "fails to get bucket ownership",
			input: testInput{
				locals:        defaultLocals,
				extraMockErr:  s3err.GetAPIError(s3err.ErrInternalError),
				extraMockResp: types.ObjectOwnership(""),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrInternalError),
			},
		},
		{
			name: "acl not supported",
			input: testInput{
				locals:        defaultLocals,
				extraMockResp: types.ObjectOwnershipBucketOwnerEnforced,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrAclNotSupported),
			},
		},
		{
			name: "invalid request body",
			input: testInput{
				locals:        defaultLocals,
				extraMockResp: types.ObjectOwnershipBucketOwnerPreferred,
				body:          []byte("invalid_body"),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrMalformedACL),
			},
		},
		{
			name: "invalid access control policy",
			input: testInput{
				locals:        defaultLocals,
				extraMockResp: types.ObjectOwnershipBucketOwnerPreferred,
				body:          invalidBody,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrMalformedACL),
			},
		},
		{
			name: "incorrect owner id",
			input: testInput{
				locals:        defaultLocals,
				extraMockResp: types.ObjectOwnershipBucketOwnerPreferred,
				body:          incorrectOwnerBody,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.APIError{
					Code:           "InvalidArgument",
					Description:    "Invalid id",
					HTTPStatusCode: http.StatusBadRequest,
				},
			},
		},
		{
			name: "both access control policy and grants",
			input: testInput{
				body:          validAccessControlPolicy,
				extraMockResp: types.ObjectOwnershipBucketOwnerPreferred,
				headers: map[string]string{
					"X-Amz-Acl": "public-read",
				},
				locals: defaultLocals,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrUnexpectedContent),
			},
		},
		{
			name: "access control policy success",
			input: testInput{
				body:          validAccessControlPolicy,
				extraMockResp: types.ObjectOwnershipBucketOwnerPreferred,
				locals:        defaultLocals,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
			},
		},
		{
			name: "invalid canned acl",
			input: testInput{
				extraMockResp: types.ObjectOwnershipBucketOwnerPreferred,
				headers: map[string]string{
					"X-Amz-Acl": "invalid_acl",
				},
				locals: defaultLocals,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidArgument),
			},
		},
		{
			name: "both canned acl and grants",
			input: testInput{
				extraMockResp: types.ObjectOwnershipBucketOwnerPreferred,
				headers: map[string]string{
					"X-Amz-Acl":        "public-read",
					"X-Amz-Grant-Read": "grt1",
				},
				locals: defaultLocals,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrBothCannedAndHeaderGrants),
			},
		},
		{
			name: "canned acl success",
			input: testInput{
				extraMockResp: types.ObjectOwnershipBucketOwnerPreferred,
				headers: map[string]string{
					"X-Amz-Acl": "public-read",
				},
				locals: defaultLocals,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
			},
		},
		{
			name: "grants update acl fails",
			input: testInput{
				extraMockResp: types.ObjectOwnershipBucketOwnerPreferred,
				headers: map[string]string{
					"X-Amz-Grant-Read": "grt1",
				},
				locals: defaultLocals,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: errors.New("accounts does not exist: grt1"),
			},
		},
		{
			name: "no option provided",
			input: testInput{
				extraMockResp: types.ObjectOwnershipBucketOwnerPreferred,
				locals:        defaultLocals,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrMissingSecurityHeader),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := &BackendMock{
				PutBucketAclFunc: func(contextMoqParam context.Context, bucket string, data []byte) error {
					return tt.input.beErr
				},
				GetBucketOwnershipControlsFunc: func(contextMoqParam context.Context, bucket string) (types.ObjectOwnership, error) {
					return tt.input.extraMockResp.(types.ObjectOwnership), tt.input.extraMockErr
				},
				GetBucketPolicyFunc: func(contextMoqParam context.Context, bucket string) ([]byte, error) {
					return nil, s3err.GetAPIError(s3err.ErrAccessDenied)
				},
			}

			ctrl := S3ApiController{
				be: be,
				iam: auth.NewIAMServiceSingle(
					auth.Account{
						Access: "root",
					}),
			}

			testController(t, ctrl.PutBucketAcl, tt.output.response, tt.output.err,
				ctxInputs{
					locals:  tt.input.locals,
					body:    tt.input.body,
					bucket:  tt.input.bucket,
					headers: tt.input.headers,
				})
		})
	}
}
