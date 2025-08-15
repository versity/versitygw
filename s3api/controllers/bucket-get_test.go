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
	"encoding/json"
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

func TestS3ApiController_GetBucketTagging(t *testing.T) {
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
			name: "backend returns error",
			input: testInput{
				locals: defaultLocals,
				beRes:  map[string]string{},
				beErr:  s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
		},
		{
			name: "successful response",
			input: testInput{
				locals: defaultLocals,
				beRes: map[string]string{
					"key": "val",
				},
			},
			output: testOutput{
				response: &Response{
					Data: s3response.Tagging{
						TagSet: s3response.TagSet{
							Tags: []s3response.Tag{
								{Key: "key", Value: "val"},
							},
						},
					},
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
				GetBucketTaggingFunc: func(contextMoqParam context.Context, bucket string) (map[string]string, error) {
					return tt.input.beRes.(map[string]string), tt.input.beErr
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
				ctrl.GetBucketTagging,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals: tt.input.locals,
					body:   tt.input.body,
				})
		})
	}
}

func TestS3ApiController_GetBucketOwnershipControls(t *testing.T) {
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
			name: "backend returns error",
			input: testInput{
				locals: defaultLocals,
				beRes:  types.ObjectOwnership(""),
				beErr:  s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
			output: testOutput{
				response: &Response{
					Data: s3response.OwnershipControls{
						Rules: []types.OwnershipControlsRule{{}},
					},
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
		},
		{
			name: "successful response",
			input: testInput{
				locals: defaultLocals,
				beRes:  types.ObjectOwnershipBucketOwnerEnforced,
			},
			output: testOutput{
				response: &Response{
					Data: s3response.OwnershipControls{
						Rules: []types.OwnershipControlsRule{{ObjectOwnership: types.ObjectOwnershipBucketOwnerEnforced}},
					},
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
				GetBucketOwnershipControlsFunc: func(contextMoqParam context.Context, bucket string) (types.ObjectOwnership, error) {
					return tt.input.beRes.(types.ObjectOwnership), tt.input.beErr
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
				ctrl.GetBucketOwnershipControls,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals: tt.input.locals,
					body:   tt.input.body,
				})
		})
	}
}

func TestS3ApiController_GetBucketVersioning(t *testing.T) {
	status := types.BucketVersioningStatusEnabled
	validRes := s3response.GetBucketVersioningOutput{
		Status: &status,
	}

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
			name: "not admin or root",
			input: testInput{
				locals: map[utils.ContextKey]any{
					utils.ContextKeyIsRoot: false,
					utils.ContextKeyParsedAcl: auth.ACL{
						Owner: "root",
					},
					utils.ContextKeyAccount: auth.Account{
						Access: "user",
						Role:   auth.RoleUser,
					},
					utils.ContextKeyPublicBucket: true,
				},
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
			name: "backend returns error",
			input: testInput{
				locals: defaultLocals,
				beRes:  s3response.GetBucketVersioningOutput{},
				beErr:  s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
			output: testOutput{
				response: &Response{
					Data: s3response.GetBucketVersioningOutput{},
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
		},
		{
			name: "successful response",
			input: testInput{
				locals: defaultLocals,
				beRes:  validRes,
			},
			output: testOutput{
				response: &Response{
					Data: validRes,
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
				GetBucketVersioningFunc: func(contextMoqParam context.Context, bucket string) (s3response.GetBucketVersioningOutput, error) {
					return tt.input.beRes.(s3response.GetBucketVersioningOutput), tt.input.beErr
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
				ctrl.GetBucketVersioning,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals: tt.input.locals,
					body:   tt.input.body,
				})
		})
	}
}

func TestS3ApiController_GetBucketCors(t *testing.T) {
	cors := &auth.CORSConfiguration{
		Rules: []auth.CORSRule{
			{
				AllowedOrigins: []string{"origin"},
				AllowedMethods: []auth.CORSHTTPMethod{http.MethodPut},
				AllowedHeaders: []auth.CORSHeader{"X-Amz-Date"},
			},
		},
	}
	beRes, err := xml.Marshal(cors)
	assert.NoError(t, err)

	var nilResp *auth.CORSConfiguration

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
			name: "backend returns error",
			input: testInput{
				locals: defaultLocals,
				beRes:  []byte{},
				beErr:  s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
		},
		{
			name: "invalid data from backend",
			input: testInput{
				locals: defaultLocals,
				beRes:  []byte("invalid_data"),
			},
			output: testOutput{
				response: &Response{
					Data: nilResp,
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: errors.New("failed to parse cors config:"),
			},
		},
		{
			name: "successful response",
			input: testInput{
				locals: defaultLocals,
				beRes:  beRes,
			},
			output: testOutput{
				response: &Response{
					Data: cors,
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
				GetBucketCorsFunc: func(contextMoqParam context.Context, bucket string) ([]byte, error) {
					return tt.input.beRes.([]byte), tt.input.beErr
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
				ctrl.GetBucketCors,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals: tt.input.locals,
					body:   tt.input.body,
				})
		})
	}
}

func TestS3ApiController_GetBucketPolicy(t *testing.T) {
	tests := []struct {
		name   string
		input  testInput
		output testOutput
	}{
		{
			name: "verify access fails",
			input: testInput{
				beRes:  []byte{},
				beErr:  s3err.GetAPIError(s3err.ErrAccessDenied),
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
			name: "backend returns error",
			input: testInput{
				locals: defaultLocals,
				beRes:  []byte{},
				beErr:  s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
			output: testOutput{
				response: &Response{
					Data: []byte{},
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
		},
		{
			name: "successful response",
			input: testInput{
				locals: defaultLocals,
				beRes:  []byte("mock_policy_resp"),
			},
			output: testOutput{
				response: &Response{
					Data: []byte("mock_policy_resp"),
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
				GetBucketPolicyFunc: func(contextMoqParam context.Context, bucket string) ([]byte, error) {
					return tt.input.beRes.([]byte), tt.input.beErr
				},
			}

			ctrl := S3ApiController{
				be: be,
			}

			testController(
				t,
				ctrl.GetBucketPolicy,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals: tt.input.locals,
					body:   tt.input.body,
				})
		})
	}
}

func TestS3ApiController_ListObjectVersions(t *testing.T) {
	listVersionsResult := s3response.ListVersionsResult{
		Name:      utils.GetStringPtr("name"),
		Prefix:    utils.GetStringPtr("prefix"),
		Delimiter: utils.GetStringPtr("delim"),
		Versions: []s3response.ObjectVersion{
			{Key: utils.GetStringPtr("my-key")},
		},
	}
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
			name: "invalid max keys",
			input: testInput{
				locals: defaultLocals,
				queries: map[string]string{
					"max-keys": "-1",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidMaxKeys),
			},
		},
		{
			name: "backend returns error",
			input: testInput{
				locals: defaultLocals,
				beRes:  s3response.ListVersionsResult{},
				beErr:  s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
			output: testOutput{
				response: &Response{
					Data: s3response.ListVersionsResult{},
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
		},
		{
			name: "successful response",
			input: testInput{
				locals: defaultLocals,
				beRes:  listVersionsResult,
			},
			output: testOutput{
				response: &Response{
					Data: listVersionsResult,
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
				ListObjectVersionsFunc: func(contextMoqParam context.Context, listObjectVersionsInput *s3.ListObjectVersionsInput) (s3response.ListVersionsResult, error) {
					return tt.input.beRes.(s3response.ListVersionsResult), tt.input.beErr
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
				ctrl.ListObjectVersions,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals:  tt.input.locals,
					body:    tt.input.body,
					queries: tt.input.queries,
				})
		})
	}
}

func TestS3ApiController_GetObjectLockConfiguration(t *testing.T) {
	cfgBytes, err := json.Marshal(
		auth.BucketLockConfig{
			Enabled: true,
		})
	assert.NoError(t, err)

	var lockCfg *types.ObjectLockConfiguration

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
			name: "backend returns error",
			input: testInput{
				locals: defaultLocals,
				beRes:  []byte{},
				beErr:  s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
		},
		{
			name: "invalid data from backend",
			input: testInput{
				locals: defaultLocals,
				beRes:  []byte{},
			},
			output: testOutput{
				response: &Response{
					Data: lockCfg,
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: fmt.Errorf("parse object lock config: "),
			},
		},
		{
			name: "successful response",
			input: testInput{
				locals: defaultLocals,
				beRes:  cfgBytes,
			},
			output: testOutput{
				response: &Response{
					Data: &types.ObjectLockConfiguration{
						ObjectLockEnabled: types.ObjectLockEnabledEnabled,
						Rule: &types.ObjectLockRule{
							DefaultRetention: nil,
						},
					},
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
				GetObjectLockConfigurationFunc: func(contextMoqParam context.Context, bucket string) ([]byte, error) {
					return tt.input.beRes.([]byte), tt.input.beErr
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
				ctrl.GetObjectLockConfiguration,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals: tt.input.locals,
					body:   tt.input.body,
				})
		})
	}
}

func TestS3ApiController_GetBucketAcl(t *testing.T) {
	aclBytes, err := json.Marshal(
		auth.ACL{
			Owner: "root",
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
			name: "backend returns error",
			input: testInput{
				locals: defaultLocals,
				beRes:  []byte{},
				beErr:  s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
		},
		{
			name: "invalid data from backend",
			input: testInput{
				locals: defaultLocals,
				beRes:  []byte{'d'},
			},
			output: testOutput{
				response: &Response{
					Data: auth.GetBucketAclOutput{},
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: fmt.Errorf("parse acl: "),
			},
		},
		{
			name: "successful response",
			input: testInput{
				locals: defaultLocals,
				beRes:  aclBytes,
			},
			output: testOutput{
				response: &Response{
					Data: auth.GetBucketAclOutput{
						Owner: &types.Owner{
							ID: utils.GetStringPtr("root"),
						},
						AccessControlList: auth.AccessControlList{
							Grants: []auth.Grant{},
						},
					},
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
				GetBucketAclFunc: func(contextMoqParam context.Context, getBucketAclInput *s3.GetBucketAclInput) ([]byte, error) {
					return tt.input.beRes.([]byte), tt.input.beErr
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
				ctrl.GetBucketAcl,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals: tt.input.locals,
					body:   tt.input.body,
				})
		})
	}
}

func TestS3ApiController_ListMultipartUploads(t *testing.T) {
	listMpResult := s3response.ListMultipartUploadsResult{
		Prefix:    "prefix",
		Delimiter: "delim",
		Bucket:    "bucket",
		Uploads: []s3response.Upload{
			{Key: "my-key"},
		},
	}
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
			name: "invalid max uploads",
			input: testInput{
				locals: defaultLocals,
				queries: map[string]string{
					"max-uploads": "-1",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidMaxUploads),
			},
		},
		{
			name: "backend returns error",
			input: testInput{
				locals: defaultLocals,
				beRes:  s3response.ListMultipartUploadsResult{},
				beErr:  s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
			output: testOutput{
				response: &Response{
					Data: s3response.ListMultipartUploadsResult{},
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
		},
		{
			name: "successful response",
			input: testInput{
				locals: defaultLocals,
				beRes:  listMpResult,
			},
			output: testOutput{
				response: &Response{
					Data: listMpResult,
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
				ListMultipartUploadsFunc: func(contextMoqParam context.Context, listMultipartUploadsInput *s3.ListMultipartUploadsInput) (s3response.ListMultipartUploadsResult, error) {
					return tt.input.beRes.(s3response.ListMultipartUploadsResult), tt.input.beErr
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
				ctrl.ListMultipartUploads,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals:  tt.input.locals,
					body:    tt.input.body,
					queries: tt.input.queries,
				})
		})
	}
}

func TestS3ApiController_ListObjectsV2(t *testing.T) {
	listV2Result := s3response.ListObjectsV2Result{
		Name:      utils.GetStringPtr("name"),
		Prefix:    utils.GetStringPtr("prefix"),
		Delimiter: utils.GetStringPtr("delim"),
		Contents: []s3response.Object{
			{Key: utils.GetStringPtr("my-key")},
		},
	}
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
			name: "invalid max keys",
			input: testInput{
				locals: defaultLocals,
				queries: map[string]string{
					"max-keys": "-1",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidMaxKeys),
			},
		},
		{
			name: "backend returns error",
			input: testInput{
				locals: defaultLocals,
				beRes:  s3response.ListObjectsV2Result{},
				beErr:  s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
			output: testOutput{
				response: &Response{
					Data: s3response.ListObjectsV2Result{},
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
		},
		{
			name: "successful response",
			input: testInput{
				locals: defaultLocals,
				beRes:  listV2Result,
			},
			output: testOutput{
				response: &Response{
					Data: listV2Result,
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
				ListObjectsV2Func: func(contextMoqParam context.Context, listObjectsV2Input *s3.ListObjectsV2Input) (s3response.ListObjectsV2Result, error) {
					return tt.input.beRes.(s3response.ListObjectsV2Result), tt.input.beErr
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
				ctrl.ListObjectsV2,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals:  tt.input.locals,
					body:    tt.input.body,
					queries: tt.input.queries,
				})
		})
	}
}

func TestS3ApiController_ListObjects(t *testing.T) {
	listResult := s3response.ListObjectsResult{
		Name:      utils.GetStringPtr("name"),
		Prefix:    utils.GetStringPtr("prefix"),
		Delimiter: utils.GetStringPtr("delim"),
		Contents: []s3response.Object{
			{Key: utils.GetStringPtr("my-key")},
		},
	}
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
			name: "invalid max keys",
			input: testInput{
				locals: defaultLocals,
				queries: map[string]string{
					"max-keys": "-1",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidMaxKeys),
			},
		},
		{
			name: "backend returns error",
			input: testInput{
				locals: defaultLocals,
				beRes:  s3response.ListObjectsResult{},
				beErr:  s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
			output: testOutput{
				response: &Response{
					Data: s3response.ListObjectsResult{},
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
		},
		{
			name: "successful response",
			input: testInput{
				locals: defaultLocals,
				beRes:  listResult,
			},
			output: testOutput{
				response: &Response{
					Data: listResult,
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
				ListObjectsFunc: func(contextMoqParam context.Context, listObjectsInput *s3.ListObjectsInput) (s3response.ListObjectsResult, error) {
					return tt.input.beRes.(s3response.ListObjectsResult), tt.input.beErr
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
				ctrl.ListObjects,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals:  tt.input.locals,
					body:    tt.input.body,
					queries: tt.input.queries,
				})
		})
	}
}
