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
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3log"
	"github.com/versity/versitygw/s3response"
)

func TestNewAdminController(t *testing.T) {
	type args struct {
		iam   auth.IAMService
		be    backend.Backend
		l     s3log.AuditLogger
		s3api S3ApiController
	}
	tests := []struct {
		name string
		args args
		want AdminController
	}{
		{
			name: "initialize admin api",
			args: args{},
			want: AdminController{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewAdminController(tt.args.iam, tt.args.be, tt.args.l, tt.args.s3api)
			assert.Equal(t, got, tt.want)
		})
	}
}

func TestAdminController_CreateUser(t *testing.T) {
	validBody, err := xml.Marshal(auth.Account{
		Access: "access",
		Secret: "secret",
		Role:   auth.RoleAdmin,
	})
	assert.NoError(t, err)

	invalidUserRoleBody, err := xml.Marshal(auth.Account{
		Access: "access",
		Secret: "secret",
		Role:   auth.Role("invalid_role"),
	})
	assert.NoError(t, err)

	tests := []struct {
		name   string
		input  testInput
		output testOutput
	}{
		{
			name: "invalid request body",
			input: testInput{
				body: []byte("invalid_request_body"),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
				err: s3err.GetAPIError(s3err.ErrMalformedXML),
			},
		},
		{
			name: "invalid user role",
			input: testInput{
				body: invalidUserRoleBody,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
				err: s3err.GetAPIError(s3err.ErrAdminInvalidUserRole),
			},
		},
		{
			name: "backend returns user exists error",
			input: testInput{
				body:  validBody,
				beErr: auth.ErrUserExists,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
				err: s3err.GetAPIError(s3err.ErrAdminUserExists),
			},
		},
		{
			name: "backend returns other error",
			input: testInput{
				body:  validBody,
				beErr: s3err.GetAPIError(s3err.ErrInvalidRequest),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidRequest),
			},
		},
		{
			name: "successful response",
			input: testInput{
				body: validBody,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						Status: http.StatusCreated,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iam := &IAMServiceMock{
				CreateAccountFunc: func(account auth.Account) error {
					return tt.input.beErr
				},
			}

			ctrl := AdminController{
				iam: iam,
			}

			testController(
				t,
				ctrl.CreateUser,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					body: tt.input.body,
				})
		})
	}
}

func TestAdminController_UpdateUser(t *testing.T) {
	validBody, err := xml.Marshal(auth.MutableProps{
		Secret: utils.GetStringPtr("secret"),
		Role:   auth.RoleAdmin,
	})
	assert.NoError(t, err)

	invalidUserRoleBody, err := xml.Marshal(auth.MutableProps{
		Secret: utils.GetStringPtr("secret"),
		Role:   auth.Role("invalid_role"),
	})
	assert.NoError(t, err)

	tests := []struct {
		name   string
		input  testInput
		output testOutput
	}{
		{
			name: "missing user access key",
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
				err: s3err.GetAPIError(s3err.ErrAdminMissingUserAcess),
			},
		},
		{
			name: "invalid request body",
			input: testInput{
				body: []byte("invalid_request_body"),
				queries: map[string]string{
					"access": "user",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
				err: s3err.GetAPIError(s3err.ErrMalformedXML),
			},
		},
		{
			name: "invalid user role",
			input: testInput{
				body: invalidUserRoleBody,
				queries: map[string]string{
					"access": "user",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
				err: s3err.GetAPIError(s3err.ErrAdminInvalidUserRole),
			},
		},
		{
			name: "backend returns user not found error",
			input: testInput{
				body:  validBody,
				beErr: auth.ErrNoSuchUser,
				queries: map[string]string{
					"access": "user",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
				err: s3err.GetAPIError(s3err.ErrAdminUserNotFound),
			},
		},
		{
			name: "backend returns other error",
			input: testInput{
				body:  validBody,
				beErr: s3err.GetAPIError(s3err.ErrInvalidRequest),
				queries: map[string]string{
					"access": "user",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidRequest),
			},
		},
		{
			name: "successful response",
			input: testInput{
				body: validBody,
				queries: map[string]string{
					"access": "user",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iam := &IAMServiceMock{
				UpdateUserAccountFunc: func(access string, props auth.MutableProps) error {
					return tt.input.beErr
				},
			}

			ctrl := AdminController{
				iam: iam,
			}

			testController(
				t,
				ctrl.UpdateUser,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					body:    tt.input.body,
					queries: tt.input.queries,
				})
		})
	}
}

func TestAdminController_DeleteUser(t *testing.T) {
	tests := []struct {
		name   string
		input  testInput
		output testOutput
	}{
		{
			name: "missing user access key",
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
				err: s3err.GetAPIError(s3err.ErrAdminMissingUserAcess),
			},
		},
		{
			name: "backend returns other error",
			input: testInput{
				beErr: s3err.GetAPIError(s3err.ErrInvalidRequest),
				queries: map[string]string{
					"access": "user",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidRequest),
			},
		},
		{
			name: "successful response",
			input: testInput{
				queries: map[string]string{
					"access": "user",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iam := &IAMServiceMock{
				DeleteUserAccountFunc: func(access string) error {
					return tt.input.beErr
				},
			}

			ctrl := AdminController{
				iam: iam,
			}

			testController(
				t,
				ctrl.DeleteUser,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					queries: tt.input.queries,
				})
		})
	}
}

func TestAdminController_ListUsers(t *testing.T) {
	accs := []auth.Account{
		{
			Access: "access",
			Secret: "secret",
		},
		{
			Access: "access",
			Secret: "secret",
		},
	}
	tests := []struct {
		name   string
		input  testInput
		output testOutput
	}{
		{
			name: "backend returns error",
			input: testInput{
				beRes: []auth.Account{},
				beErr: s3err.GetAPIError(s3err.ErrInternalError),
			},
			output: testOutput{
				response: &Response{
					Data: auth.ListUserAccountsResult{
						Accounts: []auth.Account{},
					},
					MetaOpts: &MetaOptions{},
				},
				err: s3err.GetAPIError(s3err.ErrInternalError),
			},
		},
		{
			name: "successful response",
			input: testInput{
				beRes: accs,
			},
			output: testOutput{
				response: &Response{
					Data: auth.ListUserAccountsResult{
						Accounts: accs,
					},
					MetaOpts: &MetaOptions{},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iam := &IAMServiceMock{
				ListUserAccountsFunc: func() ([]auth.Account, error) {
					return tt.input.beRes.([]auth.Account), tt.input.beErr
				},
			}

			ctrl := AdminController{
				iam: iam,
			}

			testController(
				t,
				ctrl.ListUsers,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					queries: tt.input.queries,
				})
		})
	}
}

func TestAdminController_ChangeBucketOwner(t *testing.T) {
	tests := []struct {
		name   string
		input  testInput
		output testOutput
	}{
		{
			name: "fails to get user account",
			input: testInput{
				extraMockErr: s3err.GetAPIError(s3err.ErrInternalError),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
				err: errors.New("check user account: "),
			},
		},
		{
			name: "user not found",
			input: testInput{
				extraMockErr: auth.ErrNoSuchUser,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
				err: s3err.GetAPIError(s3err.ErrAdminUserNotFound),
			},
		},
		{
			name: "backend returns error",
			input: testInput{
				beErr: s3err.GetAPIError(s3err.ErrAdminMethodNotSupported),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
				err: s3err.GetAPIError(s3err.ErrAdminMethodNotSupported),
			},
		},
		{
			name: "successful response",
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iam := &IAMServiceMock{
				GetUserAccountFunc: func(access string) (auth.Account, error) {
					return auth.Account{}, tt.input.extraMockErr
				},
			}
			be := &BackendMock{
				ChangeBucketOwnerFunc: func(contextMoqParam context.Context, bucket, owner string) error {
					return tt.input.beErr
				},
			}

			ctrl := AdminController{
				iam: iam,
				be:  be,
			}

			testController(
				t,
				ctrl.ChangeBucketOwner,
				tt.output.response,
				tt.output.err,
				ctxInputs{},
			)
		})
	}
}

func TestAdminController_ListBuckets(t *testing.T) {
	res := []s3response.Bucket{
		{
			Name:  "bucket",
			Owner: "owner",
		},
	}

	tests := []struct {
		name   string
		input  testInput
		output testOutput
	}{
		{
			name: "backend returns other error",
			input: testInput{
				beRes: []s3response.Bucket{},
				beErr: s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
			output: testOutput{
				response: &Response{
					Data: s3response.ListBucketsResult{
						Buckets: []s3response.Bucket{},
					},
					MetaOpts: &MetaOptions{},
				},
				err: s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
		},
		{
			name: "successful response",
			input: testInput{
				beRes: res,
			},
			output: testOutput{
				response: &Response{
					Data: s3response.ListBucketsResult{
						Buckets: res,
					},
					MetaOpts: &MetaOptions{},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := &BackendMock{
				ListBucketsAndOwnersFunc: func(contextMoqParam context.Context) ([]s3response.Bucket, error) {
					return tt.input.beRes.([]s3response.Bucket), tt.input.beErr
				},
			}

			ctrl := AdminController{
				be: be,
			}

			testController(
				t,
				ctrl.ListBuckets,
				tt.output.response,
				tt.output.err,
				ctxInputs{},
			)
		})
	}
}

func TestAdminController_CreateBucket(t *testing.T) {
	tests := []struct {
		name   string
		input  testInput
		output testOutput
	}{
		{
			name: "empty owner header",
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
				err: s3err.GetAPIError(s3err.ErrAdminEmptyBucketOwnerHeader),
			},
		},
		{
			name: "fails to get user account",
			input: testInput{
				extraMockErr: s3err.GetAPIError(s3err.ErrInternalError),
				headers: map[string]string{
					"x-vgw-owner": "access",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
				err: s3err.GetAPIError(s3err.ErrInternalError),
			},
		},
		{
			name: "user not found",
			input: testInput{
				extraMockErr: auth.ErrNoSuchUser,
				headers: map[string]string{
					"x-vgw-owner": "access",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
				err: s3err.GetAPIError(s3err.ErrAdminUserNotFound),
			},
		},
		{
			name: "backend returns error",
			input: testInput{
				headers: map[string]string{
					"x-vgw-owner": "access",
				},
				locals: map[utils.ContextKey]any{
					utils.ContextKeyAccount: auth.Account{
						Access: "test-user",
						Role:   "admin",
					},
				},
				beErr: s3err.GetAPIError(s3err.ErrAdminMethodNotSupported),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
				err: s3err.GetAPIError(s3err.ErrAdminMethodNotSupported),
			},
		},
		{
			name: "successful response",
			input: testInput{
				headers: map[string]string{
					"x-vgw-owner": "access",
				},
				locals: map[utils.ContextKey]any{
					utils.ContextKeyAccount: auth.Account{
						Access: "test-user",
						Role:   "admin",
					},
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						Status: http.StatusCreated,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iam := &IAMServiceMock{
				GetUserAccountFunc: func(access string) (auth.Account, error) {
					return auth.Account{}, tt.input.extraMockErr
				},
			}
			be := &BackendMock{
				CreateBucketFunc: func(contextMoqParam context.Context, createBucketInput *s3.CreateBucketInput, defaultACL []byte) error {
					return tt.input.beErr
				},
			}

			s3api := New(be, iam, nil, nil, nil, false, false, "")

			ctrl := AdminController{
				iam:   iam,
				be:    be,
				s3api: s3api,
			}

			testController(
				t,
				ctrl.CreateBucket,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals:  tt.input.locals,
					headers: tt.input.headers,
				},
			)
		})
	}
}
