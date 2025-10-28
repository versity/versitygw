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
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
)

func TestS3ApiController_HeadBucket(t *testing.T) {
	region := "us-east-1"
	tests := []struct {
		name   string
		input  testInput
		output testOutput
	}{
		{
			name: "verify access fails",
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
					utils.ContextKeyRegion: region,
				},
			},
			output: testOutput{
				response: &Response{
					Headers: map[string]*string{
						"x-amz-bucket-region": utils.GetStringPtr(region),
					},
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
				locals: map[utils.ContextKey]any{
					utils.ContextKeyIsRoot: true,
					utils.ContextKeyParsedAcl: auth.ACL{
						Owner: "root",
					},
					utils.ContextKeyAccount: auth.Account{
						Access: "root",
						Role:   auth.RoleAdmin,
					},
					utils.ContextKeyRegion: region,
				},
				beErr: s3err.GetAPIError(s3err.ErrInvalidAccessKeyID),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidAccessKeyID),
			},
		},
		{
			name: "successful response",
			input: testInput{
				locals: map[utils.ContextKey]any{
					utils.ContextKeyIsRoot: true,
					utils.ContextKeyParsedAcl: auth.ACL{
						Owner: "root",
					},
					utils.ContextKeyAccount: auth.Account{
						Access: "root",
						Role:   auth.RoleAdmin,
					},
					utils.ContextKeyRegion: region,
				},
			},
			output: testOutput{
				response: &Response{
					Headers: map[string]*string{
						"x-amz-access-point-alias": utils.GetStringPtr("false"),
						"x-amz-bucket-region":      utils.GetStringPtr(region),
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
				HeadBucketFunc: func(contextMoqParam context.Context, headBucketInput *s3.HeadBucketInput) (*s3.HeadBucketOutput, error) {
					return &s3.HeadBucketOutput{}, tt.input.beErr
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
				ctrl.HeadBucket,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals: tt.input.locals,
				})
		})
	}
}
