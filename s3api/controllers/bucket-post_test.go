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
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3event"
	"github.com/versity/versitygw/s3response"
)

func TestS3ApiController_DeleteObjects(t *testing.T) {
	validBody, err := xml.Marshal(s3response.DeleteObjects{
		Objects: []types.ObjectIdentifier{
			{Key: utils.GetStringPtr("obj")},
		},
	})
	assert.NoError(t, err)

	validRes := s3response.DeleteResult{
		Deleted: []types.DeletedObject{
			{Key: utils.GetStringPtr("key")},
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
				err: s3err.GetAPIError(s3err.ErrInvalidRequest),
			},
		},
		{
			name: "check object access returns error",
			input: testInput{
				locals:       defaultLocals,
				body:         validBody,
				extraMockErr: s3err.GetAPIError(s3err.ErrObjectLocked),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrObjectLocked),
			},
		},
		{
			name: "backend returns error",
			input: testInput{
				locals:       defaultLocals,
				beRes:        s3response.DeleteResult{},
				beErr:        s3err.GetAPIError(s3err.ErrNoSuchBucket),
				body:         validBody,
				extraMockErr: s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound),
			},
			output: testOutput{
				response: &Response{
					Data: s3response.DeleteResult{},
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
						EventName:   s3event.EventObjectRemovedDeleteObjects,
						ObjectCount: 1,
					},
				},
				err: s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
		},
		{
			name: "successful response",
			input: testInput{
				locals:       defaultLocals,
				body:         validBody,
				beRes:        validRes,
				extraMockErr: s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound),
			},
			output: testOutput{
				response: &Response{
					Data: validRes,
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
						EventName:   s3event.EventObjectRemovedDeleteObjects,
						ObjectCount: 1,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := &BackendMock{
				DeleteObjectsFunc: func(contextMoqParam context.Context, deleteObjectsInput *s3.DeleteObjectsInput) (s3response.DeleteResult, error) {
					return tt.input.beRes.(s3response.DeleteResult), tt.input.beErr
				},
				GetBucketPolicyFunc: func(contextMoqParam context.Context, bucket string) ([]byte, error) {
					return nil, s3err.GetAPIError(s3err.ErrAccessDenied)
				},
				GetObjectLockConfigurationFunc: func(contextMoqParam context.Context, bucket string) ([]byte, error) {
					return nil, tt.input.extraMockErr
				},
			}

			ctrl := S3ApiController{
				be: be,
			}

			testController(
				t,
				ctrl.DeleteObjects,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals: tt.input.locals,
					body:   tt.input.body,
				})
		})
	}
}
