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
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/oklog/ulid/v2"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3event"
)

func TestS3ApiController_DeleteObjectTagging(t *testing.T) {
	versionId := ulid.Make().String()
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
			name: "invalid versionId",
			input: testInput{
				locals: defaultLocals,
				queries: map[string]string{
					"versionId": "invalid_versionId",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidVersionId),
			},
		},
		{
			name: "backend returns error",
			input: testInput{
				queries: map[string]string{
					"versionId": versionId,
				},
				locals: defaultLocals,
				beErr:  s3err.GetAPIError(s3err.ErrInvalidRequest),
			},
			output: testOutput{
				response: &Response{
					Headers: map[string]*string{
						"x-amz-version-id": &versionId,
					},
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
						Status:      http.StatusNoContent,
						EventName:   s3event.EventObjectTaggingDelete,
					},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidRequest),
			},
		},
		{
			name: "successful response",
			input: testInput{
				locals: defaultLocals,
				queries: map[string]string{
					"versionId": versionId,
				},
			},
			output: testOutput{
				response: &Response{
					Headers: map[string]*string{
						"x-amz-version-id": &versionId,
					},
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
						Status:      http.StatusNoContent,
						EventName:   s3event.EventObjectTaggingDelete,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := &BackendMock{
				DeleteObjectTaggingFunc: func(contextMoqParam context.Context, bucket, object, versionId string) error {
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
				ctrl.DeleteObjectTagging,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals:  tt.input.locals,
					queries: tt.input.queries,
				})
		})
	}
}

func TestS3ApiController_AbortMultipartUpload(t *testing.T) {
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
				beErr:  s3err.GetAPIError(s3err.ErrInvalidRequest),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
						Status:      http.StatusNoContent,
					},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidRequest),
			},
		},
		{
			name: "successful response",
			input: testInput{
				locals: defaultLocals,
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
				AbortMultipartUploadFunc: func(contextMoqParam context.Context, abortMultipartUploadInput *s3.AbortMultipartUploadInput) error {
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
				ctrl.AbortMultipartUpload,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals: tt.input.locals,
				})
		})
	}
}

func TestS3ApiController_DeleteObject(t *testing.T) {
	delMarker, versionId := true, "versionId"
	var emptyRes *s3.DeleteObjectOutput

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
			name: "invalid versionId",
			input: testInput{
				locals: defaultLocals,
				queries: map[string]string{
					"versionId": "invalid_versionId",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidVersionId),
			},
		},
		{
			name: "object locked",
			input: testInput{
				locals:       defaultLocals,
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
				beErr:        s3err.GetAPIError(s3err.ErrInvalidRequest),
				extraMockErr: s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound),
				beRes:        emptyRes,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
						Status:      http.StatusNoContent,
						EventName:   s3event.EventObjectRemovedDelete,
					},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidRequest),
			},
		},
		{
			name: "successful response",
			input: testInput{
				locals:       defaultLocals,
				extraMockErr: s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound),
				beRes: &s3.DeleteObjectOutput{
					DeleteMarker: &delMarker,
					VersionId:    &versionId,
				},
			},
			output: testOutput{
				response: &Response{
					Headers: map[string]*string{
						"x-amz-delete-marker": utils.GetStringPtr("true"),
						"x-amz-version-id":    &versionId,
					},
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
						Status:      http.StatusNoContent,
						EventName:   s3event.EventObjectRemovedDelete,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := &BackendMock{
				DeleteObjectFunc: func(contextMoqParam context.Context, deleteObjectInput *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error) {
					return tt.input.beRes.(*s3.DeleteObjectOutput), tt.input.beErr
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
				ctrl.DeleteObject,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals:  tt.input.locals,
					queries: tt.input.queries,
				})
		})
	}
}
