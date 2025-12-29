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

func TestS3ApiController_RestoreObject(t *testing.T) {
	validRestoreBody, err := xml.Marshal(types.RestoreRequest{
		Description: utils.GetStringPtr("description"),
		Type:        types.RestoreRequestTypeSelect,
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
				body:   validRestoreBody,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
						EventName:   s3event.EventObjectRestoreCompleted,
					},
				},
				err: s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
		},
		{
			name: "successful response",
			input: testInput{
				locals: defaultLocals,
				body:   validRestoreBody,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
						EventName:   s3event.EventObjectRestoreCompleted,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := &BackendMock{
				RestoreObjectFunc: func(contextMoqParam context.Context, restoreObjectInput *s3.RestoreObjectInput) error {
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
				ctrl.RestoreObject,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals: tt.input.locals,
					body:   tt.input.body,
				})
		})
	}
}

func TestS3ApiController_SelectObjectContent(t *testing.T) {
	validSelectBody, err := xml.Marshal(s3response.SelectObjectContentPayload{
		Expression:     utils.GetStringPtr("expression"),
		ExpressionType: types.ExpressionTypeSql,
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
			name: "successful response",
			input: testInput{
				locals: defaultLocals,
				body:   validSelectBody,
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
				SelectObjectContentFunc: func(ctx context.Context, input *s3.SelectObjectContentInput) func(w *bufio.Writer) {
					return func(w *bufio.Writer) {}
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
				ctrl.SelectObjectContent,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals: tt.input.locals,
					body:   tt.input.body,
				})
		})
	}
}

func TestS3ApiController_CreateMultipartUpload(t *testing.T) {
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
			name: "invalid object lock headers",
			input: testInput{
				locals: defaultLocals,
				headers: map[string]string{
					"X-Amz-Object-Lock-Mode": string(types.ObjectLockModeGovernance),
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrObjectLockInvalidHeaders),
			},
		},
		{
			name: "invalid checksum headers",
			input: testInput{
				locals: defaultLocals,
				headers: map[string]string{
					"X-Amz-Checksum-Algorithm": "invalid_checksum_algo",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidChecksumAlgorithm),
			},
		},
		{
			name: "backend returns error",
			input: testInput{
				locals: defaultLocals,
				beErr:  s3err.GetAPIError(s3err.ErrNoSuchBucket),
				beRes:  s3response.InitiateMultipartUploadResult{},
			},
			output: testOutput{
				response: &Response{
					Data: s3response.InitiateMultipartUploadResult{},
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
				beRes:  s3response.InitiateMultipartUploadResult{},
				headers: map[string]string{
					"x-amz-checksum-algorithm": string(types.ChecksumAlgorithmCrc32),
					"x-amz-checksum-type":      string(types.ChecksumTypeComposite),
				},
			},
			output: testOutput{
				response: &Response{
					Data: s3response.InitiateMultipartUploadResult{},
					Headers: map[string]*string{
						"x-amz-checksum-algorithm": utils.ConvertToStringPtr(types.ChecksumAlgorithmCrc32),
						"x-amz-checksum-type":      utils.ConvertToStringPtr(types.ChecksumTypeComposite),
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
				CreateMultipartUploadFunc: func(contextMoqParam context.Context, createMultipartUploadInput s3response.CreateMultipartUploadInput) (s3response.InitiateMultipartUploadResult, error) {
					return tt.input.beRes.(s3response.InitiateMultipartUploadResult), tt.input.beErr
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
				ctrl.CreateMultipartUpload,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals:  tt.input.locals,
					body:    tt.input.body,
					headers: tt.input.headers,
				})
		})
	}
}

func TestS3ApiController_CompleteMultipartUpload(t *testing.T) {
	emptyMpPartsBody, err := xml.Marshal(s3response.CompleteMultipartUploadRequestBody{
		Parts: []types.CompletedPart{},
	})
	assert.NoError(t, err)
	pn := int32(1)

	validMpBody, err := xml.Marshal(s3response.CompleteMultipartUploadRequestBody{
		Parts: []types.CompletedPart{
			{
				PartNumber: &pn,
				ETag:       utils.GetStringPtr("ETag"),
			},
		},
	})
	assert.NoError(t, err)

	versionId, ETag := "versionId", "mock-ETag"

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
			name: "request body empty mp parts",
			input: testInput{
				locals: defaultLocals,
				body:   emptyMpPartsBody,
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
			name: "invalid mp parts header string",
			input: testInput{
				locals: defaultLocals,
				body:   validMpBody,
				headers: map[string]string{
					"X-Amz-Mp-Object-Size": "invalid_mp_object_size",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetInvalidMpObjectSizeErr("invalid_mp_object_size"),
			},
		},
		{
			name: "negative mp parts header value",
			input: testInput{
				locals: defaultLocals,
				body:   validMpBody,
				headers: map[string]string{
					"X-Amz-Mp-Object-Size": "-4",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetNegatvieMpObjectSizeErr(-4),
			},
		},
		{
			name: "invalid checksum headers",
			input: testInput{
				locals: defaultLocals,
				body:   validMpBody,
				headers: map[string]string{
					"X-Amz-Checksum-Crc32": "invalid_checksum",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetInvalidChecksumHeaderErr("x-amz-checksum-crc32"),
			},
		},
		{
			name: "invalid checksum type",
			input: testInput{
				locals: defaultLocals,
				body:   validMpBody,
				headers: map[string]string{
					"X-Amz-Checksum-Type": "invalid_checksum_type",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetInvalidChecksumHeaderErr("x-amz-checksum-type"),
			},
		},
		{
			name: "object is locked",
			input: testInput{
				locals:       defaultLocals,
				body:         validMpBody,
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
				body:         validMpBody,
				beErr:        s3err.GetAPIError(s3err.ErrNoSuchBucket),
				beRes:        s3response.CompleteMultipartUploadResult{},
				extraMockErr: s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound),
			},
			output: testOutput{
				response: &Response{
					Data: s3response.CompleteMultipartUploadResult{},
					Headers: map[string]*string{
						"x-amz-version-id": &versionId,
					},
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
						EventName:   s3event.EventCompleteMultipartUpload,
						VersionId:   &versionId,
						ObjectETag:  nil,
					},
				},
				err: s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
		},
		{
			name: "successful response",
			input: testInput{
				locals: defaultLocals,
				body:   validMpBody,
				beRes: s3response.CompleteMultipartUploadResult{
					ETag: &ETag,
				},
				headers: map[string]string{
					"X-Amz-Mp-Object-Size": "3",
				},
				extraMockErr: s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound),
			},
			output: testOutput{
				response: &Response{
					Data: s3response.CompleteMultipartUploadResult{
						ETag:     &ETag,
						Location: utils.GetStringPtr("http://example.com/bucket/object"),
					},
					Headers: map[string]*string{
						"x-amz-version-id": &versionId,
					},
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
						EventName:   s3event.EventCompleteMultipartUpload,
						VersionId:   &versionId,
						ObjectETag:  &ETag,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := &BackendMock{
				CompleteMultipartUploadFunc: func(contextMoqParam context.Context, completeMultipartUploadInput *s3.CompleteMultipartUploadInput) (s3response.CompleteMultipartUploadResult, string, error) {
					return tt.input.beRes.(s3response.CompleteMultipartUploadResult), versionId, tt.input.beErr
				},
				GetBucketPolicyFunc: func(contextMoqParam context.Context, bucket string) ([]byte, error) {
					return nil, s3err.GetAPIError(s3err.ErrAccessDenied)
				},
				GetObjectLockConfigurationFunc: func(contextMoqParam context.Context, bucket string) ([]byte, error) {
					return nil, tt.input.extraMockErr
				},
				GetBucketVersioningFunc: func(contextMoqParam context.Context, bucket string) (s3response.GetBucketVersioningOutput, error) {
					return s3response.GetBucketVersioningOutput{}, s3err.GetAPIError(s3err.ErrNotImplemented)
				},
			}

			ctrl := S3ApiController{
				be: be,
			}

			testController(
				t,
				ctrl.CompleteMultipartUpload,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals:  tt.input.locals,
					body:    tt.input.body,
					headers: tt.input.headers,
				})
		})
	}
}
