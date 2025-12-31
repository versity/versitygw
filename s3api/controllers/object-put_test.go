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
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3event"
	"github.com/versity/versitygw/s3response"
)

func TestS3ApiController_PutObjectTagging(t *testing.T) {
	validTaggingBody, err := xml.Marshal(
		s3response.TaggingInput{
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
						EventName:   s3event.EventObjectTaggingPut,
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
						EventName:   s3event.EventObjectTaggingPut,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := &BackendMock{
				PutObjectTaggingFunc: func(contextMoqParam context.Context, bucket, object, versionId string, tags map[string]string) error {
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
				ctrl.PutObjectTagging,
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

func TestS3ApiController_PutObjectRetention(t *testing.T) {
	retDate := time.Now().Add(time.Hour * 3)
	validRetentionBody, err := xml.Marshal(
		s3response.PutObjectRetentionInput{
			Mode: types.ObjectLockRetentionModeGovernance,
			RetainUntilDate: s3response.AmzDate{
				Time: retDate,
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
				locals:       accessDeniedLocals,
				extraMockErr: s3err.GetAPIError(s3err.ErrAccessDenied),
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
			name: "retention put not allowed",
			input: testInput{
				locals:       defaultLocals,
				body:         validRetentionBody,
				extraMockErr: s3err.GetAPIError(s3err.ErrAccessDenied),
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
				locals:       defaultLocals,
				beErr:        s3err.GetAPIError(s3err.ErrNoSuchBucket),
				body:         validRetentionBody,
				extraMockErr: s3err.GetAPIError(s3err.ErrNoSuchObjectLockConfiguration),
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
				locals:       defaultLocals,
				body:         validRetentionBody,
				extraMockErr: s3err.GetAPIError(s3err.ErrNoSuchObjectLockConfiguration),
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
				PutObjectRetentionFunc: func(contextMoqParam context.Context, bucket, object, versionId string, retention []byte) error {
					return tt.input.beErr
				},
				GetBucketPolicyFunc: func(contextMoqParam context.Context, bucket string) ([]byte, error) {
					return nil, s3err.GetAPIError(s3err.ErrAccessDenied)
				},
				GetObjectRetentionFunc: func(contextMoqParam context.Context, bucket, object, versionId string) ([]byte, error) {
					return nil, tt.input.extraMockErr
				},
			}

			ctrl := S3ApiController{
				be: be,
			}

			testController(
				t,
				ctrl.PutObjectRetention,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals:  tt.input.locals,
					body:    tt.input.body,
					headers: tt.input.headers,
					queries: tt.input.queries,
				})
		})
	}
}

func TestS3ApiController_PutObjectLegalHold(t *testing.T) {
	validBody, err := xml.Marshal(
		types.ObjectLockLegalHold{
			Status: types.ObjectLockLegalHoldStatusOn,
		})
	assert.NoError(t, err)
	invalidStatusBody, err := xml.Marshal(
		types.ObjectLockLegalHold{
			Status: types.ObjectLockLegalHoldStatus("invalid_status"),
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
			name: "invalid legal hold status",
			input: testInput{
				locals: defaultLocals,
				body:   invalidStatusBody,
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
				body:   validBody,
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
				PutObjectLegalHoldFunc: func(contextMoqParam context.Context, bucket, object, versionId string, status bool) error {
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
				ctrl.PutObjectLegalHold,
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

func TestS3ApiController_UploadPart(t *testing.T) {
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
			name: "invalid part number",
			input: testInput{
				locals: defaultLocals,
				queries: map[string]string{
					"partNumber": "-2",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidPartNumber),
			},
		},
		{
			name: "invalid content length",
			input: testInput{
				locals: defaultLocals,
				headers: map[string]string{
					"X-Amz-Decoded-Content-Length": "invalid_cLength",
				},
				queries: map[string]string{
					"partNumber": "2",
				},
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
			name: "invalid checksum header",
			input: testInput{
				locals: defaultLocals,
				headers: map[string]string{
					"X-Amz-Sdk-Checksum-Algorithm": "invalid_algo",
				},
				queries: map[string]string{
					"partNumber": "2",
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
				beRes:  &s3.UploadPartOutput{},
				queries: map[string]string{
					"partNumber": "2",
				},
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
				locals: map[utils.ContextKey]any{
					utils.ContextKeyIsRoot: true,
					utils.ContextKeyParsedAcl: auth.ACL{
						Owner: "root",
					},
					utils.ContextKeyAccount: auth.Account{
						Access: "root",
						Role:   auth.RoleAdmin,
					},
					utils.ContextKeyBodyReader: strings.NewReader("hello world"),
				},
				queries: map[string]string{
					"partNumber": "2",
				},
				headers: map[string]string{
					"Content-Length": "4",
				},
				body: []byte("bbbb"),
				beRes: &s3.UploadPartOutput{
					ETag: utils.GetStringPtr("ETag"),
				},
			},
			output: testOutput{
				response: &Response{
					Headers: map[string]*string{
						"ETag":                     utils.GetStringPtr("ETag"),
						"x-amz-checksum-crc32":     nil,
						"x-amz-checksum-crc32c":    nil,
						"x-amz-checksum-crc64nvme": nil,
						"x-amz-checksum-sha1":      nil,
						"x-amz-checksum-sha256":    nil,
					},
					MetaOpts: &MetaOptions{
						BucketOwner:   "root",
						ContentLength: 4,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := &BackendMock{
				UploadPartFunc: func(contextMoqParam context.Context, uploadPartInput *s3.UploadPartInput) (*s3.UploadPartOutput, error) {
					return tt.input.beRes.(*s3.UploadPartOutput), tt.input.beErr
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
				ctrl.UploadPart,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals:  tt.input.locals,
					body:    tt.input.body,
					headers: tt.input.headers,
					queries: tt.input.queries,
				})
		})
	}
}

func TestS3ApiController_UploadPartCopy(t *testing.T) {
	tests := []struct {
		name   string
		input  testInput
		output testOutput
	}{
		{
			name: "verify access fails",
			input: testInput{
				locals: accessDeniedLocals,
				headers: map[string]string{
					"X-Amz-Copy-Source": "bucket/key",
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
			name: "invalid copy source: invalid versionId",
			input: testInput{
				locals: defaultLocals,
				headers: map[string]string{
					"X-Amz-Copy-Source": "bucket/object?versionId=invalid_versionId",
				},
				queries: map[string]string{
					"partNumber": "2",
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
			name: "invalid copy source",
			input: testInput{
				locals: defaultLocals,
				headers: map[string]string{
					"X-Amz-Copy-Source": "bad%G1",
				},
				queries: map[string]string{
					"partNumber": "2",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidCopySourceEncoding),
			},
		},
		{
			name: "non empty request body",
			input: testInput{
				locals: defaultLocals,
				headers: map[string]string{
					"X-Amz-Copy-Source": "bucket/object",
				},
				queries: map[string]string{
					"partNumber": "2",
				},
				body: []byte("body"),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrNonEmptyRequestBody),
			},
		},
		{
			name: "invalid part number",
			input: testInput{
				locals: defaultLocals,
				headers: map[string]string{
					"X-Amz-Copy-Source": "bucket/object",
				},
				queries: map[string]string{
					"partNumber": "-2",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidPartNumber),
			},
		},
		{
			name: "backend returns error",
			input: testInput{
				locals: defaultLocals,
				beErr:  s3err.GetAPIError(s3err.ErrNoSuchBucket),
				beRes:  s3response.CopyPartResult{},
				queries: map[string]string{
					"partNumber": "2",
				},
				headers: map[string]string{
					"X-Amz-Copy-Source": "bucket/object",
				},
			},
			output: testOutput{
				response: &Response{
					Data: s3response.CopyPartResult{},
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
				queries: map[string]string{
					"partNumber": "2",
				},

				headers: map[string]string{
					"X-Amz-Copy-Source": "bucket/object",
				},
				beRes: s3response.CopyPartResult{
					CopySourceVersionId: "versionId",
				},
			},
			output: testOutput{
				response: &Response{
					Data: s3response.CopyPartResult{
						CopySourceVersionId: "versionId",
					},
					Headers: map[string]*string{
						"x-amz-copy-source-version-id": utils.GetStringPtr("versionId"),
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
				UploadPartCopyFunc: func(contextMoqParam context.Context, uploadPartCopyInput *s3.UploadPartCopyInput) (s3response.CopyPartResult, error) {
					return tt.input.beRes.(s3response.CopyPartResult), tt.input.beErr
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
				ctrl.UploadPartCopy,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals:  tt.input.locals,
					headers: tt.input.headers,
					queries: tt.input.queries,
					body:    tt.input.body,
				})
		})
	}
}

func TestS3ApiController_PutObjectAcl(t *testing.T) {
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
				beErr:  s3err.GetAPIError(s3err.ErrNotImplemented),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
						EventName:   s3event.EventObjectAclPut,
					},
				},
				err: s3err.GetAPIError(s3err.ErrNotImplemented),
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
						EventName:   s3event.EventObjectAclPut,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := &BackendMock{
				PutObjectAclFunc: func(contextMoqParam context.Context, putObjectAclInput *s3.PutObjectAclInput) error {
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
				ctrl.PutObjectAcl,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals: tt.input.locals,
				})
		})
	}
}

func TestS3ApiController_CopyObject(t *testing.T) {
	var nilResp *s3response.CopyObjectResult
	tests := []struct {
		name   string
		input  testInput
		output testOutput
	}{
		{
			name: "verify access fails",
			input: testInput{
				locals: accessDeniedLocals,
				headers: map[string]string{
					"X-Amz-Copy-Source": "bucket/object",
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
			name: "invalid copy source",
			input: testInput{
				locals: defaultLocals,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidCopySourceBucket),
			},
		},
		{
			name: "invalid copy source: versionId",
			input: testInput{
				locals: defaultLocals,
				headers: map[string]string{
					"X-Amz-Copy-Source": "bucket/object?versionId=invalid_versionId",
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
			name: "non empty request body",
			input: testInput{
				locals: defaultLocals,
				headers: map[string]string{
					"X-Amz-Copy-Source": "bucket/object",
				},
				body: []byte("body"),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrNonEmptyRequestBody),
			},
		},
		{
			name: "invalid metadata directive",
			input: testInput{
				locals: defaultLocals,
				headers: map[string]string{
					"X-Amz-Copy-Source":                     "bucket/object",
					"X-Amz-Copy-Source-If-Unmodified-Since": "20250102T150405Z",
					"X-Amz-Copy-Source-If-Modified-Since":   "20240102T150405Z",
					"X-Amz-Metadata-Directive":              "invalid_metadat_directive",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidMetadataDirective),
			},
		},
		{
			name: "invalid tagging directive",
			input: testInput{
				locals: defaultLocals,
				headers: map[string]string{
					"X-Amz-Copy-Source":       "bucket/object",
					"X-Amz-Tagging-Directive": "invalid_tagging_directive",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidTaggingDirective),
			},
		},
		{
			name: "invalid checksum algorithm",
			input: testInput{
				locals: defaultLocals,
				headers: map[string]string{
					"X-Amz-Copy-Source":        "bucket/object",
					"x-amz-checksum-algorithm": "invalid_checksum_algo",
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
			name: "invalid object lock headers",
			input: testInput{
				locals: defaultLocals,
				headers: map[string]string{
					"X-Amz-Copy-Source":      "bucket/object",
					"X-Amz-Object-Lock-Mode": "GOVERNANCE",
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
			name: "object is locked",
			input: testInput{
				locals: defaultLocals,
				headers: map[string]string{
					"X-Amz-Copy-Source": "bucket/object",
				},
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
				locals: defaultLocals,
				beErr:  s3err.GetAPIError(s3err.ErrNoSuchBucket),
				beRes:  s3response.CopyObjectOutput{},
				headers: map[string]string{
					"X-Amz-Copy-Source": "bucket/object",
				},
				extraMockErr: s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound),
			},
			output: testOutput{
				response: &Response{
					Data: nilResp,
					Headers: map[string]*string{
						"x-amz-copy-source-version-id": nil,
						"x-amz-version-id":             nil,
					},
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
						EventName:   s3event.EventObjectCreatedCopy,
					},
				},
				err: s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
		},
		{
			name: "successful response",
			input: testInput{
				locals: defaultLocals,
				headers: map[string]string{
					"X-Amz-Copy-Source": "bucket/object",
				},
				beRes: s3response.CopyObjectOutput{
					CopySourceVersionId: utils.GetStringPtr("copySourceVersionId"),
					VersionId:           utils.GetStringPtr("versionId"),
					CopyObjectResult: &s3response.CopyObjectResult{
						ETag: utils.GetStringPtr("ETag"),
					},
				},
				extraMockErr: s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound),
			},
			output: testOutput{
				response: &Response{
					Data: &s3response.CopyObjectResult{
						ETag: utils.GetStringPtr("ETag"),
					},
					Headers: map[string]*string{
						"x-amz-copy-source-version-id": utils.GetStringPtr("copySourceVersionId"),
						"x-amz-version-id":             utils.GetStringPtr("versionId"),
					},
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
						ObjectETag:  utils.GetStringPtr("ETag"),
						EventName:   s3event.EventObjectCreatedCopy,
						VersionId:   utils.GetStringPtr("versionId"),
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := &BackendMock{
				CopyObjectFunc: func(contextMoqParam context.Context, copyObjectInput s3response.CopyObjectInput) (s3response.CopyObjectOutput, error) {
					return tt.input.beRes.(s3response.CopyObjectOutput), tt.input.beErr
				},
				GetBucketPolicyFunc: func(contextMoqParam context.Context, bucket string) ([]byte, error) {
					return nil, s3err.GetAPIError(s3err.ErrAccessDenied)
				},
				GetBucketVersioningFunc: func(contextMoqParam context.Context, bucket string) (s3response.GetBucketVersioningOutput, error) {
					return s3response.GetBucketVersioningOutput{}, s3err.GetAPIError(s3err.ErrNotImplemented)
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
				ctrl.CopyObject,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals:  tt.input.locals,
					headers: tt.input.headers,
					body:    tt.input.body,
				})
		})
	}
}

func TestS3ApiController_PutObject(t *testing.T) {
	str := ""
	emptyStringPtr := &str
	objSize := int64(120)

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
			name: "locked object",
			input: testInput{
				locals:       defaultLocals,
				extraMockErr: s3err.GetAPIError(s3err.ErrInvalidRequest),
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
			name: "invalid content length",
			input: testInput{
				locals:       defaultLocals,
				extraMockErr: s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound),
				headers: map[string]string{
					"X-Amz-Decoded-Content-Length": "invalid_length",
				},
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
			name: "invalid object lock headers",
			input: testInput{
				locals:       defaultLocals,
				extraMockErr: s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound),
				headers: map[string]string{
					"X-Amz-Object-Lock-Mode": "GOVERNANCE",
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
				locals:       defaultLocals,
				extraMockErr: s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound),
				headers: map[string]string{
					"X-Amz-Sdk-Checksum-Algorithm": "invalid_algo",
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
				locals:       defaultLocals,
				extraMockErr: s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound),
				beErr:        s3err.GetAPIError(s3err.ErrNoSuchBucket),
				beRes:        s3response.PutObjectOutput{},
				body:         []byte("aaa"),
				headers: map[string]string{
					"Content-Length": "3",
				},
			},
			output: testOutput{
				response: &Response{
					Headers: map[string]*string{
						"ETag":                     emptyStringPtr,
						"x-amz-checksum-crc32":     nil,
						"x-amz-checksum-crc32c":    nil,
						"x-amz-checksum-crc64nvme": nil,
						"x-amz-checksum-sha1":      nil,
						"x-amz-checksum-sha256":    nil,
						"x-amz-checksum-type":      nil,
						"x-amz-version-id":         emptyStringPtr,
						"x-amz-object-size":        nil,
					},
					MetaOpts: &MetaOptions{
						BucketOwner:   "root",
						EventName:     s3event.EventObjectCreatedPut,
						ContentLength: 3,
						ObjectSize:    3,
						ObjectETag:    emptyStringPtr,
					},
				},
				err: s3err.GetAPIError(s3err.ErrNoSuchBucket),
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
					utils.ContextKeyBodyReader: strings.NewReader("something"),
				},
				extraMockErr: s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound),
				headers: map[string]string{
					"Content-Length": "3",
				},
				body: []byte("aaa"),
				beRes: s3response.PutObjectOutput{
					ETag:              "ETag",
					ChecksumCRC32:     utils.GetStringPtr("crc32"),
					ChecksumCRC32C:    utils.GetStringPtr("crc32c"),
					ChecksumSHA1:      utils.GetStringPtr("sha1"),
					ChecksumSHA256:    utils.GetStringPtr("sha256"),
					ChecksumCRC64NVME: utils.GetStringPtr("crc64nvme"),
					ChecksumType:      types.ChecksumTypeComposite,
					VersionID:         "versionId",
					Size:              &objSize,
				},
			},
			output: testOutput{
				response: &Response{
					Headers: map[string]*string{
						"ETag":                     utils.GetStringPtr("ETag"),
						"x-amz-checksum-crc32":     utils.GetStringPtr("crc32"),
						"x-amz-checksum-crc32c":    utils.GetStringPtr("crc32c"),
						"x-amz-checksum-crc64nvme": utils.GetStringPtr("crc64nvme"),
						"x-amz-checksum-sha1":      utils.GetStringPtr("sha1"),
						"x-amz-checksum-sha256":    utils.GetStringPtr("sha256"),
						"x-amz-checksum-type":      utils.GetStringPtr(string(types.ChecksumTypeComposite)),
						"x-amz-version-id":         utils.GetStringPtr("versionId"),
						"x-amz-object-size":        utils.ConvertToStringPtr(objSize),
					},
					MetaOpts: &MetaOptions{
						BucketOwner:   "root",
						ObjectETag:    utils.GetStringPtr("ETag"),
						EventName:     s3event.EventObjectCreatedPut,
						ContentLength: 3,
						ObjectSize:    3,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := &BackendMock{
				PutObjectFunc: func(contextMoqParam context.Context, putObjectInput s3response.PutObjectInput) (s3response.PutObjectOutput, error) {
					return tt.input.beRes.(s3response.PutObjectOutput), tt.input.beErr
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
				ctrl.PutObject,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals:  tt.input.locals,
					headers: tt.input.headers,
					body:    tt.input.body,
				})
		})
	}
}
