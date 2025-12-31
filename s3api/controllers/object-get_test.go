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
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

func TestS3ApiController_GetObjectTagging(t *testing.T) {
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
				queries: map[string]string{
					"versionId": versionId,
				},
				locals: defaultLocals,
				beRes: map[string]string{
					"key": "val",
				},
			},
			output: testOutput{
				response: &Response{
					Headers: map[string]*string{
						"x-amz-version-id": utils.GetStringPtr(versionId),
					},
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
				GetObjectTaggingFunc: func(contextMoqParam context.Context, bucket, object, versionId string) (map[string]string, error) {
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
				ctrl.GetObjectTagging,
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

func TestS3ApiController_GetObjectRetention(t *testing.T) {
	retBytes, err := json.Marshal(types.ObjectLockRetention{
		Mode: types.ObjectLockRetentionModeCompliance,
	})
	assert.NoError(t, err)

	var retention *types.ObjectLockRetention

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
					Data: retention,
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: fmt.Errorf("parse object lock retention: "),
			},
		},
		{
			name: "successful response",
			input: testInput{
				locals: defaultLocals,
				beRes:  retBytes,
			},
			output: testOutput{
				response: &Response{
					Data: &types.ObjectLockRetention{
						Mode: types.ObjectLockRetentionModeCompliance,
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
				GetObjectRetentionFunc: func(contextMoqParam context.Context, bucket, object, versionId string) ([]byte, error) {
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
				ctrl.GetObjectRetention,
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

func TestS3ApiController_GetObjectLegalHold(t *testing.T) {
	var legalHold *bool
	var emptyLegalHold *s3response.GetObjectLegalHoldResult
	status := true

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
				locals: defaultLocals,
				beRes:  legalHold,
				beErr:  s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
			output: testOutput{
				response: &Response{
					Data: emptyLegalHold,
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
				beRes:  &status,
			},
			output: testOutput{
				response: &Response{
					Data: &s3response.GetObjectLegalHoldResult{
						Status: types.ObjectLockLegalHoldStatusOn,
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
				GetObjectLegalHoldFunc: func(contextMoqParam context.Context, bucket, object, versionId string) (*bool, error) {
					return tt.input.beRes.(*bool), tt.input.beErr
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
				ctrl.GetObjectLegalHold,
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

func TestS3ApiController_GetObjectAcl(t *testing.T) {
	var emptyRes *s3.GetObjectAclOutput
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
				beRes:  emptyRes,
				beErr:  s3err.GetAPIError(s3err.ErrNotImplemented),
			},
			output: testOutput{
				response: &Response{
					Data: emptyRes,
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrNotImplemented),
			},
		},
		{
			name: "successful response",
			input: testInput{
				locals: defaultLocals,
				beRes: &s3.GetObjectAclOutput{
					Owner: &types.Owner{
						ID: utils.GetStringPtr("something"),
					},
				},
			},
			output: testOutput{
				response: &Response{
					Data: &s3.GetObjectAclOutput{
						Owner: &types.Owner{
							ID: utils.GetStringPtr("something"),
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
				GetObjectAclFunc: func(contextMoqParam context.Context, getObjectAclInput *s3.GetObjectAclInput) (*s3.GetObjectAclOutput, error) {
					return tt.input.beRes.(*s3.GetObjectAclOutput), tt.input.beErr
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
				ctrl.GetObjectAcl,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals: tt.input.locals,
					body:   tt.input.body,
				})
		})
	}
}

func TestS3ApiController_ListParts(t *testing.T) {
	listPartsResult := s3response.ListPartsResult{
		Bucket:      "my-bucket",
		Key:         "obj",
		IsTruncated: false,
		Parts: []s3response.Part{
			{ETag: "ETag"},
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
			name: "invalid part number marker",
			input: testInput{
				locals: defaultLocals,
				queries: map[string]string{
					"part-number-marker": "-1",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidPartNumberMarker),
			},
		},
		{
			name: "invalid max parts",
			input: testInput{
				locals: defaultLocals,
				queries: map[string]string{
					"max-parts": "-1",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidMaxParts),
			},
		},
		{
			name: "backend returns error",
			input: testInput{
				locals: defaultLocals,
				beRes:  s3response.ListPartsResult{},
				beErr:  s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
			output: testOutput{
				response: &Response{
					Data: s3response.ListPartsResult{},
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
				beRes:  listPartsResult,
			},
			output: testOutput{
				response: &Response{
					Data: listPartsResult,
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
				ListPartsFunc: func(contextMoqParam context.Context, listPartsInput *s3.ListPartsInput) (s3response.ListPartsResult, error) {
					return tt.input.beRes.(s3response.ListPartsResult), tt.input.beErr
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
				ctrl.ListParts,
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

func TestS3ApiController_GetObjectAttributes(t *testing.T) {
	delMarker, lastModTime, etag := true, time.Now(), "ETag"
	timeFormatted := lastModTime.UTC().Format(iso8601TimeFormatExtended)

	validRes := s3response.GetObjectAttributesResponse{
		DeleteMarker: &delMarker,
		LastModified: &lastModTime,
		VersionId:    utils.GetStringPtr("versionId"),
		ETag:         &etag,
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
			name: "invalid max parts",
			input: testInput{
				locals: defaultLocals,
				headers: map[string]string{
					"X-Amz-Max-Parts": "-1",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidMaxParts),
			},
		},
		{
			name: "invalid object attributes",
			input: testInput{
				locals: defaultLocals,
				headers: map[string]string{
					"X-Amz-Object-Attributes": "invalid_attribute",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidObjectAttributes),
			},
		},
		{
			name: "backend returns error",
			input: testInput{
				locals: defaultLocals,
				beRes:  validRes,
				beErr:  s3err.GetAPIError(s3err.ErrNoSuchBucket),
				headers: map[string]string{
					"X-Amz-Object-Attributes": "ETag",
				},
			},
			output: testOutput{
				response: &Response{
					Headers: map[string]*string{
						"x-amz-version-id":    utils.GetStringPtr("versionId"),
						"x-amz-delete-marker": utils.GetStringPtr("true"),
					},
					Data: nil,
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
				headers: map[string]string{
					"X-Amz-Object-Attributes": "ETag",
				},
			},
			output: testOutput{
				response: &Response{
					Headers: map[string]*string{
						"x-amz-version-id":    utils.GetStringPtr("versionId"),
						"x-amz-delete-marker": utils.GetStringPtr("true"),
						"Last-Modified":       &timeFormatted,
					},
					Data: s3response.GetObjectAttributesResponse{
						ETag: &etag,
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
				GetObjectAttributesFunc: func(contextMoqParam context.Context, getObjectAttributesInput *s3.GetObjectAttributesInput) (s3response.GetObjectAttributesResponse, error) {
					return tt.input.beRes.(s3response.GetObjectAttributesResponse), tt.input.beErr
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
				ctrl.GetObjectAttributes,
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

func TestS3ApiController_GetObject(t *testing.T) {
	tm := time.Now()
	cLength := int64(11)
	rdr := io.NopCloser(strings.NewReader("hello world"))
	delMarker := true

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
			name: "invalid checksum mode",
			input: testInput{
				locals: defaultLocals,
				headers: map[string]string{
					"x-amz-checksum-mode": "invalid_checksum_mode",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetInvalidChecksumHeaderErr("x-amz-checksum-mode"),
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
			name: "backend returns error",
			input: testInput{
				locals: defaultLocals,
				beErr:  s3err.GetAPIError(s3err.ErrInvalidAccessKeyID),
				beRes: &s3.GetObjectOutput{
					DeleteMarker: &delMarker,
					LastModified: &tm,
				},
			},
			output: testOutput{
				response: &Response{
					Headers: map[string]*string{
						"x-amz-delete-marker": utils.GetStringPtr("true"),
						"Last-Modified":       utils.GetStringPtr(tm.UTC().Format(timefmt)),
					},
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
				headers: map[string]string{
					"Range": "100-200",
				},
				queries: map[string]string{
					"versionId": "01BX5ZZKBKACTAV9WEVGEMMVRZ",
				},
				locals: defaultLocals,
				beRes: &s3.GetObjectOutput{
					ETag:          utils.GetStringPtr("ETag"),
					ContentType:   utils.GetStringPtr("application/xml"),
					ContentLength: &cLength,
					Body:          rdr,
				},
			},
			output: testOutput{
				response: &Response{
					Headers: map[string]*string{
						"ETag":                                utils.GetStringPtr("ETag"),
						"x-amz-restore":                       nil,
						"accept-ranges":                       nil,
						"Content-Range":                       nil,
						"Content-Disposition":                 nil,
						"Content-Encoding":                    nil,
						"Content-Language":                    nil,
						"Cache-Control":                       nil,
						"Expires":                             nil,
						"x-amz-checksum-crc32":                nil,
						"x-amz-checksum-crc64nvme":            nil,
						"x-amz-checksum-crc32c":               nil,
						"x-amz-checksum-sha1":                 nil,
						"x-amz-checksum-sha256":               nil,
						"x-amz-version-id":                    nil,
						"x-amz-mp-parts-count":                nil,
						"x-amz-object-lock-mode":              nil,
						"x-amz-object-lock-legal-hold":        nil,
						"x-amz-storage-class":                 nil,
						"x-amz-checksum-type":                 nil,
						"x-amz-object-lock-retain-until-date": nil,
						"Last-Modified":                       nil,
						"x-amz-tagging-count":                 nil,
						"Content-Type":                        utils.GetStringPtr("application/xml"),
						"Content-Length":                      utils.GetStringPtr("11"),
					},
					MetaOpts: &MetaOptions{
						BucketOwner:   "root",
						Status:        http.StatusPartialContent,
						ContentLength: cLength,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := &BackendMock{
				GetObjectFunc: func(contextMoqParam context.Context, getObjectInput *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
					return tt.input.beRes.(*s3.GetObjectOutput), tt.input.beErr
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
				ctrl.GetObject,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals:  tt.input.locals,
					headers: tt.input.headers,
					queries: tt.input.queries,
				})
		})
	}
}
