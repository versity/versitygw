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
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
)

func TestS3ApiController_HeadObject(t *testing.T) {
	tm := time.Now()
	cLength := int64(100)

	failingBeRes := &s3.HeadObjectOutput{
		LastModified: &tm,
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
			name: "invalid part number",
			input: testInput{
				locals: defaultLocals,
				queries: map[string]string{
					"partNumber": "-4",
					"versionId":  "id",
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
			name: "backend returns error",
			input: testInput{
				locals: defaultLocals,
				beErr:  s3err.GetAPIError(s3err.ErrInvalidAccessKeyID),
				beRes:  failingBeRes,
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
				queries: map[string]string{
					"partNumber": "4",
				},
				locals: defaultLocals,
				headers: map[string]string{
					"x-amz-checksum-mode": "enabled",
				},
				beRes: &s3.HeadObjectOutput{
					ETag:          utils.GetStringPtr("ETag"),
					ContentType:   utils.GetStringPtr("application/xml"),
					ContentLength: &cLength,
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
						"Content-Length":                      utils.GetStringPtr("100"),
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
				HeadObjectFunc: func(contextMoqParam context.Context, headObjectInput *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
					return tt.input.beRes.(*s3.HeadObjectOutput), tt.input.beErr
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
				ctrl.HeadObject,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals:  tt.input.locals,
					queries: tt.input.queries,
					headers: tt.input.headers,
				})
		})
	}
}
