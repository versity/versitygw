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

	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

func TestS3ApiController_ListBuckets(t *testing.T) {
	validRes := s3response.ListAllMyBucketsResult{
		Owner: s3response.CanonicalUser{
			ID: "root",
		},
		Buckets: s3response.ListAllMyBucketsList{
			Bucket: []s3response.ListAllMyBucketsEntry{
				{Name: "test"},
			},
		},
	}

	tests := []struct {
		name   string
		input  testInput
		output testOutput
	}{
		{
			name: "invalid max buckets",
			input: testInput{
				locals: defaultLocals,
				queries: map[string]string{
					"max-buckets": "-1",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{},
				},
				err: s3err.GetAPIError(s3err.ErrInvalidMaxBuckets),
			},
		},
		{
			name: "backend returns error",
			input: testInput{
				locals: defaultLocals,
				beErr:  s3err.GetAPIError(s3err.ErrNoSuchBucket),
				beRes:  s3response.ListAllMyBucketsResult{},
			},
			output: testOutput{
				response: &Response{},
				err:      s3err.GetAPIError(s3err.ErrNoSuchBucket),
			},
		},
		{
			name: "successful response",
			input: testInput{
				locals: defaultLocals,
				beRes:  validRes,
				queries: map[string]string{
					"max-buckets": "3",
				},
			},
			output: testOutput{
				response: &Response{
					Data: validRes,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := &BackendMock{
				ListBucketsFunc: func(contextMoqParam context.Context, listBucketsInput s3response.ListBucketsInput) (s3response.ListAllMyBucketsResult, error) {
					return tt.input.beRes.(s3response.ListAllMyBucketsResult), tt.input.beErr
				},
			}

			ctrl := S3ApiController{
				be: be,
			}

			testController(
				t,
				ctrl.ListBuckets,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals:  tt.input.locals,
					queries: tt.input.queries,
				})
		})
	}
}
