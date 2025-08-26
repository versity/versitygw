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

	"github.com/stretchr/testify/assert"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/s3api/middlewares"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
)

func TestS3ApiController_CORSOptions(t *testing.T) {
	maxAge := int32(10000)
	cors, err := xml.Marshal(auth.CORSConfiguration{
		Rules: []auth.CORSRule{
			{
				AllowedOrigins: []string{"example.com"},
				AllowedMethods: []auth.CORSHTTPMethod{http.MethodGet, http.MethodPost},
				AllowedHeaders: []auth.CORSHeader{"Content-Type", "Content-Disposition"},
				ExposeHeaders:  []auth.CORSHeader{"Content-Encoding", "date"},
				MaxAgeSeconds:  &maxAge,
			},
		},
	})
	assert.NoError(t, err)

	tests := []struct {
		name   string
		input  testInput
		output testOutput
	}{
		{
			name: "missing origin",
			input: testInput{
				locals: defaultLocals,
				headers: map[string]string{
					"Access-Control-Request-Method":  "GET",
					"Access-Control-Request-Headers": "Content-Type",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrMissingCORSOrigin),
			},
		},
		{
			name: "invalid method",
			input: testInput{
				locals: defaultLocals,
				headers: map[string]string{
					"Origin":                         "example.com",
					"Access-Control-Request-Method":  "invalid_method",
					"Access-Control-Request-Headers": "Content-Type",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetInvalidCORSMethodErr("invalid_method"),
			},
		},
		{
			name: "invalid headers",
			input: testInput{
				locals: defaultLocals,
				headers: map[string]string{
					"Origin":                         "example.com",
					"Access-Control-Request-Method":  "GET",
					"Access-Control-Request-Headers": "Content Type",
				},
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetInvalidCORSRequestHeaderErr("Content Type"),
			},
		},
		{
			name: "fails to get bucket cors",
			input: testInput{
				locals: defaultLocals,
				headers: map[string]string{
					"Origin":                         "example.com",
					"Access-Control-Request-Method":  "GET",
					"Access-Control-Request-Headers": "Content-Type",
				},
				beRes: []byte{},
				beErr: s3err.GetAPIError(s3err.ErrNoSuchBucket),
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
			name: "bucket cors is not enabled",
			input: testInput{
				locals: defaultLocals,
				headers: map[string]string{
					"Origin":                         "example.com",
					"Access-Control-Request-Method":  "GET",
					"Access-Control-Request-Headers": "Content-Type",
				},
				beRes: []byte{},
				beErr: s3err.GetAPIError(s3err.ErrNoSuchCORSConfiguration),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrCORSIsNotEnabled),
			},
		},
		{
			name: "fails to parse bucket cors",
			input: testInput{
				locals: defaultLocals,
				headers: map[string]string{
					"Origin":                         "example.com",
					"Access-Control-Request-Method":  "GET",
					"Access-Control-Request-Headers": "Content-Type",
				},
				beRes: []byte("invalid_cors"),
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: errors.New("failed to parse cors config:"),
			},
		},
		{
			name: "cors is not allowed",
			input: testInput{
				locals: defaultLocals,
				headers: map[string]string{
					"Origin":                         "example.com",
					"Access-Control-Request-Method":  "PUT",
					"Access-Control-Request-Headers": "Content-Type",
				},
				beRes: cors,
			},
			output: testOutput{
				response: &Response{
					MetaOpts: &MetaOptions{
						BucketOwner: "root",
					},
				},
				err: s3err.GetAPIError(s3err.ErrCORSForbidden),
			},
		},
		{
			name: "success: cors is allowed",
			input: testInput{
				locals: defaultLocals,
				headers: map[string]string{
					"Origin":                         "example.com",
					"Access-Control-Request-Method":  "GET",
					"Access-Control-Request-Headers": "content-type, Content-Disposition",
				},
				beRes: cors,
			},
			output: testOutput{
				response: &Response{
					Headers: map[string]*string{
						"Access-Control-Allow-Origin":      utils.GetStringPtr("example.com"),
						"Access-Control-Allow-Methods":     utils.GetStringPtr("GET, POST"),
						"Access-Control-Expose-Headers":    utils.GetStringPtr("Content-Encoding, date"),
						"Access-Control-Allow-Credentials": utils.GetStringPtr("true"),
						"Access-Control-Allow-Headers":     utils.GetStringPtr("content-type, content-disposition"),
						"Access-Control-Max-Age":           utils.ConvertToStringPtr(maxAge),
						"Vary":                             &middlewares.VaryHdr,
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
				GetBucketCorsFunc: func(contextMoqParam context.Context, bucket string) ([]byte, error) {
					return tt.input.beRes.([]byte), tt.input.beErr
				},
			}

			ctrl := S3ApiController{
				be: be,
			}

			testController(
				t,
				ctrl.CORSOptions,
				tt.output.response,
				tt.output.err,
				ctxInputs{
					locals:  tt.input.locals,
					headers: tt.input.headers,
				})
		})
	}
}
