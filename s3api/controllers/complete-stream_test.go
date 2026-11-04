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

// The streamed CompleteMultipartUpload over a real HTTP connection, against a client whose response-header timeout
// is shorter than the backend's assembly.

package controllers

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

func TestS3ApiController_CompleteSlowerThanTheClientHeaderTimeoutAnswers200AtOnceKeepsTheConnectionAliveAndEndsWithTheResult(t *testing.T) {
	etag := "\"etag-2\""
	tests := []struct {
		name     string
		beRes    s3response.CompleteMultipartUploadResult
		beErr    error
		wantBody string
	}{
		{"backend succeeds after 25 s", s3response.CompleteMultipartUploadResult{ETag: &etag}, nil, "<ETag>&#34;etag-2&#34;</ETag>"},
		{"backend fails after 25 s", s3response.CompleteMultipartUploadResult{}, s3err.GetAPIError(s3err.ErrNoSuchUpload), "<Code>NoSuchUpload</Code>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			be := &BackendMock{
				CompleteMultipartUploadFunc: func(context.Context, *s3.CompleteMultipartUploadInput) (s3response.CompleteMultipartUploadResult, string, error) {
					time.Sleep(25 * time.Second)
					return tt.beRes, "", tt.beErr
				},
				GetBucketPolicyFunc: func(context.Context, string) ([]byte, error) {
					return nil, s3err.GetAPIError(s3err.ErrAccessDenied)
				},
				GetObjectLockConfigurationFunc: func(context.Context, string) ([]byte, error) {
					return nil, s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound)
				},
				ValidateUploadIDFunc: func(string) error { return nil },
				GetBucketVersioningFunc: func(context.Context, string) (s3response.GetBucketVersioningOutput, error) {
					return s3response.GetBucketVersioningOutput{}, s3err.GetAPIError(s3err.ErrNotImplemented)
				},
			}
			ctrl := S3ApiController{be: be}.WithStreamedComplete()
			app := fiber.New()
			app.Post("/:bucket/*", func(ctx fiber.Ctx) error {
				for key, local := range defaultLocals {
					key.Set(ctx, local)
				}
				return ProcessController(ctx, ctrl.CompleteMultipartUpload, "CompleteMultipartUpload", &Services{})
			})
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			assert.NoError(t, err)
			go app.Listener(ln, fiber.ListenConfig{DisableStartupMessage: true})
			defer app.Shutdown()
			client := http.Client{Transport: &http.Transport{ResponseHeaderTimeout: 2 * time.Second}}
			body := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>ETag</ETag></Part></CompleteMultipartUpload>`

			resp, err := client.Post("http://"+ln.Addr().String()+"/bucket/object?uploadId=id", "application/xml", bytes.NewBufferString(body))
			assert.NoError(t, err)
			got, err := io.ReadAll(resp.Body)

			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.GreaterOrEqual(t, len(got)-len(strings.TrimLeft(string(got), " ")), 2)
			assert.Contains(t, string(got), tt.wantBody)
			assert.NoError(t, xml.Unmarshal(got, new(struct{})))
		})
	}
}
