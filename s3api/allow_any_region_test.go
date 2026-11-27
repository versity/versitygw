// Copyright 2026 Versity Software
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

package s3api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3api/controllers"
)

const (
	anyRegionGatewayRegion = "us-west-2"
	anyRegionClientRegion  = "eu-central-1"
)

// anyRegionBackend serves any bucket and creates any bucket, so a request
// that passes authentication succeeds.
type anyRegionBackend struct {
	backend.BackendUnsupported
}

func (anyRegionBackend) GetBucketAcl(context.Context, *s3.GetBucketAclInput) ([]byte, error) {
	return []byte("{}"), nil
}

func (anyRegionBackend) HeadBucket(context.Context, *s3.HeadBucketInput) (*s3.HeadBucketOutput, error) {
	return &s3.HeadBucketOutput{}, nil
}

func (anyRegionBackend) CreateBucket(context.Context, *s3.CreateBucketInput, []byte) error {
	return nil
}

// With WithAllowAnyRegion the gateway accepts a request signed for any
// region, header-signed or presigned, and CreateBucket accepts any location
// constraint. The gateway still reports its own region. Without it, the same
// requests fail.
func TestAllowAnyRegion(t *testing.T) {
	createBody := func(constraint string) string {
		return "<CreateBucketConfiguration><LocationConstraint>" + constraint + "</LocationConstraint></CreateBucketConfiguration>"
	}

	tests := []struct {
		name       string
		newRequest func(t *testing.T) *http.Request
		// the status without and with WithAllowAnyRegion
		strictStatus int
		anyStatus    int
		// the error code without WithAllowAnyRegion, for requests with a body
		strictCode string
		// a response header or body fragment that reports the gateway region,
		// checked with WithAllowAnyRegion
		wantHeader string
		wantBody   string
	}{
		{
			name: "HeadBucket",
			newRequest: func(t *testing.T) *http.Request {
				return signedRequest(t, http.MethodHead, "/bucket", anyRegionClientRegion, "", nil)
			},
			strictStatus: http.StatusBadRequest,
			anyStatus:    http.StatusOK,
			wantHeader:   anyRegionGatewayRegion,
		},
		{
			name:         "presigned HeadBucket",
			newRequest:   presignedHeadBucket,
			strictStatus: http.StatusBadRequest,
			anyStatus:    http.StatusOK,
			wantHeader:   anyRegionGatewayRegion,
		},
		{
			name: "GetBucketLocation",
			newRequest: func(t *testing.T) *http.Request {
				return signedRequest(t, http.MethodGet, "/bucket?location", anyRegionClientRegion, "", nil)
			},
			strictStatus: http.StatusBadRequest,
			anyStatus:    http.StatusOK,
			strictCode:   "AuthorizationHeaderMalformed",
			wantBody:     ">" + anyRegionGatewayRegion + "</LocationConstraint>",
		},
		{
			name: "CreateBucket in the signing region",
			newRequest: func(t *testing.T) *http.Request {
				return signedRequest(t, http.MethodPut, "/bucket", anyRegionClientRegion, createBody(anyRegionClientRegion), nil)
			},
			strictStatus: http.StatusBadRequest,
			anyStatus:    http.StatusOK,
			strictCode:   "AuthorizationHeaderMalformed",
		},
		{
			name: "CreateBucket in another region",
			newRequest: func(t *testing.T) *http.Request {
				return signedRequest(t, http.MethodPut, "/bucket", anyRegionGatewayRegion, createBody("ap-south-1"), nil)
			},
			strictStatus: http.StatusBadRequest,
			anyStatus:    http.StatusOK,
			strictCode:   "IllegalLocationConstraintException",
		},
		{
			name: "CreateBucket without a constraint",
			newRequest: func(t *testing.T) *http.Request {
				return signedRequest(t, http.MethodPut, "/bucket", anyRegionGatewayRegion, "", nil)
			},
			strictStatus: http.StatusBadRequest,
			anyStatus:    http.StatusOK,
			strictCode:   "IllegalLocationConstraintException",
		},
	}

	for _, anyRegion := range []bool{false, true} {
		var opts []Option
		mode := "strict"
		if anyRegion {
			opts = append(opts, WithAllowAnyRegion())
			mode = "any region"
		}
		app := newAnyRegionApp(t, opts...)

		for _, tt := range tests {
			t.Run(mode+"/"+tt.name, func(t *testing.T) {
				resp, err := app.Test(tt.newRequest(t))
				if err != nil {
					t.Fatalf("app.Test: %v", err)
				}
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)

				wantStatus := tt.strictStatus
				if anyRegion {
					wantStatus = tt.anyStatus
				}
				if resp.StatusCode != wantStatus {
					t.Fatalf("status %d, want %d: %s", resp.StatusCode, wantStatus, body)
				}

				if !anyRegion {
					if tt.strictCode != "" && !strings.Contains(string(body), "<Code>"+tt.strictCode+"</Code>") {
						t.Fatalf("response %s, want error code %s", body, tt.strictCode)
					}
					return
				}
				if tt.wantHeader != "" {
					if got := resp.Header.Get("x-amz-bucket-region"); got != tt.wantHeader {
						t.Fatalf("x-amz-bucket-region %q, want %q", got, tt.wantHeader)
					}
				}
				if tt.wantBody != "" && !strings.Contains(string(body), tt.wantBody) {
					t.Fatalf("response %s, want it to contain %s", body, tt.wantBody)
				}
			})
		}
	}
}

// The standalone admin server takes the same switch through
// WithAdminAllowAnyRegion.
func TestAdminAllowAnyRegion(t *testing.T) {
	tests := []struct {
		name       string
		opts       []AdminOpt
		wantStatus int
	}{
		{name: "strict", wantStatus: http.StatusBadRequest},
		{name: "any region", opts: []AdminOpt{WithAdminAllowAnyRegion()}, wantStatus: http.StatusCreated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iam := testAdminIAM()
			ctrl := controllers.New(anyRegionBackend{}, iam, nil, nil, nil, false, false, "", 0, auth.ListBucketsScopeOwned)
			opts := append([]AdminOpt{WithAdminConcurrencyLimiter(10, 10), WithAdminQuiet()}, tt.opts...)
			srv := NewAdminServer(anyRegionBackend{}, testAdminRoot, anyRegionGatewayRegion, iam, nil, ctrl, opts...)

			body := "<CreateBucketConfiguration><LocationConstraint>" + anyRegionClientRegion + "</LocationConstraint></CreateBucketConfiguration>"
			resp, err := srv.app.Test(signedAdminRequest(t, "/bucket/create", anyRegionClientRegion, body))
			if err != nil {
				t.Fatalf("app.Test: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				respBody, _ := io.ReadAll(resp.Body)
				t.Fatalf("status %d, want %d: %s", resp.StatusCode, tt.wantStatus, respBody)
			}
		})
	}
}

func newAnyRegionApp(t *testing.T, opts ...Option) *fiber.App {
	t.Helper()
	opts = append([]Option{WithConcurrencyLimiter(10, 10), WithQuiet()}, opts...)
	srv, err := New(anyRegionBackend{}, testAdminRoot, anyRegionGatewayRegion, testAdminIAM(), nil, nil, nil, nil, opts...)
	if err != nil {
		t.Fatalf("new s3 server: %v", err)
	}
	return srv.app
}

// presignedHeadBucket returns a HeadBucket presigned for the client region.
func presignedHeadBucket(t *testing.T) *http.Request {
	t.Helper()
	client := s3.New(s3.Options{
		Region:       anyRegionClientRegion,
		BaseEndpoint: aws.String("http://localhost"),
		UsePathStyle: true,
		Credentials: credentials.StaticCredentialsProvider{Value: aws.Credentials{
			AccessKeyID:     testAdminRoot.Access,
			SecretAccessKey: testAdminRoot.Secret,
		}},
	})
	req, err := s3.NewPresignClient(client).PresignHeadBucket(context.Background(), &s3.HeadBucketInput{Bucket: aws.String("bucket")})
	if err != nil {
		t.Fatalf("presign: %v", err)
	}
	return httptest.NewRequest(req.Method, req.URL, nil)
}
