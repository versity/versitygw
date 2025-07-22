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
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3event"
	"github.com/versity/versitygw/s3log"
	"github.com/versity/versitygw/s3response"
)

var (
	defaultLocals map[utils.ContextKey]any = map[utils.ContextKey]any{
		utils.ContextKeyIsRoot: true,
		utils.ContextKeyParsedAcl: auth.ACL{
			Owner: "root",
		},
		utils.ContextKeyAccount: auth.Account{
			Access: "root",
			Role:   auth.RoleAdmin,
		},
	}

	accessDeniedLocals map[utils.ContextKey]any = map[utils.ContextKey]any{
		utils.ContextKeyIsRoot: false,
		utils.ContextKeyParsedAcl: auth.ACL{
			Owner: "root",
		},
		utils.ContextKeyAccount: auth.Account{
			Access: "user",
			Role:   auth.RoleUser,
		},
	}
)

type testInput struct {
	bucket        string
	body          []byte
	locals        map[utils.ContextKey]any
	headers       map[string]string
	queries       map[string]string
	beRes         any
	beErr         error
	extraMockErr  error
	extraMockResp any
}

type testOutput struct {
	response *Response
	err      error
}

type ctxInputs struct {
	bucket  string
	object  string
	body    []byte
	locals  map[utils.ContextKey]any
	headers map[string]string
	queries map[string]string
}

func testController(t *testing.T, ctrl Controller, resp *Response, expectedErr error, input ctxInputs) {
	app := fiber.New()

	app.Post("/:bucket/*", func(ctx *fiber.Ctx) error {
		// set the request body
		ctx.Request().SetBody(input.body)
		// set the request locals
		if input.locals != nil {
			for key, local := range input.locals {
				key.Set(ctx, local)
			}
		}

		// call the controller by passing the ctx
		res, err := ctrl(ctx)
		assert.Equal(t, resp, res)
		if expectedErr != nil {
			assert.Error(t, err)

			switch expectedErr.(type) {
			case s3err.APIError:
				assert.EqualValues(t, expectedErr, err)
			default:
				assert.ErrorContains(t, err, expectedErr.Error())
			}
		} else {
			assert.NoError(t, err)
		}

		return nil
	})

	req := buildRequest(input.bucket, input.object, input.body, input.headers, input.queries)

	_, err := app.Test(req)
	assert.NoError(t, err)
}

func buildRequest(bucket, object string, body []byte, headers, queries map[string]string) *http.Request {
	if bucket == "" {
		bucket = "bucket"
	}
	if object == "" {
		object = "object"
	}
	uri := url.URL{
		Path: "/" + path.Join(bucket, object),
	}

	// set the request query params
	if queries != nil {
		q := uri.Query()
		for key, val := range queries {
			q.Set(key, val)
		}

		uri.RawQuery = q.Encode()
	}

	// create a new request
	req := httptest.NewRequest(http.MethodPost, uri.String(), bytes.NewReader(body))

	// set the request headers
	for key, val := range headers {
		req.Header.Set(key, val)
	}

	return req
}

func TestNew(t *testing.T) {
	type args struct {
		be       backend.Backend
		iam      auth.IAMService
		logger   s3log.AuditLogger
		evs      s3event.S3EventSender
		mm       metrics.Manager
		debug    bool
		readonly bool
	}
	tests := []struct {
		name string
		args args
		want S3ApiController
	}{
		{
			name: "debug enabled",
			args: args{
				debug: true,
			},
			want: S3ApiController{
				debug: true,
			},
		},
		{
			name: "debug disabled",
			args: args{
				debug: false,
			},
			want: S3ApiController{
				debug: false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := New(tt.args.be, tt.args.iam, tt.args.logger, tt.args.evs, tt.args.mm, tt.args.debug, tt.args.readonly)
			assert.Equal(t, got, tt.want)
		})
	}
}

func TestS3ApiController_HandleErrorRoute(t *testing.T) {
	tests := []struct {
		name   string
		input  testInput
		output testOutput
	}{
		{
			name: "should return the passed error",
			input: testInput{
				extraMockErr: s3err.GetAPIError(s3err.ErrAnonymousCreateMp),
			},
			output: testOutput{
				response: &Response{},
				err:      s3err.GetAPIError(s3err.ErrAnonymousCreateMp),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s3Ctrl := S3ApiController{}
			ctrl := s3Ctrl.HandleErrorRoute(tt.input.extraMockErr)
			testController(
				t,
				ctrl,
				tt.output.response,
				tt.output.err,
				ctxInputs{})
		})
	}
}

func TestSetResponseHeaders(t *testing.T) {
	type args struct {
		headers map[string]*string
	}
	tests := []struct {
		name     string
		args     args
		expected map[string]string
	}{
		{
			name: "should not set if map is nil",
			args: args{
				headers: nil,
			},
			expected: nil,
		},
		{
			name: "should set some headers",
			args: args{
				headers: map[string]*string{
					"x-amz-checksum-algorithm": utils.GetStringPtr("crc32"),
					"x-amz-meta-key":           utils.GetStringPtr("meta_key"),
					"x-amz-mp-size":            utils.GetStringPtr(""),
					"something":                nil,
				},
			},
			expected: map[string]string{
				"x-amz-checksum-algorithm": "crc32",
				"x-amz-meta-key":           "meta_key",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := fiber.New()
			ctx := app.AcquireCtx(&fasthttp.RequestCtx{})
			SetResponseHeaders(ctx, tt.args.headers)
			if tt.expected != nil {
				for key, val := range tt.expected {
					v := ctx.Response().Header.Peek(key)
					assert.Equal(t, val, string(v))
				}
			}
		})
	}
}

// mock the audit logger
type mockAuditLogger struct {
}

func (m *mockAuditLogger) Log(_ *fiber.Ctx, _ error, _ []byte, _ s3log.LogMeta) {}
func (m *mockAuditLogger) HangUp() error                                        { return nil }
func (m *mockAuditLogger) Shutdown() error                                      { return nil }

// mock S3 event sender
type mockEvSender struct {
}

func (m *mockEvSender) SendEvent(_ *fiber.Ctx, _ s3event.EventMeta) {}
func (m *mockEvSender) Close() error                                { return nil }

// mock metrics manager

type mockMetricsManager struct{}

func (m *mockMetricsManager) Send(_ *fiber.Ctx, _ error, _ string, _ int64, _ int) {}
func (m *mockMetricsManager) Close()                                               {}

func TestProcessController(t *testing.T) {
	payload, err := xml.Marshal(s3response.Bucket{
		Name: "something",
	})
	assert.NoError(t, err)

	payloadLen := len(payload) + len(xmlhdr)

	services := &Services{
		Logger:         &mockAuditLogger{},
		EventSender:    &mockEvSender{},
		MetricsManager: &mockMetricsManager{},
	}
	type args struct {
		controller Controller
		svc        *Services
	}
	type expected struct {
		status  int
		headers map[string]string
		body    []byte
	}
	tests := []struct {
		name     string
		args     args
		expected expected
	}{
		{
			name: "no services successfull response",
			args: args{
				svc: &Services{},
				controller: func(ctx *fiber.Ctx) (*Response, error) {
					return &Response{}, nil
				},
			},
			expected: expected{
				status: http.StatusOK,
			},
		},
		{
			name: "handle api error",
			args: args{
				svc: services,
				controller: func(ctx *fiber.Ctx) (*Response, error) {
					return &Response{}, s3err.GetAPIError(s3err.ErrInvalidRequest)
				},
			},
			expected: expected{
				status: http.StatusBadRequest,
				body:   s3err.GetAPIErrorResponse(s3err.GetAPIError(s3err.ErrInvalidRequest), "", "", ""),
			},
		},
		{
			name: "handle custom error",
			args: args{
				svc: services,
				controller: func(ctx *fiber.Ctx) (*Response, error) {
					return &Response{}, errors.New("custom error")
				},
			},
			expected: expected{
				status: http.StatusInternalServerError,
				body:   s3err.GetAPIErrorResponse(s3err.GetAPIError(s3err.ErrInternalError), "", "", ""),
			},
		},
		{
			name: "body parsing fails",
			args: args{
				svc: services,
				controller: func(ctx *fiber.Ctx) (*Response, error) {
					return &Response{
						Data: make(chan int),
					}, nil
				},
			},
			expected: expected{
				status: http.StatusInternalServerError,
				body:   s3err.GetAPIErrorResponse(s3err.GetAPIError(s3err.ErrInternalError), "", "", ""),
			},
		},
		{
			name: "no data payload",
			args: args{
				svc: services,
				controller: func(ctx *fiber.Ctx) (*Response, error) {
					return &Response{
						MetaOpts: &MetaOptions{
							ObjectCount: 2,
						},
					}, nil
				},
			},
			expected: expected{
				status: http.StatusOK,
			},
		},
		{
			name: "should return 204 http status",
			args: args{
				svc: services,
				controller: func(ctx *fiber.Ctx) (*Response, error) {
					return &Response{
						MetaOpts: &MetaOptions{
							Status: http.StatusNoContent,
						},
					}, nil
				},
			},
			expected: expected{
				status: http.StatusNoContent,
			},
		},
		{
			name: "already encoded payload",
			args: args{
				svc: services,
				controller: func(ctx *fiber.Ctx) (*Response, error) {
					return &Response{
						Data: []byte("encoded_data"),
					}, nil
				},
			},
			expected: expected{
				status: http.StatusOK,
				body:   []byte("encoded_data"),
				headers: map[string]string{
					"Content-Length": "12",
				},
			},
		},
		{
			name: "should set response headers",
			args: args{
				svc: services,
				controller: func(ctx *fiber.Ctx) (*Response, error) {
					return &Response{
						Headers: map[string]*string{
							"X-Amz-My-Custom-Header": utils.GetStringPtr("my_value"),
							"X-Amz-Meta-My-Meta":     utils.GetStringPtr("my_meta"),
						},
					}, nil
				},
			},
			expected: expected{
				status: http.StatusOK,
				headers: map[string]string{
					"X-Amz-My-Custom-Header": "my_value",
					"X-Amz-Meta-My-Meta":     "my_meta",
				},
			},
		},
		{
			name: "large paylod: should return internal error",
			args: args{
				svc: services,
				controller: func(ctx *fiber.Ctx) (*Response, error) {
					type Item struct {
						Value string `xml:"value"`
					}

					type payload struct {
						Items []Item `xml:"item"`
					}

					const targetSize = 5 * 1024 * 1024 // 5 MiB
					const itemCount = 500
					const valueSize = targetSize / itemCount

					p := payload{
						Items: make([]Item, itemCount),
					}

					// Preallocate one shared string of desired size
					var sb strings.Builder
					sb.Grow(valueSize)
					for range valueSize {
						sb.WriteByte('A')
					}
					largeValue := sb.String()

					for i := range p.Items {
						p.Items[i].Value = largeValue
					}

					return &Response{
						Data: p,
					}, nil
				},
			},
			expected: expected{
				body:   s3err.GetAPIErrorResponse(s3err.GetAPIError(s3err.ErrInternalError), "", "", ""),
				status: http.StatusInternalServerError,
			},
		},
		{
			name: "not encoded payload",
			args: args{
				svc: services,
				controller: func(ctx *fiber.Ctx) (*Response, error) {
					return &Response{
						Data: s3response.Bucket{
							Name: "something",
						},
					}, nil
				},
			},
			expected: expected{
				headers: map[string]string{
					"Content-Length": fmt.Sprint(payloadLen),
				},
				body:   append(xmlhdr, payload...),
				status: http.StatusOK,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := fiber.New().AcquireCtx(&fasthttp.RequestCtx{})
			err := ProcessController(ctx, tt.args.controller, metrics.ActionAbortMultipartUpload, tt.args.svc)
			assert.NoError(t, err)

			// check the status
			assert.Equal(t, tt.expected.status, ctx.Response().StatusCode())

			// check the response headers to be set
			if tt.expected.headers != nil {
				for key, val := range tt.expected.headers {
					v := ctx.Response().Header.Peek(key)
					assert.Equal(t, val, string(v))
				}
			}

			// check the response body
			if tt.expected.body != nil {
				assert.Equal(t, tt.expected.body, ctx.Response().Body())
			}
		})
	}
}

func TestProcessHandlers(t *testing.T) {
	payload, err := xml.Marshal(s3response.Checksum{
		CRC32: utils.GetStringPtr("crc32"),
	})
	assert.NoError(t, err)

	type args struct {
		controller Controller
		svc        *Services
		handlers   []fiber.Handler
		locals     map[utils.ContextKey]any
	}
	type expected struct {
		body []byte
	}
	tests := []struct {
		name     string
		args     args
		expected expected
	}{
		{
			name: "should skip the handlers",
			args: args{
				locals: map[utils.ContextKey]any{
					utils.ContextKeySkip: true,
				},
			},
		},
		{
			name: "handler returns error",
			args: args{
				handlers: []fiber.Handler{
					func(ctx *fiber.Ctx) error {
						return nil
					},
					func(ctx *fiber.Ctx) error {
						return s3err.GetAPIError(s3err.ErrAccessDenied)
					},
				},
				svc: &Services{},
			},
			expected: expected{
				body: s3err.GetAPIErrorResponse(s3err.GetAPIError(s3err.ErrAccessDenied), "", "", ""),
			},
		},
		{
			name: "should process the controller",
			args: args{
				handlers: []fiber.Handler{
					func(ctx *fiber.Ctx) error {
						return nil
					},
					func(ctx *fiber.Ctx) error {
						return nil
					},
				},
				svc: &Services{},
				controller: func(ctx *fiber.Ctx) (*Response, error) {
					return &Response{
						Data: s3response.Checksum{
							CRC32: utils.GetStringPtr("crc32"),
						},
					}, nil
				},
			},
			expected: expected{
				body: append(xmlhdr, payload...),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mdlwr := ProcessHandlers(tt.args.controller, metrics.ActionCreateBucket, tt.args.svc, tt.args.handlers...)

			app := fiber.New()

			app.Post("/:bucket/*", func(ctx *fiber.Ctx) error {
				// set the request locals
				if tt.args.locals != nil {
					for key, val := range tt.args.locals {
						key.Set(ctx, val)
					}
				}

				// call the controller by passing the ctx
				err := mdlwr(ctx)
				assert.NoError(t, err)

				// check the response body
				if tt.expected.body != nil {
					assert.Equal(t, tt.expected.body, ctx.Response().Body())
				}

				return nil
			})

			app.All("*", func(ctx *fiber.Ctx) error {
				return nil
			})

			req := buildRequest("bucket", "object", nil, nil, nil)

			_, err := app.Test(req)
			assert.NoError(t, err)
		})
	}
}

func TestWrapMiddleware(t *testing.T) {
	type args struct {
		handler fiber.Handler
		logger  s3log.AuditLogger
		mm      metrics.Manager
	}
	type expected struct {
		body []byte
	}
	tests := []struct {
		name     string
		args     args
		expected expected
	}{
		{
			name: "handler returns no error",
			args: args{
				handler: func(ctx *fiber.Ctx) error {
					return nil
				},
			},
		},
		{
			name: "handler returns api error",
			args: args{
				handler: func(ctx *fiber.Ctx) error {
					return s3err.GetAPIError(s3err.ErrAclNotSupported)
				},
				mm:     &mockMetricsManager{},
				logger: &mockAuditLogger{},
			},
			expected: expected{
				body: s3err.GetAPIErrorResponse(s3err.GetAPIError(s3err.ErrAclNotSupported), "", "", ""),
			},
		},
		{
			name: "handler returns custom error",
			args: args{
				handler: func(ctx *fiber.Ctx) error {
					return errors.New("custom error")
				},
			},
			expected: expected{
				body: s3err.GetAPIErrorResponse(s3err.GetAPIError(s3err.ErrInternalError), "", "", ""),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mdlwr := WrapMiddleware(tt.args.handler, tt.args.logger, tt.args.mm)
			app := fiber.New()

			app.Post("/:bucket/*", func(ctx *fiber.Ctx) error {
				// call the controller by passing the ctx
				err := mdlwr(ctx)
				assert.NoError(t, err)

				// check the response body
				if tt.expected.body != nil {
					assert.Equal(t, tt.expected.body, ctx.Response().Body())
				}

				return nil
			})

			app.All("*", func(ctx *fiber.Ctx) error {
				return nil
			})

			req := buildRequest("bucket", "object", nil, nil, nil)

			_, err := app.Test(req)
			assert.NoError(t, err)
		})
	}
}
