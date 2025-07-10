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
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
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
		req.Header.Add(key, val)
	}

	return req
}
