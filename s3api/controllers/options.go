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
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/s3api/debuglogger"
	"github.com/versity/versitygw/s3api/middlewares"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
)

func (s S3ApiController) CORSOptions(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	// get headers
	origin := ctx.Get("Origin")
	method := auth.CORSHTTPMethod(ctx.Get("Access-Control-Request-Method"))
	headers := ctx.Get("Access-Control-Request-Headers")

	// Origin is required
	if origin == "" {
		debuglogger.Logf("origin is missing: %v", origin)
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetAPIError(s3err.ErrMissingCORSOrigin)
	}

	// check if allowed method is valid
	if !method.IsValid() {
		debuglogger.Logf("invalid cors method: %s", method)
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, s3err.GetInvalidCORSMethodErr(method.String())
	}

	// parse and validate headers
	parsedHeaders, err := auth.ParseCORSHeaders(headers)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	cors, err := s.be.GetBucketCors(ctx.Context(), bucket)
	if err != nil {
		debuglogger.Logf("failed to get bucket cors: %v", err)
		if errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchCORSConfiguration)) {
			err = s3err.GetAPIError(s3err.ErrCORSIsNotEnabled)
			debuglogger.Logf("bucket cors is not set: %v", err)
		}
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	corsConfig, err := auth.ParseCORSOutput(cors)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	allowConfig, err := corsConfig.IsAllowed(origin, method, parsedHeaders)
	if err != nil {
		debuglogger.Logf("cors access forbidden: %v", err)
		return &Response{
			MetaOpts: &MetaOptions{
				BucketOwner: parsedAcl.Owner,
			},
		}, err
	}

	return &Response{
		Headers: map[string]*string{
			"Access-Control-Allow-Origin":      &allowConfig.Origin,
			"Access-Control-Allow-Methods":     &allowConfig.Methods,
			"Access-Control-Expose-Headers":    &allowConfig.ExposedHeaders,
			"Access-Control-Allow-Credentials": &allowConfig.AllowCredentials,
			"Access-Control-Allow-Headers":     &allowConfig.AllowHeaders,
			"Access-Control-Max-Age":           utils.ConvertPtrToStringPtr(allowConfig.MaxAge),
			"Vary":                             &middlewares.VaryHdr,
		},
		MetaOpts: &MetaOptions{
			BucketOwner: parsedAcl.Owner,
		},
	}, nil
}
