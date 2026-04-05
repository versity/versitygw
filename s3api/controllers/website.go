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
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// WebsiteErrorDocument wraps a Controller to serve the configured error
// document (or apply post-request routing rules) when the inner controller
// returns a 4xx error and website hosting is enabled for the bucket.
//
// The website configuration must be cached in the request context by the
// ResolveWebsiteIndex middleware (via ContextKeyWebsiteConfig).
func WebsiteErrorDocument(be backend.Backend, inner Controller) Controller {
	return func(ctx *fiber.Ctx) (*Response, error) {
		resp, err := inner(ctx)
		if err == nil {
			return resp, nil
		}

		serr, ok := err.(s3err.APIError)
		if !ok || serr.HTTPStatusCode < 400 || serr.HTTPStatusCode >= 500 {
			return resp, err
		}

		configVal := utils.ContextKeyWebsiteConfig.Get(ctx)
		if configVal == nil {
			return resp, err
		}
		config, ok := configVal.(*s3response.WebsiteConfiguration)
		if !ok || config == nil {
			return resp, err
		}

		bucket := ctx.Params("bucket")
		key := ctx.Params("*1")

		// Evaluate post-request routing rules (rules with HttpErrorCodeReturnedEquals).
		// Routing rules take precedence over the error document per the S3 spec.
		errorCode := strconv.Itoa(serr.HTTPStatusCode)
		if rule := config.MatchPostRequestRule(key, errorCode); rule != nil {
			protocol := ctx.Protocol()
			host := ctx.Hostname()
			location, httpCode := buildRedirectURL(rule.Redirect, key, protocol, host, rule.Condition)
			ctx.Set("Location", location)
			return &Response{
				MetaOpts: &MetaOptions{
					Status: httpCode,
				},
			}, nil
		}

		// Serve the error document if configured
		if config.ErrorDocument == nil || config.ErrorDocument.Key == "" {
			return resp, err
		}

		errorDocKey := config.ErrorDocument.Key
		result, getErr := be.GetObject(ctx.Context(), &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &errorDocKey,
		})
		if getErr != nil {
			// Error document itself not found: return original error
			return resp, err
		}
		if result.Body == nil {
			return resp, err
		}
		defer result.Body.Close()

		body, readErr := io.ReadAll(result.Body)
		if readErr != nil {
			return resp, err
		}

		// Determine content type from the error document object
		contentType := "text/html"
		if result.ContentType != nil && *result.ContentType != "" {
			contentType = *result.ContentType
		}

		ctx.Response().Header.SetContentType(contentType)

		return &Response{
			Data: body,
			MetaOpts: &MetaOptions{
				Status: serr.HTTPStatusCode,
			},
		}, nil
	}
}

// buildRedirectURL constructs a redirect location from a routing rule Redirect
// and the original request context.
func buildRedirectURL(redirect s3response.Redirect, originalKey, originalProtocol, originalHost string, condition *s3response.RoutingRuleCondition) (location string, httpCode int) {
	protocol := redirect.Protocol
	if protocol == "" {
		protocol = originalProtocol
	}

	host := redirect.HostName
	if host == "" {
		host = originalHost
	}

	key := originalKey
	if redirect.ReplaceKeyWith != "" {
		key = redirect.ReplaceKeyWith
	} else if redirect.ReplaceKeyPrefixWith != "" && condition != nil && condition.KeyPrefixEquals != "" {
		key = redirect.ReplaceKeyPrefixWith + strings.TrimPrefix(originalKey, condition.KeyPrefixEquals)
	}

	httpCode = http.StatusFound // 302 default
	if redirect.HttpRedirectCode != "" {
		if code, err := strconv.Atoi(redirect.HttpRedirectCode); err == nil {
			httpCode = code
		}
	}

	location = fmt.Sprintf("%s://%s/%s", protocol, host, key)
	return location, httpCode
}
