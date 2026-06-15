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

package website

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/s3api/middlewares"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

var websiteAllowedMethods = []string{fiber.MethodGet, fiber.MethodHead, fiber.MethodOptions}

type websiteController struct {
	be           backend.Backend
	domain       string
	domainSuffix string
	applyCORS    fiber.Handler
}

// newWebsiteController returns a controller that serves static website content.
// It resolves the bucket name from the Host header using the configured domain,
// fetches the website configuration, and serves objects accordingly.
//
// Virtual-host routing with --website-domain example.com:
//   - Host "blog.example.com"  -> bucket "blog"
//   - Host "example.com"       -> bucket "example.com" (apex)
//
// Catch-all mode (--website-domain omitted or empty):
//   - Host "blog.example.com"  -> bucket "blog.example.com"
//   - Host "mysite.org"        -> bucket "mysite.org"
func newWebsiteController(be backend.Backend, domain string) *websiteController {
	controller := &websiteController{
		be:           be,
		domain:       domain,
		domainSuffix: "." + domain,
	}
	controller.applyCORS = middlewares.ApplyBucketCORS(be, controller.resolveBucket, "")
	return controller
}

func (c *websiteController) Get(ctx fiber.Ctx) error {
	return c.serve(ctx, c.getObject)
}

func (c *websiteController) Head(ctx fiber.Ctx) error {
	return c.serve(ctx, c.headObject)
}

func (c *websiteController) Options(ctx fiber.Ctx) error {
	bucket, err := c.resolveBucket(ctx)
	if err != nil {
		return sendError(ctx, err)
	}

	origin := ctx.Get("Origin")
	method := auth.CORSHTTPMethod(ctx.Get("Access-Control-Request-Method"))
	headers := ctx.Get("Access-Control-Request-Headers")

	if origin == "" {
		debuglogger.Logf("origin is missing: %v", origin)
		return sendError(ctx, s3err.GetAPIError(s3err.ErrMissingCORSOrigin))
	}

	if !method.IsValid() {
		debuglogger.Logf("invalid cors method: %s", method)
		return sendError(ctx, s3err.GetInvalidCORSMethodErr(method.String()))
	}

	parsedHeaders, err := auth.ParseCORSHeaders(headers)
	if err != nil {
		return sendError(ctx, err)
	}

	cors, err := c.be.GetBucketCors(ctx.RequestCtx(), bucket)
	if err != nil {
		debuglogger.Logf("failed to get bucket cors: %v", err)
		if errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchCORSConfiguration)) {
			err = s3err.GetAccessForbiddenErr(s3err.ErrCORSIsNotEnabled, http.MethodOptions, s3err.ResourceTypeBucket)
			debuglogger.Logf("bucket cors is not set: %v", err)
		}
		return sendError(ctx, err)
	}

	corsConfig, err := auth.ParseCORSOutput(cors)
	if err != nil {
		return sendError(ctx, err)
	}

	allowConfig, err := corsConfig.IsAllowed(origin, method, parsedHeaders, s3err.ResourceTypeObject)
	if err != nil {
		debuglogger.Logf("cors access forbidden: %v", err)
		return sendError(ctx, err)
	}

	setCORSPreflightHeaders(ctx, allowConfig)
	ctx.Status(http.StatusOK)
	return nil
}

func registerWebsiteRoutes(app *fiber.App, be backend.Backend, domain string) {
	controller := newWebsiteController(be, domain)

	app.Head("*", controller.Head)
	app.Get("*", controller.Get)
	app.Options("*", controller.Options)
	app.All("*", controller.MethodNotAllowed)
}

func setCORSPreflightHeaders(ctx fiber.Ctx, allowConfig *auth.CORSAllowanceConfig) {
	ctx.Set("Access-Control-Allow-Origin", allowConfig.Origin)
	ctx.Set("Access-Control-Allow-Methods", allowConfig.Methods)
	ctx.Set("Access-Control-Expose-Headers", allowConfig.ExposedHeaders)
	ctx.Set("Access-Control-Allow-Credentials", allowConfig.AllowCredentials)
	ctx.Set("Access-Control-Allow-Headers", allowConfig.AllowHeaders)
	ctx.Set("Vary", middlewares.VaryHdr)
	if allowConfig.MaxAge != nil {
		ctx.Set("Access-Control-Max-Age", strconv.Itoa(int(*allowConfig.MaxAge)))
	}
}

func (c *websiteController) MethodNotAllowed(ctx fiber.Ctx) error {
	return sendError(ctx, s3err.GetMethodNotAllowedErr(ctx.Method(), s3err.ResourceTypeObject, websiteAllowedMethods))
}

type websiteRequestInfo struct {
	bucket string
	config *s3response.WebsiteConfiguration
	key    string
}

type websiteObjectReader func(ctx fiber.Ctx, bucket, key string) websiteResult

func (c *websiteController) serve(ctx fiber.Ctx, readObject websiteObjectReader) error {
	req, err := c.resolveRequest(ctx)
	if err != nil {
		return sendError(ctx, err)
	}

	if err := c.applyCORS(ctx); err != nil {
		return sendError(ctx, err)
	}

	if req.config.RedirectAllRequestsTo != nil {
		return handleRedirectAll(ctx, req.config.RedirectAllRequestsTo, req.key)
	}

	if rule := req.config.MatchPrefetchRoutingRule(req.key); rule != nil {
		return applyRedirect(ctx, rule.Redirect, rule.Condition, req.key)
	}

	resolvedKey := resolveIndexKey(req.key, req.config)
	result := readObject(ctx, req.bucket, resolvedKey)
	if result.Err == nil {
		return serveWebsiteResult(ctx, req.bucket, req.config, result, readObject)
	}
	if result.StatusCode >= http.StatusInternalServerError {
		return sendError(ctx, result.Err)
	}

	if rule := req.config.MatchPostErrorRoutingRule(req.key, result.StatusCode); rule != nil {
		return applyRedirect(ctx, rule.Redirect, rule.Condition, req.key)
	}

	return serveWebsiteResult(ctx, req.bucket, req.config, result, readObject)
}

func (c *websiteController) resolveRequest(ctx fiber.Ctx) (*websiteRequestInfo, error) {
	bucket, err := c.resolveBucket(ctx)
	if err != nil {
		return nil, err
	}

	fmt.Println(bucket)

	key := strings.TrimPrefix(ctx.Path(), "/")
	if err := validateWebsiteNames(bucket, key); err != nil {
		return nil, err
	}

	data, err := c.be.GetBucketWebsite(ctx.RequestCtx(), bucket)
	if err != nil {
		return nil, err
	}

	config, err := s3response.ParseWebsiteConfigOutput(data)
	if err != nil {
		return nil, err
	}

	return &websiteRequestInfo{
		bucket: bucket,
		config: config,
		key:    key,
	}, nil
}

func validateWebsiteNames(bucket, key string) error {
	if !utils.IsValidBucketName(bucket) {
		return s3err.GetBucketErr(s3err.ErrInvalidBucketName, bucket)
	}
	if key != "" && !utils.IsObjectNameValid(key) {
		return s3err.GetAPIError(s3err.ErrBadRequest)
	}

	return nil
}

// resolveBucket extracts the bucket name from the request host header.
//
// It strips the port when present before applying website endpoint routing.
//
// When domain is set:
//   - If host equals the domain exactly, the bucket IS the domain (apex).
//   - If host ends with ".<domain>", the bucket is the subdomain part.
//   - Otherwise, no bucket can be resolved.
//
// When domain is empty (catch-all mode):
//   - The full hostname is used as the bucket name.
func (c *websiteController) resolveBucket(ctx fiber.Ctx) (string, error) {
	host := ctx.Host()
	if host == "" {
		ctx.Set("Location", c.noBucketLocation(ctx, host))
		return "", s3err.GetAPIError(s3err.ErrNoBucketInRequest)
	}

	// Strip port from host if present. Be careful with IPv6: only strip if the
	// last colon is not inside brackets.
	host = stripHostPort(host)

	if c.domain == "" {
		return host, nil
	}

	if strings.EqualFold(host, c.domain) {
		return c.domain, nil
	}

	lowerHost := strings.ToLower(host)
	lowerDomainSuffix := strings.ToLower(c.domainSuffix)
	if strings.HasSuffix(lowerHost, lowerDomainSuffix) {
		bucket := host[:len(host)-len(c.domainSuffix)]
		if bucket != "" && !strings.Contains(bucket, ".") {
			return bucket, nil
		}
	}

	ctx.Set("Location", c.noBucketLocation(ctx, ctx.Host()))
	return "", s3err.GetAPIError(s3err.ErrNoBucketInRequest)
}

func (c *websiteController) noBucketLocation(ctx fiber.Ctx, host string) string {
	locationHost := c.domain
	if locationHost == "" {
		locationHost = stripHostPort(host)
	}
	if locationHost == "" {
		return "/"
	}
	if c.domain != "" {
		if port := hostPort(host); port != "" {
			locationHost += ":" + port
		}
	}

	return fmt.Sprintf("%s://%s/", ctx.Scheme(), locationHost)
}

func stripHostPort(host string) string {
	if idx := strings.LastIndex(host, ":"); idx != -1 && !strings.Contains(host[idx:], "]") {
		return host[:idx]
	}

	return host
}

func hostPort(host string) string {
	if idx := strings.LastIndex(host, ":"); idx != -1 && !strings.Contains(host[idx:], "]") {
		return host[idx+1:]
	}

	return ""
}

type websiteResult struct {
	Key        string
	StatusCode int
	Object     websiteObject
	Err        error
}

type websiteObject struct {
	Body                    io.ReadCloser
	Headers                 map[string]*string
	Metadata                map[string]string
	WebsiteRedirectLocation *string
}

func resolveIndexKey(key string, config *s3response.WebsiteConfiguration) string {
	if config.IndexDocument != nil && config.IndexDocument.Suffix != "" {
		if key == "" || strings.HasSuffix(key, "/") {
			return key + config.IndexDocument.Suffix
		}
	}

	return key
}

func (c *websiteController) getObject(ctx fiber.Ctx, bucket, key string) websiteResult {
	if err := auth.VerifyPublicAccess(ctx.RequestCtx(), c.be, auth.GetObjectAction, auth.PermissionRead, bucket, key); err != nil {
		return websiteResult{
			Key:        key,
			StatusCode: statusCodeFromError(err),
			Err:        err,
		}
	}

	result, err := c.be.GetObject(ctx.RequestCtx(), &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		return websiteResult{
			Key:        key,
			StatusCode: statusCodeFromError(err),
			Err:        err,
		}
	}

	return websiteResult{
		Key:        key,
		StatusCode: http.StatusOK,
		Object: websiteObject{
			Body:                    result.Body,
			Headers:                 getObjectHeaders(result),
			Metadata:                result.Metadata,
			WebsiteRedirectLocation: result.WebsiteRedirectLocation,
		},
	}
}

func (c *websiteController) headObject(ctx fiber.Ctx, bucket, key string) websiteResult {
	if err := auth.VerifyPublicAccess(ctx.RequestCtx(), c.be, auth.GetObjectAction, auth.PermissionRead, bucket, key); err != nil {
		return websiteResult{
			Key:        key,
			StatusCode: statusCodeFromError(err),
			Err:        err,
		}
	}

	result, err := c.be.HeadObject(ctx.RequestCtx(), &s3.HeadObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		return websiteResult{
			Key:        key,
			StatusCode: statusCodeFromError(err),
			Err:        err,
		}
	}

	return websiteResult{
		Key:        key,
		StatusCode: http.StatusOK,
		Object: websiteObject{
			Headers:                 headObjectHeaders(result),
			Metadata:                result.Metadata,
			WebsiteRedirectLocation: result.WebsiteRedirectLocation,
		},
	}
}

func statusCodeFromError(err error) int {
	var serr s3err.S3Error
	if errors.As(err, &serr) {
		return serr.StatusCode()
	}

	return http.StatusInternalServerError
}

// handleRedirectAll sends a 301 redirect for RedirectAllRequestsTo configuration.
func handleRedirectAll(ctx fiber.Ctx, redirect *s3response.RedirectAllRequestsTo, key string) error {
	protocol := redirect.Protocol
	if protocol == "" {
		protocol = ctx.Scheme()
	}

	location := fmt.Sprintf("%s://%s/%s", protocol, redirect.HostName, key)
	if query := string(ctx.Request().URI().QueryString()); query != "" {
		location += "?" + query
	}
	return sendRedirect(ctx, http.StatusMovedPermanently, location)
}

// applyRedirect constructs and sends a redirect response from a routing rule.
func applyRedirect(ctx fiber.Ctx, redirect *s3response.Redirect, condition *s3response.RoutingRuleCondition, originalKey string) error {
	protocol := redirect.Protocol
	if protocol == "" {
		protocol = ctx.Scheme()
	}

	host := redirect.HostName
	if host == "" {
		host = ctx.Host()
	}

	key := originalKey
	if redirect.ReplaceKeyWith != "" {
		key = redirect.ReplaceKeyWith
	} else if redirect.ReplaceKeyPrefixWith != "" && condition != nil && condition.KeyPrefixEquals != "" {
		key = redirect.ReplaceKeyPrefixWith + strings.TrimPrefix(originalKey, condition.KeyPrefixEquals)
	}

	httpCode := http.StatusMovedPermanently
	if redirect.HttpRedirectCode != "" {
		if code, err := strconv.Atoi(redirect.HttpRedirectCode); err == nil {
			httpCode = code
		}
	}

	location := fmt.Sprintf("%s://%s/%s", protocol, host, key)
	if query := string(ctx.Request().URI().QueryString()); query != "" {
		location += "?" + query
	}
	return sendRedirect(ctx, httpCode, location)
}

func sendRedirect(ctx fiber.Ctx, statusCode int, location string) error {
	ctx.Set("Location", location)
	_, _ = utils.EnsureRequestIDs(ctx)
	ctx.Status(statusCode)
	return nil
}

func getObjectHeaders(result *s3.GetObjectOutput) map[string]*string {
	return map[string]*string{
		"ETag":                result.ETag,
		"accept-ranges":       result.AcceptRanges,
		"Cache-Control":       result.CacheControl,
		"Content-Disposition": result.ContentDisposition,
		"Content-Encoding":    result.ContentEncoding,
		"Content-Language":    result.ContentLanguage,
		"Content-Length":      utils.ConvertPtrToStringPtr(result.ContentLength),
		"Content-Range":       result.ContentRange,
		"Content-Type":        result.ContentType,
		"Expires":             result.ExpiresString,
		"Last-Modified":       utils.FormatDatePtrToString(result.LastModified, http.TimeFormat),
		"x-amz-restore":       result.Restore,
		"x-amz-version-id":    result.VersionId,
	}
}

func headObjectHeaders(result *s3.HeadObjectOutput) map[string]*string {
	return map[string]*string{
		"ETag":                result.ETag,
		"accept-ranges":       result.AcceptRanges,
		"Cache-Control":       result.CacheControl,
		"Content-Disposition": result.ContentDisposition,
		"Content-Encoding":    result.ContentEncoding,
		"Content-Language":    result.ContentLanguage,
		"Content-Length":      utils.ConvertPtrToStringPtr(result.ContentLength),
		"Content-Range":       result.ContentRange,
		"Content-Type":        result.ContentType,
		"Expires":             result.ExpiresString,
		"Last-Modified":       utils.FormatDatePtrToString(result.LastModified, http.TimeFormat),
		"x-amz-restore":       result.Restore,
		"x-amz-version-id":    result.VersionId,
	}
}

func serveWebsiteResult(ctx fiber.Ctx, bucket string, config *s3response.WebsiteConfiguration, result websiteResult, readObject websiteObjectReader) error {
	if result.Err == nil {
		// Precedence: RedirectAllRequestsTo, pre-fetch routing rules, object
		// redirect metadata, then post-error routing/error documents.
		if location := backend.GetStringFromPtr(result.Object.WebsiteRedirectLocation); location != "" {
			if result.Object.Body != nil {
				_ = result.Object.Body.Close()
			}
			return sendRedirect(ctx, http.StatusMovedPermanently, location)
		}
		return serveObject(ctx, result.Object, http.StatusOK)
	}

	if config.ErrorDocument != nil && config.ErrorDocument.Key != "" {
		return serveErrorDocument(ctx, readObject, bucket, config.ErrorDocument.Key, result.StatusCode)
	}

	return sendError(ctx, result.Err)
}

func serveObject(ctx fiber.Ctx, object websiteObject, statusCode int) error {
	ctx.Status(statusCode)
	setWebsiteObjectHeaders(ctx, object)

	if object.Body == nil {
		return nil
	}
	defer object.Body.Close()

	_, err := io.Copy(ctx.Response().BodyWriter(), object.Body)
	if err != nil {
		return sendError(ctx, err)
	}

	return nil
}

func setWebsiteObjectHeaders(ctx fiber.Ctx, object websiteObject) {
	utils.SetMetaHeaders(ctx, object.Metadata)
	for key, value := range object.Headers {
		if value != nil && *value != "" {
			ctx.Set(key, *value)
		}
	}
}

// serveErrorDocument fetches and serves the configured error document.
func serveErrorDocument(ctx fiber.Ctx, readObject websiteObjectReader, bucket, errorDocKey string, statusCode int) error {
	result := readObject(ctx, bucket, errorDocKey)
	if result.Err != nil {
		return sendError(ctx, result.Err)
	}

	return serveObject(ctx, result.Object, statusCode)
}

// sendError sends a simple HTML error page.
func sendError(ctx fiber.Ctx, err error) error {
	requestId, hostId := utils.EnsureRequestIDs(ctx)
	serr, ok := err.(s3err.S3Error)
	if !ok {
		debuglogger.InternalError(err)
		serr = s3err.GetAPIError(s3err.ErrInternalError)
	}

	ctx.Response().Header.Set("x-amz-error-code", serr.BaseError().Code)
	ctx.Response().Header.Set("x-amz-error-message", serr.BaseError().Description)
	if methodErr, ok := serr.(s3err.MethodNotAllowedError); ok && len(methodErr.AllowedMethods) != 0 {
		ctx.Response().Header.Set("Allow", methodErr.AllowedMethodsString())
	}

	ctx.Response().Header.SetContentType(fiber.MIMETextHTMLCharsetUTF8)
	return ctx.Status(serr.StatusCode()).Send(serr.HTMLBody(requestId, hostId))
}
