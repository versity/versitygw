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
	"encoding/xml"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3event"
	"github.com/versity/versitygw/s3log"
)

type S3ApiController struct {
	be            backend.Backend
	iam           auth.IAMService
	logger        s3log.AuditLogger
	evSender      s3event.S3EventSender
	mm            metrics.Manager
	readonly      bool
	virtualDomain string
}

const (
	// time constants
	iso8601TimeFormatExtended = "Mon Jan _2 15:04:05 2006"
	timefmt                   = "Mon, 02 Jan 2006 15:04:05 GMT"

	maxXMLBodyLen     = 4 * 1024 * 1024
	minPartNumber     = 1
	maxPartNumber     = 10000
	defaultMaxBuckets = int32(10000)

	defaultRegion = "us-east-1"
)

var (
	xmlhdr = []byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
)

func New(be backend.Backend, iam auth.IAMService, logger s3log.AuditLogger, evs s3event.S3EventSender, mm metrics.Manager, readonly bool, virtualDomain string) S3ApiController {
	return S3ApiController{
		be:            be,
		iam:           iam,
		logger:        logger,
		evSender:      evs,
		readonly:      readonly,
		mm:            mm,
		virtualDomain: virtualDomain,
	}
}

// Returns MethodNotAllowed for unmatched routes
func (c S3ApiController) HandleErrorRoute(err error) Controller {
	return func(ctx *fiber.Ctx) (*Response, error) {
		return &Response{}, err
	}
}

// MetaOptions holds the metadata for metrics, audit logs and s3 events
type MetaOptions struct {
	ContentLength int64
	BucketOwner   string
	ObjectSize    int64
	ObjectCount   int64
	EventName     s3event.EventType
	ObjectETag    *string
	VersionId     *string
	Status        int
}

// Response is the type definition for a controller response
// Data - Response body
// Headers - Resposne headers
// MetaOpts - Meta options for metrics, audit logs and s3 events
type Response struct {
	Data     any
	Headers  map[string]*string
	MetaOpts *MetaOptions
}

// Services groups the metrics manager, s3 event sender and audit logger
type Services struct {
	Logger         s3log.AuditLogger
	EventSender    s3event.S3EventSender
	MetricsManager metrics.Manager
}

// Controller is the type definition for an s3api controller
type Controller func(ctx *fiber.Ctx) (*Response, error)

// ProcessHandlers groups a controller and multiple middlewares into a single fiber handler
func ProcessHandlers(controller Controller, s3action string, svc *Services, handlers ...fiber.Handler) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		// if skip locals is set, skip to the next rout handler
		if utils.ContextKeySkip.IsSet(ctx) {
			utils.ContextKeySkip.Delete(ctx)
			return ctx.Next()
		}

		for _, handler := range handlers {
			err := handler(ctx)
			if err != nil {
				return ProcessController(ctx, func(ctx *fiber.Ctx) (*Response, error) {
					return &Response{
						MetaOpts: &MetaOptions{},
					}, err
				}, s3action, svc)
			}
		}

		return ProcessController(ctx, controller, s3action, svc)
	}
}

// WrapMiddleware executes the given middleware and handles sending the audit logs
// and metrics. It also handles the error parsing
func WrapMiddleware(handler fiber.Handler, logger s3log.AuditLogger, mm metrics.Manager) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		err := handler(ctx)
		if err != nil {
			if mm != nil {
				mm.Send(ctx, err, metrics.ActionUndetected, 0, 0)
			}
			if logger != nil {
				logger.Log(ctx, err, ctx.Body(), s3log.LogMeta{
					Action: metrics.ActionUndetected,
				})
			}

			serr, ok := err.(s3err.APIError)
			if ok {
				ctx.Status(serr.HTTPStatusCode)
				return ctx.Send(s3err.GetAPIErrorResponse(serr, "", "", ""))
			}

			debuglogger.Logf("Internal Error, %v", err)
			ctx.Status(http.StatusInternalServerError)

			// If the error is not 's3err.APIError' return 'InternalError'
			return ctx.Send(s3err.GetAPIErrorResponse(
				s3err.GetAPIError(s3err.ErrInternalError), "", "", ""))
		}

		return ctx.Next()
	}
}

// ProcessController executes the given s3api controller and handles the metrics
// access logs and s3 events
func ProcessController(ctx *fiber.Ctx, controller Controller, s3action string, svc *Services) error {
	response, err := controller(ctx)

	// Set the response headers
	SetResponseHeaders(ctx, response.Headers)
	ensureExposeMetaHeaders(ctx)

	opts := response.MetaOpts
	if opts == nil {
		opts = &MetaOptions{}
	}
	// Send the metrics
	if svc.MetricsManager != nil {
		if opts.ObjectCount > 0 {
			svc.MetricsManager.Send(ctx, err, s3action, opts.ObjectCount, opts.Status)
		} else {
			svc.MetricsManager.Send(ctx, err, s3action, opts.ContentLength, opts.Status)
		}
	}
	// Handle the error case
	if err != nil {
		// Audit the error log
		if svc.Logger != nil {
			svc.Logger.Log(ctx, err, nil, s3log.LogMeta{
				Action:      s3action,
				BucketOwner: opts.BucketOwner,
				ObjectSize:  opts.ObjectSize,
			})
		}
		serr, ok := err.(s3err.APIError)
		if ok {
			ctx.Status(serr.HTTPStatusCode)
			return ctx.Send(s3err.GetAPIErrorResponse(serr, "", "", ""))
		}

		debuglogger.InternalError(err)
		ctx.Status(http.StatusInternalServerError)

		// If the error is not 's3err.APIError' return 'InternalError'
		return ctx.Send(s3err.GetAPIErrorResponse(
			s3err.GetAPIError(s3err.ErrInternalError), "", "", ""))
	}

	// At this point, the S3 action has succeeded in the backend and
	// the event has already occurred. This means the S3 event must be sent,
	// even if unexpected issues arise while further parsing the response payload.
	if svc.EventSender != nil && opts.EventName != "" {
		svc.EventSender.SendEvent(ctx, s3event.EventMeta{
			BucketOwner: opts.BucketOwner,
			ObjectSize:  opts.ObjectSize,
			ObjectETag:  opts.ObjectETag,
			VersionId:   opts.VersionId,
			EventName:   opts.EventName,
		})
	}

	if opts.Status == 0 {
		opts.Status = http.StatusOK
	}

	// if no data payload is provided, send the response status
	if response.Data == nil {
		if svc.Logger != nil {
			svc.Logger.Log(ctx, nil, []byte{}, s3log.LogMeta{
				Action:      s3action,
				BucketOwner: opts.BucketOwner,
				ObjectSize:  opts.ObjectSize,
			})
		}
		ctx.Status(opts.Status)
		return nil
	}

	var responseBytes []byte

	// Handle already encoded responses(text, json...)
	encodedResp, ok := response.Data.([]byte)
	if ok {
		responseBytes = encodedResp
	} else {
		if responseBytes, err = xml.Marshal(response.Data); err != nil {
			debuglogger.Logf("Internal Error, %v", err)
			if svc.Logger != nil {
				svc.Logger.Log(ctx, err, nil, s3log.LogMeta{
					Action:      s3action,
					BucketOwner: opts.BucketOwner,
					ObjectSize:  opts.ObjectSize,
				})
			}
			return ctx.Status(http.StatusInternalServerError).Send(s3err.GetAPIErrorResponse(
				s3err.GetAPIError(s3err.ErrInternalError), "", "", ""))
		}

		if len(responseBytes) > 0 {
			ctx.Response().Header.SetContentType(fiber.MIMEApplicationXML)
		}
	}

	if ok {
		if len(responseBytes) > 0 {
			ctx.Response().Header.Set("Content-Length", fmt.Sprint(len(responseBytes)))
		}

		if svc.Logger != nil {
			svc.Logger.Log(ctx, nil, responseBytes, s3log.LogMeta{
				Action:      s3action,
				BucketOwner: opts.BucketOwner,
				ObjectSize:  opts.ObjectSize,
			})
		}

		return ctx.Send(responseBytes)
	}

	msglen := len(xmlhdr) + len(responseBytes)
	if msglen > maxXMLBodyLen {
		debuglogger.Logf("XML encoded body len %v exceeds max len %v",
			msglen, maxXMLBodyLen)
		if svc.Logger != nil {
			svc.Logger.Log(ctx, err, []byte{}, s3log.LogMeta{
				Action:      s3action,
				BucketOwner: opts.BucketOwner,
				ObjectSize:  opts.ObjectSize,
			})
		}
		ctx.Status(http.StatusInternalServerError)

		return ctx.Send(s3err.GetAPIErrorResponse(
			s3err.GetAPIError(s3err.ErrInternalError), "", "", ""))
	}
	res := make([]byte, 0, msglen)
	res = append(res, xmlhdr...)
	res = append(res, responseBytes...)

	// Set the Content-Length header
	ctx.Response().Header.SetContentLength(msglen)

	if svc.Logger != nil {
		svc.Logger.Log(ctx, nil, responseBytes, s3log.LogMeta{
			Action:      s3action,
			BucketOwner: opts.BucketOwner,
			ObjectSize:  opts.ObjectSize,
		})
	}

	return ctx.Send(res)
}

func ensureExposeMetaHeaders(ctx *fiber.Ctx) {
	// Only attempt to modify expose headers when CORS is actually in use.
	if len(ctx.Response().Header.Peek("Access-Control-Allow-Origin")) == 0 {
		return
	}

	existing := strings.TrimSpace(string(ctx.Response().Header.Peek("Access-Control-Expose-Headers")))
	if existing == "*" {
		return
	}

	lowerExisting := map[string]struct{}{}
	if existing != "" {
		for _, part := range strings.Split(existing, ",") {
			p := strings.ToLower(strings.TrimSpace(part))
			if p != "" {
				lowerExisting[p] = struct{}{}
			}
		}
	}

	metaNames := map[string]struct{}{}
	for k := range ctx.Response().Header.All() {
		key := string(k)
		if strings.HasPrefix(strings.ToLower(key), "x-amz-meta-") {
			metaNames[key] = struct{}{}
		}
	}
	if len(metaNames) == 0 {
		// Still ensure ETag is present if any expose headers exist/are needed.
		if _, ok := lowerExisting["etag"]; ok {
			return
		}
		if existing == "" {
			ctx.Response().Header.Set("Access-Control-Expose-Headers", "ETag")
			return
		}
		ctx.Response().Header.Set("Access-Control-Expose-Headers", existing+", ETag")
		return
	}

	metaList := make([]string, 0, len(metaNames))
	for k := range metaNames {
		metaList = append(metaList, k)
	}
	sort.Strings(metaList)

	toAdd := make([]string, 0, 1+len(metaList))
	if _, ok := lowerExisting["etag"]; !ok {
		toAdd = append(toAdd, "ETag")
		lowerExisting["etag"] = struct{}{}
	}
	for _, h := range metaList {
		lh := strings.ToLower(h)
		if _, ok := lowerExisting[lh]; ok {
			continue
		}
		toAdd = append(toAdd, h)
		lowerExisting[lh] = struct{}{}
	}
	if len(toAdd) == 0 {
		return
	}

	if existing == "" {
		ctx.Response().Header.Set("Access-Control-Expose-Headers", strings.Join(toAdd, ", "))
		return
	}
	ctx.Response().Header.Set("Access-Control-Expose-Headers", existing+", "+strings.Join(toAdd, ", "))
}

// Sets the response headers
func SetResponseHeaders(ctx *fiber.Ctx, headers map[string]*string) {
	if headers == nil {
		return
	}

	ctx.Response().Header.DisableNormalizing()
	for key, val := range headers {
		if val == nil || *val == "" {
			continue
		}
		ctx.Response().Header.Add(key, *val)
	}
}
