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

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/s3api/debuglogger"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3event"
	"github.com/versity/versitygw/s3log"
)

var (
	xmlhdr = []byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
)

const (
	maxXMLBodyLen = 4 * 1024 * 1024
)

type MetaOptions struct {
	ContentLength int64
	Action        string
	BucketOwner   string
	ObjectSize    int64
	ObjectCount   int64
	EventName     s3event.EventType
	ObjectETag    *string
	VersionId     *string
	Status        int
}

type Response struct {
	Data     any
	Headers  map[string]*string
	MetaOpts *MetaOptions
}

type Handler func(ctx *fiber.Ctx) (*Response, error)

func ProcessResponse(handler Handler, s3logger s3log.AuditLogger, s3evnt s3event.S3EventSender, mm *metrics.Manager) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		// if skip locals is set, skip to the next rout handler
		if utils.ContextKeySkip.IsSet(ctx) {
			utils.ContextKeySkip.Delete(ctx)
			return ctx.Next()
		}

		response, err := handler(ctx)

		// Set the response headers
		SetResponseHeaders(ctx, response.Headers)

		opts := response.MetaOpts
		// Send the metrics
		if mm != nil {
			if opts.ObjectCount > 0 {
				mm.Send(ctx, err, opts.Action, opts.ObjectCount, opts.Status)
			} else {
				mm.Send(ctx, err, opts.Action, opts.ContentLength, opts.Status)
			}
		}
		// Handle the error case
		if err != nil {
			// Audit the error log
			if s3logger != nil {
				s3logger.Log(ctx, err, nil, s3log.LogMeta{
					Action:      opts.Action,
					BucketOwner: opts.BucketOwner,
					ObjectSize:  opts.ObjectSize,
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

		if opts.Status == 0 {
			opts.Status = http.StatusOK
		}

		// if no data payload is provided, send the response status
		if response.Data == nil {
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
				return err
			}

			if len(responseBytes) > 0 {
				ctx.Response().Header.Set("Content-Length", fmt.Sprint(len(responseBytes)))
				ctx.Response().Header.SetContentType(fiber.MIMEApplicationXML)
			}
		}

		if s3logger != nil {
			s3logger.Log(ctx, nil, responseBytes, s3log.LogMeta{
				Action:      opts.Action,
				BucketOwner: opts.BucketOwner,
				ObjectSize:  opts.ObjectSize,
			})
		}

		if s3evnt != nil {
			s3evnt.SendEvent(ctx, s3event.EventMeta{
				BucketOwner: opts.BucketOwner,
				ObjectSize:  opts.ObjectSize,
				ObjectETag:  opts.ObjectETag,
				VersionId:   opts.VersionId,
				EventName:   opts.EventName,
			})
		}

		if ok {
			if len(responseBytes) > 0 {
				ctx.Response().Header.Set("Content-Length", fmt.Sprint(len(responseBytes)))
			}

			return ctx.Send(responseBytes)
		}

		msglen := len(xmlhdr) + len(responseBytes)
		if msglen > maxXMLBodyLen {
			debuglogger.Logf("XML encoded body len %v exceeds max len %v",
				msglen, maxXMLBodyLen)
			ctx.Status(http.StatusInternalServerError)

			return ctx.Send(s3err.GetAPIErrorResponse(
				s3err.GetAPIError(s3err.ErrInternalError), "", "", ""))
		}
		res := make([]byte, 0, msglen)
		res = append(res, xmlhdr...)
		res = append(res, responseBytes...)

		return ctx.Send(res)
	}
}

func SetResponseHeaders(ctx *fiber.Ctx, headers map[string]*string) {
	if headers == nil {
		return
	}
	for key, val := range headers {
		if val == nil || *val == "" {
			continue
		}
		ctx.Response().Header.Add(key, *val)
	}
}

// Returns MethodNotAllowed for unmatched routes
func (c S3ApiController) HandleUnmatch(ctx *fiber.Ctx) (*Response, error) {
	return &Response{
		MetaOpts: &MetaOptions{
			Action: metrics.ActionUndetected,
		},
	}, s3err.GetAPIError(s3err.ErrMethodNotAllowed)
}
