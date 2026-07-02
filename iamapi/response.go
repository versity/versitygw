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

package iamapi

import (
	"encoding/xml"
	"net/http"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/iamapi/internal/iammiddleware"
	"github.com/versity/versitygw/iamapi/types"
	"github.com/versity/versitygw/internal/httpctx"
)

var xmlhdr = []byte(xml.Header)

const (
	// HeaderAmznRequestID is the response header that carries the request ID.
	// Re-exported from iammiddleware so callers only need to import iamapi.
	HeaderAmznRequestID = iammiddleware.HeaderAmznRequestID
	maxXMLBodyLen       = 4 * 1024 * 1024
)

type Response struct {
	Data    types.ActionResponse
	Headers map[string]*string
	Status  int
}

type ActionHandler func(ctx fiber.Ctx) (*Response, error)

func ProcessHandlers(controller ActionHandler, handlers ...fiber.Handler) fiber.Handler {
	return func(ctx fiber.Ctx) error {
		if httpctx.ContextKeySkip.IsSet(ctx) {
			httpctx.ContextKeySkip.Delete(ctx)
			return ctx.Next()
		}

		for _, handler := range handlers {
			if err := handler(ctx); err != nil {
				return ProcessController(ctx, func(ctx fiber.Ctx) (*Response, error) {
					return &Response{}, err
				})
			}
		}

		return ProcessController(ctx, controller)
	}
}

func ProcessController(ctx fiber.Ctx, controller ActionHandler) error {
	response, err := controller(ctx)
	if response == nil {
		response = &Response{}
	}

	SetResponseHeaders(ctx, response.Headers)
	requestID := iammiddleware.EnsureRequestID(ctx)

	if err != nil {
		ctx.Response().Header.SetContentType(fiber.MIMEApplicationXML)

		if apiErr, ok := err.(iamerr.APIError); ok {
			return ctx.Status(apiErr.StatusCode()).Send(apiErr.XMLBody(requestID))
		}

		debuglogger.InternalError(err)
		internalErr := iamerr.GetAPIError(iamerr.ErrInternalFailure)
		return ctx.Status(internalErr.StatusCode()).Send(internalErr.XMLBody(requestID))
	}

	status := response.Status
	if status == 0 {
		status = http.StatusOK
	}

	if response.Data == nil {
		ctx.Status(status)
		return nil
	}

	response.Data.SetRequestID(requestID)

	responseBytes, err := xml.Marshal(response.Data)
	if err != nil {
		debuglogger.InternalError(err)
		internalErr := iamerr.GetAPIError(iamerr.ErrInternalFailure)
		ctx.Response().Header.SetContentType(fiber.MIMEApplicationXML)
		return ctx.Status(internalErr.StatusCode()).Send(internalErr.XMLBody(requestID))
	}

	msglen := len(xmlhdr) + len(responseBytes)
	if msglen > maxXMLBodyLen {
		debuglogger.Logf("XML encoded body len %v exceeds max len %v", msglen, maxXMLBodyLen)
		internalErr := iamerr.GetAPIError(iamerr.ErrInternalFailure)
		ctx.Response().Header.SetContentType(fiber.MIMEApplicationXML)
		return ctx.Status(internalErr.StatusCode()).Send(internalErr.XMLBody(requestID))
	}

	res := make([]byte, 0, msglen)
	res = append(res, xmlhdr...)
	res = append(res, responseBytes...)

	ctx.Response().Header.SetContentType(fiber.MIMEApplicationXML)
	ctx.Response().Header.SetContentLength(msglen)

	return ctx.Status(status).Send(res)
}

func SetResponseHeaders(ctx fiber.Ctx, headers map[string]*string) {
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
