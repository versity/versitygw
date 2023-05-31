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

package utils

import (
	"bytes"
	"errors"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
)

func GetUserMetaData(headers *fasthttp.RequestHeader) (metadata map[string]string) {
	metadata = make(map[string]string)
	headers.VisitAll(func(key, value []byte) {
		if strings.HasPrefix(string(key), "X-Amz-Meta-") {
			trimmedKey := strings.TrimPrefix(string(key), "X-Amz-Meta-")
			headerValue := string(value)
			metadata[trimmedKey] = headerValue
		}
	})

	return
}

func CreateHttpRequestFromCtx(ctx *fiber.Ctx) (*http.Request, error) {
	req := ctx.Request()

	httpReq, err := http.NewRequest(string(req.Header.Method()), req.URI().String(), bytes.NewReader(req.Body()))
	if err != nil {
		return nil, errors.New("error in creating an http request")
	}

	// Set the request headers
	req.Header.VisitAll(func(key, value []byte) {
		keyStr := string(key)
		if keyStr == "X-Amz-Date" || keyStr == "X-Amz-Content-Sha256" || keyStr == "Host" {
			httpReq.Header.Add(keyStr, string(value))
		}
	})

	// Set the Content-Length header
	httpReq.ContentLength = int64(len(req.Body()))

	// Set the Host header
	httpReq.Host = string(req.Header.Host())

	return httpReq, nil
}
