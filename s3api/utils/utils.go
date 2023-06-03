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
		if includeHeader(keyStr) {
			httpReq.Header.Add(keyStr, string(value))
		}
	})

	// Content-Length header ignored for signing
	httpReq.ContentLength = 0

	// Set the Host header
	httpReq.Host = string(req.Header.Host())

	return httpReq, nil
}

func includeHeader(hdr string) bool {
	switch {
	case strings.EqualFold(hdr, "Cache-Control"):
		return true
	case strings.EqualFold(hdr, "Content-Disposition"):
		return true
	case strings.EqualFold(hdr, "Content-Encoding"):
		return true
	case strings.EqualFold(hdr, "Content-Language"):
		return true
	case strings.EqualFold(hdr, "Content-Md5"):
		return true
	case strings.EqualFold(hdr, "Content-Type"):
		return true
	case strings.EqualFold(hdr, "Expires"):
		return true
	case strings.EqualFold(hdr, "If-Match"):
		return true
	case strings.EqualFold(hdr, "If-Modified-Since"):
		return true
	case strings.EqualFold(hdr, "If-None-Match"):
		return true
	case strings.EqualFold(hdr, "If-Unmodified-Since"):
		return true
	case strings.EqualFold(hdr, "Range"):
		return true
	case strings.EqualFold(hdr, "X-Amz-Acl"):
		return true
	case strings.EqualFold(hdr, "X-Amz-Copy-Source"):
		return true
	case strings.EqualFold(hdr, "X-Amz-Copy-Source-If-Match"):
		return true
	case strings.EqualFold(hdr, "X-Amz-Copy-Source-If-Modified-Since"):
		return true
	case strings.EqualFold(hdr, "X-Amz-Copy-Source-If-None-Match"):
		return true
	case strings.EqualFold(hdr, "X-Amz-Copy-Source-If-Unmodified-Since"):
		return true
	case strings.EqualFold(hdr, "X-Amz-Copy-Source-Range"):
		return true
	case strings.EqualFold(hdr, "X-Amz-Copy-Source-Server-Side-Encryption-Customer-Algorithm"):
		return true
	case strings.EqualFold(hdr, "X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key"):
		return true
	case strings.EqualFold(hdr, "X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key-Md5"):
		return true
	case strings.EqualFold(hdr, "X-Amz-Grant-Full-control"):
		return true
	case strings.EqualFold(hdr, "X-Amz-Grant-Read"):
		return true
	case strings.EqualFold(hdr, "X-Amz-Grant-Read-Acp"):
		return true
	case strings.EqualFold(hdr, "X-Amz-Grant-Write"):
		return true
	case strings.EqualFold(hdr, "X-Amz-Grant-Write-Acp"):
		return true
	case strings.EqualFold(hdr, "X-Amz-Metadata-Directive"):
		return true
	case strings.EqualFold(hdr, "X-Amz-Mfa"):
		return true
	case strings.EqualFold(hdr, "X-Amz-Request-Payer"):
		return true
	case strings.EqualFold(hdr, "X-Amz-Server-Side-Encryption"):
		return true
	case strings.EqualFold(hdr, "X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id"):
		return true
	case strings.EqualFold(hdr, "X-Amz-Server-Side-Encryption-Customer-Algorithm"):
		return true
	case strings.EqualFold(hdr, "X-Amz-Server-Side-Encryption-Customer-Key"):
		return true
	case strings.EqualFold(hdr, "X-Amz-Server-Side-Encryption-Customer-Key-Md5"):
		return true
	case strings.EqualFold(hdr, "X-Amz-Storage-Class"):
		return true
	case strings.EqualFold(hdr, "X-Amz-Website-Redirect-Location"):
		return true
	case strings.EqualFold(hdr, "X-Amz-Content-Sha256"):
		return true
	case strings.EqualFold(hdr, "X-Amz-Tagging"):
		return true
	case strings.HasPrefix(hdr, "X-Amz-Object-Lock-"):
		return true
	case strings.HasPrefix(hdr, "X-Amz-Meta-"):
		return true
	default:
		return false
	}
}
