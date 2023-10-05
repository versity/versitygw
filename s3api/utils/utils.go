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
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
	"github.com/versity/versitygw/s3err"
)

var (
	bucketNameRegexp   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]+[a-z0-9]$`)
	bucketNameIpRegexp = regexp.MustCompile(`^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$`)
)

func GetUserMetaData(headers *fasthttp.RequestHeader) (metadata map[string]string) {
	metadata = make(map[string]string)
	headers.DisableNormalizing()
	headers.VisitAllInOrder(func(key, value []byte) {
		hKey := string(key)
		if strings.HasPrefix(strings.ToLower(hKey), "x-amz-meta-") {
			trimmedKey := hKey[11:]
			headerValue := string(value)
			metadata[trimmedKey] = headerValue
		}
	})
	headers.EnableNormalizing()

	return
}

func CreateHttpRequestFromCtx(ctx *fiber.Ctx, signedHdrs []string) (*http.Request, error) {
	req := ctx.Request()

	httpReq, err := http.NewRequest(string(req.Header.Method()), req.URI().String(), bytes.NewReader(req.Body()))
	if err != nil {
		return nil, errors.New("error in creating an http request")
	}

	// Set the request headers
	req.Header.VisitAll(func(key, value []byte) {
		keyStr := string(key)
		if includeHeader(keyStr, signedHdrs) {
			httpReq.Header.Add(keyStr, string(value))
		}
	})

	// Check if Content-Length in signed headers
	// If content length is non 0, then the header will be included
	if !includeHeader("Content-Length", signedHdrs) {
		httpReq.ContentLength = 0
	}

	// Set the Host header
	httpReq.Host = string(req.Header.Host())

	return httpReq, nil
}

func SetMetaHeaders(ctx *fiber.Ctx, meta map[string]string) {
	ctx.Response().Header.DisableNormalizing()
	for key, val := range meta {
		ctx.Response().Header.Set(fmt.Sprintf("X-Amz-Meta-%s", key), val)
	}
	ctx.Response().Header.EnableNormalizing()
}

func ParseUint(str string) (int32, error) {
	if str == "" {
		return 1000, nil
	}
	num, err := strconv.ParseUint(str, 10, 16)
	if err != nil {
		return 1000, s3err.GetAPIError(s3err.ErrInvalidMaxKeys)
	}
	return int32(num), nil
}

type CustomHeader struct {
	Key   string
	Value string
}

func SetResponseHeaders(ctx *fiber.Ctx, headers []CustomHeader) {
	for _, header := range headers {
		ctx.Set(header.Key, header.Value)
	}
}

func IsValidBucketName(bucket string) bool {
	if len(bucket) < 3 || len(bucket) > 63 {
		return false
	}
	// Checks to contain only digits, lowercase letters, dot, hyphen.
	// Checks to start and end with only digits and lowercase letters.
	if !bucketNameRegexp.MatchString(bucket) {
		return false
	}
	// Checks not to be a valid IP address
	if bucketNameIpRegexp.MatchString(bucket) {
		return false
	}
	return true
}

func includeHeader(hdr string, signedHdrs []string) bool {
	for _, shdr := range signedHdrs {
		if strings.EqualFold(hdr, shdr) {
			return true
		}
	}
	return false
}
