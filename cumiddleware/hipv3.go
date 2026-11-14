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

package cumiddleware

import (
	"context"
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v3"

	"github.com/versity/versitygw/rdma/rcdial"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
)

// HeaderRDMAv3Token is the header a hipobj-rc-v3 client carries on a
// GetObject or PutObject (UploadPart) request. Its value names the
// client's RDMA CM listener and the memory region of the transfer
// (see rcdial.Token for the wire form). The name deliberately
// differs from the cuObject X-Amz-Rdma-Token: the two schemes never
// share a header.
const HeaderRDMAv3Token = "x-amz-rc-rdma-token"

// HeaderRDMAv3Reply is set on a response whose data moved over RDMA:
// "<httpStatus>:<bytesTransferred-hex16>". It is set only on success;
// failures keep their normal S3 error bodies without it.
const HeaderRDMAv3Reply = "x-amz-rc-rdma-reply"

// User-value keys, string constants so *fasthttp.RequestCtx.Value
// finds them after the controller hands the request context to the
// backend.
const (
	localKeyV3Descriptor = "hipv3.rdma.descriptor"
)

// GetV3Descriptor returns the parsed v3 token of the request behind
// ctx (the backend receives the *fasthttp.RequestCtx, whose Value
// exposes the user values the middleware set), if any.
func GetV3Descriptor(ctx context.Context) (rcdial.Token, bool) {
	if ctx == nil {
		return rcdial.Token{}, false
	}
	v := ctx.Value(localKeyV3Descriptor)
	if v == nil {
		return rcdial.Token{}, false
	}
	t, ok := v.(rcdial.Token)
	return t, ok
}

// sameOperationParams lists, per method, the query parameters that
// select input of the SAME operation and therefore keep a request on
// the v3 path. Anything else (acl, tagging, uploads, ...) selects a
// different operation and the middleware passes the request through
// untouched.
var sameOperationParams = map[string]map[string]bool{
	"GET": {"versionId": true},
	"PUT": {"uploadId": true, "partNumber": true},
}

// isObjectPath reports whether the URL path names an object (at
// least one segment after the bucket); bucket-level operations like
// GET /bucket or PUT /bucket stay off the v3 path.
func isObjectPath(path string) bool {
	trimmed := strings.Trim(path, "/")
	return strings.Contains(trimmed, "/")
}

// RDMAv3Middleware extracts the hipobj-rc-v3 token. Without the
// header, or when the query selects another operation, the request
// passes through unchanged. With a malformed token the middleware
// answers 400 directly (terminal response: the global error handler
// collapses ordinary fiber errors into 500). The middleware never
// rewrites the request: SigV4 verification sees the original bytes.
func RDMAv3Middleware(ctx fiber.Ctx) error {
	token := ctx.Get(HeaderRDMAv3Token)
	if token == "" {
		return ctx.Next()
	}
	if !isObjectPath(ctx.Path()) {
		return ctx.Next()
	}
	method := ctx.Method()
	allowed := sameOperationParams[method]
	if allowed == nil {
		return ctx.Next()
	}
	for name := range ctx.Queries() {
		if !allowed[name] {
			return ctx.Next()
		}
	}
	parsed, err := rcdial.ParseToken(token)
	if err != nil {
		s3e := s3err.InvalidArgumentError{
			ArgumentName:  HeaderRDMAv3Token,
			ArgumentValue: fmt.Sprintf("%q: %v", truncToken(token), err),
			Description:   "The x-amz-rc-rdma-token header is not a valid hipobj-rc-v3 token",
		}
		requestID, hostID := utils.EnsureRequestIDs(ctx)
		ctx.Response().Header.SetContentType(fiber.MIMEApplicationXML)
		ctx.Status(s3e.StatusCode())
		return ctx.Send(s3e.XMLBody(requestID, hostID))
	}
	ctx.RequestCtx().SetUserValue(localKeyV3Descriptor, parsed)
	return ctx.Next()
}

// truncToken keeps the error response bounded when the header is
// garbage of arbitrary length.
func truncToken(s string) string {
	const max = 64
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
