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

// Package cumiddleware provides Fiber middleware for cuObject RDMA descriptor
// extraction. The middleware reads cuObject-specific HTTP headers and stores
// them as fasthttp user-values so the backend can detect RDMA-accelerated
// requests.
//
// Important: versitygw passes ctx.RequestCtx() (*fasthttp.RequestCtx) to the
// backend, not the fiber.Ctx or any context.WithValue wrapper. Values must
// therefore be stored via RequestCtx.SetUserValue (string key) so that
// context.Context.Value(stringKey) retrieves them correctly.

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"

	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
)

// String keys used for fasthttp user-value storage.
// Must be string constants so *fasthttp.RequestCtx.Value(key) finds them.
const (
	localKeyRDMADescr       = "cuobj.rdma.descr"
	localKeyRDMASize        = "cuobj.rdma.size"
	localKeyRDMARemoteStart = "cuobj.rdma.remote_start"
)

// Header names used by the cuObject client to pass RDMA descriptor info.
//
// HeaderRDMADescr/HeaderRDMASize/HeaderRDMARemoteAddr are a legacy 3-header
// scheme used only by this repo's own test tools (cmd/cuobjtest,
// cmd/rdmatest). The real cuObject/minio-cpp SDK does not send these; it
// sends a single combined HeaderRDMAToken instead. Both schemes are
// supported so existing test tooling keeps working.
const (
	HeaderRDMADescr      = "X-CuObj-RDMA-Descr"
	HeaderRDMASize       = "X-CuObj-Content-Length"
	HeaderRDMARemoteAddr = "X-CuObj-Remote-Buf-Start"

	// HeaderRDMAToken is the single combined header sent by the real
	// cuObject client SDK (e.g. minio-cpp). Its value is a colon-delimited
	// token per the cuObj RDMA descriptor protocol. The whole token is
	// passed through verbatim to the RDMA backend as the descriptor.
	//
	// This is the canonical definition of the wire format; the encoder in
	// cuwrapper/rdma_host_client_wrapper.cpp (build_token) must stay in
	// sync with it. Fields, in order, colon-delimited, lowercase hex:
	//
	//   # | Field                                  | Type     | Width
	//   --|-----------------------------------------|----------|-----------
	//   1 | Remote base address (GPUMEM/SYSMEM)      | uint64   | 16 chars
	//   2 | Max size of buffer region from base addr | uint32   | 8 chars
	//   3 | Remote key (rkey)                        | uint32   | 8 chars
	//   4 | LID of the client NIC                    | uint16   | 4 chars
	//   5 | DCTN                                     | uint32   | 6 chars
	//   6 | GID present (1|0)                        | bool     | 1 char
	//   7 | GID of client NIC                        | 16 bytes | 32 chars
	//
	// Example: "0102030405060708:01020304:01020304:0102:010203:1:0102030405060708090a0b0c0d0e0f10"
	HeaderRDMAToken = "X-Amz-Rdma-Token"

	// HeaderRDMAReply is the response header sent after a successful
	// RDMA-offloaded PUT/GET, per NVIDIA's documented cuObject workflow:
	// "If the transfer is successfully offloaded to RDMA, the proxy responds
	// with x-amz-rdma-reply." This implementation carries a numeric RDMA
	// status code (e.g. HTTP-style 200/204/206 success classes) and is set
	// only after the RDMA operation has actually succeeded.
	HeaderRDMAReply = "X-Amz-Rdma-Reply"

	// HeaderRDMABytesTransferred is the statistics header documented
	// alongside HeaderRDMAToken/HeaderRDMAReply ("x-amz-rdma-bytes-transferred
	// (for statistics)"). This header carries the numeric transferred-byte
	// count and is set together with HeaderRDMAReply — see SetRDMAReplyHeader.
	HeaderRDMABytesTransferred = "X-Amz-Rdma-Bytes-Transferred"
)

// CuObjMiddleware extracts cuObject RDMA headers and stores them in
// the fasthttp request context so the backend can retrieve them via the
// GetRDMA* helper functions.
//
// If neither the legacy descriptor header nor the combined RDMA token
// header is present, the request passes through unchanged — the backend
// will use the normal (non-RDMA) code path.
//
// If a descriptor is present but required fields are malformed, a 400 Bad
// Request is returned immediately.
func CuObjMiddleware(ctx fiber.Ctx) error {
	descr := ctx.Get(HeaderRDMADescr)
	token := ctx.Get(HeaderRDMAToken)
	if descr == "" && token == "" {
		return ctx.Next()
	}

	// Store directly on the underlying fasthttp RequestCtx so values survive
	// the ctx.RequestCtx() call the versitygw controller uses to invoke the backend.
	rctx := ctx.RequestCtx()

	if descr != "" {
		// Legacy 3-header scheme.
		rctx.SetUserValue(localKeyRDMADescr, descr)

		if sizeStr := ctx.Get(HeaderRDMASize); sizeStr != "" {
			size, err := strconv.ParseInt(sizeStr, 10, 64)
			if err != nil || size <= 0 {
				return fiber.NewError(fiber.StatusBadRequest,
					HeaderRDMASize+": must be a positive integer")
			}
			rctx.SetUserValue(localKeyRDMASize, size)
		}

		if addrStr := ctx.Get(HeaderRDMARemoteAddr); addrStr != "" {
			addr, err := strconv.ParseUint(addrStr, 10, 64)
			if err != nil {
				return fiber.NewError(fiber.StatusBadRequest,
					HeaderRDMARemoteAddr+": must be a non-negative integer")
			}
			rctx.SetUserValue(localKeyRDMARemoteStart, addr)
		}

		return ctx.Next()
	}

	// Combined token scheme (real cuObject client SDK). The descriptor
	// passed to the RDMA backend is the raw token string; the remote base
	// address is parsed from the token's first field, and the transfer size
	// normally comes from the standard Content-Length header (RDMA replaces
	// only the HTTP body, not the usual Content-Length semantics). A genuine
	// RDMA control request can legitimately carry no HTTP body at all, in
	// which case Content-Length is 0/absent; fall back to the token's own
	// registered-buffer-size field (already part of the documented wire
	// format) rather than leaving the backend with no usable size.
	//
	// Fixed-width binary RC token schemes (e.g. AMD hipObject's 88-hex-char
	// token) are structurally incompatible with this gateway's DC transport.
	// Reject them with 501 instead of a 400 parse error so such clients can
	// fall back to the HTTP data path: they treat a response without
	// x-amz-rdma-reply as "RDMA not supported", so the reply header is
	// deliberately left unset. The error is serialized and sent directly
	// (terminal response) because the global error handler collapses
	// non-fiber errors into 500.
	if isRCTokenScheme(token) {
		requestID, hostID := utils.EnsureRequestIDs(ctx)
		err := s3err.GetNotImplementedErr(HeaderRDMAToken, "")
		ctx.Response().Header.SetContentType(fiber.MIMEApplicationXML)
		ctx.Status(err.HTTPStatusCode)
		return ctx.Send(err.XMLBody(requestID, hostID))
	}

	rctx.SetUserValue(localKeyRDMADescr, token)

	remoteStart, err := parseRDMATokenBaseAddr(token)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, HeaderRDMAToken+": "+err.Error())
	}
	rctx.SetUserValue(localKeyRDMARemoteStart, remoteStart)

	if size := rctx.Request.Header.ContentLength(); size > 0 {
		rctx.SetUserValue(localKeyRDMASize, int64(size))
	} else if bufSize, err := parseRDMATokenBufferSize(token); err == nil && bufSize > 0 {
		rctx.SetUserValue(localKeyRDMASize, int64(bufSize))
	}

	return ctx.Next()
}

// isHexDigit reports whether c is an ASCII hexadecimal digit.
func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
		(c >= 'A' && c <= 'F')
}

// isRCTokenScheme reports whether the token's first colon-delimited field
// is longer than any cuObject base address can be: a cuObject base address
// is a hex-encoded uint64 (at most 16 hex chars, see the token layout
// comment above), while fixed-width binary RC token schemes such as AMD
// hipObject's (44-byte payload hex-encoded to 88 chars, optionally
// suffixed ":addr:size") always exceed it. Non-hex first fields are left
// to the regular cuObject parsing, which reports them as malformed.
// Note this deliberately reclassifies 17+-char non-canonical hex values
// (e.g. leading zeros) as unsupported; well-formed cuObject tokens are
// unaffected.
func isRCTokenScheme(token string) bool {
	i := strings.IndexByte(token, ':')
	first := token
	if i >= 0 {
		first = token[:i]
	}
	if len(first) <= 16 {
		return false
	}
	for j := 0; j < len(first); j++ {
		if !isHexDigit(first[j]) {
			return false
		}
	}
	return true
}

// parseRDMATokenBaseAddr extracts the remote base address — the first
// colon-delimited field, a hex-encoded uint64 — from a cuObj RDMA token.
func parseRDMATokenBaseAddr(token string) (uint64, error) {
	i := 0
	for i < len(token) && token[i] != ':' {
		i++
	}
	if i == 0 || i == len(token) {
		return 0, errors.New("malformed RDMA token: missing base address field")
	}
	addr, err := strconv.ParseUint(token[:i], 16, 64)
	if err != nil {
		return 0, fmt.Errorf("malformed RDMA token base address: %w", err)
	}
	return addr, nil
}

// parseRDMATokenBufferSize extracts the registered buffer size — the second
// colon-delimited field, a hex-encoded uint32 — from a cuObj RDMA token. Used
// as a size fallback when the request has no positive Content-Length.
func parseRDMATokenBufferSize(token string) (uint32, error) {
	fields := strings.SplitN(token, ":", 3)
	if len(fields) < 2 || fields[1] == "" {
		return 0, errors.New("malformed RDMA token: missing buffer size field")
	}
	size, err := strconv.ParseUint(fields[1], 16, 32)
	if err != nil {
		return 0, fmt.Errorf("malformed RDMA token buffer size: %w", err)
	}
	return uint32(size), nil
}

// GetRDMADescriptor retrieves the RDMA descriptor from the context.
// Returns ("", false) if the request is not an RDMA-accelerated request.
func GetRDMADescriptor(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(localKeyRDMADescr).(string)
	return v, ok && v != ""
}

// GetRDMASize retrieves the RDMA content length from the context.
func GetRDMASize(ctx context.Context) (int64, bool) {
	v, ok := ctx.Value(localKeyRDMASize).(int64)
	return v, ok
}

// GetRDMARemoteStart retrieves the remote buffer start address from the context.
// Defaults to 0 if not set.
func GetRDMARemoteStart(ctx context.Context) uint64 {
	v, _ := ctx.Value(localKeyRDMARemoteStart).(uint64)
	return v
}

// SetRDMAReplyHeader sets the HeaderRDMAReply (status code) and
// HeaderRDMABytesTransferred (byte count) response headers, signaling to the
// client that the transfer was completed via RDMA rather than the HTTP body.
// Call only after the RDMA transfer has actually succeeded. ctx must be the
// same *fasthttp.RequestCtx handed to the backend by versitygw; it is a no-op
// otherwise (e.g. in unit tests without an HTTP layer).
func SetRDMAReplyHeader(ctx context.Context, rdmaStatus int, transferredBytes int64) {
	rctx, ok := ctx.(*fasthttp.RequestCtx)
	if !ok {
		return
	}
	rctx.Response.Header.Set(HeaderRDMAReply, strconv.Itoa(rdmaStatus))
	rctx.Response.Header.Set(HeaderRDMABytesTransferred, strconv.FormatInt(transferredBytes, 10))
}

// InjectRDMAContext returns a copy of ctx with RDMA descriptor values set.
// This bypasses the Fiber middleware and is intended for testing and direct
// backend invocation without an HTTP layer.
func InjectRDMAContext(ctx context.Context, descr string, size int64, remoteStart uint64) context.Context {
	//lint:ignore SA1029 string keys required for fasthttp RequestCtx cross-package value lookup
	ctx = context.WithValue(ctx, localKeyRDMADescr, descr)
	//lint:ignore SA1029 string keys required for fasthttp RequestCtx cross-package value lookup
	ctx = context.WithValue(ctx, localKeyRDMASize, size)
	//lint:ignore SA1029 string keys required for fasthttp RequestCtx cross-package value lookup
	ctx = context.WithValue(ctx, localKeyRDMARemoteStart, remoteStart)
	return ctx
}
