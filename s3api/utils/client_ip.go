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

package utils

import (
	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/internal/clientip"
)

// Re-exports for the S3 callers, which have always reached these through
// s3api/utils. The implementation is in internal/clientip so the standalone
// IAM and WebUI packages can use it without importing the S3 side.
type TrustedProxies = clientip.TrustedProxies

const (
	ClientIPHeaderForwardedFor = clientip.ClientIPHeaderForwardedFor
	ClientIPHeaderRealIP       = clientip.ClientIPHeaderRealIP
)

// ClientIPTag is clientip.Tag for the S3 loggers.
var ClientIPTag = clientip.Tag

func NormalizeClientIPHeader(header string) (string, error) {
	return clientip.NormalizeClientIPHeader(header)
}

func ParseTrustedProxies(list string) (TrustedProxies, error) {
	return clientip.ParseTrustedProxies(list)
}

func ClientIP(ctx fiber.Ctx) string {
	return clientip.ClientIP(ctx)
}

// ClientIPMiddleware is clientip.Middleware for the S3 and website servers.
func ClientIPMiddleware(header string, trusted TrustedProxies) fiber.Handler {
	return clientip.Middleware(header, trusted)
}
