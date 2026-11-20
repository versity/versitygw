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
	"encoding/base64"
	"regexp"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

func TestNewS3RequestID(t *testing.T) {
	id := NewS3RequestID()

	assert.Regexp(t, regexp.MustCompile(`^[0-9A-Z]{16}$`), id)
}

func TestNewS3HostID(t *testing.T) {
	id := NewS3HostID()

	decoded, err := base64.StdEncoding.DecodeString(id)
	assert.NoError(t, err)
	assert.Len(t, decoded, s3HostIDBytes)
}

func TestEnsureRequestIDs(t *testing.T) {
	ctx := fiber.New().AcquireCtx(&fasthttp.RequestCtx{})

	requestID, hostID := EnsureRequestIDs(ctx)
	requestIDAgain, hostIDAgain := EnsureRequestIDs(ctx)

	assert.Equal(t, requestID, requestIDAgain)
	assert.Equal(t, hostID, hostIDAgain)
	assert.Equal(t, requestID, RequestID(ctx))
	assert.Equal(t, hostID, HostID(ctx))
	assert.Equal(t, requestID, string(ctx.Response().Header.PeekCanonical([]byte(HeaderAmzRequestID))))
	assert.Equal(t, hostID, string(ctx.Response().Header.PeekCanonical([]byte(HeaderAmzID2))))
}

func TestEnsureRequestIDsNormalizingToggled(t *testing.T) {
	for _, disableFirst := range []bool{false, true} {
		ctx := fiber.New().AcquireCtx(&fasthttp.RequestCtx{})
		if disableFirst {
			ctx.Response().Header.DisableNormalizing()
		}
		EnsureRequestIDs(ctx)

		// flip the flag the way SetResponseHeaders does mid-request
		if disableFirst {
			ctx.Response().Header.EnableNormalizing()
		} else {
			ctx.Response().Header.DisableNormalizing()
		}
		EnsureRequestIDs(ctx)

		keys := map[string]int{}
		for k := range ctx.Response().Header.All() {
			if strings.HasPrefix(strings.ToLower(string(k)), "x-amz-") {
				keys[string(k)]++
			}
		}
		assert.Equal(t, map[string]int{HeaderAmzRequestID: 1, HeaderAmzID2: 1}, keys)
	}
}
