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

package middlewares

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/versity/versitygw/s3api/utils"
)

func TestRequestIDs(t *testing.T) {
	app := fiber.New()
	app.Use(RequestIDs())
	app.Get("/", func(ctx *fiber.Ctx) error {
		assert.NotEmpty(t, utils.RequestID(ctx))
		assert.NotEmpty(t, utils.HostID(ctx))
		return ctx.SendStatus(http.StatusNoContent)
	})

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/", nil))
	assert.NoError(t, err)

	requestID := resp.Header.Get(utils.HeaderAmzRequestID)
	hostID := resp.Header.Get(utils.HeaderAmzID2)

	assert.Regexp(t, regexp.MustCompile(`^[0-9A-Z]{16}$`), requestID)
	assert.NotEmpty(t, hostID)
	assert.NotEqual(t, requestID, hostID)
}
