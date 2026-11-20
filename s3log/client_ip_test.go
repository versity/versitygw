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

package s3log

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/versity/versitygw/s3api/utils"
)

// TestFileLoggerRemoteIP verifies that the access log records the address
// resolved by the client IP middleware rather than the socket peer address.
func TestFileLoggerRemoteIP(t *testing.T) {
	logfile := filepath.Join(t.TempDir(), "access.log")
	logger, err := InitFileLogger(logfile)
	require.NoError(t, err)
	defer logger.Shutdown()

	app := fiber.New()
	app.Get("/", func(ctx fiber.Ctx) error {
		utils.ContextKeyClientIP.Set(ctx, "203.0.113.7")
		logger.Log(ctx, nil, nil, LogMeta{})
		return ctx.SendStatus(http.StatusNoContent)
	})

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/", nil))
	require.NoError(t, err)
	resp.Body.Close()

	content, err := os.ReadFile(logfile)
	require.NoError(t, err)
	assert.Contains(t, string(content), " 203.0.113.7 ")
}
