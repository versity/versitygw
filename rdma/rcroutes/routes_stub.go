// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT ANY KIND, either express or implied.
// See the License for the specific language governing permissions
// and limitations under the License.

//go:build !(linux && amd64 && cgo)

// Package rcroutes serves the /.hipobj-rc control routes of the
// hipobj-rc-v2 two-phase transfer protocol. This file is a stub
// for platforms without RDMA support.
package rcroutes

import (
	"github.com/gofiber/fiber/v3"

	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3api/middlewares"
)

// Handler serves the three control routes (stub).
type Handler struct{}

// New builds a stub route handler; the routes answer 501.
func New(svc any, be backend.Backend, iam auth.IAMService,
	readonly, disableACL bool) *Handler {
	return &Handler{}
}

// Register mounts stub routes answering 501 Not Implemented.
func (h *Handler) Register(app *fiber.App, root middlewares.RootUserConfig,
	region string) {
	notImplemented := func(ctx fiber.Ctx) error {
		return fiber.NewError(fiber.StatusNotImplemented,
			"RDMA not supported on this platform")
	}
	app.Post("/.hipobj-rc/prepare", notImplemented)
	app.Post("/.hipobj-rc/ready", notImplemented)
	app.Post("/.hipobj-rc/cancel", notImplemented)
}
