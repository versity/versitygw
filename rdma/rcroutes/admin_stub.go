// Copyright 2026 Versity Software
// Copyright 2026 Gluesys Inc. and Jihyeon Gim
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

// Admin session snapshot route (stub for platforms without RDMA
// support).
//go:build !(linux && amd64 && cgo)

package rcroutes

import (
	"errors"

	"github.com/gofiber/fiber/v3"
)

// AdminSnapshot is a stub; the route is never registered without the
// RC data plane.
func (h *Handler) AdminSnapshot(ctx fiber.Ctx) error {
	return fiber.NewError(fiber.StatusNotFound,
		errors.New("rdma rc data plane not available").Error())
}
