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

// Admin session snapshot route for the RC data plane.
//go:build linux && amd64 && cgo

package rcroutes

import (
	"github.com/gofiber/fiber/v3"

	"github.com/versity/versitygw/rdma/rcserver"
)

// AdminSnapshot serves the RC session snapshot on the admin surface.
// The route is registered only when the RC plane is enabled and the
// standalone admin server runs; middleware before it has already
// verified the admin signature and role.
func (h *Handler) AdminSnapshot(ctx fiber.Ctx) error {
	sessions, err := h.svc.SessionsSnapshot()
	if err != nil {
		return WriteRouteError(ctx, mapRcError(err))
	}
	type sessionRecord struct {
		SessionID    string `json:"session_id"`
		Op           string `json:"op"`
		Target       string `json:"target"`
		State        string `json:"state"`
		ReapPending  bool   `json:"reap_pending"`
		AgeMs        uint64 `json:"age_ms"`
		StagingBytes uint64 `json:"staging_bytes"`
	}
	stateNames := map[uint8]string{
		rcserver.SnapshotStatePrepared:     "prepared",
		rcserver.SnapshotStatePublishing:   "publishing",
		rcserver.SnapshotStateTransferring: "transferring",
		rcserver.SnapshotStateCompleting:   "completing",
		rcserver.SnapshotStateReaping:      "reaping",
	}
	out := make([]sessionRecord, 0, len(sessions))
	for _, s := range sessions {
		name, ok := stateNames[s.State]
		if !ok {
			name = "unknown"
		}
		out = append(out, sessionRecord{
			SessionID:    s.SessionID,
			Op:           s.Op,
			Target:       s.Target,
			State:        name,
			ReapPending:  s.ReapPending,
			AgeMs:        s.AgeMs,
			StagingBytes: s.StagingBytes,
		})
	}
	return ctx.JSON(fiber.Map{"sessions": out})
}
