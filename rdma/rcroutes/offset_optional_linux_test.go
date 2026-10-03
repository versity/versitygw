// Copyright 2026 Versity Software
// Copyright 2026 Gluesys Inc. and Jihyeon Gim
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an "AS
// IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied.  See the License for the specific language
// governing permissions and limitations under the License.

//go:build linux && amd64 && cgo && rdma

package rcroutes

import (
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v3"

	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/rdma/rcserver"
	"github.com/versity/versitygw/s3api/utils"
)

// The offset header is optional: clients omit it whenever the
// transfer starts at zero, so an omitted header, an explicit zero,
// and a malformed value must be told apart. The first two must
// reach the session server with the same offset; only the third
// rejects with 400.
func TestPrepareOffsetHeaderOptional(t *testing.T) {
	// An offset-capturing service records what the route parsed.
	captured := []uint64{}
	svc := &offsetCapService{fixedService: newFixedService(), seen: &captured}
	h := &Handler{svc: svc, be: &fakeBackend{}, mpMaxParts: 100,
		ops: newOpsTracker(0)}

	// Omitted header: runPrepare posts without x-amz-rdma-offset.
	if code := runPrepareNoOffset(t, h, nil); code != 200 {
		t.Fatalf("omitted offset status = %d, want 200", code)
	}
	// Explicit zero still passes through the same path.
	if code := runPrepareNoOffset(t, h, map[string]string{"x-amz-rdma-offset": "0"}); code != 200 {
		t.Fatalf("explicit zero offset status = %d, want 200", code)
	}
	if len(captured) != 2 || captured[0] != 0 || captured[1] != 0 {
		t.Fatalf("captured offsets = %v, want [0 0]", captured)
	}

	// A malformed non-empty value still rejects with 400.
	if code := runPrepareNoOffset(t, h, map[string]string{"x-amz-rdma-offset": "not-a-number"}); code != 400 {
		t.Fatalf("malformed offset status = %d, want 400", code)
	}
	if len(captured) != 2 {
		t.Fatalf("malformed offset reached the session server: %v", captured)
	}
}

// runPrepareNoOffset posts a PREPARE without x-amz-rdma-offset,
// applying overrides on top (an override can add the header back).
func runPrepareNoOffset(t *testing.T, h *Handler, overrides map[string]string) int {
	t.Helper()
	app := fiber.New()
	app.Post("/.hipobj-rc/prepare", func(c fiber.Ctx) error {
		utils.ContextKeyAccount.Set(c, auth.Account{Access: "ak"})
		utils.ContextKeyIsRoot.Set(c, true)
		return h.Prepare(c)
	})
	req, _ := http.NewRequest(fiber.MethodPost, "/.hipobj-rc/prepare", nil)
	base := map[string]string{
		"x-amz-rdma-protocol": "hipobj-rc-v2",
		"x-amz-rdma-op":       "PUT",
		"x-amz-rdma-target":   "/bkt/obj",
		"x-amz-rdma-size":     "64",
		"x-amz-rdma-psn":      "00000f",
		"x-amz-rdma-cookie":   "01020304",
	}
	for k, v := range overrides {
		base[k] = v
	}
	for k, v := range base {
		req.Header.Set(k, v)
	}
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	return resp.StatusCode
}

// offsetCapService records the offset of every Prepare it serves.
type offsetCapService struct {
	*fixedService
	seen *[]uint64
}

func (o *offsetCapService) Prepare(req rcserver.PrepareRequest) (*rcserver.PrepareResponse, error) {
	*o.seen = append(*o.seen, req.Offset)
	return &rcserver.PrepareResponse{
		SessionID: "0123456789abcdef0123456789abcdef",
		ServerPsn: 7,
	}, nil
}

func (o *offsetCapService) FinishPrepare(sessionID string, ok bool) error {
	return nil
}
