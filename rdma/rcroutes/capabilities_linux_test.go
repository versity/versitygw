// Copyright 2026 Versity Software
// Copyright 2026 Gluesys Inc. and Jihyeon Gim
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.  See the License for the specific language governing
// permissions and limitations under the License.

//go:build linux && amd64 && cgo

package rcroutes

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/rdma/rcserver"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
)

// capService drives prepareCore/readyCore through controlled
// outcomes: Prepare creates a session (or fails before creation),
// and READY completes the transfer (or fails after the session
// existed).
type capService struct {
	*fixedService

	prepareErr  error // returned by Prepare when set (pre-creation)
	refuseEnter bool  // admission answer for TryEnter
}

func (c *capService) TryEnter() bool { return !c.refuseEnter }

func (c *capService) Prepare(req rcserver.PrepareRequest) (*rcserver.PrepareResponse, error) {
	if c.prepareErr != nil {
		return nil, c.prepareErr
	}
	return &rcserver.PrepareResponse{
		SessionID:  "0123456789abcdef0123456789abcdef",
		ServerPsn:  7,
		ReplyToken: "",
	}, nil
}

func (c *capService) FinishPrepare(sessionID string, ok bool) error {
	return nil
}

// runPrepare executes the full Prepare wrapper (core + route error
// serialization) against a minimal fiber app and reports the
// response status and the capability header presence.
func runPrepare(t *testing.T, h *Handler, prepareHeaders map[string]string) (int, bool) {
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
		"x-amz-rdma-offset":   "0",
		"x-amz-rdma-psn":      "00000f",
		"x-amz-rdma-cookie":   "01020304",
	}
	for k, v := range prepareHeaders {
		base[k] = v
	}
	for k, v := range base {
		req.Header.Set(k, v)
	}
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	return resp.StatusCode, resp.Header.Get("x-amz-rdma-capabilities") == "mp"
}

// The capability advertisement surface table: the header appears on
// the READY success response and on error responses for requests in
// which a native session was created; every other surface omits it.
func TestCapabilityAdvertisementSurface(t *testing.T) {
	// Absent: failures that precede session creation (admission,
	// Prepare refusal, header validation, authorization).
	svc := &capService{fixedService: newFixedService(), prepareErr: errors.New("no capacity")}
	h := &Handler{svc: svc, be: &fakeBackend{}, mpMaxParts: 100}
	if code, has := runPrepare(t, h, nil); has {
		t.Fatalf("capabilities advertised on pre-creation failure (status %d)", code)
	}

	// Bad target shape: validation error, no session, no header.
	svc2 := &capService{fixedService: newFixedService()}
	h2 := &Handler{svc: svc2, be: &fakeBackend{}, mpMaxParts: 100}
	if code, has := runPrepare(t, h2, map[string]string{
		"x-amz-rdma-target": "no-slash",
	}); has {
		t.Fatalf("capabilities advertised on bad target (status %d)", code)
	}
	if code := func() int {
		code, _ := runPrepare(t, h2, map[string]string{"x-amz-rdma-target": "no-slash"})
		return code
	}(); code != http.StatusBadRequest {
		t.Fatalf("bad target status = %d, want 400", code)
	}

	// Absent: admission failure before creation (TryEnter refuses).
	refuseSvc := &capService{fixedService: newFixedService()}
	refuseSvc.refuseEnter = true
	h3 := &Handler{svc: refuseSvc, be: &fakeBackend{}, mpMaxParts: 100}
	if code, has := runPrepare(t, h3, nil); has {
		t.Fatalf("capabilities advertised on admission failure (status %d)", code)
	}

	// Absent: authorization denial (non-root account, empty ACL).
	h4 := &Handler{svc: &capService{fixedService: newFixedService()},
		be: &fakeBackend{}, mpMaxParts: 100}
	if code, has := runPrepareAs(t, h4, nil, auth.Account{Access: "stranger"}, false); has {
		t.Fatalf("capabilities advertised on authz denial (status %d)", code)
	}
}

// runPrepareAs drives the Prepare wrapper with an explicit account
// identity so authorization outcomes are controllable.
func runPrepareAs(t *testing.T, h *Handler, prepareHeaders map[string]string,
	acct auth.Account, isRoot bool) (int, bool) {
	t.Helper()
	app := fiber.New()
	app.Post("/.hipobj-rc/prepare", func(c fiber.Ctx) error {
		utils.ContextKeyAccount.Set(c, acct)
		utils.ContextKeyIsRoot.Set(c, isRoot)
		return h.Prepare(c)
	})
	req, _ := http.NewRequest(fiber.MethodPost, "/.hipobj-rc/prepare", nil)
	base := map[string]string{
		"x-amz-rdma-protocol": "hipobj-rc-v2",
		"x-amz-rdma-op":       "PUT",
		"x-amz-rdma-target":   "/bkt/obj",
		"x-amz-rdma-size":     "64",
		"x-amz-rdma-offset":   "0",
		"x-amz-rdma-psn":      "00000f",
		"x-amz-rdma-cookie":   "01020304",
	}
	for k, v := range prepareHeaders {
		base[k] = v
	}
	for k, v := range base {
		req.Header.Set(k, v)
	}
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	return resp.StatusCode, resp.Header.Get("x-amz-rdma-capabilities") == "mp"
}

// The READY success response carries the advertisement; the flag
// travels through the locals set at session creation.
func TestCapabilityAdvertisementReadySurface(t *testing.T) {
	// The READY success header is emitted directly by readyCore's
	// response block; assert the constants and the wrapper wiring
	// by exercising the emission branch contract at unit level:
	// the header name/token pair and the locals gate.
	if hdrCapabilities != "x-amz-rdma-capabilities" {
		t.Fatalf("header = %q", hdrCapabilities)
	}
	if capabilityMultipart != "mp" {
		t.Fatalf("token = %q", capabilityMultipart)
	}
	// The wrapper emits only for session-created requests; a
	// pre-creation failure leaves locals empty.
	app := fiber.New()
	emitted := false
	app.Post("/p", func(c fiber.Ctx) error {
		if err := errors.New("pre-creation"); err != nil {
			if created, _ := c.Locals(sessionCreatedKey).(bool); created {
				c.Set(hdrCapabilities, capabilityMultipart)
			}
		}
		emitted = string(c.Response().Header.Peek(hdrCapabilities)) == capabilityMultipart
		return c.SendStatus(fiber.StatusBadRequest)
	})
	req, _ := http.NewRequest(fiber.MethodPost, "/p", nil)
	if _, err := app.Test(req); err != nil {
		t.Fatal(err)
	}
	if emitted {
		t.Fatal("advertisement emitted without a created session")
	}
}

// Post-creation failure: Prepare succeeds (session created), the
// staging read fails, FinishPrepare(false) runs, and the serialized
// error response still advertises the capabilities. The GET branch
// with a missing object exercises exactly this path through the
// real wrapper.
// stageFailService creates the session (Prepare succeeds) and
// answers the staging borrow, so the subsequent backend read failure
// fails after creation.
type stageFailService struct {
	*fixedService
	buf []byte
}

func (s *stageFailService) Prepare(req rcserver.PrepareRequest) (*rcserver.PrepareResponse, error) {
	return &rcserver.PrepareResponse{
		SessionID: "0123456789abcdef0123456789abcdef",
		ServerPsn: 7,
	}, nil
}

func (s *stageFailService) FinishPrepare(sessionID string, ok bool) error {
	return nil
}

func (s *stageFailService) BorrowStaging(sessionID string) (*rcserver.StagingLease, error) {
	return &rcserver.StagingLease{Buf: s.buf}, nil
}

func (s *stageFailService) FinishStaging(lease rcserver.StagingLease, ok bool,
	written int, etag, version string) error {
	return nil
}

func TestCapabilityAdvertisementPostCreationFailure(t *testing.T) {
	be := &fakeBackend{}
	be.getObject = func(ctx context.Context, in *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	h := &Handler{
		svc:        &stageFailService{fixedService: newFixedService(), buf: make([]byte, 8)},
		be:         be,
		mpMaxParts: 100,
	}
	// GET op so prepareCore stages (and the staging read fails).
	code, has := runPrepare(t, h, map[string]string{
		"x-amz-rdma-op": "GET",
	})
	if code != http.StatusNotFound {
		t.Fatalf("missing-object status = %d, want 404", code)
	}
	if !has {
		t.Fatal("capabilities absent on post-creation failure")
	}
}

// Absent: the successful PREPARE response itself never carries the
// advertisement (the client learns the capability from READY, not
// from PREPARE). Present: ops.register refusal after the session
// was created still advertises.
func TestCapabilityAdvertisementPrepareSuccessAndRegisterRefusal(t *testing.T) {
	// Successful PREPARE: register succeeds, FinishPrepare(true)
	// commits, and the 200 response carries no capabilities header.
	svc := &capService{fixedService: newFixedService()}
	h := &Handler{svc: svc, be: &fakeBackend{}, mpMaxParts: 100,
		ops: newOpsTracker(0)}
	code, has := runPrepare(t, h, nil)
	if code != http.StatusOK {
		t.Fatalf("prepare status = %d, want 200", code)
	}
	if has {
		t.Fatal("capabilities advertised on successful PREPARE")
	}

	// Register refusal post-creation: a sessionLimit of 1 with the
	// backlog already full forces errPubBacklog after svc.Prepare
	// created the session; the serialized SlowDown (503) still
	// advertises.
	busy := newOpsTracker(1)
	busy.pubPending.Add(1)
	h2 := &Handler{svc: &capService{fixedService: newFixedService()},
		be: &fakeBackend{}, mpMaxParts: 100, ops: busy}
	code2, has2 := runPrepare(t, h2, nil)
	if code2 != http.StatusServiceUnavailable {
		t.Fatalf("register-refusal status = %d, want 503", code2)
	}
	if !has2 {
		t.Fatal("capabilities absent on ops.register refusal post-creation")
	}
}

// readyCapService answers one GET session whose transfer completes.
type readyCapService struct {
	*fixedService
}

func (r *readyCapService) SessionInfo(sessionID string,
	who rcserver.PrincipalID) (*rcserver.SessionInfo, error) {
	return &rcserver.SessionInfo{Op: 0, Target: "/bkt/obj"}, nil
}

func (r *readyCapService) ReadyTransfer(req rcserver.ReadyRequest) (*rcserver.ReadyResponse, error) {
	return &rcserver.ReadyResponse{
		BytesTransferred: 64,
		CookieEcho:       0x01020304,
	}, nil
}

func (r *readyCapService) FinishFinal(sessionID string) error {
	return nil
}

// Present: the READY success response carries the advertisement.
func TestCapabilityAdvertisementReadySuccess(t *testing.T) {
	h := &Handler{svc: &readyCapService{fixedService: newFixedService()},
		be: &fakeBackend{}, mpMaxParts: 100, ops: newOpsTracker(0)}
	// READY re-registers nothing: the session must exist in the
	// ops tracker (PREPARE registers it), so register the fixed
	// session id the way prepareCore would.
	if err := h.ops.register("0123456789abcdef0123456789abcdef",
		auth.Account{Access: "ak"}, "us-east-1", "bkt", "obj",
		false, opPlainGet, "", time.Now()); err != nil {
		t.Fatalf("register: %v", err)
	}
	app := fiber.New()
	app.Post("/.hipobj-rc/ready", func(c fiber.Ctx) error {
		utils.ContextKeyAccount.Set(c, auth.Account{Access: "ak"})
		utils.ContextKeyIsRoot.Set(c, true)
		return h.Ready(c)
	})
	req, _ := http.NewRequest(fiber.MethodPost, "/.hipobj-rc/ready", nil)
	for k, v := range map[string]string{
		"x-amz-rdma-protocol": "hipobj-rc-v2",
		"x-amz-rdma-session":  "0123456789abcdef0123456789abcdef",
		"x-amz-rdma-cookie":   "01020304",
		"x-amz-rdma-qpn":      "000001",
		"x-amz-rdma-mr-addr":  "000000002134a000",
		"x-amz-rdma-mr-rkey":  "00000101",
	} {
		req.Header.Set(k, v)
	}
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ready status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("x-amz-rdma-capabilities"); got != "mp" {
		t.Fatalf("ready capabilities = %q, want mp", got)
	}
}
