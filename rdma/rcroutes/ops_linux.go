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

//go:build linux && amd64 && cgo

package rcroutes

import (
	"fmt"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"

	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/rdma/rcserver"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3event"
	"github.com/versity/versitygw/s3log"
)

// OpsServices carries the operational service instances the RC routes
// report into. All three may be nil; publication then becomes a no-op
// so the control plane works without any configured backend.
type OpsServices struct {
	Logger  s3log.AuditLogger
	Metrics metrics.Manager
	Events  s3event.S3EventSender
}

// opsEmitter is the operational context captured at PREPARE and held
// until the final outcome is known: enough to synthesize an access
// record carrying the session's object rather than the wire path.
type opsEmitter struct {
	ops    OpsServices
	app    *fiber.App
	acct   auth.Account
	region string
	bucket string
	key    string
	isPut  bool
	start  time.Time
}

// synthesize builds a fiber context whose path and request locals
// describe the session's logical object operation, so the standard
// access-log and event pipelines observe GET/PUT of bucket/key
// instead of the fixed RDMA control path.
func (e *opsEmitter) synthesize() (fiber.Ctx, func()) {
	ctx := e.app.AcquireCtx(&fasthttp.RequestCtx{})
	method := fiber.MethodGet
	if e.isPut {
		method = fiber.MethodPut
	}
	ctx.Method(method)
	// The access logger and the event schema both split this path
	// into bucket/key, so the synthesized path must be the object
	// path in canonical form.
	ctx.Path("/" + e.bucket + "/" + e.key)
	utils.ContextKeyAccount.Set(ctx, e.acct)
	utils.ContextKeyRegion.Set(ctx, e.region)
	utils.ContextKeyStartTime.Set(ctx, e.start)
	utils.ContextKeyIsRoot.Set(ctx, false)
	requestID, hostID := utils.EnsureRequestIDs(ctx)
	ctx.Request().Header.Add("X-Amz-Request-Id", requestID)
	ctx.Request().Header.Add("X-Amz-Id-2", hostID)
	return ctx, func() { e.app.ReleaseCtx(ctx) }
}

// publish emits the final audit record, request metric, and (for a
// committed PUT) the object-created event. Exactly-once delivery is
// the tracker's job; this method just performs one emission.
func (e *opsEmitter) publish(err error, bytes int64) {
	if e == nil || (e.ops.Logger == nil && e.ops.Metrics == nil && e.ops.Events == nil) {
		return
	}
	ctx, release := e.synthesize()
	defer release()

	action := metrics.ActionGetObject
	if e.isPut {
		action = metrics.ActionPutObject
	}
	status := httpStatusFromError(err)

	if e.ops.Metrics != nil {
		e.ops.Metrics.Send(ctx, err, action, bytes, status)
	}
	if e.ops.Logger != nil {
		e.ops.Logger.Log(ctx, err, nil, s3log.LogMeta{
			Action: action,
		})
	}
	// The object-created event fires at commit time only; error
	// publications never carry it.
	if e.ops.Events != nil && err == nil && e.isPut {
		e.ops.Events.SendEvent(ctx, s3event.EventMeta{
			EventName:  s3event.EventObjectCreatedPut,
			ObjectSize: bytes,
		})
	}
}

// httpStatusFromError maps an operation error to the HTTP status
// the S3 surface would have answered with, using the same route
// error mapping as the wire response so operational records never
// disagree with what the client saw.
func httpStatusFromError(err error) int {
	if err == nil {
		return 200
	}
	return routeError(err).HTTPStatusCode
}

// sessionRecord is one tracked session with its captured context.
type sessionRecord struct {
	emit    *opsEmitter
	done    bool
	pending bool
}

// opsTracker owns terminal publication: each session (and each
// pre-session request) is published exactly once, by whichever path
// confirms the final outcome first. It carries its own throwaway
// fiber app: the synthesized contexts only carry path and locals,
// never route state, so they must not share the gateway app.
type opsTracker struct {
	mu       sync.Mutex
	sessions map[string]*sessionRecord
	ops      OpsServices
	app      *fiber.App
}

func newOpsTracker() *opsTracker {
	return &opsTracker{
		sessions: map[string]*sessionRecord{},
		app:      fiber.New(),
	}
}

// SetOpsServices installs the operational service instances. The
// gateway creates the logger, metrics manager, and event sender
// after the RC routes exist, so the tracker starts empty and the
// embedder injects them once RunVersityGW has built them. Sessions
// registered before the injection publish nothing (there are none:
// the server is not listening yet).
func (t *opsTracker) SetOpsServices(ops OpsServices) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ops = ops
}

// opsSnapshot returns the current service set under the lock.
func (t *opsTracker) opsSnapshot() OpsServices {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ops
}

// register captures the operational context of a successfully created
// session so a later terminal path can publish its final outcome.
func (t *opsTracker) register(sessionID string, acct auth.Account,
	region, bucket, key string, isPut bool, start time.Time) {
	emit := &opsEmitter{
		ops:    t.opsSnapshot(),
		app:    t.app,
		acct:   acct,
		region: region,
		bucket: bucket,
		key:    key,
		isPut:  isPut,
		start:  start,
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sessions[sessionID] = &sessionRecord{emit: emit, pending: true}
}

// claim removes the session's publication slot and returns its
// captured context; the second caller gets nil and publishes nothing.
func (t *opsTracker) claim(sessionID string) *opsEmitter {
	t.mu.Lock()
	defer t.mu.Unlock()
	rec, ok := t.sessions[sessionID]
	if !ok {
		return nil
	}
	delete(t.sessions, sessionID)
	if !rec.pending {
		return nil
	}
	return rec.emit
}

// onTerminal is the native teardown callback path: publish sessions
// that no handler ever claimed (expired, abandoned, or canceled
// without a READY).
func (t *opsTracker) onTerminal(ev rcserver.TerminalEvent) {
	if t == nil {
		return
	}
	emit := t.claim(ev.SessionID)
	if emit == nil {
		return
	}
	// An expired or abandoned session never reached a final object
	// result; the bytes staged for it did not become a transfer.
	emit.publish(errSessionExpired, 0)
}

// publishClaimed publishes the terminal record from the request
// path (READY completion or failure). A nil tracker (no operational
// services) and an unknown session (already claimed or never
// registered) are both silent no-ops.
func (t *opsTracker) publishClaimed(sessionID string, err error, bytes ...int64) {
	if t == nil {
		return
	}
	emit := t.claim(sessionID)
	if emit == nil {
		return
	}
	var n int64
	if len(bytes) > 0 {
		n = bytes[0]
	}
	emit.publish(err, n)
}

// publishRequest emits an operation record for a request that ended
// before any session existed (authentication, authorization, or
// header failures): no tracking table entry, single emission.
func (t *opsTracker) publishRequest(ctx fiber.Ctx, acct auth.Account,
	err error, bucket, key string, isPut bool) {
	if t == nil {
		return
	}
	emit := &opsEmitter{
		ops:    t.ops,
		app:    t.app,
		acct:   acct,
		region: regionFromCtx(ctx),
		bucket: bucket,
		key:    key,
		isPut:  isPut,
		start:  time.Now(),
	}
	emit.publish(err, 0)
}

// regionFromCtx reads the region the gateway middleware stored on
// the live request; the synthesized publication reuses it.
func regionFromCtx(ctx fiber.Ctx) string {
	if v, ok := utils.ContextKeyRegion.Get(ctx).(string); ok {
		return v
	}
	return ""
}

var errSessionExpired = fmt.Errorf("session expired")
