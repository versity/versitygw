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
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"

	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/rdma/rcserver"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
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
// Every string field is owned storage: nothing may reference the
// request's pooled buffers once PREPARE returns, because fasthttp
// reuses them for the next request.
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
// instead of the fixed RDMA control path. The path string is the
// emitter's own storage: event senders serialize asynchronously, so
// the synthesized context must never hand them pooled buffers.
func (e *opsEmitter) synthesize() (fiber.Ctx, func()) {
	ctx := e.app.AcquireCtx(&fasthttp.RequestCtx{})
	method := fiber.MethodGet
	if e.isPut {
		method = fiber.MethodPut
	}
	ctx.Method(method)
	// The access logger and the event schema both split this path
	// into bucket/key, so the synthesized path must be the object
	// path in canonical form. fiber copies override strings it
	// stores as the path original; the derived c.path below is
	// a fresh allocation, which is what outlives the release.
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
//
// The operational sinks classify plain errors as 500 on their own,
// which would disagree with the status the client saw. Before the
// record reaches them, the error is rendered as its mapped S3 error,
// so the audit log, the metric, and the wire response all carry the
// same classification.
func (e *opsEmitter) publish(err error, bytes int64) {
	if e == nil || (e.ops.Logger == nil && e.ops.Metrics == nil && e.ops.Events == nil) {
		return
	}
	sinkErr := err
	if err != nil {
		var s3Err s3err.S3Error
		if !errors.As(err, &s3Err) {
			sinkErr = routeError(err)
		}
	}
	ctx, release := e.synthesize()
	defer release()

	action := metrics.ActionGetObject
	if e.isPut {
		action = metrics.ActionPutObject
	}
	status := httpStatusFromError(sinkErr)

	if e.ops.Metrics != nil {
		e.ops.Metrics.Send(ctx, sinkErr, action, bytes, status)
	}
	if e.ops.Logger != nil {
		e.ops.Logger.Log(ctx, sinkErr, nil, s3log.LogMeta{
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
// the S3 surface would have answered with. The callers pass mapped
// S3 errors, so the status is simply the error's own.
func httpStatusFromError(err error) int {
	if err == nil {
		return 200
	}
	return routeError(err).HTTPStatusCode
}

// sessionRecord is one tracked session with its captured context.
type sessionRecord struct {
	emit *opsEmitter
	// reserved marks a record the request path holds exclusively:
	// it took ownership before invoking a native completion call
	// that would fire the teardown callback synchronously, so the
	// callback must not publish on its behalf.
	reserved bool
}

// opsTracker owns terminal publication: each session (and each
// pre-session request) is published exactly once, by whichever path
// confirms the final outcome first. It carries its own throwaway
// fiber.App for synthesizing publication contexts, independent of
// the gateway's request routing.
type opsTracker struct {
	mu       sync.Mutex
	ops      OpsServices
	sessions map[string]*sessionRecord
	// earlyTerminals parks teardown notifications that arrived
	// before the session's registration; register consumes them.
	earlyTerminals map[string]rcserver.TerminalEvent
	app            *fiber.App
}

func newOpsTracker() *opsTracker {
	return &opsTracker{
		sessions:       map[string]*sessionRecord{},
		earlyTerminals: map[string]rcserver.TerminalEvent{},
		app:            fiber.New(),
	}
}

// SetOpsServices installs the operational service instances. The
// gateway creates the logger, metrics manager, and event sender
// after the RC routes exist, so the tracker starts empty and the
// services arrive here. Sessions registered before the injection
// publish nothing (there are none: the gateway wires this before
// it starts serving).
func (t *opsTracker) SetOpsServices(ops OpsServices) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ops = ops
}

// register captures the operational context of a successfully created
// session so a later terminal path can publish its final outcome.
// The strings are cloned: they originate from the request's pooled
// header buffer, which does not survive the response.
//
// handleEarlyTerminal covers the FinishPrepare race: the native call
// that finalizes PREPARE can reap an already-expired session and fire
// the teardown callback before register runs. When the callback wins
// that race it parks the event, and register consumes it instead of
// leaving an entry whose only notification already happened.
func (t *opsTracker) register(sessionID string, acct auth.Account,
	region, bucket, key string, isPut bool, start time.Time) {
	emit := &opsEmitter{
		ops:    t.loadOps(),
		app:    t.app,
		acct:   acct,
		region: region,
		bucket: strings.Clone(bucket),
		key:    strings.Clone(key),
		isPut:  isPut,
		start:  start,
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	// A teardown notification that arrived before this registration
	// owns the publication: publish now and store nothing.
	if _, parked := t.earlyTerminals[sessionID]; parked {
		delete(t.earlyTerminals, sessionID)
		go emit.publish(errSessionExpired, 0)
		return
	}
	t.sessions[sessionID] = &sessionRecord{emit: emit}
}

// unregister drops a session entry whose PREPARE finalization
// failed: the native side is gone, so the teardown callback has
// either already published or will find nothing. A parked early
// notification is dropped with it (the failure publication covers
// the outcome).
func (t *opsTracker) unregister(sessionID string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.sessions, sessionID)
	delete(t.earlyTerminals, sessionID)
}

// reserve takes exclusive ownership of a session's publication
// before the request path invokes a native completion call
// (FinishFinal, FinishPut, or a reap-triggering mutation). Those
// calls fire the teardown callback synchronously while the session
// record is still live; reserving first keeps the callback from
// publishing an expiry record for a transfer that is completing
// right now.
func (t *opsTracker) reserve(sessionID string) *opsEmitter {
	t.mu.Lock()
	defer t.mu.Unlock()
	rec, ok := t.sessions[sessionID]
	if !ok || rec.reserved {
		return nil
	}
	rec.reserved = true
	return rec.emit
}

// unreserve restores callback ownership when a reserved completion
// call did not after all retire the session (the caller failed
// before any state change). The record goes back to normal tracking
// unless a teardown notification landed meanwhile.
func (t *opsTracker) unreserve(sessionID string, emit *opsEmitter) {
	if t == nil || emit == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	rec, ok := t.sessions[sessionID]
	if !ok {
		// The session is gone: the completion call retired it and
		// the reserved emitter is the only remaining owner, so
		// nothing to restore.
		return
	}
	rec.reserved = false
}

func (t *opsTracker) loadOps() OpsServices {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ops
}

// claim removes the session from the table and returns its emitter
// to exactly one publisher. A reserved record is only claimable by
// its reserving request path (the callback skips it).
func (t *opsTracker) claim(sessionID string, byRequest bool) *opsEmitter {
	t.mu.Lock()
	defer t.mu.Unlock()
	rec, ok := t.sessions[sessionID]
	if !ok {
		return nil
	}
	if rec.reserved && !byRequest {
		return nil
	}
	delete(t.sessions, sessionID)
	return rec.emit
}

// onTerminal is the native teardown callback path: publish sessions
// that no handler ever claimed (expired, abandoned, or canceled
// without a READY).
func (t *opsTracker) onTerminal(ev rcserver.TerminalEvent) {
	if t == nil {
		return
	}
	emit := t.claim(ev.SessionID, false)
	if emit != nil {
		// An expired or abandoned session never reached a final
		// object result; the bytes staged for it did not become
		// a transfer.
		emit.publish(errSessionExpired, 0)
		return
	}
	// A session tearing down before its registration ran: park the
	// event so register can publish instead of orphaning a record
	// whose only notification already happened.
	t.mu.Lock()
	if _, live := t.sessions[ev.SessionID]; !live {
		t.earlyTerminals[ev.SessionID] = ev
	}
	t.mu.Unlock()
}

// publishClaimed publishes the terminal record from the request
// path (READY completion or failure). A nil tracker (no operational
// services) and an unknown session (already claimed or never
// registered) are both silent no-ops.
func (t *opsTracker) publishClaimed(sessionID string, err error, bytes ...int64) {
	if t == nil {
		return
	}
	emit := t.claim(sessionID, true)
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
		ops:    t.loadOps(),
		app:    t.app,
		acct:   acct,
		region: regionFromCtx(ctx),
		bucket: strings.Clone(bucket),
		key:    strings.Clone(key),
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

// expiredOutcomeError renders a parked teardown notification as the
// error the publication carries: an internal S3 error whose code
// names the expiry, so the audit log keeps the descriptive code the
// plain error used to carry instead of the generic mapping.
type sessionExpiredError struct {
	s3err.APIError
}

var errSessionExpired = sessionExpiredError{APIError: s3err.APIError{
	Code:           "SessionExpired",
	Description:    "The RDMA transfer session expired before completion",
	HTTPStatusCode: 500,
}}
