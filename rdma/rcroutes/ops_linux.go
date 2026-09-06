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
	"net/http"
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
	// Commit metadata the PUT path fills in before publishing the
	// success record, so the object-created event carries the
	// backend-assigned ETag and version like the regular put
	// pipeline's event does.
	etag    string
	version string
	hasEtag bool
	hasVer  bool
}

// setCommitMeta records the backend-assigned object metadata for
// the success publication's event payload.
func (e *opsEmitter) setCommitMeta(etag, version string) {
	if e == nil {
		return
	}
	e.etag = etag
	e.hasEtag = true
	e.version = version
	e.hasVer = true
}

// synthesize builds a fiber context whose path and request locals
// describe the session's logical object operation, so the standard
// access-log and event pipelines observe GET/PUT of bucket/key
// instead of the fixed RDMA control path. The app runs with
// Immutable: string accessors copy instead of exposing the pooled
// context buffer, which matters because event senders serialize
// asynchronously and would otherwise read a reused buffer.
//
// Route parameters cannot be populated this way (they come from
// route matching, which a synthesized request never runs), so the
// metrics bucket tag is absent on RC publications; the audit log
// derives the bucket from the path instead and stays accurate.
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
//
// The operational sinks classify plain errors as 500 on their own
// and unwrap nothing, so the publication always hands them the
// error in its normalized S3 form: the audit log, the metric, and
// the wire response then carry the same classification.
func (e *opsEmitter) publish(err error, bytes int64) {
	if e == nil || (e.ops.Logger == nil && e.ops.Metrics == nil && e.ops.Events == nil) {
		return
	}
	sinkErr := normalizeSinkError(err)
	ctx, release := e.synthesize()
	defer release()

	action := metrics.ActionGetObject
	if e.isPut {
		action = metrics.ActionPutObject
	}
	status := http.StatusOK
	if sinkErr != nil {
		status = sinkErr.(s3err.APIError).HTTPStatusCode
	}

	if e.ops.Metrics != nil {
		e.ops.Metrics.Send(ctx, sinkErr, action, bytes, status)
	}
	if e.ops.Logger != nil {
		e.ops.Logger.Log(ctx, sinkErr, nil, s3log.LogMeta{
			Action: action,
			// The object size field reports the transferred
			// byte count the record carries, so a successful
			// GET/PUT shows real bytes instead of zero.
			ObjectSize: bytes,
		})
	}
	// The object-created event fires at commit time only; error
	// publications never carry it.
	if e.ops.Events != nil && err == nil && e.isPut {
		meta := s3event.EventMeta{
			EventName:  s3event.EventObjectCreatedPut,
			ObjectSize: bytes,
		}
		if e.hasEtag {
			etag := e.etag
			meta.ObjectETag = &etag
		}
		if e.hasVer {
			ver := e.version
			meta.VersionId = &ver
		}
		e.ops.Events.SendEvent(ctx, meta)
	}
}

// normalizeSinkError renders any operation error as the plain
// s3err.APIError the sinks expect: wrapped S3 errors keep their
// payload (the audit loggers assert the S3Error interface directly
// and would misclassify a wrapper), and non-S3 errors map through
// the same route error mapping the wire response uses.
func normalizeSinkError(err error) error {
	if err == nil {
		return nil
	}
	var s3Err s3err.S3Error
	if errors.As(err, &s3Err) {
		return s3Err.BaseError()
	}
	return routeError(err)
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

// sessionOutcome is the terminal outcome of a tracked session.
type sessionOutcome struct {
	err  error // nil on success
	byt  int64 // bytes transferred on success
	done bool  // outcome recorded
}

// sessionRecord is one tracked session with its captured context.
type sessionRecord struct {
	emit *opsEmitter
	out  sessionOutcome
	// reserved marks a record the request path owns: the native
	// teardown callback skips it (the request path will publish
	// exactly once itself), so a completion call that fires the
	// callback before returning cannot publish a placeholder.
	reserved bool
	// terminal marks a teardown that arrived while the record was
	// reserved: the native session is gone and no second callback
	// will come, so a later release of the reservation resolves
	// the stashed outcome instead of leaving an orphan.
	terminal bool
}

// opsTracker owns terminal publication: each session publishes
// exactly once. The request paths only ever RECORD an outcome; the
// native teardown callback - which the ABI guarantees fires exactly
// once per destroyed session, after every completion call - is the
// single publisher. This removes every ownership race: a recorded
// outcome cannot be double-published, and a record the callback
// already consumed cannot be resurrected.
//
// Sink execution never runs on the caller's thread: the native
// reaper invokes the callback, and an operational sink can block
// (a synchronous file write on a stalled filesystem), which would
// stall reaping for every other session. Publications hand off to
// a dedicated worker through a bounded queue; when the queue is
// full the publication runs inline as a last resort, keeping the
// guarantee that no record is silently dropped while still capping
// how long a callback may wait.
type opsTracker struct {
	mu        sync.Mutex
	ops       OpsServices
	sessions  map[string]*sessionRecord
	app       *fiber.App
	pubq      chan pubJob
	overflow  chan struct{}
	done      chan struct{}
	drain     chan struct{}
	drainOnce sync.Once
}

// pubJob is one deferred publication handed to the worker.
type pubJob struct {
	emit *opsEmitter
	err  error
	byt  int64
}

// pubQueueDepth bounds how many publications may wait in the
// handoff queue before the caller falls back to inline execution.
const pubQueueDepth = 256

// pubOverflowSlots bounds how many callers may run overflow
// publications inline at once; further callers block on the
// semaphore until a slot frees.
const pubOverflowSlots = 8

func newOpsTracker() *opsTracker {
	t := &opsTracker{
		sessions: map[string]*sessionRecord{},
		app: fiber.New(fiber.Config{
			Immutable: true,
		}),
		pubq:     make(chan pubJob, pubQueueDepth),
		overflow: make(chan struct{}, pubOverflowSlots),
		done:     make(chan struct{}),
		drain:    make(chan struct{}),
	}
	go func() {
		defer close(t.done)
		for {
			select {
			case job, ok := <-t.pubq:
				if !ok {
					return
				}
				job.emit.publish(job.err, job.byt)
			case <-t.drain:
				// Drain mode: empty whatever is already
				// queued, then exit. Producers past this
				// point publish inline.
				for {
					select {
					case job, ok := <-t.pubq:
						if !ok {
							return
						}
						job.emit.publish(job.err, job.byt)
					default:
						return
					}
				}
			}
		}
	}()
	return t
}

// Shutdown drains pending publications and stops the worker. The
// gateway must call this BEFORE closing the operational sinks: a
// queued publication that runs after its logger closed is lost.
// After Shutdown, dispatch publishes inline (the queue no longer
// moves), so late terminals still record instead of vanishing.
func (t *opsTracker) Shutdown() {
	if t == nil {
		return
	}
	t.drainOnce.Do(func() {
		close(t.drain)
		<-t.done
	})
}

// dispatch hands a publication to the worker. It must never block
// indefinitely: when the queue is full (the worker itself stuck in
// a sink), the publication runs inline so the record is still
// delivered and the caller - possibly the native reaper - returns.
// dispatch hands a publication to the worker. It must never block
// indefinitely: when the queue is full the caller runs the
// publication itself under an overflow semaphore, which bounds how
// many overflow publications may wait at once. Overflow callers
// beyond the semaphore block - the alternative (one goroutine per
// job) grows without bound under a stalled sink, and dropping the
// record loses the publication entirely. The callers that reach
// overflow are the native reaper or a request handler; waiting
// there is bounded by the semaphore and by the worker draining,
// and is the price of never losing a record.
func (t *opsTracker) dispatch(job pubJob) {
	// After the worker exited (shutdown drain), the queue no
	// longer moves: publish inline so the record is not
	// stranded behind a send nobody will receive.
	select {
	case <-t.done:
		job.emit.publish(job.err, job.byt)
		return
	default:
	}
	select {
	case t.pubq <- job:
		return
	default:
	}
	// Queue full and worker alive. Run inline under the overflow
	// semaphore.
	t.overflow <- struct{}{}
	defer func() { <-t.overflow }()
	job.emit.publish(job.err, job.byt)
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

// register captures the operational context of a successfully
// created session so the terminal outcome can be published later.
// The strings are cloned: they originate from the request's pooled
// header buffer, which does not survive the response.
//
// The account is captured by value but its string fields still
// reference request storage on some IAM paths, so the sink-relevant
// identity is cloned as well.
func (t *opsTracker) register(sessionID string, acct auth.Account,
	region, bucket, key string, isPut bool, start time.Time) {
	acct.Access = strings.Clone(acct.Access)
	emit := &opsEmitter{
		ops:    t.loadOps(),
		app:    t.app,
		acct:   acct,
		region: strings.Clone(region),
		bucket: strings.Clone(bucket),
		key:    strings.Clone(key),
		isPut:  isPut,
		start:  start,
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	t.sessions[sessionID] = &sessionRecord{emit: emit}
}

// unregister drops a session entry whose PREPARE finalization
// failed before the session was committed: the native side either
// rejected it (no callback will come) or already reaped it (the
// callback found no record and published nothing). The failure
// itself is published as a request record by the caller.
func (t *opsTracker) unregister(sessionID string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.sessions, sessionID)
}

// failOutcome publishes a failed finalization exactly once: when
// the finalizing call already reaped the session its callback
// published (the entry is gone, this is a no-op); when no callback
// will ever come (the native side rejected the call) the entry is
// consumed and published here. A reserved record belongs to an
// in-flight completion owner (a concurrent READY's denial must not
// steal its publication), so it is left untouched.
func (t *opsTracker) failOutcome(sessionID string, err error) {
	if t == nil {
		return
	}
	t.mu.Lock()
	rec, ok := t.sessions[sessionID]
	if ok && !rec.reserved {
		delete(t.sessions, sessionID)
	} else {
		ok = false
	}
	t.mu.Unlock()
	if !ok {
		return
	}
	t.dispatch(pubJob{emit: rec.emit, err: err})
}

// reserve marks a session record as owned by its request path: the
// teardown callback skips a reserved record because the request
// path publishes the real outcome itself. Returns the emitter when
// the record exists and was not reserved yet.
func (t *opsTracker) reserve(sessionID string) *opsEmitter {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	rec, ok := t.sessions[sessionID]
	if !ok || rec.reserved {
		return nil
	}
	rec.reserved = true
	return rec.emit
}

// releaseReservation returns a reserved record to the pool
// without publishing: the transfer claim it was held for rolled
// back, so the session lives on and the next claimant (another
// READY, or the reaper) must still find an unreserved record.
// If the native session already tore down while the record was
// reserved (terminal stashed), the session is gone: consume the
// record and publish the stashed outcome, since no second
// callback will arrive.
func (t *opsTracker) releaseReservation(sessionID string, emit *opsEmitter) {
	if t == nil {
		return
	}
	t.mu.Lock()
	rec, ok := t.sessions[sessionID]
	if !ok || !rec.reserved || rec.emit != emit {
		t.mu.Unlock()
		return
	}
	if !rec.terminal {
		rec.reserved = false
		t.mu.Unlock()
		return
	}
	delete(t.sessions, sessionID)
	t.mu.Unlock()
	t.dispatch(pubJob{emit: rec.emit, err: rec.out.err, byt: rec.out.byt})
}

// publishReserved publishes through a reserved record and drops it:
// the single publication of a request-owned session outcome.
func (t *opsTracker) publishReserved(sessionID string, emit *opsEmitter, err error, bytes int64) {
	if t == nil {
		return
	}
	t.mu.Lock()
	rec, ok := t.sessions[sessionID]
	// Ownership check: only the reservation holder publishes. A
	// stale holder (its reservation was released or the record
	// was replaced) must not delete or publish the current
	// owner's record.
	if !ok || rec.emit != emit {
		t.mu.Unlock()
		return
	}
	delete(t.sessions, sessionID)
	t.mu.Unlock()
	if emit != nil {
		t.dispatch(pubJob{emit: emit, err: err, byt: bytes})
	}
}

func (t *opsTracker) loadOps() OpsServices {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ops
}

// onTerminal is the native teardown callback: the single publisher
// of session records. It consumes the recorded outcome (success,
// failure, or expiry when no outcome was ever recorded) and removes
// the entry, so exactly one publication happens per session no
// matter which path confirmed the result.
func (t *opsTracker) onTerminal(ev rcserver.TerminalEvent) {
	if t == nil {
		return
	}
	t.mu.Lock()
	rec, ok := t.sessions[ev.SessionID]
	if !ok {
		t.mu.Unlock()
		return
	}
	// A reserved record belongs to its request path, which
	// publishes the real outcome itself: the callback (fired
	// synchronously by a completion call, before the request
	// path could confirm the result) must not touch it. But the
	// terminal is still a fact: if the reservation is released
	// later (claim rollback) and no second callback will ever
	// come - the native session is gone - the stashed event
	// resolves then, instead of being lost.
	if rec.reserved {
		if !rec.out.done {
			rec.out = sessionOutcome{err: expiredError(ev), done: true}
		}
		rec.terminal = true
		t.mu.Unlock()
		return
	}
	delete(t.sessions, ev.SessionID)
	t.mu.Unlock()

	if !rec.out.done {
		// No request path ever confirmed a result: the session
		// expired, was abandoned, or was canceled. The event's
		// outcome carries the native reason.
		rec.out = sessionOutcome{err: expiredError(ev), done: true}
	}
	t.dispatch(pubJob{emit: rec.emit, err: rec.out.err, byt: rec.out.byt})
}

// expiredError renders an unclaimed teardown as the error the
// publication carries, derived from the native outcome so the
// record names the real terminal reason. The classification stays
// aligned with the wire mapping: every transfer-level failure the
// READY call reports as RC_E_WIRE (wire, verify, or execution
// timeout) publishes as the same 502 the client would have seen,
// and only a session that expired without any transfer attempt
// keeps the expiry code.
func expiredError(ev rcserver.TerminalEvent) error {
	switch ev.Outcome {
	case int(rcserver.ReadyWireFail), int(rcserver.ReadyVerifyFail),
		int(rcserver.ReadyTimeout):
		return rcserver.ErrWire
	default:
		return errSessionExpired
	}
}

// publishRequest emits an operation record for a request that ended
// before any session existed (authentication, authorization, or
// header failures): no tracking table entry, single emission.
func (t *opsTracker) publishRequest(ctx fiber.Ctx, acct auth.Account,
	err error, bucket, key string, isPut bool) {
	if t == nil {
		return
	}
	acct.Access = strings.Clone(acct.Access)
	emit := &opsEmitter{
		ops:    t.loadOps(),
		app:    t.app,
		acct:   acct,
		region: strings.Clone(regionFromCtx(ctx)),
		bucket: strings.Clone(bucket),
		key:    strings.Clone(key),
		isPut:  isPut,
		start:  time.Now(),
	}
	t.dispatch(pubJob{emit: emit, err: err})
}

// regionFromCtx reads the region the gateway middleware stored on
// the live request; the synthesized publication reuses it.
func regionFromCtx(ctx fiber.Ctx) string {
	if v, ok := utils.ContextKeyRegion.Get(ctx).(string); ok {
		return v
	}
	return ""
}

// sessionExpiredError is the S3 error an expired or abandoned
// session publishes: an internal error whose code names the
// expiry, so the audit log keeps a descriptive code.
type sessionExpiredError struct {
	s3err.APIError
}

var errSessionExpired = sessionExpiredError{APIError: s3err.APIError{
	Code:           "SessionExpired",
	Description:    "The RDMA transfer session expired before completion",
	HTTPStatusCode: 500,
}}
