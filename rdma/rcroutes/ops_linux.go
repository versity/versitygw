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
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
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
	// committed records that the backend created the object.
	// The creation event keys off this fact, not off the final
	// publication's error status: a committed PUT whose native
	// finalizer later failed still created the object, and its
	// creation event must not be lost.
	committed bool
	// eventSent guards the creation event against a second
	// publication path (stashed terminal consumed by a release).
	eventSent bool
}

// markCommitted records the backend commit fact together with the
// backend-assigned object metadata. The creation event fires for
// any publication after this, including an error publication from
// a failed native finalizer: the object exists regardless of the
// finalizer's fate.
func (e *opsEmitter) markCommitted(etag, version string) {
	if e == nil {
		return
	}
	e.etag = etag
	e.hasEtag = true
	e.version = version
	e.hasVer = true
	e.committed = true
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
		// The bucket dimension comes from the captured session,
		// not the route: the synthesized context has no matched
		// route, so Params("bucket") would be empty here.
		e.ops.Metrics.SendWithBucket(ctx, sinkErr, action, bytes, status, e.bucket)
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
	// The object-created event keys off the backend commit fact,
	// not the publication's error status: a committed PUT whose
	// native finalizer failed still created the object, so its
	// creation event must survive. Uncommitted PUTs (backend
	// failure) never carry it.
	if e.ops.Events != nil && e.committed && e.isPut && !e.eventSent {
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
		e.eventSent = true
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
	// claimGen identifies the current reservation. Each reserve
	// bumps it, so a release or publication from an earlier
	// reservation is rejected even though the record's emitter
	// pointer is reused across claims.
	claimGen uint64
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
	mu       sync.Mutex
	ops      OpsServices
	sessions map[string]*sessionRecord
	app      *fiber.App
	pubq     chan pubJob
	// overflow holds publications that arrived while the queue
	// buffer was full. A native callback must never wait on a
	// slow sink, so dispatch appends here (under pubmu) instead
	// of blocking or running the sink itself, and the worker
	// drains this list after the channel empties.
	//
	// pubmu guards the accept-vs-drain boundary: overflow, and
	// the stopped transition, change only under it. Sinks never
	// execute under pubmu - the worker detaches queued work and
	// publishes outside the lock - so a slow sink delays records
	// but never blocks a dispatcher.
	pubmu      sync.Mutex
	overflow   []pubJob
	reqBacklog atomic.Int64
	reqDropped atomic.Int64
	// pubPending counts queued-but-unpublished session records.
	// The native side releases its session quota when it fires
	// the teardown notification, not when the audit record lands,
	// so successive sessions can queue more records than the
	// live-session limit allows. Admission control closes that
	// gap: a new session is refused while too many of its
	// predecessors' records are still unpublished, so a stalled
	// sink delays new sessions instead of accumulating memory.
	pubPending atomic.Int64
	// sessionLimit is the native concurrent-session quota; the
	// admission budget scales with it.
	sessionLimit int
	stopped      bool
	done         chan struct{}
	drain        chan struct{}
	drainOnce    sync.Once
}

// pubJob is one deferred publication handed to the worker.
type pubJob struct {
	emit  *opsEmitter
	err   error
	byt   int64
	isReq bool
}

// pubQueueSoftCap is the buffered pre-allocation of the
// publication queue, not a bound: the overflow list in dispatch
// holds whatever exceeds it, so a slow sink never blocks a
// native callback.
const pubQueueSoftCap = 256

// pubRequestBacklogCap bounds the queued records that carry no
// session. Session publications are structurally bounded (each
// session publishes exactly once and the session table has a
// hard limit), but request publications - failed authentications
// - arrive with no session at all, and a stalled sink would let
// them accumulate without limit. Beyond this depth the record is
// dropped and counted, trading a bounded window of lost
// request-audit records for memory safety under overload.
const pubRequestBacklogCap = 4096

// newOpsTracker builds the tracker. The publication queue is
// conceptually unbounded: a callback thread must never run a
// sink (a blocked sink would stall the native reaper and defer
// RC shutdown), so dispatch always hands off without waiting,
// whatever the backlog. Capacity accounting cannot bound the
// backlog - queued records accumulate across successive sessions
// and authentication failures consume no session at all - so the
// worker is the only sink executor and the queue absorbs
// whatever the sinks cannot keep up with. Each job is a few
// pointers; a stalled sink delays records, it does not lose
// them.
func newOpsTracker(sessionLimit int) *opsTracker {
	t := &opsTracker{
		sessions: map[string]*sessionRecord{},
		app: fiber.New(fiber.Config{
			Immutable: true,
		}),
		pubq:         make(chan pubJob, pubQueueSoftCap),
		done:         make(chan struct{}),
		drain:        make(chan struct{}),
		sessionLimit: sessionLimit,
	}
	go func() {
		defer close(t.done)
		for {
			select {
			case job, ok := <-t.pubq:
				if !ok {
					return
				}
				t.run(job)
				// Service the overflow list after every
				// channel job: bursts that exceed the
				// buffer publish as soon as the sink
				// recovers instead of waiting for
				// shutdown. The list is detached under
				// the lock and published outside it, so a
				// slow sink never blocks a dispatcher.
				for _, job := range t.takeOverflow() {
					t.run(job)
				}
			case <-t.drain:
				// Drain mode. The accept-vs-drain boundary:
				// under pubmu the worker marks itself
				// stopped, empties the channel and detaches
				// the overflow list. A dispatch that
				// acquires the mutex before the stopped
				// transition is drained here; one that
				// acquires it after sees stopped (or done,
				// closed only after the unlock) and takes
				// its post-drain path. Sinks run after the
				// unlock, never under the lock.
				t.pubmu.Lock()
				t.stopped = true
				var pending []pubJob
				for {
					select {
					case job, ok := <-t.pubq:
						if !ok {
							t.pubmu.Unlock()
							for _, job := range pending {
								t.run(job)
							}
							return
						}
						pending = append(pending, job)
					default:
						pending = append(pending, t.overflow...)
						t.overflow = nil
						t.pubmu.Unlock()
						for _, job := range pending {
							t.run(job)
						}
						return
					}
				}
			}
		}
	}()
	return t
}

// takeOverflow detaches the overflow list under pubmu. Called by
// the worker only; the caller publishes the returned jobs outside
// the lock.
func (t *opsTracker) takeOverflow() []pubJob {
	t.pubmu.Lock()
	defer t.pubmu.Unlock()
	pending := t.overflow
	t.overflow = nil
	return pending
}

// run publishes one job and releases its reservations: the
// request-backlog slot and the session admission credit the
// record was holding.
func (t *opsTracker) run(job pubJob) {
	job.emit.publish(job.err, job.byt)
	if job.isReq {
		t.reqBacklog.Add(-1)
		return
	}
	t.pubPending.Add(-1)
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
		if n := t.reqDropped.Load(); n > 0 {
			// Overload during shutdown: records without a session
			// were dropped once the request backlog hit its cap.
			// Surfaced once here rather than per record.
			fmt.Fprintf(os.Stderr, "rdma-rc: dropped %d request audit records at the publication backlog cap\n", n)
		}
	})
}

// dispatch hands a publication to the worker without ever
// blocking the caller or running a sink on the calling thread:
// the native reaper invokes terminal callbacks, and an
// operational sink can block indefinitely, which must never
// stall reaping or RC shutdown. The channel buffer absorbs the
// common case; when it is full the job goes to the overflow
// list, which the worker drains after the channel. After the
// worker exits (shutdown drain), a session-terminal job is
// published inline - its producer (Close, after quiescing
// native producers) is not a native callback - while request
// publications are dropped by publishRequest before reaching
// here.
func (t *opsTracker) dispatch(job pubJob) {
	// The pubmu critical section is the accept-vs-drain boundary:
	// the drain sweep marks stopped under the same lock, so an
	// append either lands before the sweep (and is drained) or
	// observes stopped and runs inline.
	t.pubmu.Lock()
	if t.stopped {
		t.pubmu.Unlock()
		t.run(job)
		return
	}
	select {
	case t.pubq <- job:
		t.pubmu.Unlock()
	default:
		t.overflow = append(t.overflow, job)
		t.pubmu.Unlock()
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

// register captures the operational context of a successfully
// created session so the terminal outcome can be published later.
// The strings are cloned: they originate from the request's pooled
// header buffer, which does not survive the response.
//
// The account is captured by value but its string fields still
// reference request storage on some IAM paths, so the sink-relevant
// identity is cloned as well.
// errPubBacklog reports admission refusal: too many earlier
// sessions still have unpublished audit records, so accepting
// another would grow the publication backlog without bound while
// a sink is stalled.
var errPubBacklog = errors.New("publication backlog at capacity")

func (t *opsTracker) register(sessionID string, acct auth.Account,
	region, bucket, key string, isPut bool, start time.Time) error {
	// Admission control: the native quota counts live sessions,
	// but teardown notifications fire before the audit records
	// land, so session turnover can queue more records than the
	// quota bounds. Refusing new sessions while the unpublished
	// backlog reaches the quota turns a stalled sink into
	// latency (the client retries) instead of unbounded memory.
	// The check and the credit acquisition share the session
	// mutex so concurrent registrations cannot each observe the
	// same headroom and overshoot together. Unbounded when
	// sessionLimit is unset (tests).
	if t.sessionLimit > 0 {
		t.mu.Lock()
		full := t.pubPending.Load() >= int64(t.sessionLimit)
		if !full {
			t.pubPending.Add(1)
		}
		t.mu.Unlock()
		if full {
			return errPubBacklog
		}
	} else {
		t.mu.Lock()
		t.pubPending.Add(1)
		t.mu.Unlock()
	}
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
	return nil
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
	if _, ok := t.sessions[sessionID]; ok {
		delete(t.sessions, sessionID)
		// Release the admission credit the registration took:
		// no callback will ever publish for this entry, so
		// leaving the credit held would permanently shrink the
		// admission budget.
		t.pubPending.Add(-1)
	}
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

// reservation couples the emitter with the generation of the
// claim that owns it: release and publication validate the
// generation, so a stale claim cannot act on a newer one.
type reservation struct {
	emit *opsEmitter
	gen  uint64
}

// reserve marks a session record as owned by its request path: the
// teardown callback skips a reserved record because the request
// path publishes the real outcome itself. Returns the reservation
// when the record exists and was not reserved yet.
func (t *opsTracker) reserve(sessionID string) *reservation {
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
	rec.claimGen++
	return &reservation{emit: rec.emit, gen: rec.claimGen}
}

// releaseReservation returns a reserved record to the pool
// without publishing: the transfer claim it was held for rolled
// back, so the session lives on and the next claimant (another
// READY, or the reaper) must still find an unreserved record.
// If the native session already tore down while the record was
// reserved (terminal stashed), the session is gone: consume the
// record and publish the stashed outcome, since no second
// callback will arrive.
func (t *opsTracker) releaseReservation(sessionID string, rsv *reservation) {
	if t == nil {
		return
	}
	t.mu.Lock()
	rec, ok := t.sessions[sessionID]
	if !ok || !rec.reserved || rsv == nil || rec.claimGen != rsv.gen {
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
func (t *opsTracker) publishReserved(sessionID string, rsv *reservation, err error, bytes int64) {
	if t == nil {
		return
	}
	t.mu.Lock()
	rec, ok := t.sessions[sessionID]
	// Ownership check: only the current reservation generation
	// publishes. A stale claim (its reservation was released or
	// superseded) must not delete or publish the current
	// owner's record.
	if !ok || rsv == nil || rec.claimGen != rsv.gen {
		t.mu.Unlock()
		return
	}
	delete(t.sessions, sessionID)
	t.mu.Unlock()
	t.dispatch(pubJob{emit: rsv.emit, err: err, byt: bytes})
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
// These requests run outside the admission barrier (verification
// may block on uncancellable IAM lookups), so a record produced
// after the shutdown drain began is dropped rather than published
// into closed sinks.
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
	// The accept-vs-drain boundary decides: a record accepted
	// before the drain sweep is published by the worker; one
	// that arrives after is dropped here (not published inline),
	// because a request publication has no owner left to
	// guarantee its sinks are still open.
	t.dispatchOrDrop(pubJob{emit: emit, err: err})
}

// dispatchOrDrop is dispatch with request-publication semantics:
// after the worker stopped through the drain the job is dropped
// instead of published inline, and the queued backlog of session-
// less records is capped so a stalled sink cannot accumulate them
// without bound.
func (t *opsTracker) dispatchOrDrop(job pubJob) {
	t.pubmu.Lock()
	if t.stopped {
		t.pubmu.Unlock()
		return
	}
	if t.reqBacklog.Load() >= pubRequestBacklogCap {
		// Overload policy: drop and count. The record carries no
		// session and no owner can reissue it. Incremented under
		// pubmu so Shutdown's report (also under pubmu via the
		// drain's stopped transition) cannot miss it.
		t.reqDropped.Add(1)
		t.pubmu.Unlock()
		return
	}
	job.isReq = true
	t.reqBacklog.Add(1)
	select {
	case t.pubq <- job:
		t.pubmu.Unlock()
	default:
		t.overflow = append(t.overflow, job)
		t.pubmu.Unlock()
	}
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
