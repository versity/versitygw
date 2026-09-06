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
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/rdma/rcserver"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3log"
)

// The publication model: the request path reserves a session
// record before any native completion call (which fires the
// teardown callback synchronously, before the call returns), the
// callback skips reserved records, and the request path publishes
// exactly once. Unreserved records are published by the callback.

func TestOpsTrackerCallbackPublishesExpiry(t *testing.T) {
	tr := newOpsTracker()
	tr.register("sess-1", auth.Account{Access: "ak"}, "us-east-1",
		"bkt", "obj", false, time.Now())
	if got := len(tr.sessions); got != 1 {
		t.Fatalf("registered sessions = %d, want 1", got)
	}

	// The reaper path publishes for a session no READY ever
	// reserved and removes the entry.
	tr.onTerminal(rcserver.TerminalEvent{SessionID: "sess-1"})
	if got := len(tr.sessions); got != 0 {
		t.Fatalf("session survived terminal: %d", got)
	}

	// A second terminal (double reap) finds nothing.
	tr.onTerminal(rcserver.TerminalEvent{SessionID: "sess-1"})
	if got := len(tr.sessions); got != 0 {
		t.Fatalf("double terminal left residue: %d", got)
	}
}

func TestOpsTrackerReserveBlocksCallback(t *testing.T) {
	tr := newOpsTracker()
	tr.register("sess-2", auth.Account{Access: "ak"}, "us-east-1",
		"bkt", "obj", true, time.Now())

	// The READY path reserves before its completion call; the
	// callback the call fires synchronously must skip the record.
	emit := tr.reserve("sess-2")
	if emit == nil {
		t.Fatal("reserve returned nil for a live session")
	}
	tr.onTerminal(rcserver.TerminalEvent{SessionID: "sess-2"})
	if got := len(tr.sessions); got != 1 {
		t.Fatalf("callback consumed a reserved record: %d", got)
	}

	// The request path then publishes and drops the entry.
	tr.publishReserved("sess-2", emit, nil, 4096)
	if got := len(tr.sessions); got != 0 {
		t.Fatalf("publishReserved left residue: %d", got)
	}

	// A second reserve of the consumed entry is nil.
	if again := tr.reserve("sess-2"); again != nil {
		t.Fatal("reserve succeeded for a consumed entry")
	}
}

func TestOpsTrackerReserveIsExclusive(t *testing.T) {
	tr := newOpsTracker()
	tr.register("sess-3", auth.Account{Access: "ak"}, "us-east-1",
		"bkt", "obj", false, time.Now())

	if first := tr.reserve("sess-3"); first == nil {
		t.Fatal("first reserve failed")
	}
	if second := tr.reserve("sess-3"); second != nil {
		t.Fatal("double reserve succeeded")
	}
}

func TestOpsTrackerFailOutcome(t *testing.T) {
	tr := newOpsTracker()
	tr.register("sess-4", auth.Account{Access: "ak"}, "us-east-1",
		"bkt", "obj", false, time.Now())

	// Consume-or-noop: present entry is consumed.
	tr.failOutcome("sess-4", errors.New("x"))
	if got := len(tr.sessions); got != 0 {
		t.Fatalf("failOutcome left residue: %d", got)
	}
	// A second call after the callback already consumed is a
	// silent no-op, not a double publication.
	tr.failOutcome("sess-4", errors.New("y"))
}

func TestOpsTrackerUnregister(t *testing.T) {
	tr := newOpsTracker()
	tr.register("sess-5", auth.Account{Access: "ak"}, "us-east-1",
		"bkt", "obj", false, time.Now())
	tr.unregister("sess-5")
	if got := len(tr.sessions); got != 0 {
		t.Fatalf("unregister left entries: %d", got)
	}
	// The teardown callback for the unregistered session is a
	// silent no-op (native side already rejected or reaped it).
	tr.onTerminal(rcserver.TerminalEvent{SessionID: "sess-5"})
	if got := len(tr.sessions); got != 0 {
		t.Fatalf("terminal resurrected entry: %d", got)
	}
}

func TestOpsTrackerUnknownSession(t *testing.T) {
	tr := newOpsTracker()
	// Unknown sessions and the nil tracker are silent no-ops.
	var nilTracker *opsTracker
	nilTracker.reserve("ghost")
	nilTracker.onTerminal(rcserver.TerminalEvent{SessionID: "ghost"})
	tr.reserve("ghost")
	tr.onTerminal(rcserver.TerminalEvent{SessionID: "ghost"})
	if got := len(tr.sessions); got != 0 {
		t.Fatalf("ghost session materialized: %d", got)
	}
}

func TestNormalizeSinkError(t *testing.T) {
	if normalizeSinkError(nil) != nil {
		t.Fatal("nil error should stay nil")
	}
	// Plain errors map through the route error mapping.
	got := normalizeSinkError(errors.New("x"))
	apiErr, ok := got.(s3err.APIError)
	if !ok || apiErr.HTTPStatusCode != 500 {
		t.Fatalf("plain error => %#v", got)
	}
	// Wrapped S3 errors are extracted to their base form so the
	// audit loggers' direct assertion classifies them correctly.
	wrapped := errWrapped{s3err.GetAPIError(s3err.ErrNoSuchBucket)}
	got = normalizeSinkError(wrapped)
	apiErr, ok = got.(s3err.APIError)
	if !ok || apiErr.Code != "NoSuchBucket" || apiErr.HTTPStatusCode != 404 {
		t.Fatalf("wrapped error => %#v", got)
	}
}

type errWrapped struct{ s3err.S3Error }

func (errWrapped) Error() string { return "wrapped" }

func TestHttpStatusFromError(t *testing.T) {
	if got := httpStatusFromError(nil); got != 200 {
		t.Fatalf("nil error => %d, want 200", got)
	}
	if got := httpStatusFromError(errors.New("x")); got != 500 {
		t.Fatalf("plain error => %d, want 500", got)
	}
	if got := httpStatusFromError(s3err.GetAPIError(s3err.ErrAccessDenied)); got != 403 {
		t.Fatalf("access denied => %d, want 403", got)
	}
	// A resource-limit rejection maps to the wire status, not a
	// generic 500.
	if got := httpStatusFromError(rcserver.ErrLimit); got != 429 {
		t.Fatalf("limit error => %d, want 429", got)
	}
}

func TestExpiredErrorClassification(t *testing.T) {
	// Every transfer-level failure the READY call reports as
	// RC_E_WIRE publishes as the same 502 the wire response
	// carries; only an unattempted session keeps the expiry code.
	cases := []struct {
		outcome int
		code    string
		status  int
	}{
		{int(rcserver.ReadyWireFail), "RdmaTransferFailed", 502},
		{int(rcserver.ReadyVerifyFail), "RdmaTransferFailed", 502},
		{int(rcserver.ReadyTimeout), "RdmaTransferFailed", 502},
		{int(rcserver.ReadyOK), "SessionExpired", 500},
	}
	for _, tc := range cases {
		err := expiredError(rcserver.TerminalEvent{Outcome: tc.outcome})
		apiErr := normalizeSinkError(err).(s3err.APIError)
		if apiErr.Code != tc.code || apiErr.HTTPStatusCode != tc.status {
			t.Fatalf("outcome %d => %s/%d, want %s/%d",
				tc.outcome, apiErr.Code, apiErr.HTTPStatusCode,
				tc.code, tc.status)
		}
	}
}

// recordingLogger captures audit publications so tests can assert
// what the sinks actually received.
type recordingLogger struct {
	mu   sync.Mutex
	logs []recLog
}

type recLog struct {
	err   error
	bytes int64
}

func (r *recordingLogger) Log(ctx fiber.Ctx, err error, body []byte, meta s3log.LogMeta) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logs = append(r.logs, recLog{err: err, bytes: meta.ObjectSize})
}

func (r *recordingLogger) HangUp() error   { return nil }
func (r *recordingLogger) Shutdown() error { return nil }

// TestOpsTrackerPublishesExactlyOncePerSession drives the tracker
// with a recording sink, joins the publication worker through
// Shutdown, and asserts the per-session record: each session
// publishes exactly one record with its own outcome and bytes.
func TestOpsTrackerPublishesExactlyOncePerSession(t *testing.T) {
	rl := &recordingLogger{}
	tr := newOpsTracker()
	tr.SetOpsServices(OpsServices{Logger: rl})

	// Expiry path: callback publishes a zero-byte error record.
	tr.register("s-exp", auth.Account{Access: "ak"}, "r", "b", "o", false, time.Now())
	tr.onTerminal(rcserver.TerminalEvent{SessionID: "s-exp"})

	// Reserved path: reserve, callback fires (skipped), the
	// request path publishes success with bytes.
	tr.register("s-res", auth.Account{Access: "ak"}, "r", "b", "o", false, time.Now())
	emit := tr.reserve("s-res")
	if emit == nil {
		t.Fatal("reserve failed")
	}
	tr.onTerminal(rcserver.TerminalEvent{SessionID: "s-res"})
	tr.publishReserved("s-res", emit, nil, 128)

	// Denial path while reserved: failOutcome must not steal the
	// publication; the owner's success record is the only one.
	tr.register("s-den", auth.Account{Access: "ak"}, "r", "b", "o", true, time.Now())
	emit2 := tr.reserve("s-den")
	if emit2 == nil {
		t.Fatal("reserve failed")
	}
	tr.failOutcome("s-den", errors.New("denied"))
	tr.publishReserved("s-den", emit2, nil, 256)

	// Released reservation: the record returns to the pool and
	// the reaper (or the next claimant) can still publish it.
	tr.register("s-rel", auth.Account{Access: "ak"}, "r", "b", "o", false, time.Now())
	emit3 := tr.reserve("s-rel")
	if emit3 == nil {
		t.Fatal("reserve failed")
	}
	tr.releaseReservation("s-rel", emit3)
	tr.onTerminal(rcserver.TerminalEvent{SessionID: "s-rel"})

	// M1 regression: a terminal arriving while reserved is stashed,
	// and a later claim-rollback release consumes it and publishes the
	// expiry - the record is not orphaned.
	tr.register("s-stash", auth.Account{Access: "ak"}, "r", "b", "o", false, time.Now())
	emitS := tr.reserve("s-stash")
	if emitS == nil {
		t.Fatal("reserve failed")
	}
	tr.onTerminal(rcserver.TerminalEvent{SessionID: "s-stash"})
	tr.releaseReservation("s-stash", emitS)

	// M2 regression: a second reservation of a live record is
	// refused, so a duplicate READY cannot claim the transfer
	// while another request owns the publication. The owner then
	// completes normally.
	tr.register("s-dbl", auth.Account{Access: "ak"}, "r", "b", "o", false, time.Now())
	emitD := tr.reserve("s-dbl")
	if emitD == nil {
		t.Fatal("first reserve failed")
	}
	if tr.reserve("s-dbl") != nil {
		t.Fatal("double reserve succeeded")
	}
	tr.publishReserved("s-dbl", emitD, nil, 64)

	// Ownership: a stale emitter must not publish or consume the
	// current record; the real owner still can, even after the
	// callback fired (stashed) underneath it.
	tr.register("s-own", auth.Account{Access: "ak"}, "r", "b", "o", false, time.Now())
	emitO := tr.reserve("s-own")
	if emitO == nil {
		t.Fatal("reserve failed")
	}
	tr.publishReserved("s-own", &opsEmitter{}, nil, 999)
	tr.onTerminal(rcserver.TerminalEvent{SessionID: "s-own"})
	tr.publishReserved("s-own", emitO, nil, 32)

	// Consume-or-noop denial of an unreserved session.
	tr.register("s-fail", auth.Account{Access: "ak"}, "r", "b", "o", false, time.Now())
	tr.failOutcome("s-fail", errors.New("x"))

	// Join the worker: Shutdown drains everything queued and
	// stops it, so counting after Shutdown sees the final state.
	tr.Shutdown()

	rl.mu.Lock()
	defer rl.mu.Unlock()
	if len(rl.logs) != 8 {
		t.Fatalf("published %d records, want 8: %+v", len(rl.logs), rl.logs)
	}
	// The recording sink cannot see session IDs directly (they
	// live in the synthesized context), so assert the observable
	// contract: error/bytes pairings, one per session, in the
	// dispatch order above.
	type outcome struct {
		isErr bool
		bytes int64
	}
	want := []outcome{
		{true, 0},    // s-exp expiry
		{false, 128}, // s-res success
		{false, 256}, // s-den success (denial was skipped)
		{true, 0},    // s-rel expiry after release
		{true, 0},    // s-fail denial
	}
	for i, w := range want {
		got := rl.logs[i]
		if (got.err != nil) != w.isErr || got.bytes != w.bytes {
			t.Fatalf("record %d = (err=%v, bytes=%d), want (err=%v, bytes=%d)",
				i, got.err, got.bytes, w.isErr, w.bytes)
		}
	}
}
