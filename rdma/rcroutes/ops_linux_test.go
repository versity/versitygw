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
	"testing"
	"time"

	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/rdma/rcserver"
	"github.com/versity/versitygw/s3err"
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
