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
<<<<<<< Updated upstream
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
// either express or implied. See the License for the specific
// language governing permissions and limitations under the
// License.
=======
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
>>>>>>> Stashed changes

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

// The tests exercise the tracker's ownership semantics: the session
// table is the single source of truth for who may publish, so the
// assertions watch table membership rather than the emission itself
// (emission is a no-op without operational services wired in).

func TestOpsTrackerExpiryPublication(t *testing.T) {
	tr := newOpsTracker()
	tr.register("sess-1", auth.Account{Access: "ak"}, "us-east-1",
		"bkt", "obj", false, time.Now())
	if got := len(tr.sessions); got != 1 {
		t.Fatalf("registered sessions = %d, want 1", got)
	}

	// The reaper path claims and removes the session.
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

func TestOpsTrackerRequestPathClaims(t *testing.T) {
	tr := newOpsTracker()
	tr.register("sess-2", auth.Account{Access: "ak"}, "us-east-1",
		"bkt", "obj", true, time.Now())

	// READY completion claims the publication first.
	tr.publishClaimed("sess-2", nil, 4096)
	if got := len(tr.sessions); got != 0 {
		t.Fatalf("request path left session: %d", got)
	}

	// The late reaper callback finds nothing left.
	tr.onTerminal(rcserver.TerminalEvent{SessionID: "sess-2"})
	if got := len(tr.sessions); got != 0 {
		t.Fatalf("reaper re-added session: %d", got)
	}
}

func TestOpsTrackerUnknownSession(t *testing.T) {
	tr := newOpsTracker()
	// Unknown sessions and the nil tracker are silent no-ops.
	var nilTracker *opsTracker
	nilTracker.publishClaimed("ghost", nil, 1)
	nilTracker.onTerminal(rcserver.TerminalEvent{SessionID: "ghost"})
	tr.publishClaimed("ghost", nil, 1)
	tr.onTerminal(rcserver.TerminalEvent{SessionID: "ghost"})
	if got := len(tr.sessions); got != 0 {
		t.Fatalf("ghost session materialized: %d", got)
	}
}

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
}
