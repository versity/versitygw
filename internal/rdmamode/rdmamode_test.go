// Copyright 2026 Versity Software
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

package rdmamode

import (
	"math"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/versity/versitygw/backend"
)

func TestModeMatrix(t *testing.T) {
	tests := []struct {
		name           string
		rdmaIP         string
		rcEnable       bool
		wantV1, wantV2 bool
	}{
		{"neither", "", false, false, false},
		{"v1 only", "192.0.2.1", false, true, false},
		{"v2 only", "", true, false, true},
		{"both", "192.0.2.1", true, true, true},
		{"v1 ip with whitespace", "  ", false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v1, v2 := Mode(tt.rdmaIP, tt.rcEnable)
			if v1 != tt.wantV1 || v2 != tt.wantV2 {
				t.Fatalf("Mode(%q, %v) = (%v, %v), want (%v, %v)",
					tt.rdmaIP, tt.rcEnable,
					v1, v2, tt.wantV1, tt.wantV2)
			}
		})
	}
}

func TestV1ValidationCQDepthBoundary(t *testing.T) {
	// The v1 tunable narrows to uint32; the boundary itself must
	// pass and the first value beyond it must fail.
	base := V1Settings{
		Port: 19100, RetryCount: 2, PoolBufSize: 1024, PoolBufCnt: 16,
		NumDCIs: 8, TunablesSet: true,
	}
	base.CQDepth = math.MaxUint32
	if msg := V1ValidationError(base); msg != "" {
		t.Fatalf("MaxUint32 rejected: %q", msg)
	}
	base.CQDepth = math.MaxUint32 + 1
	if msg := V1ValidationError(base); msg == "" {
		t.Fatal("MaxUint32+1 accepted")
	}
}

func TestV1ValidationError(t *testing.T) {
	if msg := V1ValidationError(V1Settings{
		Port: 99999, RetryCount: 99, PoolBufSize: -1,
	}); msg == "" {
		t.Fatal("expected an error for invalid settings")
	}
	if msg := V1ValidationError(V1Settings{
		Port: 19100, RetryCount: 2, PoolBufSize: 1024, PoolBufCnt: 16,
	}); msg != "" {
		t.Fatalf("valid settings reported %q", msg)
	}
}

// sequenceRC records when Close starts and finishes, so tests
// can prove the backend waits for it.
type sequenceRC struct {
	mu       sync.Mutex
	started  int
	finished int
	release  chan struct{}
}

func (r *sequenceRC) Close() {
	r.mu.Lock()
	r.started++
	r.mu.Unlock()
	<-r.release
	r.mu.Lock()
	r.finished++
	r.mu.Unlock()
}

func (r *sequenceRC) counts() (started, finished int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.started, r.finished
}

// sequenceBackend records Shutdown calls and whether the RC close
// had finished when each ran.
type sequenceBackend struct {
	backend.BackendUnsupported
	rc        *sequenceRC
	mu        sync.Mutex
	shutdowns int
	rcDone    bool
}

func (b *sequenceBackend) Shutdown() {
	started, finished := b.rc.counts()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.shutdowns++
	b.rcDone = started >= 1 && finished >= 1
}

func TestBackendShutdownClosesRCFirst(t *testing.T) {
	rc := &sequenceRC{release: make(chan struct{})}
	be := &sequenceBackend{rc: rc}
	wrapped := WrapBackendShutdownAfterRC(be, rc)

	done := make(chan struct{})
	go func() {
		wrapped.Shutdown()
		close(done)
	}()

	// While RC close is blocked, the backend must not shut down.
	// Wait for the close to start; goroutine scheduling needs a
	// moment even though the channel blocks it from finishing.
	started := make(chan struct{})
	go func() {
		for {
			s, _ := rc.counts()
			if s >= 1 {
				close(started)
				return
			}
			runtime.Gosched()
		}
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("RC close never started")
	}
	be.mu.Lock()
	early := be.shutdowns
	be.mu.Unlock()
	if early != 0 {
		t.Fatalf("backend shut down %d times before RC close finished", early)
	}

	close(rc.release)
	<-done

	be.mu.Lock()
	shutdowns, rcDone := be.shutdowns, be.rcDone
	be.mu.Unlock()
	if shutdowns != 1 {
		t.Fatalf("backend shutdown %d times, want 1", shutdowns)
	}
	if !rcDone {
		t.Fatal("backend shut down before RC close finished")
	}
}

func TestBackendShutdownExactlyOnce(t *testing.T) {
	// The gateway lifecycle and a startup rollback may both call
	// Shutdown on the wrapped backend; every step must run once.
	rc := &sequenceRC{release: make(chan struct{})}
	close(rc.release)
	be := &sequenceBackend{rc: rc}
	wrapped := WrapBackendShutdownAfterRC(be, rc)

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wrapped.Shutdown()
		}()
	}
	wg.Wait()

	s, f := rc.counts()
	if s != 1 || f != 1 {
		t.Fatalf("RC close started %d, finished %d; want 1, 1", s, f)
	}
	be.mu.Lock()
	shutdowns := be.shutdowns
	be.mu.Unlock()
	if shutdowns != 1 {
		t.Fatalf("backend shutdown %d times, want exactly 1", shutdowns)
	}
}

func TestShutdownOnceBackendClosesOnce(t *testing.T) {
	// A rollback defer and the gateway lifecycle can both call
	// Shutdown on a bare backend; the once wrapper must collapse
	// them into a single close.
	rc := &sequenceRC{release: make(chan struct{})}
	close(rc.release)
	be := &sequenceBackend{rc: rc}
	wrapped := WrapShutdownOnce(be)

	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wrapped.Shutdown()
		}()
	}
	wg.Wait()

	be.mu.Lock()
	shutdowns := be.shutdowns
	be.mu.Unlock()
	if shutdowns != 1 {
		t.Fatalf("backend shutdown %d times, want 1", shutdowns)
	}
}

func TestRCWrapperChainsOntoOnceBackend(t *testing.T) {
	// The gateway wraps the base backend once, then the RC
	// wrapper on top. The RC close runs before the delegated
	// shutdown, and repeated calls through either layer reach
	// the base backend exactly once.
	rc := &sequenceRC{release: make(chan struct{})}
	close(rc.release)
	base := &sequenceBackend{rc: rc}
	onceWrapped := WrapShutdownOnce(base)
	rcWrapped := WrapBackendShutdownAfterRC(onceWrapped, rc)

	rcWrapped.Shutdown()
	rcWrapped.Shutdown()
	onceWrapped.Shutdown()

	s, f := rc.counts()
	if s != 1 || f != 1 {
		t.Fatalf("RC close started %d, finished %d; want 1, 1", s, f)
	}
	base.mu.Lock()
	shutdowns := base.shutdowns
	base.mu.Unlock()
	if shutdowns != 1 {
		t.Fatalf("base backend shutdown %d times, want 1", shutdowns)
	}
}
