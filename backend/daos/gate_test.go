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

//go:build linux && cgo && daos

package daos

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// gateCloseWaitsForReaders checks that dfsFS.Close, which takes the
// write lock, does not run its release callbacks while a reader that
// holds the read lock is still inside its call.
func TestGateCloseWaitsForReaders(t *testing.T) {
	f := &dfsFS{}
	var releaseRan atomic.Bool
	var inRead atomic.Bool

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		f.gate.RLock()
		inRead.Store(true)
		// hold the read side like a cgo call in flight
		time.Sleep(150 * time.Millisecond)
		f.gate.RUnlock()
	}()

	// wait until the reader holds the lock
	deadline := time.Now().Add(2 * time.Second)
	for !inRead.Load() {
		if time.Now().After(deadline) {
			t.Fatal("reader never started")
		}
		time.Sleep(time.Millisecond)
	}

	closed := make(chan struct{})
	go func() {
		f.gate.Lock()
		releaseRan.Store(true)
		f.gate.Unlock()
		close(closed)
	}()

	select {
	case <-closed:
		t.Fatal("write lock acquired while reader still held the read lock")
	case <-time.After(50 * time.Millisecond):
		// expected: Close must still be waiting
	}
	if releaseRan.Load() {
		t.Fatal("release ran before the reader returned")
	}
	wg.Wait()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("write lock never acquired after readers drained")
	}
}
