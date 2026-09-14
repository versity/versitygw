// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an "AS
// IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied.  See the License for the specific language
// governing permissions and limitations under the License.

//go:build linux && amd64

package rcobj

import (
	"context"
	"sync"
	"testing"
)

// TestEligibilityFailClosed pins the C3 properties: connection
// replacement turns admission negative, and no bytes are admitted
// before a fresh probe succeeds.
func TestEligibilityFailClosed(t *testing.T) {
	var mu sync.Mutex
	gen := uint64(1)
	probes := 0
	e := NewEligibility(func(ctx context.Context) (uint64, bool, error) {
		mu.Lock()
		defer mu.Unlock()
		probes++
		return gen, true, nil
	})
	if err := e.Probe(context.Background()); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !e.Admit(1) {
		t.Fatal("gen 1 must be admitted after positive probe")
	}

	// Replacement: fail-closed until re-probe.
	mu.Lock()
	gen = 2
	mu.Unlock()
	e.OnConnectionChange(2)
	if e.Admit(2) {
		t.Fatal("replacement generation admitted before re-probe")
	}
	if e.Admit(1) {
		t.Fatal("stale generation admitted after replacement")
	}
	if err := e.Probe(context.Background()); err != nil {
		t.Fatalf("re-probe: %v", err)
	}
	if !e.Admit(2) {
		t.Fatal("new generation not admitted after fresh probe")
	}
	mu.Lock()
	defer mu.Unlock()
	if probes != 2 {
		t.Fatalf("probes = %d want 2", probes)
	}
}

// TestEligibilityNegativeProbe pins the negative path: a declining
// endpoint keeps admission closed even as generations change.
func TestEligibilityNegativeProbe(t *testing.T) {
	e := NewEligibility(func(ctx context.Context) (uint64, bool, error) {
		return 1, false, nil
	})
	if err := e.Probe(context.Background()); err == nil {
		t.Fatal("declining probe must error")
	}
	if e.Admit(1) {
		t.Fatal("declined endpoint admitted")
	}
}
