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
	"errors"
	"net/http"
	"strings"
	"sync"
)

// Eligibility is the v2 admission layer (port plan section 7, C3):
// admission evidence comes from a one-byte GET probe through the
// real API, capability headers are captured by the PREPARE callback,
// and the wrapper turns negative (fail-closed) on connection
// replacement or redirect until a fresh probe succeeds. No admitted
// bytes flow before a positive probe.
type Eligibility struct {
	mu           sync.Mutex
	probe        ProbeFn
	negative     bool
	lastProbeErr error
	// conns tracks the physical transport identity of the last
	// admitted control exchange so replacement invalidates.
	connGen uint64
}

// ProbeFn performs the one-byte GET probe through the real API and
// reports the transport identity the probe rode on. Production
// wires the http round trip; tests script it.
type ProbeFn func(ctx context.Context) (connGen uint64, ok bool, err error)

// NewEligibility creates the v2 admission layer.
func NewEligibility(probe ProbeFn) *Eligibility {
	return &Eligibility{probe: probe}
}

// Probe runs the admission probe once per generation: a positive
// verdict admits the current transport generation, any failure or
// replacement turns the layer negative until a fresh probe
// succeeds.
func (e *Eligibility) Probe(ctx context.Context) error {
	gen, ok, err := e.probe(ctx)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lastProbeErr = err
	if err != nil || !ok {
		e.negative = true
		if err != nil {
			return err
		}
		return errors.New("rcobj: endpoint declined v2 admission")
	}
	e.negative = false
	e.connGen = gen
	return nil
}

// Admit reports whether the current transport generation may carry
// admitted bytes. gen comes from the connection identity captured
// at the send boundary of each request.
func (e *Eligibility) Admit(gen uint64) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.negative {
		return false
	}
	return gen == e.connGen && e.connGen != 0
}

// OnConnectionChange invalidates admission when the transport is
// replaced (pool rotation, redirect, redial). The next transfer
// must re-probe before any admitted bytes flow.
func (e *Eligibility) OnConnectionChange(newGen uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.negative = true
	e.connGen = newGen
}

// Gen exposes the admitted generation (0 when none).
func (e *Eligibility) Gen() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.connGen
}

// HTTPProbe builds a ProbeFn from an http client and endpoint: it
// issues the one-byte GET and treats transport success as the
// admission signal; the PREPARE callback's capability headers are
// the per-transfer verdict.
func HTTPProbe(client *http.Client, endpoint string) ProbeFn {
	return func(ctx context.Context) (uint64, bool, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			strings.TrimSuffix(endpoint, "/")+"/probe", nil)
		if err != nil {
			return 0, false, err
		}
		req.Header.Set("Range", "bytes=0-0")
		resp, err := client.Do(req)
		if err != nil {
			return 0, false, err
		}
		defer resp.Body.Close()
		// Only a real API response (2xx) is positive evidence:
		// redirects and errors mean the endpoint did not serve
		// the object API this transfer path needs.
		return transportGen(resp), resp.StatusCode >= 200 && resp.StatusCode < 300, nil
	}
}

// transportGen derives a stable identity from the response's
// transport connection, when the runtime exposes one.
func transportGen(resp *http.Response) uint64 {
	if resp == nil {
		return 0
	}
	if tc, ok := resp.Request.Context().Value(connGenKey{}).(uint64); ok {
		return tc
	}
	return 0
}

type connGenKey struct{}

// A 3xx on the probe or any admitted exchange is a transport
// replacement, not an upgrade: callers report it through
// OnConnectionChange so the layer turns negative (fail-closed)
// until a fresh probe succeeds.
