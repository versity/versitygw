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
	"sync/atomic"
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
	// invals counts connection changes. A probe snapshots the
	// count before it runs and only publishes its result when
	// the count still matches: evidence gathered on a transport
	// that was replaced mid-probe is stale and must not lift
	// the negative state.
	invals uint64
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
	e.mu.Lock()
	start := e.invals
	e.mu.Unlock()
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
	if e.invals != start {
		// The transport was replaced while this probe was in
		// flight: its evidence predates the replacement and
		// must not re-admit. The layer stays negative until a
		// fresh probe on the new transport succeeds.
		e.negative = true
		return errors.New("rcobj: transport replaced during probe")
	}
	e.negative = false
	e.connGen = gen
	return nil
}

// Admit reports whether the current transport generation may carry
// admitted bytes. gen comes from the connection identity captured
// at the send boundary of each request; when the caller has no
// per-connection identity (raw-socket probe transport), pass Gen
// and the layer decides on its fail-closed state alone.
func (e *Eligibility) Admit(gen uint64) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.negative {
		return false
	}
	if gen != e.connGen {
		// The caller rides a transport the probe never saw:
		// fail closed until fresh evidence arrives.
		return false
	}
	return e.connGen != 0
}

// OnConnectionChange invalidates admission when the transport is
// replaced (pool rotation, redirect, redial). The next transfer
// must re-probe before any admitted bytes flow.
func (e *Eligibility) OnConnectionChange(newGen uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.negative = true
	e.invals++
	e.connGen = newGen
}

// Admitted reports whether the layer currently holds positive
// evidence: the one question a PREPARE needs before the wire.
func (e *Eligibility) Admitted() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return !e.negative && e.connGen != 0
}

// Gen exposes the admitted generation (0 when none).
func (e *Eligibility) Gen() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.connGen
}

// HTTPProbe builds a ProbeFn from an http client and endpoint: it
// issues a one-byte ranged GET of the probe object and treats a
// direct 2xx as the admission signal. The probe object path
// follows the object API convention (<bucket>/<key>); pass the
// base endpoint and the bucket/key the deployment provisions for
// admission. Redirects are refused here, not delegated to the
// client, because a redirect means the endpoint that answered is
// not the one the transfer would use.
func HTTPProbe(client *http.Client, endpoint, bucket, key string) ProbeFn {
	// The probe must not silently follow a redirect: keep the
	// caller's transport while pinning the redirect policy.
	c := client
	if c == nil {
		c = http.DefaultClient
	}
	return func(ctx context.Context) (uint64, bool, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			strings.TrimSuffix(endpoint, "/")+probeObjectPath(bucket, key), nil)
		if err != nil {
			return 0, false, err
		}
		req.Header.Set("Range", "bytes=0-0")
		// Redirects are negative evidence: stop before following.
		base := *c
		noRedirect := base
		noRedirect.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
		resp, err := noRedirect.Do(req)
		if err != nil {
			return 0, false, err
		}
		defer resp.Body.Close()
		gen := probeGenCounter.Add(1)
		ok := resp.StatusCode >= 200 && resp.StatusCode < 300
		return gen, ok, nil
	}
}

// probeGenCounter distinguishes successful probes on transports
// the package cannot otherwise identify: each probe attempt gets
// a fresh value, so a later OnConnectionChange (which reports 0)
// still turns the layer negative until the next probe succeeds.
var probeGenCounter atomic.Uint64

// A 3xx on the probe or any admitted exchange is a transport
// replacement, not an upgrade: callers report it through
// OnConnectionChange so the layer turns negative (fail-closed)
// until a fresh probe succeeds.
