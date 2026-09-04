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

// Package rdmamode resolves which RDMA paths a gateway runs and
// orders their shutdown. It is deliberately free of cgo so the
// behavior is testable on any build platform.
package rdmamode

import (
	"fmt"
	"math"
	"strings"
	"sync"

	"github.com/versity/versitygw/backend"
)

// Mode resolves which RDMA paths run: the cuObject v1 backend
// follows the legacy --rdma-ip contract, and the hipobj-rc-v2
// control routes follow --rdma-rc-enable. Neither flag implies
// the other.
func Mode(rdmaIP string, rcEnable bool) (v1, v2 bool) {
	return strings.TrimSpace(rdmaIP) != "", rcEnable
}

// V1Settings carries the cuObject v1 tunings that are validated
// only while the v1 backend runs.
type V1Settings struct {
	Port        uint
	RetryCount  uint
	PoolBufSize int
	PoolBufCnt  int
	TunablesSet bool
	NumDCIs     int
	CQDepth     uint
}

// V1ValidationError describes the first invalid v1 setting, or
// the empty string when every setting is valid. Stale v1 values
// in the environment must not block v2-only or plain-S3
// startup, so the gateway consults this only when v1 is on.
func V1ValidationError(s V1Settings) string {
	switch {
	case s.Port > 65535:
		return fmt.Sprintf("rdma-port %d is out of range (0-65535)", s.Port)
	case s.RetryCount > 7:
		return fmt.Sprintf("rdma-retry-count %d is out of range (0-7)", s.RetryCount)
	case s.PoolBufSize <= 0:
		return fmt.Sprintf("pool-buf-size %d must be positive", s.PoolBufSize)
	case s.PoolBufCnt <= 0:
		return fmt.Sprintf("pool-buf-count %d must be positive", s.PoolBufCnt)
	case s.TunablesSet && s.NumDCIs <= 0:
		return fmt.Sprintf("rdma-num-dcis %d must be positive", s.NumDCIs)
	case s.TunablesSet && s.CQDepth > math.MaxUint32:
		return fmt.Sprintf("rdma-cq-depth %d exceeds the 32-bit limit", s.CQDepth)
	default:
		return ""
	}
}

// Closer is the close operation of the RC session service. It is
// idempotent.
type Closer interface{ Close() }

// BackendShutdownAfterRC forwards a backend and closes the RC
// service before the wrapped backend shuts down. The RC handlers
// reference the backend and IAM service, so the RC service must
// stop accepting and drain before either dependency is closed by
// the gateway lifecycle. The whole shutdown, including the
// delegated backend call, runs exactly once: several closers
// (the gateway lifecycle and a deferred rollback in the startup
// path) may call Shutdown on the same instance, and the wrapped
// backends are not guaranteed to be idempotent.
type BackendShutdownAfterRC struct {
	backend.Backend
	rc     Closer
	closed sync.Once
}

// Shutdown closes the RC service, then the wrapped backend, once.
func (b *BackendShutdownAfterRC) Shutdown() {
	b.closed.Do(func() {
		b.rc.Close()
		b.Backend.Shutdown()
	})
}

// ShutdownOnceBackend makes a backend Shutdown idempotent. The
// gateway startup path defers a rollback close while the gateway
// lifecycle also shuts its backend down; a bare backend has no
// idempotency guarantee of its own.
type ShutdownOnceBackend struct {
	backend.Backend
	once sync.Once
}

// Shutdown closes the wrapped backend at most once.
func (b *ShutdownOnceBackend) Shutdown() {
	b.once.Do(func() { b.Backend.Shutdown() })
}

// WrapShutdownOnce returns be with an idempotent Shutdown.
func WrapShutdownOnce(be backend.Backend) backend.Backend {
	return &ShutdownOnceBackend{Backend: be}
}

// WrapBackendShutdownAfterRC returns be with a Shutdown that
// closes rc first.
func WrapBackendShutdownAfterRC(be backend.Backend, rc Closer) backend.Backend {
	return &BackendShutdownAfterRC{Backend: be, rc: rc}
}
