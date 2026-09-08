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
	"time"

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

// V2Settings carries the hipobj-rc-v2 tunings that are validated
// only while the RC data plane runs. Counts arrive as uint64 from
// the CLI and narrow to uint32 at the DeviceOpts boundary, so the
// range is checked before the narrowing cast. Timeouts feed
// deadline arithmetic (nowMs + timeout), so an upper bound keeps
// the sum from wrapping.
type V2Settings struct {
	MaxSessions         uint64
	MaxUserSessions     uint64
	MaxStagingBytes     uint64
	MaxUserStagingBytes uint64
	MaxQPs              uint64
	MaxUserQPs          uint64
	MaxReadySlots       uint64
	TPrepMs             uint64
	TExecMs             uint64
}

// v2TimeoutCeiling bounds the RC timeouts well below the uint64
// wrap point of nowMs + timeout arithmetic in the C core.
const v2TimeoutCeiling = uint64(24 * time.Hour / time.Millisecond)

// V2ValidationError describes the first invalid v2 setting, or
// the empty string when every setting is valid. Stale v2 values
// in the environment must not block v1-only or plain-S3 startup,
// so the gateway consults this only when v2 is on.
func V2ValidationError(s V2Settings) string {
	switch {
	case s.MaxSessions < 1 || s.MaxSessions > math.MaxUint32:
		return fmt.Sprintf("rdma-rc-max-sessions %d is out of range (1-%d)", s.MaxSessions, uint64(math.MaxUint32))
	case s.MaxUserSessions < 1 || s.MaxUserSessions > math.MaxUint32:
		return fmt.Sprintf("rdma-rc-max-user-sessions %d is out of range (1-%d)", s.MaxUserSessions, uint64(math.MaxUint32))
	case s.MaxStagingBytes < 1:
		return fmt.Sprintf("rdma-rc-max-staging-bytes %d must be positive", s.MaxStagingBytes)
	case s.MaxUserStagingBytes < 1:
		return fmt.Sprintf("rdma-rc-max-user-staging-bytes %d must be positive", s.MaxUserStagingBytes)
	case s.MaxQPs < 1 || s.MaxQPs > math.MaxUint32:
		return fmt.Sprintf("rdma-rc-max-qps %d is out of range (1-%d)", s.MaxQPs, uint64(math.MaxUint32))
	case s.MaxUserQPs < 1 || s.MaxUserQPs > math.MaxUint32:
		return fmt.Sprintf("rdma-rc-max-user-qps %d is out of range (1-%d)", s.MaxUserQPs, uint64(math.MaxUint32))
	case s.MaxReadySlots < 1 || s.MaxReadySlots > math.MaxUint32:
		return fmt.Sprintf("rdma-rc-max-ready-slots %d is out of range (1-%d)", s.MaxReadySlots, uint64(math.MaxUint32))
	case s.TPrepMs < 1 || s.TPrepMs > v2TimeoutCeiling:
		return fmt.Sprintf("rdma-rc-prep-timeout-ms %d is out of range (1-%d)", s.TPrepMs, v2TimeoutCeiling)
	case s.TExecMs < 1 || s.TExecMs > v2TimeoutCeiling:
		return fmt.Sprintf("rdma-rc-exec-timeout-ms %d is out of range (1-%d)", s.TExecMs, v2TimeoutCeiling)
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
