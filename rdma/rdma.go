// Copyright 2026 Versity Software
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

// Package rdma provides Go bindings to libcuobjserver via CGO.
package rdma

/*
#cgo CFLAGS: -I${SRCDIR}/../include -I${SRCDIR}/../cuwrapper
#cgo LDFLAGS: -L${SRCDIR} -l:libcuobjwrapper.a -L/usr/lib64 -lcuobjserver -lstdc++ -ldl
#include "cuobjserver_wrapper.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"unsafe"
)

const (
	cuobjLogPathInfo  = 0x0001
	cuobjLogPathDebug = 0x0002
	cuobjLogPathError = 0x0004

	// cuobjProtoRDMADCV1 is the CUOBJ_PROTO_RDMA_DC_V1 protocol identifier.
	cuobjProtoRDMADCV1 = 1001
)

var debugTelemetryEnabled atomic.Bool

// ConfigureTelemetry controls cuObjServer telemetry logging.
// When debug is true, enable info+debug+error logs to stderr/stdout path.
func ConfigureTelemetry(debug bool) {
	debugTelemetryEnabled.Store(debug)
	C.cuobj_server_setup_telemetry(0)
	if debug {
		C.cuobj_server_set_telem_flags(C.uint(cuobjLogPathInfo | cuobjLogPathDebug | cuobjLogPathError))
		return
	}
	C.cuobj_server_set_telem_flags(C.uint(cuobjLogPathError))
}

// DebugTelemetryEnabled reports whether verbose RDMA diagnostics are enabled.
func DebugTelemetryEnabled() bool {
	return debugTelemetryEnabled.Load()
}

// Buffer wraps an RDMA-registered memory region.
type Buffer struct {
	cbuf    *C.cuobj_rdma_buffer_t
	hostPtr unsafe.Pointer
	size    int
}

// HostPtr returns the underlying host memory pointer.
func (b *Buffer) HostPtr() unsafe.Pointer { return b.hostPtr }

// Size returns the buffer size in bytes.
func (b *Buffer) Size() int { return b.size }

// Slice returns the buffer contents as a Go byte slice backed by C-allocated
// memory. Returns nil after DeregisterBuffer.
func (b *Buffer) Slice() []byte {
	return unsafe.Slice((*byte)(b.hostPtr), b.size)
}

// Server wraps a cuObjServer instance.
type Server struct {
	csrv        *C.cuobj_server_t
	sessionOpen bool
	mu          sync.Mutex
}

// tunablesToC converts a RDMATunables value to the equivalent C struct.
func tunablesToC(t RDMATunables) C.cuobj_rdma_tunables_t {
	var ct C.cuobj_rdma_tunables_t
	ct.num_dcis = C.int(t.NumDCIs)
	ct.cq_depth = C.uint(t.CQDepth)
	ct.dc_key = C.ulong(t.DCKey)
	ct.service_level = C.int(t.ServiceLevel)
	ct.timeout = C.uint8_t(t.Timeout)
	ct.hop_limit = C.uint(t.HopLimit)
	ct.pkey_index = C.int(t.PKeyIndex)
	ct.delay_interval = C.uint32_t(t.DelayInterval)
	ct.delay_mode = C.int(t.DelayMode)
	ct.retry_cnt = C.uint8_t(t.RetryCount)
	if t.QPResetOnFailure {
		ct.qp_reset_on_failure = 1
	}
	ct.traffic_class = C.uint(t.TrafficClass)
	ct.max_rd_atomic = C.int(t.MaxRdAtomic)
	return ct
}

// NewServer creates a cuObjServer bound to the given RDMA IP and port.
// Uses CUOBJ_PROTO_RDMA_DC_V1 (1001). If tunables is non-nil, the 4-argument
// constructor is used so the tunable parameters apply to the initial session
// started by the constructor. Pass nil to use library defaults.
func NewServer(ip string, port uint16, tunables *RDMATunables) (*Server, error) {
	cip := C.CString(ip)
	defer C.free(unsafe.Pointer(cip))

	var csrv *C.cuobj_server_t
	if tunables != nil {
		ct := tunablesToC(*tunables)
		csrv = C.cuobj_server_create_with_config(cip, C.ushort(port), cuobjProtoRDMADCV1, &ct)
	} else {
		csrv = C.cuobj_server_create(cip, C.ushort(port), cuobjProtoRDMADCV1)
	}
	if csrv == nil {
		return nil, fmt.Errorf("rdma: failed to create cuObjServer on %s:%d", ip, port)
	}
	srv := &Server{csrv: csrv}
	// Some library versions start the session as part of construction;
	// record that readiness so StartSession can be a no-op and Close/CloseSession
	// use a consistent ownership model.
	if srv.IsConnected() {
		srv.sessionOpen = true
	}
	return srv, nil
}

// StartSession initiates the RDMA listening session.
// StartSession must not be called concurrently with CloseSession or Close.
func (s *Server) StartSession() error {
	s.mu.Lock()
	alreadyOpen := s.sessionOpen
	s.mu.Unlock()
	if alreadyOpen {
		return nil
	}
	rc := C.cuobj_server_start_session(s.csrv)
	if rc != 0 {
		if s.IsConnected() {
			s.mu.Lock()
			s.sessionOpen = true
			s.mu.Unlock()
			return nil
		}
		return fmt.Errorf("rdma: startRDMASession failed (rc=%d)", rc)
	}
	s.mu.Lock()
	s.sessionOpen = true
	s.mu.Unlock()
	return nil
}

// InitRDMAConfig applies RDMA tuning parameters. Must be called before StartSession.
func (s *Server) InitRDMAConfig(t RDMATunables) error {
	ct := tunablesToC(t)
	if rc := C.cuobj_server_init_rdma_config(s.csrv, &ct); rc != 0 {
		return fmt.Errorf("rdma: initRDMAConfigParams failed (rc=%d)", rc)
	}
	return nil
}

// IsConnected returns the RDMA connection status.
func (s *Server) IsConnected() bool {
	return C.cuobj_server_is_connected(s.csrv) != 0
}

// AllocHostBuffer allocates a 4KB-aligned host buffer of the given size.
func (s *Server) AllocHostBuffer(size int) (unsafe.Pointer, error) {
	if size <= 0 {
		return nil, fmt.Errorf("rdma: allocHostBuffer size %d must be positive", size)
	}
	ptr := C.cuobj_server_alloc_host_buffer(s.csrv, C.size_t(size))
	if ptr == nil {
		return nil, fmt.Errorf("rdma: allocHostBuffer(%d) failed", size)
	}
	return ptr, nil
}

// FreeHostBuffer releases a buffer previously allocated by AllocHostBuffer.
func (s *Server) FreeHostBuffer(ptr unsafe.Pointer) {
	if ptr != nil {
		C.cuobj_server_free_host_buffer(ptr)
	}
}

// RegisterBuffer registers a host memory region for RDMA and returns a Buffer handle.
func (s *Server) RegisterBuffer(ptr unsafe.Pointer, size int) (*Buffer, error) {
	if ptr == nil {
		return nil, errors.New("rdma: registerBuffer ptr must not be nil")
	}
	if size <= 0 {
		return nil, fmt.Errorf("rdma: registerBuffer size %d must be positive", size)
	}
	cbuf := C.cuobj_server_register_buffer(s.csrv, ptr, C.size_t(size))
	if cbuf == nil {
		return nil, errors.New("rdma: registerBuffer failed")
	}
	return &Buffer{cbuf: cbuf, hostPtr: ptr, size: size}, nil
}

// DeregisterBuffer deregisters a previously registered RDMA buffer.
func (s *Server) DeregisterBuffer(buf *Buffer) {
	if buf != nil && buf.cbuf != nil {
		C.cuobj_server_deregister_buffer(s.csrv, buf.cbuf)
		buf.cbuf = nil
		buf.hostPtr = nil
		buf.size = 0
	}
}

// AllocateChannel obtains a unique channel ID for concurrent RDMA operations.
func (s *Server) AllocateChannel() (uint16, error) {
	ch := C.cuobj_server_allocate_channel(s.csrv)
	if ch == C.UINT16_MAX {
		return 0, errors.New("rdma: no free channel IDs")
	}
	return uint16(ch), nil
}

// FreeChannel releases a previously allocated channel ID.
func (s *Server) FreeChannel(id uint16) {
	C.cuobj_server_free_channel(s.csrv, C.uint16_t(id))
}

// HandleGet performs an RDMA WRITE (server→client) to serve a GET request.
// The local buffer must already contain the data to send.
// Returns bytes transferred.
func (s *Server) HandleGet(key string, buf *Buffer, remoteStart uint64, size int64, rdmaDescr string, channel uint16) (int64, error) {
	if buf == nil || buf.cbuf == nil {
		return 0, errors.New("rdma: invalid or deregistered buffer")
	}
	if size <= 0 {
		return 0, fmt.Errorf("rdma: transfer size %d must be positive", size)
	}
	if size > MaxTransferSize {
		return 0, fmt.Errorf("rdma: transfer size %d exceeds max %d", size, MaxTransferSize)
	}

	ckey := C.CString(key)
	defer C.free(unsafe.Pointer(ckey))
	cdescr := C.CString(rdmaDescr)
	defer C.free(unsafe.Pointer(cdescr))

	n := C.cuobj_server_handle_get(s.csrv, ckey, buf.cbuf,
		C.uint64_t(remoteStart), C.size_t(size), cdescr, C.uint16_t(channel))
	if n < 0 {
		return 0, fmt.Errorf("rdma: handleGetObject failed (rc=%d)", n)
	}
	return int64(n), nil
}

// HandlePut performs an RDMA READ (client→server) to serve a PUT request.
// After return, the local buffer contains the data read from the client.
// Returns bytes transferred.
func (s *Server) HandlePut(key string, buf *Buffer, remoteStart uint64, size int64, rdmaDescr string, channel uint16) (int64, error) {
	if buf == nil || buf.cbuf == nil {
		return 0, errors.New("rdma: invalid or deregistered buffer")
	}
	if size <= 0 {
		return 0, fmt.Errorf("rdma: transfer size %d must be positive", size)
	}
	if size > MaxTransferSize {
		return 0, fmt.Errorf("rdma: transfer size %d exceeds max %d", size, MaxTransferSize)
	}

	ckey := C.CString(key)
	defer C.free(unsafe.Pointer(ckey))
	cdescr := C.CString(rdmaDescr)
	defer C.free(unsafe.Pointer(cdescr))

	n := C.cuobj_server_handle_put(s.csrv, ckey, buf.cbuf,
		C.uint64_t(remoteStart), C.size_t(size), cdescr, C.uint16_t(channel))
	if n < 0 {
		return 0, fmt.Errorf("rdma: handlePutObject failed (rc=%d)", n)
	}
	return int64(n), nil
}

// CloseSession tears down the RDMA session.
func (s *Server) CloseSession() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.csrv != nil && s.sessionOpen {
		C.cuobj_server_close_session(s.csrv)
		s.sessionOpen = false
	}
}

// Close destroys the cuObjServer instance. The Server must not be used afterward.
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.csrv != nil {
		if s.sessionOpen {
			C.cuobj_server_close_session(s.csrv)
			s.sessionOpen = false
		}
		C.cuobj_server_destroy(s.csrv)
		s.csrv = nil
	}
}
