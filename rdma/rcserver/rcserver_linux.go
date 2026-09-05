// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT ANY KIND, either express or implied.
// See the License for the specific language governing permissions
// and limitations under the License.

//go:build linux && amd64 && cgo

// Package rcserver binds the RC session server (rdma/librcserver.a)
// that implements the hipobj-rc-v2 two-phase transfer protocol.
//
// The gateway owns routing, authentication, and the object backend;
// the C side owns the session state machine, QP/CQ/MR lifetimes, the
// data phase, and session reaping. Every cgo call is synchronous
// from the request goroutine.
package rcserver

/*
#cgo CFLAGS: -I${SRCDIR}/../../cuwrapper/rc
#cgo LDFLAGS: -L${SRCDIR}/.. -l:librcserver.a -lstdc++ -ldl -lpthread
#include "rc_server_abi.h"
#include <stdlib.h>

// Shim: a C function pointer that forwards into the exported Go
// sink. Go closures cannot be stored as C callbacks, so the
// level/file/line/msg are marshalled through this fixed trampoline.
extern void rcgo_log_sink(void *ctx, int level, char *msg,
                          char *file, int line);
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"log"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"
)

// Status codes mirrored from rc_server_abi.h.
const (
	StatusOK           = C.RC_OK
	StatusErrArg       = C.RC_E_ARG
	StatusErrState     = C.RC_E_STATE
	StatusErrSession   = C.RC_E_SESSION
	StatusErrStale     = C.RC_E_STALE
	StatusErrNoSession = C.RC_E_NO_SESSION
	StatusErrDouble    = C.RC_E_DOUBLE
	StatusErrWire      = C.RC_E_WIRE
	StatusErrShort     = C.RC_E_SHORT
	StatusErrTrunc     = C.RC_E_TRUNC
	StatusErrLimit     = C.RC_E_LIMIT
	StatusErrInternal  = C.RC_E_INTERNAL
)

// DeviceOpts configures device selection and resource limits.
type DeviceOpts struct {
	// GidHint selects the device whose GID starts with this dotted
	// prefix; empty picks the first verbs device.
	GidHint string
	Port    uint8
	GidIdx  int
	// Global limits.
	MaxSessions         uint32
	MaxStagingBytes     uint64
	MaxQPs              uint32
	MaxUserSessions     uint32
	MaxUserStagingBytes uint64
	MaxUserQPs          uint32
	// Timeouts in milliseconds.
	TPrepMs uint64
	TExecMs uint64
	// Concurrency slots (0 picks the C-side default 64/32).
	MaxReadySlots uint32
	MaxStageSlots uint32
	// Debug enables level-2 (debug) RC diagnostics through the
	// log sink; false keeps error-only reporting. Mirrors the
	// gateway --debug flag.
	Debug bool
}

// PrincipalID is the SHA-256 digest identifying the requester.
type PrincipalID [32]byte

// PrepareRequest carries the PREPARE wire parameters.
type PrepareRequest struct {
	Principal   PrincipalID
	Op          uint8 // 0 = GET, 1 = PUT
	Target      string
	Offset      uint64
	Size        uint64
	ClientPsn   uint32
	Cookie      uint32
	ClientToken string // 88-hex, optional
}

// PrepareResponse is the PREPARE reply.
type PrepareResponse struct {
	SessionID   string
	ServerQpn   uint32
	ServerPsn   uint32
	StagingAddr uint64
	StagingRkey uint32
	ReplyToken  string
}

// Handle is an opaque consume-once lease identifier.
type Handle struct {
	Epoch uint64
	Nonce uint64
}

// StagingLease is a borrowed GET staging buffer. The caller must
// return it with FinishStaging exactly once.
type StagingLease struct {
	Buf      []byte
	Capacity int
	Handle   Handle
}

// PutView is a borrowed PUT data view. The caller must return it
// with FinishPut exactly once.
type PutView struct {
	Buf    []byte
	Len    int
	Handle Handle
}

// ReadyRequest carries the READY wire parameters.
type ReadyRequest struct {
	Principal    PrincipalID
	SessionID    string
	Cookie       uint32
	ClientQpn    uint32
	ClientMrAddr uint64
	ClientMrRkey uint32
}

// ReadyResponse is the READY reply.
type ReadyResponse struct {
	BytesTransferred uint64
	CookieEcho       uint32
	// Outcome mirrors the RC_READY_* enum: returned atomically
	// with the transfer result so a concurrent READY cannot
	// rewrite it between the transfer and the read.
	Outcome   int
	Etag      string
	VersionID string
}

// SessionInfo describes a session for READY re-authorization.
type SessionInfo struct {
	Op     uint8 // 0 = GET, 1 = PUT
	Target string
}

// RCSvc owns the RC session server. Handlers must call TryEnter
// before any session call and Leave when the request completes
// (defer). Close stops admissions, cancels the service context
// (bound to every handler's backend I/O so in-flight requests
// unblock), waits for every entered call to leave, then tears the
// server down; it is idempotent and safe from any goroutine.
type RCSvc struct {
	srv     *C.rc_server
	closing atomic.Bool
	ops     atomic.Int64
	once    sync.Once
	ctx     context.Context
	cancel  context.CancelFunc
}

// Context returns the service-lifetime context. Handlers bind
// their backend calls to it so Close unblocks in-flight I/O.
func (s *RCSvc) Context() context.Context {
	return s.ctx
}

// rcLogSink receives every diagnostic line the C server emits.
// It is stateless and process-global on purpose: the sink must be
// valid from init through destroy, independent of any single
// RCSvc instance. Lines are copied out immediately (the C msg
// buffer is only valid for the duration of the callback) and
// written to the standard error logger. rcLogMu serializes the
// copy because log.Logger is safe for concurrent use but keeps
// a single writer cheap.
var (
	rcLogMu    sync.Mutex
	rcLogLevel atomic.Int32
	rcLog      = log.New(log.Writer(), "vgwrdma rc: ", 0)
)

//export rcgo_log_sink
func rcgo_log_sink(_ unsafe.Pointer, level C.int, msg *C.char,
	file *C.char, line C.int) {
	// Level gating mirrors the C contract: 0 (error) always
	// arrives here; 2 (debug) only when the service opted in.
	if int32(level) > rcLogLevel.Load() {
		return
	}
	m := C.GoString(msg)
	f := ""
	if file != nil {
		f = C.GoString(file)
	}
	rcLogMu.Lock()
	rcLog.Printf("%s (%s:%d) level=%d", m, f, int(line), int(level))
	rcLogMu.Unlock()
}

// installLogSink wires the C server's diagnostics into the Go
// sink. debug selects level 2 (debug) versus level 0 (errors
// only); the C side keeps stderr error reporting when the sink
// is absent, so a nil install is a no-op by design.
func installLogSink(srv *C.rc_server, debug bool) {
	if debug {
		rcLogLevel.Store(2)
	} else {
		rcLogLevel.Store(0)
	}
	C.rc_server_set_log_sink(srv,
		(*[0]byte)(C.rcgo_log_sink), nil)
}

// Init opens the verbs device and returns a service.
func Init(opts DeviceOpts) (*RCSvc, error) {
	copts := C.rc_device_opts{
		port:                   C.uint8_t(opts.Port),
		gid_index:              C.int(opts.GidIdx),
		max_sessions:           C.uint32_t(opts.MaxSessions),
		max_user_sessions:      C.uint32_t(opts.MaxUserSessions),
		max_staging_bytes:      C.uint64_t(opts.MaxStagingBytes),
		max_user_staging_bytes: C.uint64_t(opts.MaxUserStagingBytes),
		max_qps:                C.uint32_t(opts.MaxQPs),
		max_user_qps:           C.uint32_t(opts.MaxUserQPs),
		t_prep_ms:              C.uint64_t(opts.TPrepMs),
		t_exec_ms:              C.uint64_t(opts.TExecMs),
		max_ready_slots:        C.uint32_t(opts.MaxReadySlots),
		max_stage_slots:        C.uint32_t(opts.MaxStageSlots),
	}
	var gidHint *C.char
	if opts.GidHint != "" {
		gidHint = C.CString(opts.GidHint)
		defer C.free(unsafe.Pointer(gidHint))
	}
	copts.gid_hint = gidHint

	var srv *C.rc_server
	if rc := C.rc_server_init(&copts, &srv); rc != C.RC_OK {
		return nil, fmt.Errorf("rcserver: init failed: status %d", int(rc))
	}
	installLogSink(srv, opts.Debug)
	ctx, cancel := context.WithCancel(context.Background())
	return &RCSvc{srv: srv, ctx: ctx, cancel: cancel}, nil
}

// TryEnter admits a request into the service. It returns false once
// Close has begun; the caller must not touch the service then.
func (s *RCSvc) TryEnter() bool {
	if s.closing.Load() {
		return false
	}
	s.ops.Add(1)
	if s.closing.Load() {
		s.ops.Add(-1)
		return false
	}
	return true
}

// Leave releases a TryEnter admission.
func (s *RCSvc) Leave() {
	s.ops.Add(-1)
}

// Close shuts the service down: it stops admissions, marks every
// session for reaping, waits for all in-flight handlers to
// finish, and destroys the server. Safe to call multiple times.
//
// Convergence: every blocking call an RC handler makes after
// TryEnter is bounded - GET staging, PUT commit, and the
// bucket-ACL lookup run under the service context and unblock on
// the cancel below; and the authorization helpers (VerifyAccess,
// CheckObjectAccess) consume the fiber request context, which the
// gateway shuts down before RunVersityGW returns - and Close
// runs after RunVersityGW returns in every current caller - so
// those calls are cancelled by the fiber shutdown that precedes
// Close.
func (s *RCSvc) Close() {
	s.once.Do(func() {
		s.closing.Store(true)
		// Cancel the service context first: handlers bind their
		// backend I/O to it, so in-flight GET staging and PUT
		// commits unblock instead of stretching the ops wait
		// below into an unbounded spin.
		s.cancel()
		if s.srv != nil {
			// Mark every session reap-pending first so the
			// destroy path below can actually collect them;
			// sessions with drained refs are reaped here.
			C.rc_cancel_all(s.srv)
		}
		for s.ops.Load() > 0 {
			runtime.Gosched()
		}
		if s.srv != nil {
			C.rc_server_destroy(s.srv)
			s.srv = nil
		}
	})
}

func statusErr(rc C.int, op string) error {
	if rc == C.RC_OK {
		return nil
	}
	return fmt.Errorf("rcserver: %s: status %d", op, int(rc))
}

// Sentinel errors matched by errors.Is for each ABI status.
var (
	ErrArg       = errors.New("rcserver: invalid argument")
	ErrState     = errors.New("rcserver: wrong session state")
	ErrSession   = errors.New("rcserver: owner mismatch")
	ErrStale     = errors.New("rcserver: stale handle or session")
	ErrNoSession = errors.New("rcserver: no such session")
	ErrDouble    = errors.New("rcserver: duplicate borrow")
	ErrWire      = errors.New("rcserver: verbs transfer failure")
	ErrShort     = errors.New("rcserver: short transfer")
	ErrTrunc     = errors.New("rcserver: value too long")
	ErrLimit     = errors.New("rcserver: resource limit")
	ErrInternal  = errors.New("rcserver: internal error")
)

// statusError maps an ABI status to a descriptive error value.
func statusError(rc C.int) error {
	switch rc {
	case C.RC_OK:
		return nil
	case C.RC_E_ARG:
		return ErrArg
	case C.RC_E_STATE:
		return ErrState
	case C.RC_E_SESSION:
		return ErrSession
	case C.RC_E_STALE:
		return ErrStale
	case C.RC_E_NO_SESSION:
		return ErrNoSession
	case C.RC_E_DOUBLE:
		return ErrDouble
	case C.RC_E_WIRE:
		return ErrWire
	case C.RC_E_SHORT:
		return ErrShort
	case C.RC_E_TRUNC:
		return ErrTrunc
	case C.RC_E_LIMIT:
		return ErrLimit
	default:
		return ErrInternal
	}
}

// strIn borrows string bytes for a synchronous rc_str_in value argument.
// For a string view embedded in a request struct passed by pointer, use
// pinnedStrIn instead: the cgo pointer check rejects request structs that
// contain unpinned Go string data. C must not retain or modify the borrowed
// bytes.
func strIn(s string) C.rc_str_in {
	if s == "" {
		return C.rc_str_in{ptr: nil, len: 0}
	}
	return C.rc_str_in{
		ptr: (*C.char)(unsafe.Pointer(unsafe.StringData(s))),
		len: C.uint32_t(len(s)),
	}
}

// pinnedStrIn builds a strIn view and pins the string bytes for the
// duration of the enclosing cgo call. The caller owns the Pinner and
// must defer Unpin before the first pinnedStrIn call. Pinning an
// interior pointer pins the whole backing allocation.
func pinnedStrIn(s string, pins *runtime.Pinner) C.rc_str_in {
	in := strIn(s)
	if in.ptr != nil {
		pins.Pin(unsafe.Pointer(in.ptr))
	}
	return in
}

// cStr reads a fixed C char array of length n into a Go string.
func cStr(p *C.char, n C.uint32_t) string {
	if n == 0 {
		return ""
	}
	return C.GoStringN(p, C.int(n))
}

// Prepare creates a session (PREPARE).
func (s *RCSvc) Prepare(req PrepareRequest) (*PrepareResponse, error) {
	if s.srv == nil {
		return nil, errors.New("rcserver: service closed")
	}
	var pins runtime.Pinner
	defer pins.Unpin()
	var principal C.rc_principal_id
	copy((*[32]byte)(unsafe.Pointer(&principal.id[0]))[:], req.Principal[:])

	token := pinnedStrIn(req.ClientToken, &pins)
	target := pinnedStrIn(req.Target, &pins)
	creq := C.rc_prepare_req{
		principal:    principal,
		op:           C.uint8_t(req.Op),
		target:       target,
		offset:       C.uint64_t(req.Offset),
		size:         C.uint64_t(req.Size),
		client_psn:   C.uint32_t(req.ClientPsn),
		cookie:       C.uint32_t(req.Cookie),
		client_token: token,
	}
	var cresp C.rc_prepare_resp
	rc := C.rc_prepare(s.srv, &creq, &cresp)
	if rc != C.RC_OK {
		return nil, statusError(rc)
	}
	return &PrepareResponse{
		SessionID:   cStr(&cresp.session_id[0], cresp.session_len),
		ServerQpn:   uint32(cresp.server_qpn),
		ServerPsn:   uint32(cresp.server_psn),
		StagingAddr: uint64(cresp.staging_addr),
		StagingRkey: uint32(cresp.staging_rkey),
		ReplyToken:  cStr(&cresp.reply_token[0], cresp.reply_len),
	}, nil
}

// FinishPrepare commits or aborts a PREPARE.
func (s *RCSvc) FinishPrepare(sessionID string, committed bool) error {
	if s.srv == nil {
		return errors.New("rcserver: service closed")
	}
	in := strIn(sessionID)
	rc := C.rc_finish_prepare(s.srv, in, C.int(btoi(committed)))
	runtime.KeepAlive(sessionID)
	return statusError(rc)
}

// BorrowStaging borrows the GET staging buffer.
func (s *RCSvc) BorrowStaging(sessionID string) (*StagingLease, error) {
	if s.srv == nil {
		return nil, errors.New("rcserver: service closed")
	}
	in := strIn(sessionID)
	var lease C.rc_staging_lease
	rc := C.rc_borrow_staging(s.srv, in, &lease)
	runtime.KeepAlive(sessionID)
	if rc != C.RC_OK {
		return nil, statusError(rc)
	}
	return &StagingLease{
		Buf: unsafe.Slice((*byte)(unsafe.Pointer(lease.buf)),
			lease.capacity),
		Capacity: int(lease.capacity),
		Handle: Handle{
			Epoch: uint64(lease.handle.session_epoch),
			Nonce: uint64(lease.handle.nonce),
		},
	}, nil
}

// FinishStaging returns a staging lease (GET).
func (s *RCSvc) FinishStaging(lease StagingLease, ok bool,
	written int, etag, versionID string) error {
	if s.srv == nil {
		return errors.New("rcserver: service closed")
	}
	h := C.rc_handle{
		session_epoch: C.uint64_t(lease.Handle.Epoch),
		nonce:         C.uint64_t(lease.Handle.Nonce),
	}
	clease := C.rc_staging_lease{handle: h}
	inEtag := strIn(etag)
	inVer := strIn(versionID)
	rc := C.rc_finish_staging(s.srv, clease, C.int(btoi(ok)),
		C.size_t(written), inEtag, inVer)
	runtime.KeepAlive(etag)
	runtime.KeepAlive(versionID)
	return statusError(rc)
}

// SessionInfo looks up a session's op and target (READY auth).
func (s *RCSvc) SessionInfo(sessionID string, who PrincipalID) (*SessionInfo, error) {
	if s.srv == nil {
		return nil, errors.New("rcserver: service closed")
	}
	var principal C.rc_principal_id
	copy((*[32]byte)(unsafe.Pointer(&principal.id[0]))[:], who[:])
	in := strIn(sessionID)
	var out C.rc_session_info_resp
	rc := C.rc_session_info(s.srv, in, principal, &out)
	runtime.KeepAlive(sessionID)
	if rc != C.RC_OK {
		return nil, statusError(rc)
	}
	return &SessionInfo{
		Op:     uint8(out.op),
		Target: cStr(&out.target[0], out.target_len),
	}, nil
}

// ReadyTransfer runs the data phase (READY).
func (s *RCSvc) ReadyTransfer(req ReadyRequest) (*ReadyResponse, error) {
	if s.srv == nil {
		return nil, errors.New("rcserver: service closed")
	}
	var pins runtime.Pinner
	defer pins.Unpin()
	var principal C.rc_principal_id
	copy((*[32]byte)(unsafe.Pointer(&principal.id[0]))[:], req.Principal[:])
	in := pinnedStrIn(req.SessionID, &pins)
	creq := C.rc_ready_req{
		principal:      principal,
		session_id:     in,
		cookie:         C.uint32_t(req.Cookie),
		client_qpn:     C.uint32_t(req.ClientQpn),
		client_mr_addr: C.uint64_t(req.ClientMrAddr),
		client_mr_rkey: C.uint32_t(req.ClientMrRkey),
	}
	var cresp C.rc_ready_resp
	rc := C.rc_ready_transfer(s.srv, &creq, &cresp)
	if rc != C.RC_OK {
		return nil, statusError(rc)
	}
	return &ReadyResponse{
		BytesTransferred: uint64(cresp.bytes_transferred),
		CookieEcho:       uint32(cresp.cookie_echo),
		Outcome:          int(cresp.outcome),
		Etag:             cStr(&cresp.etag[0], cresp.etag_len),
		VersionID:        cStr(&cresp.version_id[0], cresp.version_len),
	}, nil
}

// Ready outcome detail codes (rc_ready_resp.outcome).
const (
	ReadyOK         = C.RC_READY_OK
	ReadyBusy       = C.RC_READY_BUSY
	ReadyTimeout    = C.RC_READY_TIMEOUT
	ReadyVerifyFail = C.RC_READY_VERIFY_FAIL
	ReadyWireFail   = C.RC_READY_WIRE_FAIL
)

// GetPutData borrows the PUT data view.
func (s *RCSvc) GetPutData(sessionID string) (*PutView, error) {
	if s.srv == nil {
		return nil, errors.New("rcserver: service closed")
	}
	in := strIn(sessionID)
	var view C.rc_put_view
	rc := C.rc_get_put_data(s.srv, in, &view)
	runtime.KeepAlive(sessionID)
	if rc != C.RC_OK {
		return nil, statusError(rc)
	}
	return &PutView{
		Buf: unsafe.Slice((*byte)(unsafe.Pointer(view.buf)), view.len),
		Len: int(view.len),
		Handle: Handle{
			Epoch: uint64(view.handle.session_epoch),
			Nonce: uint64(view.handle.nonce),
		},
	}, nil
}

// FinishPut returns a PUT data view with the commit outcome.
func (s *RCSvc) FinishPut(view PutView, committed bool,
	etag, versionID string) error {
	if s.srv == nil {
		return errors.New("rcserver: service closed")
	}
	h := C.rc_handle{
		session_epoch: C.uint64_t(view.Handle.Epoch),
		nonce:         C.uint64_t(view.Handle.Nonce),
	}
	cview := C.rc_put_view{handle: h}
	inEtag := strIn(etag)
	inVer := strIn(versionID)
	rc := C.rc_finish_put(s.srv, cview, C.int(btoi(committed)),
		inEtag, inVer)
	runtime.KeepAlive(etag)
	runtime.KeepAlive(versionID)
	return statusError(rc)
}

// FinishFinal marks the FINAL response committed.
func (s *RCSvc) FinishFinal(sessionID string) error {
	if s.srv == nil {
		return errors.New("rcserver: service closed")
	}
	in := strIn(sessionID)
	rc := C.rc_finish_final(s.srv, in)
	runtime.KeepAlive(sessionID)
	return statusError(rc)
}

// Cancel cancels a session (owner-checked).
func (s *RCSvc) Cancel(sessionID string, who PrincipalID) error {
	if s.srv == nil {
		return errors.New("rcserver: service closed")
	}
	var principal C.rc_principal_id
	copy((*[32]byte)(unsafe.Pointer(&principal.id[0]))[:], who[:])
	in := strIn(sessionID)
	rc := C.rc_cancel(s.srv, in, principal)
	runtime.KeepAlive(sessionID)
	return statusError(rc)
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}
