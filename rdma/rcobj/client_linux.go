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

//go:build linux && amd64 && cgo && !cuobjclient_host

// Package rcobj binds the hipobj-rc-v2 client library (libhipobj) to
// Go. The library owns the RDMA data plane and drives the transfer
// state machine; the four control-plane callbacks (PREPARE, READY
// request/response, CANCEL) are implemented here with net/http and
// gateway SigV4, per the hipobj.h callback contract.
package rcobj

/*
#cgo CFLAGS: -I/home/potatogim/workspace/github/hipObject/include
#cgo LDFLAGS: -lhipobj
#include <stdlib.h>
#include <hipobj.h>

// Plain-C adapters so the archive's callback signatures bind to the
// GoInt/GoUint64-shaped parameters cgo generates for the exported
// functions below.
typedef int (*prepare_fn)(void*, const hipObjTransferReqV2_t*,
                          hipObjPrepareReplyV2_t*);
typedef int (*ready_req_fn)(void*, const hipObjTransferReqV2_t*);
typedef int (*finish_fn)(void*, const hipObjTransferReqV2_t*,
                         hipObjFinalReplyV2_t*);
typedef int (*cancel_fn)(void*, const hipObjTransferReqV2_t*);

typedef int (*prepare_fn)(void*, const hipObjTransferReqV2_t*,
                          hipObjPrepareReplyV2_t*);
typedef int (*ready_req_fn)(void*, const hipObjTransferReqV2_t*);
typedef int (*finish_fn)(void*, const hipObjTransferReqV2_t*,
                         hipObjFinalReplyV2_t*);
typedef int (*cancel_fn)(void*, const hipObjTransferReqV2_t*);

extern int rcobjGoPrepareTramp(void *ctx, void *req, void *out);
extern int rcobjGoReadyRequestTramp(void *ctx, void *req);
extern int rcobjGoFinishReadyTramp(void *ctx, void *req, void *out);
extern int rcobjGoCancelTramp(void *ctx, void *req);

static int rcobjPrepareAdapter(void *ctx, const hipObjTransferReqV2_t *req,
                               hipObjPrepareReplyV2_t *out) {
  return rcobjGoPrepareTramp(ctx, (void*)req, (void*)out);
}
static int rcobjReadyReqAdapter(void *ctx,
                                const hipObjTransferReqV2_t *req) {
  return rcobjGoReadyRequestTramp(ctx, (void*)req);
}
static int rcobjFinishAdapter(void *ctx, const hipObjTransferReqV2_t *req,
                              hipObjFinalReplyV2_t *out) {
  return rcobjGoFinishReadyTramp(ctx, (void*)req, (void*)out);
}
static int rcobjCancelAdapter(void *ctx, const hipObjTransferReqV2_t *req) {
  return rcobjGoCancelTramp(ctx, (void*)req);
}

static void rcobjSetOps(hipObjOpsV2_t *ops) {
  ops->sendPrepare = &rcobjPrepareAdapter;
  ops->sendReadyRequest = &rcobjReadyReqAdapter;
  ops->finishReady = &rcobjFinishAdapter;
  ops->sendCancel = &rcobjCancelAdapter;
}
*/
import "C"

import (
	"fmt"
	"sync"
	"unsafe"
)

// Error codes mirrored from hipobj.h.
const (
	OpSuccess            = 0
	OpInvalidValue       = 1
	OpNotInitialized     = 2
	OpAlreadyInitialized = 3
	OpRdmaError          = 4
	OpS3Error            = 5
	OpBufNotRegistered   = 6
	OpBufAlreadyReg      = 7
	OpNicNotFound        = 8
	OpDmabufNotSupported = 9
	OpSizeTooLarge       = 10
	OpInternalError      = 11
	OpNotSupported       = 12
	OpBusy               = 13
)

// OpError reports the operation-level error of a failed call.
type OpError struct {
	Op       string
	Code     int
	HipError int
}

func (e *OpError) Error() string {
	if e.HipError != 0 {
		return fmt.Sprintf("%s: op error %d (hip %d)", e.Op, e.Code, e.HipError)
	}
	return fmt.Sprintf("%s: op error %d", e.Op, e.Code)
}

// NotSupported reports whether err is the server's explicit
// hipobj-rc-v2 unsupported verdict, which permits an HTTP fallback.
func NotSupported(err error) bool {
	oe, ok := err.(*OpError)
	return ok && oe.Code == OpNotSupported
}

func opErr(op string, rc C.hipObjError_t) error {
	code := int(rc.opError)
	if code == OpSuccess {
		return nil
	}
	return &OpError{Op: op, Code: code, HipError: int(rc.hipError)}
}

// Config carries the v2 init settings. ControlEndpoint is required
// ("http://host:port"; https is rejected by the callbacks).
type Config struct {
	ControlEndpoint     string
	DeviceIndex         int
	NicHint             string
	ConnectDeadlineMs   uint32
	TransferDeadlineMs  uint32
	CancelCleanupBudget uint32

	Credentials Credentials
	Region      string
}

// Client is a live libhipobj v2 client.
type Client struct {
	mu     sync.Mutex
	closed bool

	// Callback context handed to C: a C-allocated slot carrying one
	// uint64 id, resolved back to this client through ctxRegistry.
	slot unsafe.Pointer
	id   uint64

	// Control-plane implementation (HTTP + SigV4).
	ctrl *controlPlane
	ops  C.hipObjOpsV2_t
}

var (
	ctxMu       sync.Mutex
	ctxRegistry = map[uint64]*Client{}
	ctxNextID   uint64
)

const ctxSlotSize = 8

// Init initializes the library for v2 transfers with the control
// callbacks implemented by this package.
func Init(cfg Config) (*Client, error) {
	if cfg.ControlEndpoint == "" {
		return nil, fmt.Errorf("rcobj: control endpoint is required")
	}
	ccfg := C.hipObjConfigV2_t{}
	ep := C.CString(cfg.ControlEndpoint)
	defer C.free(unsafe.Pointer(ep))
	ccfg.control.controlEndpoint = ep
	ccfg.connectDeadlineMs = C.uint32_t(cfg.ConnectDeadlineMs)
	ccfg.transferDeadlineMs = C.uint32_t(cfg.TransferDeadlineMs)
	ccfg.cancelCleanupBudgetMs = C.uint32_t(cfg.CancelCleanupBudget)
	ccfg.v1.gpuDevice = C.int(cfg.DeviceIndex)
	if cfg.NicHint != "" {
		nic := C.CString(cfg.NicHint)
		defer C.free(unsafe.Pointer(nic))
		ccfg.v1.nicHint = nic
	}

	if rc := C.hipObjInitV2(&ccfg); rc.opError != C.hipObjSuccess {
		return nil, opErr("init", rc)
	}

	slot := C.malloc(ctxSlotSize)
	if slot == nil {
		C.hipObjShutdown()
		return nil, fmt.Errorf("rcobj: callback slot: no memory")
	}
	ctxMu.Lock()
	ctxNextID++
	id := ctxNextID
	cl := &Client{slot: slot, id: id}
	ctxRegistry[id] = cl
	ctxMu.Unlock()
	*(*uint64)(slot) = id

	cl.ctrl = newControlPlane(cfg)
	var ops C.hipObjOpsV2_t
	C.rcobjSetOps(&ops)
	cl.ops = ops
	return cl, nil
}

// Shutdown tears the library down and releases the callback slot.
func (c *Client) Shutdown() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	rc := C.hipObjShutdown()
	ctxMu.Lock()
	delete(ctxRegistry, c.id)
	ctxMu.Unlock()
	if c.slot != nil {
		C.free(c.slot)
		c.slot = nil
	}
	return opErr("shutdown", rc)
}

// registerBuffer / deregisterBuffer wrap the device-MR registration
// the v2 entry points require.
func (c *Client) RegisterBuffer(devPtr unsafe.Pointer, size uint64) error {
	rc := C.hipObjBufRegister(devPtr, C.size_t(size))
	return opErr("register", rc)
}

func (c *Client) DeregisterBuffer(devPtr unsafe.Pointer) error {
	rc := C.hipObjBufDeregister(devPtr)
	return opErr("deregister", rc)
}

// Get performs a v2 GET into a registered device buffer.
func (c *Client) Get(bucket, key string, devPtr unsafe.Pointer,
	size, offset uint64, query string) error {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return &OpError{Op: "get", Code: OpNotInitialized}
	}

	cb, kd, err := c.borrowStrings(bucket, key, query)
	if err != nil {
		return err
	}
	defer cb()
	rc := C.hipObjGetV2(kd.b, kd.k, devPtr, C.uint64_t(size),
		C.uint64_t(offset), kd.q, &c.ops, c.slot)
	return opErr("get", rc)
}

// Put performs a v2 PUT from a registered device buffer.
func (c *Client) Put(bucket, key string, devPtr unsafe.Pointer,
	size, offset uint64, query string) error {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return &OpError{Op: "put", Code: OpNotInitialized}
	}

	cb, kd, err := c.borrowStrings(bucket, key, query)
	if err != nil {
		return err
	}
	defer cb()
	rc := C.hipObjPutV2(kd.b, kd.k, devPtr, C.uint64_t(size),
		C.uint64_t(offset), kd.q, &c.ops, c.slot)
	return opErr("put", rc)
}

// Valloc allocates host memory for a registered buffer so the
// registration pointer is not a Go-heap pointer (cgo argument
// rule). Free releases it.
func Valloc(size int) unsafe.Pointer {
	return C.malloc(C.size_t(size))
}

// Free releases memory from Valloc.
func Free(p unsafe.Pointer) {
	if p != nil {
		C.free(p)
	}
}

// borrowed C strings for one call; free releases them.
type borrowed struct {
	b, k, q *C.char
}

func (c *Client) borrowStrings(bucket, key, query string) (func(), borrowed, error) {
	b := C.CString(bucket)
	k := C.CString(key)
	var q *C.char
	if query != "" {
		q = C.CString(query)
	}
	return func() {
		C.free(unsafe.Pointer(b))
		C.free(unsafe.Pointer(k))
		if q != nil {
			C.free(unsafe.Pointer(q))
		}
	}, borrowed{b: b, k: k, q: q}, nil
}

//export rcobjGoPrepareTramp
func rcobjGoPrepareTramp(ctx unsafe.Pointer, req, out unsafe.Pointer) int32 {
	cl := clientFromCtx(ctx)
	if cl == nil {
		return -1
	}
	return int32(cl.ctrl.prepare(copyReq((*C.hipObjTransferReqV2_t)(req)),
		(*C.hipObjPrepareReplyV2_t)(out)))
}

//export rcobjGoReadyRequestTramp
func rcobjGoReadyRequestTramp(ctx, req unsafe.Pointer) int32 {
	cl := clientFromCtx(ctx)
	if cl == nil {
		return -1
	}
	return int32(cl.ctrl.readyRequest(
		copyReq((*C.hipObjTransferReqV2_t)(req))))
}

//export rcobjGoFinishReadyTramp
func rcobjGoFinishReadyTramp(ctx, req, out unsafe.Pointer) int32 {
	cl := clientFromCtx(ctx)
	if cl == nil {
		return -1
	}
	return int32(cl.ctrl.finishReady(
		copyReq((*C.hipObjTransferReqV2_t)(req)),
		(*C.hipObjFinalReplyV2_t)(out)))
}

//export rcobjGoCancelTramp
func rcobjGoCancelTramp(ctx, req unsafe.Pointer) int32 {
	cl := clientFromCtx(ctx)
	if cl == nil {
		return -1
	}
	return int32(cl.ctrl.cancel(
		copyReq((*C.hipObjTransferReqV2_t)(req))))
}

func clientFromCtx(ctx unsafe.Pointer) *Client {
	if ctx == nil {
		return nil
	}
	id := *(*uint64)(ctx)
	ctxMu.Lock()
	cl := ctxRegistry[id]
	ctxMu.Unlock()
	return cl
}

// transferReq is the Go-side copy of a callback request; strings are
// copied immediately (the library's borrow contract requires it).
type transferReq struct {
	Method    string
	Bucket    string
	Key       string
	Query     string
	Token     string
	Session   string
	Target    string
	Size      uint64
	Offset    uint64
	Cookie    uint32
	ClientPsn uint32
	Deadline  uint32
	Remaining uint32
	Endpoint  string
	Nic       string
	NicPort   int
	NicGid    int

	ClientQpn    uint32
	ClientMrAddr uint64
	ClientMrRkey uint32
}

func copyReq(req *C.hipObjTransferReqV2_t) transferReq {
	r := transferReq{
		Method:    C.GoString(req.method),
		Bucket:    C.GoString(req.bucket),
		Key:       C.GoString(req.key),
		Size:      uint64(req.size),
		Offset:    uint64(req.offset),
		Cookie:    uint32(req.cookie),
		ClientPsn: uint32(req.clientPsn),
		Deadline:  uint32(req.deadlineMs),
		Remaining: uint32(req.remainingMs),
		NicPort:   int(req.nicPort),
		NicGid:    int(req.nicGidIndex),

		ClientQpn:    uint32(req.clientQpn),
		ClientMrAddr: uint64(req.clientMrAddr),
		ClientMrRkey: uint32(req.clientMrRkey),
	}
	if req.query != nil {
		r.Query = C.GoString(req.query)
	}
	if req.token != nil {
		r.Token = C.GoString(req.token)
	}
	if req.session != nil {
		r.Session = C.GoString(req.session)
	}
	if req.target != nil {
		r.Target = C.GoString(req.target)
	}
	if req.endpoint != nil && req.endpoint.controlEndpoint != nil {
		r.Endpoint = C.GoString(req.endpoint.controlEndpoint)
	}
	if req.nic != nil {
		r.Nic = C.GoString(req.nic)
	}
	return r
}
