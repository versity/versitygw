//go:build linux && amd64 && cgo && rdma

package rcdial

/*
#cgo CFLAGS: -I${SRCDIR}/../../cuwrapper
#cgo LDFLAGS: -L${SRCDIR}/.. -l:librdialwrapper.a -lrdmacm -libverbs
#include <stdlib.h>
#include "rdial_wrapper.h"
*/
import "C"

import (
	"fmt"
	"syscall"
	"unsafe"
)

// transportAvailable reports whether this build carries the cgo
// RDMA CM transport.
const transportAvailable = true

// _ETIMEDOUT mirrors the C errno the wrapper returns for a timed-out
// transfer.
const _ETIMEDOUT = syscall.ETIMEDOUT

// conn is a live RDMA CM connection to a client listener. All
// staging memory lives on the C heap: Go allocations are never
// registered with the HCA, so nothing the device touches can move.
type conn struct {
	c *C.struct_rdial_conn
}

var _ connIface = (*conn)(nil)

// cgoDial connects to ip:port within timeoutMS milliseconds.
func cgoDial(ip string, port uint16, timeoutMS int) (*conn, error) {
	cip := C.CString(ip)
	defer C.free(unsafe.Pointer(cip))
	var c *C.struct_rdial_conn
	rc := C.rdial_dial(cip, C.uint16_t(port), C.int(timeoutMS), &c)
	if rc != 0 {
		return nil, fmt.Errorf("rdial: dial %s:%d: %w", ip, port, errno(C.long(rc)))
	}
	return &conn{c: c}, nil
}

// readStaging performs the RDMA READ into a C-owned buffer and
// returns a Go slice aliasing it plus the function that releases the
// C memory. The adapter copies the data out and frees inside the
// same call, so no Go-visible alias outlives the C buffer. On a
// timeout the wrapper keeps the buffer alive (a work request may
// still be writing it); the free function flushes by tearing the
// connection down before releasing the memory.
func (cn *conn) read(localLen uint64, rkey uint32, remoteAddr uint64, timeoutMS int) ([]byte, func(), error) {
	var staging unsafe.Pointer
	n := C.rdial_read(cn.c, C.uint32_t(rkey), C.uint64_t(remoteAddr),
		C.uint64_t(localLen), C.int(timeoutMS), &staging)
	if n < 0 {
		if int64(n) == -int64(_ETIMEDOUT) {
			// The timed-out READ WR may still be filling the
			// staging buffer; flush it before any reuse.
			cn.close(0)
		}
		return nil, nil, fmt.Errorf("rdial: read: %w", errno(n))
	}
	if staging == nil {
		return nil, nil, fmt.Errorf("rdial: read: no staging returned")
	}
	buf := unsafe.Slice((*byte)(staging), int(n))
	free := func() { C.rdial_free(staging) }
	return buf, free, nil
}

// writeStaging copies data into a C-owned buffer (allocated with
// rdial_alloc) and posts the RDMA WRITE from it. Only the C buffer
// is ever registered; the Go slice is gone before the transfer. On
// a timeout the work request may still be reading the buffer, so
// the connection is torn down before the buffer is freed.
func (cn *conn) write(data []byte, rkey uint32, remoteAddr uint64, timeoutMS int) (int, error) {
	staging := C.rdial_alloc(C.uint64_t(len(data)))
	if staging == nil {
		return 0, fmt.Errorf("rdial: staging alloc of %d bytes failed", len(data))
	}
	dst := unsafe.Slice((*byte)(staging), len(data))
	copy(dst, data)
	n := C.rdial_write(cn.c, staging, C.uint32_t(rkey),
		C.uint64_t(remoteAddr), C.uint64_t(len(data)), C.int(timeoutMS))
	if n < 0 {
		if int64(n) == -int64(_ETIMEDOUT) {
			// Flush the outstanding WR before releasing the
			// buffer it may still be reading.
			cn.close(0)
		}
		C.rdial_free(staging)
		return 0, fmt.Errorf("rdial: write: %w", errno(n))
	}
	return int(n), nil
}

func (cn *conn) close(timeoutMS int) {
	C.rdial_close(cn.c, C.int(timeoutMS))
	cn.c = nil
}

// errno converts a C negative errno into a Go error value.
func errno(rc C.long) error {
	return fmt.Errorf("errno %d", int64(rc))
}
