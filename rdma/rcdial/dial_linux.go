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
	"unsafe"
)

// conn is a live RDMA CM connection to a client listener.
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

func (cn *conn) read(local []byte, rkey uint32, remoteAddr uint64, timeoutMS int) (int, error) {
	n := C.rdial_read(cn.c, unsafe.Pointer(&local[0]), C.uint32_t(rkey),
		C.uint64_t(remoteAddr), C.uint64_t(len(local)), C.int(timeoutMS))
	if n < 0 {
		return 0, fmt.Errorf("rdial: read: %w", errno(n))
	}
	return int(n), nil
}

func (cn *conn) write(local []byte, rkey uint32, remoteAddr uint64, timeoutMS int) (int, error) {
	n := C.rdial_write(cn.c, unsafe.Pointer(&local[0]), C.uint32_t(rkey),
		C.uint64_t(remoteAddr), C.uint64_t(len(local)), C.int(timeoutMS))
	if n < 0 {
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
