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
	"net"
	"unsafe"
)

// ooDialer is the production dialer over the TCP parameter
// exchange: for fabrics without kernel CM the connection is
// established by exchanging QP parameters with the client's
// listener and programming the QP directly. Transfers use the same
// C wrapper entry points as the CM dial.
type ooDialer struct{ cfg Config }

// newOOBDialer binds the "oob" transport on rdma builds; the stub
// build binds the same name to stubDialer.
func newOOBDialer(cfg Config) Dialer { return ooDialer{cfg: cfg} }

func (d ooDialer) TransportSupported() bool { return true }

func (d ooDialer) Dial(t Token) (Conn, error) {
	host, portStr, err := net.SplitHostPort(t.ListenAddr())
	if err != nil {
		return nil, fmt.Errorf("rcdial: listener address: %w", err)
	}
	var port uint64
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil || port == 0 || port > 65535 {
		return nil, fmt.Errorf("rcdial: listener port %q", portStr)
	}
	cip := C.CString(host)
	defer C.free(unsafe.Pointer(cip))
	var c *C.struct_rdial_conn
	rc := C.rdial_dial_oob(cip, C.uint16_t(port), C.int(d.cfg.dialMS()), &c)
	if rc != 0 {
		return nil, fmt.Errorf("rdial: oob dial %s:%d: %w", host, port, errno(C.long(rc)))
	}
	return &connAdapter{c: &conn{c: c}, cfg: d.cfg}, nil
}
