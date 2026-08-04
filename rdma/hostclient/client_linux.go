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

// Package hostclient implements the client side of the cuObject RDMA DC
// protocol using libibverbs + mlx5 direct verbs, with no CUDA/GPU dependency.
//
// It is the host-memory counterpart to the GPU-based NVIDIA libcuobjclient:
// it registers host memory, exposes a passive DC target the gateway can RDMA
// READ/WRITE, and produces the RDMA descriptor token the gateway expects in
// the S3 request headers.
package hostclient

/*
#cgo CFLAGS: -I${SRCDIR}/../../cuwrapper
#cgo LDFLAGS: -L${SRCDIR}/.. -l:libhostclientwrapper.a -libverbs -lmlx5 -lstdc++
#include <stdlib.h>
#include "rdma_host_client_wrapper.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// DefaultDCKey is the cuObjServer default Dynamic Connection key. The client
// DC target must use a key matching the server's DCKey tunable.
const DefaultDCKey uint64 = 0xffeeddcc

// Client owns a passive DC target endpoint and a single registered host buffer.
// A Client is not safe for concurrent use.
type Client struct {
	c    *C.rdma_host_client_t
	buf  unsafe.Pointer
	size int
}

// NewClient opens the RDMA device and builds the DC target endpoint.
// dev selects the device by name (e.g. "mlx5_0"); empty picks the first.
// port is the HCA port (usually 1). gidIndex selects the RoCE GID (see
// `ibv_devinfo -v`). dcKey must match the server's DCKey (DefaultDCKey by
// default).
func NewClient(dev string, port uint8, gidIndex int, dcKey uint64) (*Client, error) {
	var cdev *C.char
	if dev != "" {
		cdev = C.CString(dev)
		defer C.free(unsafe.Pointer(cdev))
	}
	h := C.rdma_host_client_create(cdev, C.uint8_t(port), C.int(gidIndex), C.uint64_t(dcKey))
	if h == nil {
		return nil, errors.New("hostclient: allocation failed")
	}
	c := &Client{c: h}
	if msg := C.rdma_host_client_last_error(h); msg != nil {
		err := fmt.Errorf("hostclient: %s", C.GoString(msg))
		c.Close()
		return nil, err
	}
	return c, nil
}

// Register allocates and registers a host buffer of the given size and returns
// a Go slice backed by it. The slice is valid until the next Register call or
// Close. Copy PUT data into the slice before the transfer; read GET data out
// of it afterward.
func (c *Client) Register(size int) ([]byte, error) {
	if c.c == nil {
		return nil, errors.New("hostclient: closed")
	}
	if size <= 0 {
		return nil, fmt.Errorf("hostclient: invalid size %d", size)
	}
	ptr := C.rdma_host_client_alloc(c.c, C.size_t(size))
	if ptr == nil {
		return nil, fmt.Errorf("hostclient: register failed: %s", c.lastError())
	}
	c.buf = unsafe.Pointer(ptr)
	c.size = size
	return unsafe.Slice((*byte)(ptr), size), nil
}

// Token returns the RDMA descriptor token for the currently registered buffer.
// See cumiddleware.HeaderRDMAToken for the canonical wire-format field table.
func (c *Client) Token() (string, error) {
	if c.c == nil {
		return "", errors.New("hostclient: closed")
	}
	t := C.rdma_host_client_token(c.c)
	if t == nil {
		return "", errors.New("hostclient: no registered buffer")
	}
	return C.GoString(t), nil
}

// Buffer returns the current registered buffer as a Go slice, or nil.
func (c *Client) Buffer() []byte {
	if c.c == nil || c.buf == nil || c.size == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(c.buf), c.size)
}

// BufferAddr returns the virtual address of the registered buffer. This is the
// remote base address the gateway uses as the RDMA start offset; it matches the
// address encoded in Token.
func (c *Client) BufferAddr() uint64 {
	if c.c == nil || c.buf == nil {
		return 0
	}
	return uint64(uintptr(c.buf))
}

// Close releases the buffer and tears down the endpoint.
func (c *Client) Close() {
	if c.c == nil {
		return
	}
	C.rdma_host_client_destroy(c.c)
	c.c = nil
	c.buf = nil
	c.size = 0
}

func (c *Client) lastError() string {
	if msg := C.rdma_host_client_last_error(c.c); msg != nil {
		return C.GoString(msg)
	}
	return "unknown error"
}
