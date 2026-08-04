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

//go:build linux && amd64 && cgo && cuobjclient_host

// This file implements the cuObjClient Session API on top of the host-memory
// RDMA client (package rdma/hostclient). It contains no CUDA/GPU dependency and
// is selected with the `cuobjclient_host` build tag for RDMA-capable hosts that
// have no GPU.
//
// The RDMA endpoint is configured from the environment so the NewSession(size)
// SDK signature stays identical to the GPU build:
//
//	VGWRDMA_RDMA_DEV    RDMA device name (default: first device, e.g. mlx5_0)
//	VGWRDMA_RDMA_PORT   HCA port number (default: 1)
//	VGWRDMA_GID_INDEX   RoCE GID index from `ibv_devinfo -v`
//	                    (default: auto-select first non-link-local GID)
//	VGWRDMA_DC_KEY      Dynamic Connection key, decimal or 0x-hex
//	                    (default: matches server DCKey 0xffeeddcc)
package cuobjclient

import (
	"fmt"
	"os"
	"strconv"

	s3lib "github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/versity/versitygw/rdma/hostclient"
)

// Session owns a host buffer registered for cuObject RDMA transfers via the
// host-memory RDMA client. Session methods are not safe for concurrent use.
type Session struct {
	client      *hostclient.Client
	buf         []byte
	token       string
	size        int
	remoteStart uint64
}

// NewSession creates a host-memory RDMA session for a fixed transfer size.
func NewSession(size int) (*Session, error) {
	if size <= 0 {
		return nil, fmt.Errorf("invalid size %d", size)
	}
	if size > MaxTransferSize {
		return nil, fmt.Errorf("invalid size %d: exceeds MaxTransferSize (%d)", size, MaxTransferSize)
	}

	dev := os.Getenv("VGWRDMA_RDMA_DEV")
	port := envUint8("VGWRDMA_RDMA_PORT", 1)
	gidIndex := envInt("VGWRDMA_GID_INDEX", -1)
	dcKey := envUint64("VGWRDMA_DC_KEY", hostclient.DefaultDCKey)

	client, err := hostclient.NewClient(dev, port, gidIndex, dcKey)
	if err != nil {
		return nil, err
	}

	buf, err := client.Register(size)
	if err != nil {
		client.Close()
		return nil, err
	}
	token, err := client.Token()
	if err != nil {
		client.Close()
		return nil, err
	}

	return &Session{
		client:      client,
		buf:         buf,
		token:       token,
		size:        size,
		remoteStart: client.BufferAddr(),
	}, nil
}

// Close releases the registered host buffer and closes the RDMA client.
// After Close returns, the Session must not be used.
func (s *Session) Close() {
	if s.client == nil {
		return
	}
	s.client.Close()
	s.client = nil
	s.buf = nil
}

// Upload copies src into the registered host buffer and performs a PUT. The
// gateway RDMA-reads the buffer contents during the request.
func (s *Session) Upload(base *s3lib.Client, bucket, key string, src []byte) error {
	if len(src) != s.size {
		return fmt.Errorf("upload size mismatch: got %d bytes, want %d", len(src), s.size)
	}
	copy(s.buf, src)
	return doPut(base, bucket, key, int64(s.size), s.token, s.remoteStart)
}

// Download performs a GET; the gateway RDMA-writes into the registered host
// buffer, then the bytes are copied into dst.
func (s *Session) Download(base *s3lib.Client, bucket, key string, dst []byte) error {
	if len(dst) != s.size {
		return fmt.Errorf("download size mismatch: got %d bytes, want %d", len(dst), s.size)
	}
	for i := range s.buf {
		s.buf[i] = 0
	}
	if err := doGet(base, bucket, key, int64(s.size), s.token, s.remoteStart); err != nil {
		return err
	}
	copy(dst, s.buf)
	return nil
}

func envUint8(name string, def uint8) uint8 {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.ParseUint(v, 10, 8)
	if err != nil {
		return def
	}
	return uint8(n)
}

func envInt(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envUint64(name string, def uint64) uint64 {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.ParseUint(v, 0, 64)
	if err != nil {
		return def
	}
	return n
}
