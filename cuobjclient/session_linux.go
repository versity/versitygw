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

//go:build linux && amd64 && cgo && !cuobjclient_host

package cuobjclient

/*
#cgo CFLAGS: -I/usr/include -I${SRCDIR}/../cuwrapper
#cgo LDFLAGS: -L${SRCDIR}/../rdma -l:libcuobjclientwrapper.a -L/usr/lib64 -lcuobjclient -lcudart -lstdc++ -ldl
#include <stdlib.h>
#include "cuobjclient_wrapper.h"
*/
import "C"

import (
	"fmt"
	"unsafe"

	s3lib "github.com/aws/aws-sdk-go-v2/service/s3"
)

const (
	cuObjOpGet = 0
	cuObjOpPut = 1
)

// Session owns a CUDA buffer registered for cuObject RDMA token exchange.
type Session struct {
	ctx         *C.cuobj_client_ctx_t
	gpuBuf      unsafe.Pointer
	size        int
	remoteStart uint64
}

// NewSession creates a GPU-backed cuObject session for a fixed transfer size.
// The returned session allocates CUDA memory, registers the descriptor with
// cuobjclient, and prepares RDMA token generation for Upload and Download.
// size must be in the range [1, MaxTransferSize].
// A Session is reusable for multiple transfers as long as each Upload or
// Download uses buffers with length equal to the size passed to NewSession.
// Callers should keep a session open for repeated sequential operations and
// call Close once the session is no longer needed.
// Session methods are not safe for concurrent use. Do not call Upload,
// Download, or Close from multiple goroutines at the same time on the same
// Session value.
// Call Close when finished to release all resources.
func NewSession(size int) (*Session, error) {
	if size <= 0 {
		return nil, fmt.Errorf("invalid size %d", size)
	}
	if size > MaxTransferSize {
		return nil, fmt.Errorf("invalid size %d: exceeds MaxTransferSize (%d)", size, MaxTransferSize)
	}

	ctx := C.cuobj_client_create()
	if ctx == nil {
		return nil, fmt.Errorf("cuobj_client_create failed")
	}

	s := &Session{ctx: ctx, size: size}
	buf := C.cuobj_client_cuda_malloc(C.size_t(size))
	if buf == nil {
		s.Close()
		return nil, fmt.Errorf("cudaMalloc(%d) failed", size)
	}
	s.gpuBuf = buf

	if err := s.register(); err != nil {
		s.Close()
		return nil, err
	}

	s.remoteStart = uint64(C.cuobj_client_ptr_to_u64(s.gpuBuf))
	return s, nil
}

// Close releases the GPU buffer and destroys the cuObject client context.
// After Close returns, the Session must not be used.
func (s *Session) Close() {
	if s.ctx == nil {
		return
	}
	if s.gpuBuf != nil {
		_ = s.unregister()
		_ = s.cudaFree()
		s.gpuBuf = nil
	}
	C.cuobj_client_destroy(s.ctx)
	s.ctx = nil
}

// Upload copies src into the session GPU buffer and performs a PUT operation
// using cuObject RDMA headers.
// src length must exactly match the size passed to NewSession.
func (s *Session) Upload(base *s3lib.Client, bucket, key string, src []byte) error {
	if len(src) != s.size {
		return fmt.Errorf("upload size mismatch: got %d bytes, want %d", len(src), s.size)
	}
	if err := s.copyH2D(src); err != nil {
		return err
	}
	token, err := s.getToken(cuObjOpPut)
	if err != nil {
		return err
	}
	defer s.putToken(token)
	return doPut(base, bucket, key, int64(s.size), C.GoString(token), s.remoteStart)
}

// Download performs a GET operation into the session GPU buffer and copies the
// resulting bytes back into dst.
// dst length must exactly match the size passed to NewSession.
func (s *Session) Download(base *s3lib.Client, bucket, key string, dst []byte) error {
	if len(dst) != s.size {
		return fmt.Errorf("download size mismatch: got %d bytes, want %d", len(dst), s.size)
	}
	if err := s.memset(0); err != nil {
		return err
	}
	token, err := s.getToken(cuObjOpGet)
	if err != nil {
		return err
	}
	defer s.putToken(token)
	if err := doGet(base, bucket, key, int64(s.size), C.GoString(token), s.remoteStart); err != nil {
		return err
	}
	return s.copyD2H(dst)
}

func (s *Session) register() error {
	rc := C.cuobj_client_register_descriptor(s.ctx, s.gpuBuf, C.size_t(s.size))
	if rc != 0 {
		return fmt.Errorf("cuMemObjGetDescriptor failed (rc=%d)", int(rc))
	}
	return nil
}

func (s *Session) unregister() error {
	rc := C.cuobj_client_unregister_descriptor(s.ctx, s.gpuBuf)
	if rc != 0 {
		return fmt.Errorf("cuMemObjPutDescriptor failed (rc=%d)", int(rc))
	}
	return nil
}

func (s *Session) cudaFree() error {
	rc := C.cuobj_client_cuda_free(s.gpuBuf)
	if rc != 0 {
		return fmt.Errorf("cudaFree failed: %s", C.GoString(C.cuobj_client_cuda_error_string(rc)))
	}
	return nil
}

func (s *Session) memset(val int) error {
	rc := C.cuobj_client_cuda_memset(s.gpuBuf, C.int(val), C.size_t(s.size))
	if rc != 0 {
		return fmt.Errorf("cudaMemset failed: %s", C.GoString(C.cuobj_client_cuda_error_string(rc)))
	}
	return nil
}

func (s *Session) copyH2D(src []byte) error {
	if len(src) == 0 {
		return nil
	}
	rc := C.cuobj_client_cuda_memcpy_h2d(s.gpuBuf, unsafe.Pointer(&src[0]), C.size_t(len(src)))
	if rc != 0 {
		return fmt.Errorf("cudaMemcpy H2D failed: %s", C.GoString(C.cuobj_client_cuda_error_string(rc)))
	}
	return nil
}

func (s *Session) copyD2H(dst []byte) error {
	if len(dst) == 0 {
		return nil
	}
	rc := C.cuobj_client_cuda_memcpy_d2h(unsafe.Pointer(&dst[0]), s.gpuBuf, C.size_t(len(dst)))
	if rc != 0 {
		return fmt.Errorf("cudaMemcpy D2H failed: %s", C.GoString(C.cuobj_client_cuda_error_string(rc)))
	}
	return nil
}

func (s *Session) getToken(op int) (*C.char, error) {
	t := C.cuobj_client_get_rdma_token(s.ctx, s.gpuBuf, C.size_t(s.size), C.size_t(0), C.int(op))
	if t == nil {
		return nil, fmt.Errorf("cuMemObjGetRDMAToken failed")
	}
	return t, nil
}

func (s *Session) putToken(token *C.char) {
	if token == nil {
		return
	}
	_ = C.cuobj_client_put_rdma_token(s.ctx, token)
}
