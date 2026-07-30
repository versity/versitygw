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

// Package bufferpool provides a pool of pre-registered RDMA buffers
// to avoid per-request allocation and registration overhead.
package bufferpool

import (
	"context"
	"errors"
	"fmt"

	"github.com/versity/versitygw/rdma"
)

// Pool manages a fixed set of RDMA-registered host memory buffers.
type Pool struct {
	server  *rdma.Server
	bufSize int
	ch      chan *rdma.Buffer
	all     []*rdma.Buffer
}

// NewPool pre-allocates and registers count buffers of bufSize bytes each.
func NewPool(server *rdma.Server, bufSize, count int) (*Pool, error) {
	if count <= 0 {
		return nil, errors.New("bufferpool: count must be > 0")
	}
	if bufSize <= 0 {
		return nil, errors.New("bufferpool: bufSize must be > 0")
	}

	p := &Pool{
		server:  server,
		bufSize: bufSize,
		ch:      make(chan *rdma.Buffer, count),
		all:     make([]*rdma.Buffer, 0, count),
	}

	for i := range count {
		ptr, err := server.AllocHostBuffer(bufSize)
		if err != nil {
			p.Close()
			return nil, fmt.Errorf("bufferpool: alloc buffer %d: %w", i, err)
		}

		buf, err := server.RegisterBuffer(ptr, bufSize)
		if err != nil {
			server.FreeHostBuffer(ptr)
			p.Close()
			return nil, fmt.Errorf("bufferpool: register buffer %d: %w", i, err)
		}

		p.all = append(p.all, buf)
		p.ch <- buf
	}

	return p, nil
}

// Acquire blocks until a buffer is available or ctx is cancelled.
// Returns the buffer and its backing byte slice.
func (p *Pool) Acquire(ctx context.Context) (*rdma.Buffer, []byte, error) {
	select {
	case buf := <-p.ch:
		return buf, buf.Slice(), nil
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
}

// Release returns a buffer to the pool.
func (p *Pool) Release(buf *rdma.Buffer) {
	p.ch <- buf
}

// Close deregisters and frees all buffers. The pool must not be used afterward.
func (p *Pool) Close() {
	for _, buf := range p.all {
		// Capture the host pointer before DeregisterBuffer clears it, so the
		// underlying allocation from AllocHostBuffer can still be freed.
		ptr := buf.HostPtr()
		p.server.DeregisterBuffer(buf)
		p.server.FreeHostBuffer(ptr)
	}
	p.all = nil
}
