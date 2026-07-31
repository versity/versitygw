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

package posix

import (
	"bufio"
	"io"
	"log"
	"sync"
)

func withReadBufferSize(r io.ReadCloser, size int) io.ReadCloser {
	if size <= 0 {
		return r
	}

	return &bufferedReadCloser{
		r: bufio.NewReaderSize(r, size),
		c: r,
	}
}

type bufferedReadCloser struct {
	r *bufio.Reader
	c io.Closer
}

func (b *bufferedReadCloser) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func (b *bufferedReadCloser) Close() error {
	return b.c.Close()
}

var odirectUnsupportedWarnByOp sync.Map

func warnODirectUnsupportedOnce(op string, err error) {
	v, _ := odirectUnsupportedWarnByOp.LoadOrStore(op, &sync.Once{})
	v.(*sync.Once).Do(func() {
		log.Printf("WARNING: O_DIRECT is enabled but unsupported (%s: %v); falling back to buffered I/O. This warning is shown once per operation.", op, err)
	})
}
