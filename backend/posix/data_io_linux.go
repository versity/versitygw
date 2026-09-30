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

//go:build linux

package posix

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"

	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/debuglogger"
	"golang.org/x/sys/unix"
)

// openDataRead opens object data for reading and applies O_DIRECT when
// requested. O_DIRECT is best-effort and falls back to buffered I/O when
// unsupported by the filesystem.
func openDataRead(name string, useODirect bool) (*os.File, error) {
	if !useODirect {
		return os.Open(name)
	}

	f, err := os.OpenFile(name, syscall.O_RDONLY|syscall.O_DIRECT, 0)
	if err != nil {
		if isODirectUnsupportedOpenErr(err) {
			warnODirectUnsupportedOnce("openDataRead", err)
			return os.Open(name)
		}

		return nil, err
	}

	return f, nil
}

func buildGetObjectBody(f *os.File, _ string, startOffset, length, objSize int64, useODirect bool, readBufferSize int) (io.ReadCloser, error) {
	// openDataRead may have silently opened without O_DIRECT.
	if useODirect && isODirectFile(f) {
		return newODirectReader(f, startOffset, length, readBufferSize), nil
	}

	if startOffset == 0 && length == objSize {
		return f, nil
	}

	rdr := io.NewSectionReader(f, startOffset, length)
	return withReadBufferSize(&backend.FileSectionReadCloser{R: rdr, F: f}, readBufferSize), nil
}

func isODirectFile(f *os.File) bool {
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	return err == nil && flags&unix.O_DIRECT != 0
}

var odirectReadBufPool sync.Pool

// odirectReader serves [off, end) of f using block-aligned preads into an
// aligned buffer, as O_DIRECT requires for offset, length, and memory.
type odirectReader struct {
	mu     sync.Mutex
	f      *os.File
	direct bool
	off    int64
	end    int64
	buf    []byte
	bufOff int64
	bufLen int
}

func newODirectReader(f *os.File, off, length int64, bufSize int) *odirectReader {
	size := max(odirectAlign, (bufSize+odirectAlign-1)/odirectAlign*odirectAlign)
	buf, ok := odirectReadBufPool.Get().(*[]byte)
	if !ok || len(*buf) != size {
		b := alignedBuffer(size)
		buf = &b
	}
	return &odirectReader{
		f:      f,
		direct: true,
		off:    off,
		end:    off + length,
		buf:    *buf,
	}
}

func (r *odirectReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	chunk, err := r.chunkLocked()
	if err != nil {
		return 0, err
	}
	n := copy(p, chunk)
	r.off += int64(n)
	return n, nil
}

func (r *odirectReader) WriteTo(w io.Writer) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var written int64
	for {
		chunk, err := r.chunkLocked()
		if err == io.EOF {
			return written, nil
		}
		if err != nil {
			return written, err
		}
		n, err := w.Write(chunk)
		r.off += int64(n)
		written += int64(n)
		if err != nil {
			return written, err
		}
	}
}

func (r *odirectReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.buf != nil {
		buf := r.buf
		odirectReadBufPool.Put(&buf)
		r.buf = nil
	}
	return r.f.Close()
}

// chunkLocked returns the buffered bytes starting at r.off, reading more if needed.
func (r *odirectReader) chunkLocked() ([]byte, error) {
	if r.buf == nil {
		return nil, os.ErrClosed
	}
	if r.off >= r.end {
		return nil, io.EOF
	}
	if r.off < r.bufOff || r.off >= r.bufOff+int64(r.bufLen) {
		if err := r.fillLocked(); err != nil {
			return nil, err
		}
	}

	stop := int64(r.bufLen)
	if rem := r.end - r.bufOff; rem < stop {
		stop = rem
	}
	return r.buf[r.off-r.bufOff : stop], nil
}

func (r *odirectReader) fillLocked() error {
	alignedOff := r.off &^ (odirectAlign - 1)
	buf := r.buf
	if need := (r.end - alignedOff + odirectAlign - 1) &^ (odirectAlign - 1); need < int64(len(buf)) {
		buf = buf[:int(need)]
	}
	n, err := pread(r.f, buf, alignedOff)
	if n == 0 && r.direct && isODirectRuntimeFallbackErr(err) {
		debuglogger.Logf("O_DIRECT read of %s failed at offset %d, falling back to buffered I/O: %v", r.f.Name(), alignedOff, err)
		if ferr := r.switchToBufferedLocked(); ferr != nil {
			return fmt.Errorf("reopen object in buffered mode after O_DIRECT read failure: %w", ferr)
		}
		n, err = pread(r.f, buf, alignedOff)
	}

	r.bufOff, r.bufLen = alignedOff, n
	if r.off < alignedOff+int64(n) {
		return nil
	}
	if err == nil || err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

func (r *odirectReader) switchToBufferedLocked() error {
	bf, err := os.Open(filepath.Join(procfddir, strconv.Itoa(int(r.f.Fd()))))
	if err != nil {
		return err
	}
	if err := r.f.Close(); err != nil {
		_ = bf.Close()
		return err
	}
	r.f = bf
	r.direct = false
	return nil
}

// pread issues a single pread; os.File.ReadAt would loop into an unaligned
// offset after a short read at EOF, which O_DIRECT can reject.
func pread(f *os.File, b []byte, off int64) (int, error) {
	for {
		n, err := unix.Pread(int(f.Fd()), b, off)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, io.EOF
		}
		return n, nil
	}
}
