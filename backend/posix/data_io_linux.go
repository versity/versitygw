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

func buildGetObjectBody(f *os.File, path string, startOffset, length, objSize int64, useODirect bool, readBufferSize int) (io.ReadCloser, error) {
	if startOffset == 0 && length == objSize {
		if useODirect {
			return newODirectReadFallbackFile(path, f, true), nil
		}
		return f, nil
	}

	if !useODirect {
		rdr := io.NewSectionReader(f, startOffset, length)
		return withReadBufferSize(&backend.FileSectionReadCloser{R: rdr, F: f}, readBufferSize), nil
	}

	rf := newODirectReadFallbackFile(path, f, true)

	if _, err := rf.Seek(startOffset, io.SeekStart); err != nil {
		_ = rf.Close()
		return nil, fmt.Errorf("seek range start: %w", err)
	}

	return withReadBufferSize(&readerWithCloser{r: io.LimitReader(rf, length), c: rf}, readBufferSize), nil
}

type readerWithCloser struct {
	r io.Reader
	c io.Closer
}

func (r *readerWithCloser) Read(p []byte) (int, error) {
	return r.r.Read(p)
}

func (r *readerWithCloser) Close() error {
	return r.c.Close()
}

type odirectReadFallbackFile struct {
	mu         sync.Mutex
	path       string
	f          *os.File
	useODirect bool
}

func newODirectReadFallbackFile(path string, f *os.File, useODirect bool) *odirectReadFallbackFile {
	return &odirectReadFallbackFile{
		path:       path,
		f:          f,
		useODirect: useODirect,
	}
}

func (r *odirectReadFallbackFile) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	n, err := r.f.Read(p)
	if err != nil && n == 0 && r.useODirect && isODirectRuntimeFallbackErr(err) {
		if fallbackErr := r.switchToBufferedAtCurrentOffsetLocked(); fallbackErr != nil {
			return 0, fallbackErr
		}

		return r.f.Read(p)
	}

	return n, err
}

func (r *odirectReadFallbackFile) WriteTo(w io.Writer) (int64, error) {
	r.mu.Lock()
	useODirect := r.useODirect
	f := r.f
	r.mu.Unlock()

	if !useODirect {
		return io.Copy(w, &onlyRead{r})
	}

	writerTo, ok := interface{}(f).(io.WriterTo)
	if !ok {
		return io.Copy(w, &onlyRead{r})
	}

	n, err := writerTo.WriteTo(w)
	if err == nil || !isODirectRuntimeFallbackErr(err) {
		return n, err
	}

	r.mu.Lock()
	fallbackErr := r.switchToBufferedAtCurrentOffsetLocked()
	r.mu.Unlock()
	if fallbackErr != nil {
		return n, fallbackErr
	}

	m, err := io.Copy(w, &onlyRead{r})
	return n + m, err
}

func (r *odirectReadFallbackFile) Seek(offset int64, whence int) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Seek(offset, whence)
}

func (r *odirectReadFallbackFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}

func (r *odirectReadFallbackFile) switchToBufferedAtOffset(offset int64) error {
	fd := strconv.Itoa(int(r.f.Fd()))
	bf, openErr := os.Open(filepath.Join(procfddir, fd))
	if openErr != nil {
		return openErr
	}

	if _, seekErr := bf.Seek(offset, io.SeekStart); seekErr != nil {
		_ = bf.Close()
		return seekErr
	}

	if closeErr := r.f.Close(); closeErr != nil {
		_ = bf.Close()
		return closeErr
	}

	r.f = bf
	r.useODirect = false

	return nil
}

func (r *odirectReadFallbackFile) switchToBufferedAtCurrentOffsetLocked() error {
	offset, seekErr := r.f.Seek(0, io.SeekCurrent)
	if seekErr != nil {
		return seekErr
	}

	return r.switchToBufferedAtOffset(offset)
}
