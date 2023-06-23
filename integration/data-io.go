package integration

import (
	"crypto/rand"
	"crypto/sha256"
	"hash"
	"io"
)

type RReader struct {
	buf      []byte
	dataleft int
	hash     hash.Hash
}

func NewDataReader(totalsize, bufsize int) *RReader {
	b := make([]byte, bufsize)
	rand.Read(b)
	return &RReader{
		buf:      b,
		dataleft: totalsize,
		hash:     sha256.New(),
	}
}

func (r *RReader) Read(p []byte) (int, error) {
	n := min(len(p), len(r.buf), r.dataleft)
	r.dataleft -= n
	err := error(nil)
	if n == 0 {
		err = io.EOF
	}
	r.hash.Write(r.buf[:n])
	return copy(p, r.buf[:n]), err
}

func (r *RReader) Sum() []byte {
	return r.hash.Sum(nil)
}

type ZReader struct {
	buf      []byte
	dataleft int
}

func NewZeroReader(totalsize, bufsize int) *ZReader {
	b := make([]byte, bufsize)
	return &ZReader{buf: b, dataleft: totalsize}
}

func (r *ZReader) Read(p []byte) (int, error) {
	n := min(len(p), len(r.buf), r.dataleft)
	r.dataleft -= n
	err := error(nil)
	if n == 0 {
		err = io.EOF
	}
	return copy(p, r.buf[:n]), err
}

func min(values ...int) int {
	if len(values) == 0 {
		return 0
	}

	min := values[0]
	for _, v := range values {
		if v < min {
			min = v
		}
	}

	return min
}

type NW struct{}

func NewNullWriter() NW {
	return NW{}
}

func (NW) WriteAt(p []byte, off int64) (n int, err error) {
	return len(p), nil
}
