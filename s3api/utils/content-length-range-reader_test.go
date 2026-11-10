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

package utils

import (
	"errors"
	"io"
	"math"
	"strings"
	"sync"
	"testing"

	"github.com/versity/versitygw/s3err"
)

// endlessReader gives bytes without end and counts them. It does not fill the
// buffers it is given.
type endlessReader struct{ n int64 }

func (e *endlessReader) Read(p []byte) (int, error) {
	e.n += int64(len(p))

	return len(p), nil
}

// sizedReader gives n bytes and then io.EOF. It does not fill the buffers it
// is given.
type sizedReader struct{ left int64 }

func (s *sizedReader) Read(p []byte) (int, error) {
	if s.left <= 0 {
		return 0, io.EOF
	}
	n := int(min(int64(len(p)), s.left))
	s.left -= int64(n)

	return n, nil
}

// dataThenErrReader gives data, then fails with err.
type dataThenErrReader struct {
	data string
	err  error
}

func (f *dataThenErrReader) Read(p []byte) (int, error) {
	if f.data == "" {
		return 0, f.err
	}
	n := copy(p, f.data)
	f.data = f.data[n:]

	return n, nil
}

func tooLargeErr(t *testing.T, err error) s3err.EntityTooLargeError {
	t.Helper()

	var tooLarge s3err.EntityTooLargeError
	if !errors.As(err, &tooLarge) {
		t.Fatalf("expected EntityTooLarge, got %v", err)
	}

	return tooLarge
}

func tooSmallErr(t *testing.T, err error) s3err.EntityTooSmallError {
	t.Helper()

	var tooSmall s3err.EntityTooSmallError
	if !errors.As(err, &tooSmall) {
		t.Fatalf("expected EntityTooSmall, got %v", err)
	}

	return tooSmall
}

func TestContentLengthRangeReaderInRange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		data   string
		lo, hi int64
	}{
		{name: "between the min and the max", data: "hello", lo: 2, hi: 9},
		{name: "at the min", data: "he", lo: 2, hi: 9},
		{name: "at the max", data: "hello", lo: 2, hi: 5},
		{name: "empty, with no min", data: "", lo: 0, hi: 5},
		{name: "empty, with a max of zero", data: "", lo: 0, hi: 0},
		{name: "any size", data: "hello", lo: 0, hi: math.MaxInt64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rdr := NewContentLengthRangeReader(strings.NewReader(tt.data), tt.lo, tt.hi, int64(len(tt.data)))
			got, err := io.ReadAll(rdr)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(got) != tt.data {
				t.Fatalf("unexpected data: got %q want %q", got, tt.data)
			}
			if rdr.Err() != nil {
				t.Fatalf("unexpected error: %v", rdr.Err())
			}
		})
	}
}

func TestContentLengthRangeReaderOverMax(t *testing.T) {
	t.Parallel()

	t.Run("a byte over the max", func(t *testing.T) {
		t.Parallel()

		rdr := NewContentLengthRangeReader(strings.NewReader("hello"), 0, 4, 5)
		_, err := io.ReadAll(rdr)

		tooLarge := tooLargeErr(t, err)
		if tooLarge.ProposedSize != 5 || tooLarge.MaxSizeAllowed != 4 {
			t.Fatalf("unexpected sizes: proposed %d max %d, want 5 and 4", tooLarge.ProposedSize, tooLarge.MaxSizeAllowed)
		}
		if rdr.Err() != err {
			t.Fatalf("expected Err to be the error of the read, got %v", rdr.Err())
		}
	})

	t.Run("fails every read once it failed", func(t *testing.T) {
		t.Parallel()

		src := &endlessReader{}
		rdr := NewContentLengthRangeReader(src, 0, 10, 100)

		buf := make([]byte, 64)
		_, first := rdr.Read(buf)
		tooLargeErr(t, first)

		readBefore := src.n
		n, again := rdr.Read(buf)
		if n != 0 || again != first {
			t.Fatalf("expected the same error again, got %d bytes and %v", n, again)
		}
		if src.n != readBefore {
			t.Fatal("read the file after it failed")
		}
	})

	t.Run("does not read the rest of the file", func(t *testing.T) {
		t.Parallel()

		src := &endlessReader{}
		rdr := NewContentLengthRangeReader(src, 0, 10, 1<<30)
		_, err := io.ReadAll(rdr)

		// the file goes on, so the size reported is the one the request proposes
		tooLarge := tooLargeErr(t, err)
		if tooLarge.ProposedSize != 1<<30 || tooLarge.MaxSizeAllowed != 10 {
			t.Fatalf("unexpected sizes: proposed %d max %d, want %d and 10", tooLarge.ProposedSize, tooLarge.MaxSizeAllowed, 1<<30)
		}
		if src.n > 4096 {
			t.Fatalf("read %d bytes of a file for a max of 10", src.n)
		}
	})

	t.Run("does not give the bytes over the max", func(t *testing.T) {
		t.Parallel()

		rdr := NewContentLengthRangeReader(strings.NewReader("hello world"), 0, 5, 11)
		n, err := rdr.Read(make([]byte, 64))

		tooLargeErr(t, err)
		if n != 0 {
			t.Fatalf("expected no bytes with the error, got %d", n)
		}
	})

	t.Run("a max of zero", func(t *testing.T) {
		t.Parallel()

		rdr := NewContentLengthRangeReader(strings.NewReader("a"), 0, 0, 1)
		_, err := io.ReadAll(rdr)

		tooLarge := tooLargeErr(t, err)
		if tooLarge.ProposedSize != 1 || tooLarge.MaxSizeAllowed != 0 {
			t.Fatalf("unexpected sizes: proposed %d max %d, want 1 and 0", tooLarge.ProposedSize, tooLarge.MaxSizeAllowed)
		}
	})

	t.Run("over the max as the file ends", func(t *testing.T) {
		t.Parallel()

		rdr := NewContentLengthRangeReader(&eofWithDataReader{data: []byte("hello")}, 0, 4, 5)
		_, err := io.ReadAll(rdr)

		tooLarge := tooLargeErr(t, err)
		if tooLarge.ProposedSize != 5 {
			t.Fatalf("unexpected proposed size: got %d want 5", tooLarge.ProposedSize)
		}
	})
}

func TestContentLengthRangeReaderUnderMin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  io.Reader
	}{
		{name: "the end after the data", src: strings.NewReader("hi")},
		{name: "the end with the data", src: &eofWithDataReader{data: []byte("hi")}},
		{name: "a byte at a time", src: &oneByteReader{data: []byte("hi")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rdr := NewContentLengthRangeReader(tt.src, 3, 10, 2)
			_, err := io.ReadAll(rdr)

			tooSmall := tooSmallErr(t, err)
			if tooSmall.ProposedSize != 2 || tooSmall.MinSizeAllowed != 3 {
				t.Fatalf("unexpected sizes: proposed %d min %d, want 2 and 3", tooSmall.ProposedSize, tooSmall.MinSizeAllowed)
			}
			if rdr.Err() != err {
				t.Fatalf("expected Err to be the error of the read, got %v", rdr.Err())
			}
		})
	}

	t.Run("an empty file", func(t *testing.T) {
		t.Parallel()

		rdr := NewContentLengthRangeReader(strings.NewReader(""), 1, 10, 0)
		_, err := io.ReadAll(rdr)

		tooSmall := tooSmallErr(t, err)
		if tooSmall.ProposedSize != 0 || tooSmall.MinSizeAllowed != 1 {
			t.Fatalf("unexpected sizes: proposed %d min %d, want 0 and 1", tooSmall.ProposedSize, tooSmall.MinSizeAllowed)
		}
	})

	t.Run("not before the file ends", func(t *testing.T) {
		t.Parallel()

		rdr := NewContentLengthRangeReader(strings.NewReader("hi"), 3, 10, 2)

		buf := make([]byte, 8)
		n, err := rdr.Read(buf)
		if n != 2 || err != nil {
			t.Fatalf("expected the bytes without an error, got %d and %v", n, err)
		}
	})
}

// postForm is a POST Object form whose file is content, with tail after it.
func postForm(content, tail string) string {
	return "--abc\r\n" +
		"Content-Disposition: form-data; name=\"key\"\r\n" +
		"\r\n" +
		"value\r\n" +
		"--abc\r\n" +
		"Content-Disposition: form-data; name=\"file\"\r\n" +
		"\r\n" +
		content + tail
}

const fieldAfterFile = "\r\n--abc\r\n" +
	"Content-Disposition: form-data; name=\"content-type\"\r\n" +
	"\r\n" +
	"text/plain" +
	"\r\n--abc--\r\n"

func TestContentLengthRangeReaderReportsTheFileSize(t *testing.T) {
	t.Parallel()

	// the proposal of a form with a field after the file is the size of the
	// file and the field, which is not what is refused
	t.Run("a file with a field after it", func(t *testing.T) {
		t.Parallel()

		body := postForm("hello world", fieldAfterFile)
		parsed, err := NewMultipartParser(strings.NewReader(body), "abc", int64(len(body)))
		if err != nil {
			t.Fatalf("new multipart parser: %v", err)
		}
		form, err := parsed.Parse()
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if form.ProposedSize <= int64(len("hello world")) {
			t.Fatalf("expected a proposed size over the file's, got %d", form.ProposedSize)
		}

		rdr := NewContentLengthRangeReader(form.FileRdr, 0, 5, form.ProposedSize)
		_, err = io.ReadAll(rdr)

		tooLarge := tooLargeErr(t, err)
		if tooLarge.ProposedSize != int64(len("hello world")) || tooLarge.MaxSizeAllowed != 5 {
			t.Fatalf("unexpected sizes: proposed %d max %d, want %d and 5", tooLarge.ProposedSize, tooLarge.MaxSizeAllowed, len("hello world"))
		}
	})

	// the file goes on past what is read: its size is not known, and what the
	// request proposes is the size of a form that ends with the file
	t.Run("a large file that ends the form", func(t *testing.T) {
		t.Parallel()

		content := strings.Repeat("a", 1<<20)
		body := postForm(content, "\r\n--abc--\r\n")
		parsed, err := NewMultipartParser(strings.NewReader(body), "abc", int64(len(body)))
		if err != nil {
			t.Fatalf("new multipart parser: %v", err)
		}
		form, err := parsed.Parse()
		if err != nil {
			t.Fatalf("parse: %v", err)
		}

		rdr := NewContentLengthRangeReader(form.FileRdr, 0, 5, form.ProposedSize)
		_, err = io.ReadAll(rdr)

		tooLarge := tooLargeErr(t, err)
		if tooLarge.ProposedSize != int64(len(content)) || tooLarge.MaxSizeAllowed != 5 {
			t.Fatalf("unexpected sizes: proposed %d max %d, want %d and 5", tooLarge.ProposedSize, tooLarge.MaxSizeAllowed, len(content))
		}
	})

	t.Run("a proposal under what was read", func(t *testing.T) {
		t.Parallel()

		rdr := NewContentLengthRangeReader(&endlessReader{}, 0, 10, 4)
		_, err := rdr.Read(make([]byte, 64))

		// the 64 bytes of the read and the one that looked for the end
		tooLarge := tooLargeErr(t, err)
		if tooLarge.ProposedSize != 65 {
			t.Fatalf("unexpected proposed size: got %d want 65", tooLarge.ProposedSize)
		}
	})
}

func TestContentLengthRangeReaderMaxIsWhatS3Takes(t *testing.T) {
	t.Parallel()

	const fiveGiB = 5 << 30

	for name, hi := range map[string]int64{
		"no max":                         math.MaxInt64,
		"a max over what S3 takes":       fiveGiB * 4,
		"a max of what S3 takes exactly": fiveGiB,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			buf := make([]byte, 1<<20)

			rdr := NewContentLengthRangeReader(&sizedReader{left: fiveGiB}, 0, hi, fiveGiB)
			for {
				_, err := rdr.Read(buf)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("read 5 GiB: %v", err)
				}
			}

			rdr = NewContentLengthRangeReader(&sizedReader{left: fiveGiB + 1}, 0, hi, fiveGiB+1)
			var err error
			for err == nil {
				_, err = rdr.Read(buf)
			}
			tooLarge := tooLargeErr(t, err)
			if tooLarge.MaxSizeAllowed != fiveGiB || tooLarge.ProposedSize != fiveGiB+1 {
				t.Fatalf("unexpected sizes: proposed %d max %d, want %d and %d", tooLarge.ProposedSize, tooLarge.MaxSizeAllowed, int64(fiveGiB+1), int64(fiveGiB))
			}
		})
	}
}

func TestContentLengthRangeReaderErr(t *testing.T) {
	t.Parallel()

	t.Run("the error of the file's reader", func(t *testing.T) {
		t.Parallel()

		boom := errors.New("connection reset")
		rdr := NewContentLengthRangeReader(&dataThenErrReader{data: "abc", err: boom}, 0, 10, 3)
		got, err := io.ReadAll(rdr)

		if err != boom || string(got) != "abc" {
			t.Fatalf("expected %q and the error as it is, got %q and %v", "abc", got, err)
		}
		if rdr.Err() != boom {
			t.Fatalf("expected Err to be the error of the file's reader, got %v", rdr.Err())
		}
	})

	t.Run("an S3 error of the file's reader", func(t *testing.T) {
		t.Parallel()

		malformed := s3err.GetAPIError(s3err.ErrMalformedPOSTRequest)
		rdr := NewContentLengthRangeReader(&dataThenErrReader{data: "abc", err: malformed}, 0, 10, 3)
		_, err := io.ReadAll(rdr)

		if err != malformed || rdr.Err() != malformed {
			t.Fatalf("expected the error as it is, got %v and %v", err, rdr.Err())
		}
	})

	t.Run("no error at the end of a file in range", func(t *testing.T) {
		t.Parallel()

		rdr := NewContentLengthRangeReader(strings.NewReader("abc"), 1, 10, 3)
		if _, err := io.ReadAll(rdr); err != nil {
			t.Fatalf("read: %v", err)
		}
		if rdr.Err() != nil {
			t.Fatalf("unexpected error: %v", rdr.Err())
		}
	})
}

func TestContentLengthRangeReaderEndedBefore(t *testing.T) {
	t.Parallel()

	rdr := NewContentLengthRangeReader(strings.NewReader("hello"), 0, 10, 20)
	if rdr.EndedBefore(20) {
		t.Fatal("the file did not end before it was read")
	}

	buf := make([]byte, 64)
	if n, err := rdr.Read(buf); n != 5 || err != nil {
		t.Fatalf("expected the bytes, got %d and %v", n, err)
	}
	if rdr.EndedBefore(20) {
		t.Fatal("the file did not end before its end was reached")
	}

	if _, err := rdr.Read(buf); err != io.EOF {
		t.Fatalf("expected the end, got %v", err)
	}
	for n, want := range map[int64]bool{20: true, 6: true, 5: false, 4: false, 0: false} {
		if got := rdr.EndedBefore(n); got != want {
			t.Fatalf("EndedBefore(%d): got %v want %v", n, got, want)
		}
	}
}

// A backend can still be reading the file when the caller asks how it went.
func TestContentLengthRangeReaderConcurrentErr(t *testing.T) {
	t.Parallel()

	rdr := NewContentLengthRangeReader(&sizedReader{left: 1 << 20}, 1<<30, 1<<30, 1<<20)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		buf := make([]byte, 100)
		for {
			if _, err := rdr.Read(buf); err != nil {
				return
			}
		}
	}()

	for i := 0; i < 1000; i++ {
		_ = rdr.Err()
		_ = rdr.EndedBefore(1 << 20)
	}
	wg.Wait()

	tooSmallErr(t, rdr.Err())
}
