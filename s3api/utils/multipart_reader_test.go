package utils

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/versity/versitygw/s3err"
)

type chunkedReader struct {
	data  []byte
	steps []int
	pos   int
	idx   int
}

func (r *chunkedReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}

	n := len(p)
	if r.idx < len(r.steps) && r.steps[r.idx] < n {
		n = r.steps[r.idx]
	}
	remaining := len(r.data) - r.pos
	if remaining < n {
		n = remaining
	}

	copy(p, r.data[r.pos:r.pos+n])
	r.pos += n
	r.idx++
	return n, nil
}

func newMultipartParserForTest(t *testing.T, body, boundary string) *MultipartParser {
	t.Helper()

	mp, err := NewMultipartParser(strings.NewReader(body), boundary, int64(len(body)))
	if err != nil {
		t.Fatalf("new multipart parser: %v", err)
	}

	return mp
}

func TestNewMultipartParserValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		body      io.Reader
		boundary  string
		length    int64
		wantError error
	}{
		{
			name:      "nil body",
			boundary:  "abc",
			length:    1,
			wantError: errors.New("nil body reader"),
		},
		{
			name:      "negative content length",
			body:      strings.NewReader("x"),
			boundary:  "abc",
			length:    -1,
			wantError: errors.New("invalid request content-length: -1"),
		},
		{
			name:      "empty boundary",
			body:      strings.NewReader("x"),
			boundary:  "  ",
			length:    1,
			wantError: s3err.GetAPIError(s3err.ErrMalformedPOSTRequest),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewMultipartParser(tt.body, tt.boundary, tt.length)
			if err == nil {
				t.Fatal("expected error")
			}
			if err.Error() != tt.wantError.Error() {
				t.Fatalf("unexpected error: got %v want %v", err, tt.wantError)
			}
		})
	}
}

func TestMultipartParserParseSuccess(t *testing.T) {
	t.Parallel()

	body := strings.Join([]string{
		"----abc\r\n",
		"Content-Disposition: form-data; name=\"key\"\r\n",
		"\r\n",
		"uploads/photo.jpg\r\n",
		"----abc\r\n",
		"Content-Disposition: form-data; name=\"success_action_status\"\r\n",
		"\r\n",
		"201\r\n",
		"----abc\r\n",
		"Content-Disposition: form-data; name=\"x-amz-meta-color\"\r\n",
		"\r\n",
		"blue\r\n",
		"----abc\r\n",
		"Content-Disposition: form-data; name=\"x-amz-meta-color\"\r\n",
		"\r\n",
		"green\r\n",
		"----abc\r\n",
		"Content-Disposition: form-data; name=\"file\"; filename=\"photo.jpg\"\r\n",
		"Content-Type: image/jpeg\r\n",
		"\r\n",
		"file-body-123",
		"\r\n----abc--\r\n",
	}, "")

	mp := newMultipartParserForTest(t, body, "--abc")

	got, err := mp.Parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if got.Fields["key"] != "uploads/photo.jpg" {
		t.Fatalf("unexpected key field: %q", got.Fields["key"])
	}
	if got.Fields["success_action_status"] != "201" {
		t.Fatalf("unexpected status field: %q", got.Fields["success_action_status"])
	}
	if got.Fields["x-amz-meta-color"] != "blue,green" {
		t.Fatalf("unexpected merged metadata field: %q", got.Fields["x-amz-meta-color"])
	}
	if got.ContentLength != int64(len("file-body-123")) {
		t.Fatalf("unexpected file content-length: got %d want %d", got.ContentLength, len("file-body-123"))
	}

	fileData, err := io.ReadAll(got.FileRdr)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if string(fileData) != "file-body-123" {
		t.Fatalf("unexpected file data: %q", fileData)
	}

	n, err := got.FileRdr.Read(make([]byte, 1))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF after file reader drained, got n=%d err=%v", n, err)
	}
}

func TestMultipartParserParsePreservesMultilineFieldValue(t *testing.T) {
	t.Parallel()

	body := strings.Join([]string{
		"--abc\r\n",
		"Content-Disposition: form-data; name=\"policy\"\r\n",
		"\r\n",
		"line-one\r\n",
		"line-two\r\n",
		"--abc\r\n",
		"Content-Disposition: form-data; name=\"file\"; filename=\"note.txt\"\r\n",
		"\r\n",
		"payload",
		"\r\n--abc--\r\n",
	}, "")

	mp := newMultipartParserForTest(t, body, "abc")

	got, err := mp.Parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if got.Fields["policy"] != "line-one\r\nline-two" {
		t.Fatalf("unexpected multiline field: %q", got.Fields["policy"])
	}
}

func TestMultipartParserRecognizesFilenameOnlyFilePart(t *testing.T) {
	t.Parallel()

	body := strings.Join([]string{
		"--abc\r\n",
		"Content-Disposition: form-data; name=\"key\"\r\n",
		"\r\n",
		"value\r\n",
		"--abc\r\n",
		"Content-Disposition: form-data; name=\"upload\"; filename=\"blob.bin\"\r\n",
		"\r\n",
		"xyz",
		"\r\n--abc--\r\n",
	}, "")

	mp := newMultipartParserForTest(t, body, "abc")

	got, err := mp.Parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.ContentLength != 3 {
		t.Fatalf("unexpected file content-length: got %d want 3", got.ContentLength)
	}

	fileData, err := io.ReadAll(got.FileRdr)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if string(fileData) != "xyz" {
		t.Fatalf("unexpected file data: %q", fileData)
	}
}

func TestMultipartParserParseErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want error
	}{
		{
			name: "invalid initial boundary",
			body: strings.Join([]string{
				"--wrong\r\n",
				"Content-Disposition: form-data; name=\"file\"; filename=\"x\"\r\n",
				"\r\n",
				"payload\r\n",
				"--abc--\r\n",
			}, ""),
			want: s3err.GetAPIError(s3err.ErrMalformedPOSTRequest),
		},
		{
			name: "missing content disposition header",
			body: strings.Join([]string{
				"--abc\r\n",
				"Content-Type: text/plain\r\n",
				"\r\n",
				"value\r\n",
				"--abc--\r\n",
			}, ""),
			want: s3err.GetAPIError(s3err.ErrMalformedPOSTRequest),
		},
		{
			name: "invalid header format",
			body: strings.Join([]string{
				"--abc\r\n",
				"Content-Disposition form-data; name=\"key\"\r\n",
				"\r\n",
				"value\r\n",
				"--abc--\r\n",
			}, ""),
			want: s3err.GetAPIError(s3err.ErrMalformedPOSTRequest),
		},
		{
			name: "invalid content disposition media type",
			body: strings.Join([]string{
				"--abc\r\n",
				"Content-Disposition: attachment; name=\"key\"\r\n",
				"\r\n",
				"value\r\n",
				"--abc--\r\n",
			}, ""),
			want: s3err.GetAPIError(s3err.ErrMalformedPOSTRequest),
		},
		{
			name: "missing content disposition name",
			body: strings.Join([]string{
				"--abc\r\n",
				"Content-Disposition: form-data\r\n",
				"\r\n",
				"value\r\n",
				"--abc--\r\n",
			}, ""),
			want: s3err.GetAPIError(s3err.ErrMalformedPOSTRequest),
		},
		{
			name: "missing file part",
			body: strings.Join([]string{
				"--abc\r\n",
				"Content-Disposition: form-data; name=\"key\"\r\n",
				"\r\n",
				"value\r\n",
				"--abc--\r\n",
			}, ""),
			want: s3err.GetAPIError(s3err.ErrPOSTFileRequired),
		},
		{
			name: "line without crlf terminator",
			body: strings.Join([]string{
				"--abc\n",
				"Content-Disposition: form-data; name=\"file\"; filename=\"x\"\r\n",
				"\r\n",
				"payload\r\n",
				"--abc--\r\n",
			}, ""),
			want: s3err.GetAPIError(s3err.ErrMalformedPOSTRequest),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mp := newMultipartParserForTest(t, tt.body, "abc")
			_, err := mp.Parse()
			if !errors.Is(err, tt.want) {
				t.Fatalf("unexpected error: got %v want %v", err, tt.want)
			}
		})
	}
}

func TestMultipartParserFileReaderRequiresFinalBoundary(t *testing.T) {
	t.Parallel()

	body := strings.Join([]string{
		"--abc\r\n",
		"Content-Disposition: form-data; name=\"file\"; filename=\"x\"\r\n",
		"\r\n",
		"payload-without-closing-boundary",
	}, "")

	mp := newMultipartParserForTest(t, body, "abc")

	got, err := mp.Parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	_, err = io.ReadAll(got.FileRdr)
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrMalformedPOSTRequest)) {
		t.Fatalf("expected malformed post request, got %v", err)
	}
}

func TestFinalFileReaderStopsAtFinalBoundary(t *testing.T) {
	t.Parallel()

	r := &finalFileReader{
		r:       bufio.NewReader(strings.NewReader("hello world\r\n--abc--\r\ntrailing-data")),
		trailer: []byte("\r\n--abc--\r\n"),
	}

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}

	if string(got) != "hello world" {
		t.Fatalf("unexpected body: got %q", got)
	}

	n, err := r.Read(make([]byte, 8))
	if n != 0 {
		t.Fatalf("expected zero bytes after EOF, got %d", n)
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF after final boundary, got %v", err)
	}
}

func TestFinalFileReaderHandlesBoundarySplitAcrossReads(t *testing.T) {
	t.Parallel()

	src := &chunkedReader{
		data:  []byte("hello world\r\n--abc--\r\nignored"),
		steps: []int{5, 3, 2, 1, 4, 2, 3, 10},
	}
	r := &finalFileReader{
		r:       bufio.NewReader(src),
		trailer: []byte("\r\n--abc--\r\n"),
	}

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}

	if string(got) != "hello world" {
		t.Fatalf("unexpected body: got %q", got)
	}
}

func TestFinalFileReaderMissingFinalBoundary(t *testing.T) {
	t.Parallel()

	r := &finalFileReader{
		r:       bufio.NewReader(strings.NewReader("hello world")),
		trailer: []byte("\r\n--abc--\r\n"),
	}

	_, err := io.ReadAll(r)
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrMalformedPOSTRequest)) {
		t.Fatalf("expected malformed post request, got %v", err)
	}
}

func TestFinalFileReaderLengthCountsOnlyFileBytes(t *testing.T) {
	t.Parallel()

	fileContent := "hello world"
	// trailer bytes must not be included in Length()
	src := fileContent + "\r\n--abc--\r\n"

	r := &finalFileReader{
		r:       bufio.NewReader(strings.NewReader(src)),
		trailer: []byte("\r\n--abc--\r\n"),
	}

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if string(got) != fileContent {
		t.Fatalf("unexpected body: got %q want %q", got, fileContent)
	}
	if r.Length() != int64(len(fileContent)) {
		t.Fatalf("unexpected length: got %d want %d", r.Length(), len(fileContent))
	}
}

func TestFinalFileReaderLengthZeroBeforeRead(t *testing.T) {
	t.Parallel()

	r := &finalFileReader{
		r:       bufio.NewReader(strings.NewReader("data\r\n--b--\r\n")),
		trailer: []byte("\r\n--b--\r\n"),
	}

	if r.Length() != 0 {
		t.Fatalf("expected length 0 before any reads, got %d", r.Length())
	}
}

func TestFinalFileReaderLengthIncrementalReads(t *testing.T) {
	t.Parallel()

	fileContent := "abcdefgh"
	src := &chunkedReader{
		data:  []byte(fileContent + "\r\n--abc--\r\n"),
		steps: []int{3, 3, 2, 10},
	}
	r := &finalFileReader{
		r:       bufio.NewReader(src),
		trailer: []byte("\r\n--abc--\r\n"),
	}

	var total int
	buf := make([]byte, 4)
	for {
		n, err := r.Read(buf)
		total += n
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("unexpected read error: %v", err)
		}
	}

	if r.Length() != int64(len(fileContent)) {
		t.Fatalf("length after incremental reads: got %d want %d", r.Length(), len(fileContent))
	}
	if int64(total) != r.Length() {
		t.Fatalf("total bytes returned by Read (%d) does not match Length() (%d)", total, r.Length())
	}
}

func TestMultipartParserFileReaderLength(t *testing.T) {
	t.Parallel()

	fileContent := "file-body-123"
	body := strings.Join([]string{
		"--abc\r\n",
		"Content-Disposition: form-data; name=\"key\"\r\n",
		"\r\n",
		"mykey\r\n",
		"--abc\r\n",
		"Content-Disposition: form-data; name=\"file\"; filename=\"f.bin\"\r\n",
		"\r\n",
		fileContent,
		"\r\n--abc--\r\n",
	}, "")

	mp := newMultipartParserForTest(t, body, "abc")

	got, err := mp.Parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if got.FileRdr.Length() != 0 {
		t.Fatalf("expected Length 0 before reading, got %d", got.FileRdr.Length())
	}

	if _, err := io.ReadAll(got.FileRdr); err != nil {
		t.Fatalf("read all: %v", err)
	}

	if got.FileRdr.Length() != int64(len(fileContent)) {
		t.Fatalf("unexpected Length after read: got %d want %d", got.FileRdr.Length(), len(fileContent))
	}
}
