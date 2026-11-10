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
	if got.ProposedSize != int64(len("file-body-123")) {
		t.Fatalf("unexpected proposed file size: got %d want %d", got.ProposedSize, len("file-body-123"))
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
	if got.ProposedSize != 3 {
		t.Fatalf("unexpected proposed file size: got %d want 3", got.ProposedSize)
	}

	fileData, err := io.ReadAll(got.FileRdr)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if string(fileData) != "xyz" {
		t.Fatalf("unexpected file data: %q", fileData)
	}
}

func TestMultipartParserSkipsPreamble(t *testing.T) {
	t.Parallel()

	for name, preamble := range map[string]string{
		"text":       "This is the preamble.\r\n",
		"blank line": "\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			body := preamble + strings.Join([]string{
				"--abc\r\n",
				"Content-Disposition: form-data; name=\"key\"\r\n",
				"\r\n",
				"value\r\n",
				"--abc\r\n",
				"Content-Disposition: form-data; name=\"file\"\r\n",
				"\r\n",
				"payload",
				"\r\n--abc--\r\n",
			}, "")

			got, err := newMultipartParserForTest(t, body, "abc").Parse()
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got.Fields["key"] != "value" {
				t.Fatalf("unexpected key field: %q", got.Fields["key"])
			}
		})
	}
}

func TestMultipartParserJoinsFoldedHeaders(t *testing.T) {
	t.Parallel()

	body := strings.Join([]string{
		"--abc\r\n",
		"Content-Disposition: form-data;\r\n",
		" name=\"key\"\r\n",
		"\r\n",
		"value\r\n",
		"--abc\r\n",
		"Content-Disposition: form-data;\r\n",
		"\tname=\"file\"; filename=\"note.txt\"\r\n",
		"\r\n",
		"payload",
		"\r\n--abc--\r\n",
	}, "")

	got, err := newMultipartParserForTest(t, body, "abc").Parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Fields["key"] != "value" {
		t.Fatalf("unexpected key field: %q", got.Fields["key"])
	}

	fileData, err := io.ReadAll(got.FileRdr)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if string(fileData) != "payload" {
		t.Fatalf("unexpected file data: %q", fileData)
	}
}

func TestMultipartParserIgnoresFieldsAfterFile(t *testing.T) {
	t.Parallel()

	body := strings.Join([]string{
		"--abc\r\n",
		"Content-Disposition: form-data; name=\"file\"; filename=\"note.txt\"\r\n",
		"\r\n",
		"payload",
		"\r\n--abc\r\n",
		"Content-Disposition: form-data; name=\"content-type\"\r\n",
		"\r\n",
		"text/plain",
		"\r\n--abc--\r\n",
	}, "")

	got, err := newMultipartParserForTest(t, body, "abc").Parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := got.Fields["content-type"]; ok {
		t.Fatalf("unexpected field after the file: %q", got.Fields["content-type"])
	}

	// The request proposes the field after the file as part of it: the
	// proposed size is more than the file's own.
	if got.ProposedSize <= int64(len("payload")) {
		t.Fatalf("expected a proposed size over %d, got %d", len("payload"), got.ProposedSize)
	}

	fileData, err := io.ReadAll(got.FileRdr)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if string(fileData) != "payload" {
		t.Fatalf("unexpected file data: %q", fileData)
	}
	// the file ends at the first boundary: what is read is the file alone
	if got.FileRdr.Length() != int64(len("payload")) {
		t.Fatalf("unexpected file length: got %d want %d", got.FileRdr.Length(), len("payload"))
	}
}

// preDataForm is a form with a field of padding bytes before the file.
func preDataForm(padding int) string {
	return "--abc\r\n" +
		"Content-Disposition: form-data; name=\"x-ignore-padding\"\r\n" +
		"\r\n" +
		strings.Repeat("a", padding) +
		"\r\n--abc\r\n" +
		"Content-Disposition: form-data; name=\"file\"\r\n" +
		"\r\n" +
		"payload" +
		"\r\n--abc--\r\n"
}

// preDataPaddingAtLimit puts preDataForm's bytes before the file content at
// exactly maxPreDataLength.
var preDataPaddingAtLimit = maxPreDataLength - (len(preDataForm(0)) - len("payload\r\n--abc--\r\n"))

func TestMultipartParserAcceptsDataBeforeFileAtLimit(t *testing.T) {
	t.Parallel()

	if _, err := newMultipartParserForTest(t, preDataForm(preDataPaddingAtLimit), "abc").Parse(); err != nil {
		t.Fatalf("parse: %v", err)
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
			want: s3err.GetInvalidArgumentErr(s3err.InvalidArgPOSTFileRequired, "0"),
		},
		{
			name: "data before the file over the limit",
			body: preDataForm(preDataPaddingAtLimit + 1),
			want: s3err.GetAPIError(s3err.ErrMaxPostPreDataLengthExceeded),
		},
		{
			name: "header line over the limit, without a newline",
			body: "--abc\r\nContent-Disposition: " + strings.Repeat("a", 1<<20),
			want: s3err.GetAPIError(s3err.ErrMaxPostPreDataLengthExceeded),
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

// TestMultipartParserPreDataLimitErrorBody checks the response S3 sends for
// fields before the file that are too large: its message, typo included, and
// the MaxPostPreDataLengthBytes element.
func TestMultipartParserPreDataLimitErrorBody(t *testing.T) {
	t.Parallel()

	_, err := newMultipartParserForTest(t, preDataForm(preDataPaddingAtLimit+1), "abc").Parse()

	var s3Err s3err.S3Error
	if !errors.As(err, &s3Err) {
		t.Fatalf("expected an s3 error, got %v", err)
	}

	want := `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<Error>` +
		`<Code>MaxPostPreDataLengthExceeded</Code>` +
		`<Message>Your POST request fields preceeding the upload file was too large.</Message>` +
		`<MaxPostPreDataLengthBytes>20480</MaxPostPreDataLengthBytes>` +
		`<RequestId>req</RequestId>` +
		`<HostId>host</HostId>` +
		`</Error>`
	if got := string(s3Err.XMLBody("req", "host")); got != want {
		t.Fatalf("unexpected error body:\n got: %s\nwant: %s", got, want)
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
