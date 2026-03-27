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
	"bufio"
	"bytes"
	"fmt"
	"io"
	"mime"
	"net/textproto"
	"strings"

	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/s3err"
)

const finalBoundaryDelimiterLen = 8 // len("\r\n--") + len("--\r\n")

// MultipartParser parses S3 browser-based POST multipart/form-data in a streaming way.
// It buffers regular form fields, but it does not buffer the file part.
type MultipartParser struct {
	br                   *bufio.Reader
	boundary             string
	requestContentLength int64
	bytesRead            int64
}

// NewMultipartParser creates a new streaming multipart parser.
// boundary should be the raw boundary value from Content-Type, without the leading "--".
// If accidentally "--<boundary>" has been passed, it is normalized.
func NewMultipartParser(body io.Reader, boundary string, requestContentLength int64) (*MultipartParser, error) {
	if body == nil {
		debuglogger.Logf("multipart parser requires non-nil body reader")
		return nil, fmt.Errorf("nil body reader")
	}
	if requestContentLength < 0 {
		debuglogger.Logf("invalid multipart request content-length: %d", requestContentLength)
		return nil, fmt.Errorf("invalid request content-length: %d", requestContentLength)
	}

	boundary = strings.TrimSpace(boundary)
	boundary = strings.TrimPrefix(boundary, "--")
	if boundary == "" {
		debuglogger.Logf("multipart boundary is empty")
		return nil, s3err.GetAPIError(s3err.ErrMalformedPOSTRequest)
	}

	return &MultipartParser{
		br:                   bufio.NewReader(body),
		boundary:             boundary,
		requestContentLength: requestContentLength,
	}, nil
}

// MpFileReader is the streaming interface for the file part of a multipart POST.
// It extends io.Reader with a Length method that returns the number of file-content
// bytes actually delivered to callers (boundary and delimiter bytes are not counted).
type MpFileReader interface {
	io.Reader
	Length() int64
}

type MpParseResult struct {
	// Fields contains all non-file form fields collected before the file part.
	Fields map[string]string
	// FileRdr streams the file payload without buffering the entire part in memory.
	FileRdr MpFileReader
	// ContentLength is the expected byte length of the file payload only.
	ContentLength int64
}

// Parse parses all non-file fields and returns:
//   - form values
//   - a streaming file reader
//   - file content length
//
// The returned file reader MUST be read until EOF, otherwise final-boundary
// validation is not triggered.
func (mp *MultipartParser) Parse() (*MpParseResult, error) {
	fields := make(map[string]string)

	if err := mp.expectInitialBoundary(); err != nil {
		return nil, err
	}

	for {
		headers, err := mp.readHeaders()
		if err != nil {
			return nil, err
		}

		cd, ok := headers[textproto.CanonicalMIMEHeaderKey("Content-Disposition")]
		if !ok {
			debuglogger.Logf("multipart part is missing Content-Disposition header")
			return nil, s3err.GetAPIError(s3err.ErrMalformedPOSTRequest)
		}

		disp, params, err := mime.ParseMediaType(cd)
		if err != nil {
			debuglogger.Logf("invalid multipart Content-Disposition header %q: %v", cd, err)
			return nil, s3err.GetAPIError(s3err.ErrMalformedPOSTRequest)
		}
		if disp != "form-data" {
			debuglogger.Logf("unexpected multipart disposition: %s", disp)
			return nil, s3err.GetAPIError(s3err.ErrMalformedPOSTRequest)
		}

		name := strings.ToLower(params["name"])
		if name == "" {
			debuglogger.Logf("multipart part is missing field name")
			return nil, s3err.GetAPIError(s3err.ErrMalformedPOSTRequest)
		}

		_, hasFilename := params["filename"]
		isFilePart := name == "file" || hasFilename

		// At this point, headers + blank line have already been consumed,
		// so bytesRead points exactly at the first byte of file content.
		if isFilePart {
			fileContentLength := mp.requestContentLength - mp.bytesRead - int64(len(mp.boundary)) - finalBoundaryDelimiterLen
			if fileContentLength < 0 {
				debuglogger.Logf("calculated negative multipart file content-length: %d", fileContentLength)
				return nil, fmt.Errorf("calculated negative file content-length: %d", fileContentLength)
			}

			fr := &finalFileReader{
				r:       mp.br,
				trailer: []byte("\r\n--" + mp.boundary + "--\r\n"),
			}

			return &MpParseResult{
				Fields:        fields,
				FileRdr:       fr,
				ContentLength: fileContentLength,
			}, nil
		}

		value, err := mp.readFieldValue()
		if err != nil {
			return nil, err
		}

		if strings.HasPrefix(name, "x-amz-meta-") {
			val, ok := fields[name]
			if ok {
				fields[name] = val + "," + value
				continue
			}
		}

		fields[name] = value
	}
}

func (mp *MultipartParser) expectInitialBoundary() error {
	line, _, err := mp.readLine()
	if err != nil {
		return s3err.GetAPIError(s3err.ErrMalformedPOSTRequest)
	}

	want := "--" + mp.boundary
	if line != want {
		debuglogger.Logf("unexpected initial multipart boundary: got %q want %q", line, want)
		return s3err.GetAPIError(s3err.ErrMalformedPOSTRequest)
	}
	return nil
}

func (mp *MultipartParser) readHeaders() (map[string]string, error) {
	headers := make(map[string]string)

	for {
		line, _, err := mp.readLine()
		if err != nil {
			return nil, s3err.GetAPIError(s3err.ErrMalformedPOSTRequest)
		}

		// Blank line terminates headers.
		if line == "" {
			return headers, nil
		}

		key, value, ok := strings.Cut(line, ":")
		if !ok {
			debuglogger.Logf("invalid multipart header line: %q", line)
			return nil, s3err.GetAPIError(s3err.ErrMalformedPOSTRequest)
		}

		key = textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		headers[key] = value
	}
}

// readFieldValue reads a regular form field until the next boundary line.
// It keeps exact field bytes except for the final CRLF that belongs to the boundary separator.
func (mp *MultipartParser) readFieldValue() (string, error) {
	boundaryLine := "--" + mp.boundary
	finalBoundaryLine := boundaryLine + "--"

	var buf bytes.Buffer

	for {
		line, raw, err := mp.readLine()
		if err != nil {
			return "", err
		}

		switch line {
		case boundaryLine:
			trimTrailingCRLF(&buf)
			return buf.String(), nil

		case finalBoundaryLine:
			debuglogger.Logf("multipart POST ended before file part was found")
			return "", s3err.GetAPIError(s3err.ErrPOSTFileRequired)

		default:
			buf.Write(raw)
		}
	}
}

// readLine reads one CRLF-terminated line, counts consumed bytes,
// returns the line without trailing CRLF, and also the raw bytes including CRLF.
func (mp *MultipartParser) readLine() (string, []byte, error) {
	s, err := mp.br.ReadString('\n')
	if err != nil {
		debuglogger.Logf("failed to read multipart line: %v", err)
		return "", nil, s3err.GetAPIError(s3err.ErrMalformedPOSTRequest)
	}

	mp.bytesRead += int64(len(s))

	if !strings.HasSuffix(s, "\r\n") {
		debuglogger.Logf("multipart line is not CRLF-terminated: %q", s)
		return "", nil, s3err.GetAPIError(s3err.ErrMalformedPOSTRequest)
	}

	return strings.TrimSuffix(s, "\r\n"), []byte(s), nil
}

func trimTrailingCRLF(buf *bytes.Buffer) {
	b := buf.Bytes()
	if len(b) >= 2 && b[len(b)-2] == '\r' && b[len(b)-1] == '\n' {
		buf.Truncate(len(b) - 2)
	}
}

// finalFileReader streams file bytes until it reaches the final multipart boundary:
//
//	\r\n--<boundary>--\r\n
//
// Any epilogue bytes after that final boundary are ignored.
type finalFileReader struct {
	r *bufio.Reader
	// trailer is the exact byte sequence that terminates the file part.
	trailer []byte
	// buf keeps unread bytes plus a trailer-sized lookbehind window so
	// boundary bytes split across reads are not emitted as file content.
	buf []byte
	// bytesRead counts only the file-content bytes delivered to callers.
	// Boundary and delimiter bytes are never included in this count.
	bytesRead int64

	done   bool
	failed error
	eof    bool
}

func (r *finalFileReader) Read(p []byte) (int, error) {
	if r.failed != nil {
		return 0, r.failed
	}
	if r.done {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}

	for {
		// If the final boundary is already in the buffer, return only file
		// bytes before it and stop cleanly once the boundary starts at buf[0].
		if idx := bytes.Index(r.buf, r.trailer); idx >= 0 {
			if idx == 0 {
				r.buf = nil
				r.done = true
				return 0, io.EOF
			}

			n := copy(p, r.buf[:idx])
			r.buf = r.buf[n:]
			r.bytesRead += int64(n)
			return n, nil
		}

		// Bytes before this point cannot be part of a future trailer match, so
		// they are safe to release to the caller.
		safe := len(r.buf) - len(r.trailer) + 1
		if safe > 0 {
			n := copy(p, r.buf[:safe])
			r.buf = r.buf[n:]
			r.bytesRead += int64(n)
			return n, nil
		}

		if r.eof {
			// Reaching EOF without finding the expected closing boundary means
			// the multipart body was truncated or malformed.
			debuglogger.Logf("multipart file stream ended before final boundary %q", string(r.trailer))
			r.failed = s3err.GetAPIError(s3err.ErrMalformedPOSTRequest)
			return 0, r.failed
		}

		chunk := make([]byte, 4096)
		n, err := r.r.Read(chunk)
		if n > 0 {
			r.buf = append(r.buf, chunk[:n]...)
		}

		if err == io.EOF {
			r.eof = true
			continue
		}
		if err != nil {
			debuglogger.Logf("failed to read multipart file data: %v", err)
			r.failed = err
			return 0, err
		}
	}
}

// Length returns the total number of file-content bytes delivered to callers so far.
// Multipart boundary and delimiter bytes are never counted.
func (r *finalFileReader) Length() int64 {
	return r.bytesRead
}
