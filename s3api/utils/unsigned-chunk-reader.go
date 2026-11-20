// Copyright 2024 Versity Software
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
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"io"
	"math/bits"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/cespare/xxhash/v2"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/s3err"
	"github.com/zeebo/xxh3"
)

var (
	trailerDelim       = []byte{'\n', '\r', '\n'}
	minChunkSize int64 = 8192
)

// UnsignedChunkReader decodes AWS aws-chunked unsigned streaming request
// bodies. It strips chunk headers/trailers, validates chunk framing and trailing
// checksums, and exposes only object payload bytes through Read.
//
// The reader is intentionally streaming: chunk payload bytes are read directly
// into the caller's buffer. It only keeps bounded header/trailer parsing state
// and a few counters, so a large client-declared chunk does not become a large
// allocation in the gateway.
//
// Its memory use does not grow with the body, valid or not: framing lines
// (chunk sizes and the trailer header) are parsed in place in the maxHeaderSize
// read buffer and cannot outgrow it. Past its creation, the reader allocates
// only a few small values, once, to check the trailing checksum.
type UnsignedChunkReader struct {
	reader         *bufio.Reader
	checksumType   checksumType
	parsedChecksum string
	hasher         hash.Hash
	// chunkDataLeft is the number of object data bytes still unread from the
	// current chunk. These bytes are streamed directly into the caller's buffer
	chunkDataLeft int64
	// needChunkEnd means the current chunk payload has been fully returned and
	// the next Read must consume the chunk's trailing "\r\n" before parsing the
	// next chunk header
	needChunkEnd bool
	// isEOF is set after the zero-sized chunk and trailer are parsed, so later
	// reads return io.EOF without touching the underlying request body again.
	isEOF bool
	// The chunk-size rule needs information about the previous chunk: if the
	// next parsed chunk is non-zero, the previous chunk was not the final chunk
	// and must have been at least minChunkSize
	chunkNumber     int64
	lastChunkNumber int64
	lastChunkSize   int64
	seenChunk       bool
	// TODO: Keep these fields ready for the future InvalidChunkSizeError shape:
	// <Chunk> should be invalidChunkNumber and <BadChunkSize> should be
	// invalidChunkSize
	invalidChunkNumber int64
	invalidChunkSize   int64

	cLength int64
	// This data is necessary for the decoded content length mismatch error
	// TODO: add 'NumberBytesExpected' and 'NumberBytesProvided' in the error
	dataRead int64
}

func (ucr *UnsignedChunkReader) decodedBytesReturned() int64 {
	return ucr.dataRead - ucr.chunkDataLeft
}

func (ucr *UnsignedChunkReader) logState(prefix string) {
	debuglogger.Logf("%s:\n  returned_decoded_bytes=%v\n  declared_chunk_bytes=%v\n  current_chunk_left=%v\n  chunk_number=%v\n  last_chunk_number=%v\n  last_chunk_size=%v\n  need_chunk_end=%v",
		prefix,
		ucr.decodedBytesReturned(),
		ucr.dataRead,
		ucr.chunkDataLeft,
		ucr.chunkNumber,
		ucr.lastChunkNumber,
		ucr.lastChunkSize,
		ucr.needChunkEnd)
}

func NewUnsignedChunkReader(r io.Reader, ct checksumType, decContentLength int64) (*UnsignedChunkReader, error) {
	var hasher hash.Hash
	var err error
	if ct != "" {
		hasher, err = getHasher(ct)
	}
	if err != nil {
		debuglogger.Logf("unsigned chunk reader failed to initialize hash calculator for trailing checksum type %q and decoded content length %v: %v", ct, decContentLength, err)
		return nil, err
	}

	debuglogger.Infof("initializing unsigned chunk reader:\n  decoded_content_length=%v\n  checksum_type=%q", decContentLength, ct)
	return &UnsignedChunkReader{
		reader:       bufio.NewReaderSize(r, maxHeaderSize),
		checksumType: ct,
		hasher:       hasher,
		cLength:      decContentLength,
	}, nil
}

// Algorithm returns the checksum algorithm
func (ucr *UnsignedChunkReader) Algorithm() string {
	return strings.TrimPrefix(string(ucr.checksumType), "x-amz-checksum-")
}

// Checksum returns the parsed trailing checksum
func (ucr *UnsignedChunkReader) Checksum() string {
	return ucr.parsedChecksum
}

func (ucr *UnsignedChunkReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	if ucr.isEOF {
		return 0, io.EOF
	}

	var n int

	for n < len(p) {
		// Once a chunk body is drained, validate its CRLF boundary before any
		// more data can be returned. This preserves chunk framing validation
		// while still allowing the body bytes themselves to pass through.
		if ucr.needChunkEnd {
			if err := ucr.readAndSkip('\r', '\n'); err != nil {
				debuglogger.Logf("unsigned chunk reader failed to validate chunk payload delimiter: expected trailing \\r\\n after chunk %v with %v bytes already copied into caller buffer: %v", ucr.lastChunkNumber, n, err)
				ucr.logState("unsigned chunk reader state after chunk payload delimiter failure")
				return n, err
			}
			ucr.needChunkEnd = false
		}

		if ucr.chunkDataLeft == 0 {
			// No payload is pending, so the next bytes must be the chunk-size
			chunkSize, err := ucr.extractChunkSize()
			if err != nil {
				debuglogger.Logf("unsigned chunk reader failed to parse next chunk header after copying %v bytes into caller buffer: %v", n, err)
				ucr.logState("unsigned chunk reader state after chunk header parse failure")
				return n, err
			}

			if chunkSize == 0 {
				// The zero-sized chunk ends the object data stream. At this
				// point all declared chunk payload bytes have been consumed, so
				// validate the decoded content length and then parse trailers.
				ucr.isEOF = true
				if ucr.cLength != ucr.dataRead {
					debuglogger.Logf("unsigned chunk reader decoded content length mismatch at final chunk: expected %v decoded bytes, parsed %v decoded bytes from chunk headers", ucr.cLength, ucr.dataRead)
					ucr.logState("unsigned chunk reader state after decoded content length mismatch")
					err := s3err.GetAPIError(s3err.ErrContentLengthMismatch)
					return n, err
				}

				if err := ucr.readTrailer(); err != nil {
					debuglogger.Logf("unsigned chunk reader failed to parse or validate trailers after final chunk: %v", err)
					ucr.logState("unsigned chunk reader state after trailer failure")
					return n, err
				}

				return n, io.EOF
			}

			ucr.dataRead += chunkSize
			ucr.chunkDataLeft = chunkSize
		}

		contentLeft := ucr.remainingContentLength()
		if contentLeft == 0 && ucr.chunkDataLeft > 0 {
			// The client declared more chunk payload bytes than the decoded
			// content length allows. Do not pass those bytes to the backend
			// writer; return the S3 error from this reader instead.
			return n, ucr.handleExcessChunkData()
		}

		// Read only as much object data as fits in p, the current chunk, and the
		// decoded content length. This is the key streaming path: data is copied
		// from the request body into p without allocating a chunk-sized buffer.
		limit := min(int64(len(p)-n), ucr.chunkDataLeft, contentLeft)
		readEnd := int64(n) + limit
		read, err := ucr.reader.Read(p[n:readEnd])
		if read > 0 {
			if ucr.hasher != nil {
				if _, hashErr := ucr.hasher.Write(p[n : n+read]); hashErr != nil {
					debuglogger.Logf("unsigned chunk reader failed to update trailing checksum hash after reading %v bytes from chunk %v: %v", read, ucr.lastChunkNumber, hashErr)
					ucr.logState("unsigned chunk reader state after checksum hash failure")
					return n, hashErr
				}
			}
			ucr.chunkDataLeft -= int64(read)
			n += read
			if ucr.chunkDataLeft == 0 {
				ucr.needChunkEnd = true
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				debuglogger.Logf("unsigned chunk reader reached EOF while reading chunk %v payload: copied %v bytes into caller buffer, %v bytes still expected in current chunk", ucr.lastChunkNumber, n, ucr.chunkDataLeft)
				err = s3err.GetAPIError(s3err.ErrIncompleteBody)
			} else {
				debuglogger.Logf("unsigned chunk reader failed while reading chunk %v payload after copying %v bytes into caller buffer: %v", ucr.lastChunkNumber, n, err)
			}
			ucr.logState("unsigned chunk reader state after chunk payload read failure")
			return n, err
		}
		if read == 0 {
			debuglogger.Infof("unsigned chunk reader read zero bytes from underlying reader before filling caller buffer:\n  buffer_size=%v\n  returned_bytes=%v", len(p), n)
			return n, nil
		}
	}

	// Checked here rather than left to Infof: its arguments escape, so the
	// call would allocate on every Read even with debug logging disabled.
	if debuglogger.IsDebugEnabled() {
		debuglogger.Infof("Read:\n  buffer_size=%v\n  bytes_returned_this_read=%v\n  decoded_bytes_returned_total=%v\n  current_chunk_left_for_next_read=%v\n  need_chunk_end_for_next_read=%v\n  current_chunk_number=%v\n  declared_chunk_bytes=%v",
			len(p),
			n,
			ucr.decodedBytesReturned(),
			ucr.chunkDataLeft,
			ucr.needChunkEnd,
			ucr.lastChunkNumber,
			ucr.dataRead)
	}

	return n, nil
}

func (ucr *UnsignedChunkReader) remainingContentLength() int64 {
	// dataRead is the sum of parsed chunk sizes, while chunkDataLeft is the
	// unread part of the current chunk. Their difference is the decoded object
	// byte count already returned or ready to return to the caller.
	read := ucr.dataRead - ucr.chunkDataLeft
	if read >= ucr.cLength {
		return 0
	}

	return ucr.cLength - read
}

func (ucr *UnsignedChunkReader) handleExcessChunkData() error {
	// When the decoded content length is exhausted in the middle of a chunk,
	// distinguish "extra payload data" from "chunk ended before its declared
	// size". The latter is an incomplete body; the former is a content-length
	// mismatch. Peek keeps the bytes buffered and avoids forwarding either case
	// to the backend writer.
	buf, err := ucr.reader.Peek(2)
	if len(buf) > 0 && buf[0] != '\r' {
		debuglogger.Logf("unsigned chunk reader decoded content length exhausted in chunk %v, but next byte is payload data instead of chunk delimiter: expected decoded length %v", ucr.lastChunkNumber, ucr.cLength)
		ucr.logState("unsigned chunk reader state after excess chunk payload detection")
		return s3err.GetAPIError(s3err.ErrContentLengthMismatch)
	}
	if len(buf) > 1 && buf[1] != '\n' {
		debuglogger.Logf("unsigned chunk reader decoded content length exhausted in chunk %v, but next bytes are not a valid chunk delimiter: got %q, expected \\r\\n", ucr.lastChunkNumber, buf)
		ucr.logState("unsigned chunk reader state after invalid delimiter at decoded length boundary")
		return s3err.GetAPIError(s3err.ErrContentLengthMismatch)
	}
	if err != nil {
		debuglogger.Logf("unsigned chunk reader could not peek chunk delimiter after decoded content length was exhausted: %v", err)
		ucr.logState("unsigned chunk reader state after delimiter peek failure")
		return s3err.GetAPIError(s3err.ErrIncompleteBody)
	}

	debuglogger.Logf("unsigned chunk reader found a chunk delimiter before declared chunk %v payload was fully read: %v bytes still expected", ucr.lastChunkNumber, ucr.chunkDataLeft)
	ucr.logState("unsigned chunk reader state after short chunk payload detection")
	return s3err.GetAPIError(s3err.ErrIncompleteBody)
}

// Reads and validates the bytes provided from the underlying io.Reader
//
// It runs at least once per chunk, so the logs below take a copy of data: were
// data itself logged, it would escape and every call would allocate it.
func (ucr *UnsignedChunkReader) readAndSkip(data ...byte) error {
	for i, d := range data {
		b, err := ucr.reader.ReadByte()
		if err != nil {
			debuglogger.Logf("unsigned chunk reader failed to read expected byte %d of delimiter %q: expected %q, err: %v", i+1, string(data), d, err)
			return s3err.GetAPIError(s3err.ErrIncompleteBody)
		}

		if b != d {
			debuglogger.Logf("unsigned chunk reader delimiter mismatch at byte %d of %q: expected %q, got %q", i+1, string(data), d, b)
			return s3err.GetAPIError(s3err.ErrIncompleteBody)
		}
	}

	return nil
}

// Extracts the chunk size from the payload
func (ucr *UnsignedChunkReader) extractChunkSize() (int64, error) {
	line, err := ucr.readLine()
	if err != nil {
		debuglogger.Logf("unsigned chunk reader failed to read chunk size line for chunk %v: %v", ucr.chunkNumber+1, err)
		return 0, err
	}

	// The line lives in the read buffer, so it is parsed before the '\n' is
	// read. Both failures are reported the same way, so their order does not
	// change the result.
	chunkSize, parseErr := strconv.ParseInt(string(bytes.TrimSpace(line)), 16, 64)
	if parseErr != nil || chunkSize < 0 {
		debuglogger.Logf("unsigned chunk reader failed to parse chunk %v size %q as non-negative hexadecimal int64: %v", ucr.chunkNumber+1, line, parseErr)
		return 0, s3err.GetAPIError(s3err.ErrIncompleteBody)
	}

	if err := ucr.readAndSkip('\n'); err != nil {
		debuglogger.Logf("unsigned chunk reader chunk %v size header is not followed by \\n after \\r: %v", ucr.chunkNumber+1, err)
		return 0, err
	}
	ucr.chunkNumber++

	if !ucr.isValidChunkSize(chunkSize) {
		debuglogger.Logf("unsigned chunk reader invalid chunk size detected while parsing chunk %v: previous chunk %v had size %v, current chunk size is %v", ucr.chunkNumber, ucr.invalidChunkNumber, ucr.invalidChunkSize, chunkSize)
		return chunkSize, s3err.GetAPIError(s3err.ErrInvalidChunkSize)
	}

	ucr.lastChunkNumber = ucr.chunkNumber
	ucr.lastChunkSize = chunkSize
	ucr.seenChunk = true

	// guarded for the same reason as the log at the end of Read
	if debuglogger.IsDebugEnabled() {
		debuglogger.Infof("chunk size extracted: %v", chunkSize)
	}

	return chunkSize, nil
}

// readLine reads a framing line, either a chunk-size line or the trailer
// header, up to its terminating '\r', and returns it without the '\r'. Checking
// the '\n' that follows is left to the caller.
//
// The line is returned in place from the read buffer, so reading it never
// allocates, and it has to fit there: a line that fills all maxHeaderSize bytes
// of the buffer without a '\r' is rejected, rather than collected somewhere
// larger. This is what keeps a client that sends a never-ending line from
// growing the gateway's memory.
//
// The returned slice is only valid until the next read from ucr.reader, so the
// caller must be done with it before reading the '\n'.
func (ucr *UnsignedChunkReader) readLine() ([]byte, error) {
	line, err := ucr.reader.ReadSlice('\r')
	if errors.Is(err, bufio.ErrBufferFull) {
		debuglogger.Logf("unsigned chunk reader framing line exceeds the maximum allowed size: no \\r within %v bytes", maxHeaderSize)
		return nil, s3err.GetAPIError(s3err.ErrIncompleteBody)
	}
	if err != nil {
		debuglogger.Logf("unsigned chunk reader failed to read framing line up to its \\r delimiter after %v bytes: %v", len(line), err)
		return nil, s3err.GetAPIError(s3err.ErrIncompleteBody)
	}

	return line[:len(line)-1], nil
}

// isValidChunkSize checks if the parsed chunk size is valid
// they follow one rule: all chunk sizes except for the last one
// should be greater than 8192
func (ucr *UnsignedChunkReader) isValidChunkSize(size int64) bool {
	if !ucr.seenChunk {
		// any valid number is valid as a first chunk size
		return true
	}

	// any chunk size, except the last one should be greater than 8192
	if size != 0 && ucr.lastChunkSize < minChunkSize {
		ucr.invalidChunkNumber = ucr.lastChunkNumber
		ucr.invalidChunkSize = ucr.lastChunkSize
		debuglogger.Logf("unsigned chunk reader previous chunk is too small to be followed by another data chunk:\n  invalid_chunk_number=%v\n  bad_chunk_size=%v\n  min_chunk_size=%v\n  next_chunk_size=%v", ucr.invalidChunkNumber, ucr.invalidChunkSize, minChunkSize, size)
		return false
	}

	return true
}

// Reads and validates the trailer that follows the final zero-sized chunk:
// either just "\r\n" when no trailing header is sent, or a single
// "<checksum-header>:<checksum>\r\n" line followed by the closing "\r\n".
//
// The header line is read like a chunk-size line, in place and bounded by the
// read buffer, so a trailer that never ends is rejected once the buffer fills
// instead of being buffered in memory.
func (ucr *UnsignedChunkReader) readTrailer() error {
	line, err := ucr.readLine()
	if err != nil {
		debuglogger.Logf("unsigned chunk reader failed to read trailer header after final chunk: %v", err)
		return err
	}

	// The line lives in the read buffer, so everything needed from it is taken
	// before the terminator is read. The terminator is still checked first, so
	// a body cut short is reported as such whatever its trailer holds.
	header := bytes.TrimSpace(line)
	hasHeader := len(header) != 0
	var checksum string
	var parseErr error
	if hasHeader {
		checksum, parseErr = ucr.parseTrailerHeader(header)
	} else if ucr.checksumType != "" {
		debuglogger.Logf("unsigned chunk reader expected trailing checksum %s, but final trailer header is empty", ucr.checksumType)
		parseErr = s3err.GetAPIError(s3err.ErrMalformedTrailer)
	}

	if len(line) == 0 {
		// No trailer was sent: the '\r' just read opened the closing "\r\n",
		// so only its '\n' is left.
		err = ucr.readAndSkip('\n')
	} else {
		err = ucr.readAndSkip(trailerDelim...)
	}
	if err != nil {
		debuglogger.Logf("unsigned chunk reader trailer terminator is incomplete: %v", err)
		return err
	}

	if parseErr != nil {
		return parseErr
	}
	if !hasHeader {
		return nil
	}

	ucr.parsedChecksum = checksum
	debuglogger.Infof("parsed the trailing header:%s:%s", ucr.checksumType, checksum)

	// Validate checksum
	return ucr.validateChecksum()
}

// parseTrailerHeader parses a trimmed, non-empty trailer header line and
// returns the checksum it carries. The header must be exactly one
// "<checksum-header>:<checksum>" pair, naming the algorithm x-amz-trailer
// announced.
func (ucr *UnsignedChunkReader) parseTrailerHeader(header []byte) (string, error) {
	key, checksum, found := bytes.Cut(header, []byte{':'})
	if !found || bytes.IndexByte(checksum, ':') != -1 {
		debuglogger.Logf("unsigned chunk reader malformed trailer header %q: expected exactly one ':' separator", header)
		return "", s3err.GetAPIError(s3err.ErrMalformedTrailer)
	}

	checksumKey := checksumType(key)
	if !checksumKey.isValid() {
		debuglogger.Logf("unsigned chunk reader malformed trailer header %q: unsupported checksum key %q", header, key)
		return "", s3err.GetAPIError(s3err.ErrMalformedTrailer)
	}

	if checksumKey != ucr.checksumType {
		debuglogger.Logf("unsigned chunk reader trailer checksum type mismatch: expected %q from x-amz-trailer, got %q in trailer header", ucr.checksumType, key)
		return "", s3err.GetAPIError(s3err.ErrMalformedTrailer)
	}

	return string(checksum), nil
}

// Validates the trailing checksum sent at the end
func (ucr *UnsignedChunkReader) validateChecksum() error {
	algo := types.ChecksumAlgorithm(strings.ToUpper(strings.TrimPrefix(string(ucr.checksumType), "x-amz-checksum-")))
	// validate the checksum
	if !IsValidChecksum(ucr.parsedChecksum, algo) {
		debuglogger.Logf("unsigned chunk reader parsed trailing checksum has invalid format: algo=%s, checksum=%s", algo, ucr.parsedChecksum)
		return s3err.GetInvalidTrailingChecksumHeaderErr(string(ucr.checksumType))
	}

	checksum := ucr.calculateChecksum()

	// compare the calculated and parsed checksums
	if checksum != ucr.parsedChecksum {
		debuglogger.Logf("unsigned chunk reader trailing checksum mismatch: algo=%s, parsed_checksum=%v, calculated_checksum=%v, decoded_bytes=%v", algo, ucr.parsedChecksum, checksum, ucr.decodedBytesReturned())
		return s3err.GetChecksumBadDigestErr(algo)
	}

	return nil
}

// calculateChecksum calculates the checksum with the unsigned reader hasher
func (ucr *UnsignedChunkReader) calculateChecksum() string {
	csum := ucr.hasher.Sum(nil)
	return base64.StdEncoding.EncodeToString(csum)
}

// Returns the hash calculator based on the hash type provided
func getHasher(ct checksumType) (hash.Hash, error) {
	switch ct {
	case checksumTypeCrc32:
		return crc32.NewIEEE(), nil
	case checksumTypeCrc32c:
		return crc32.New(crc32.MakeTable(crc32.Castagnoli)), nil
	case checksumTypeCrc64nvme:
		table := crc64.MakeTable(bits.Reverse64(0xad93d23594c93659))
		return crc64.New(table), nil
	case checksumTypeSha1:
		return sha1.New(), nil
	case checksumTypeSha256:
		return sha256.New(), nil
	case checksumTypeSha512:
		return sha512.New(), nil
	case checksumTypeMd5:
		return md5.New(), nil
	case checksumTypeXxhash64:
		return xxhash.New(), nil
	case checksumTypeXxhash3:
		return xxh3.New(), nil
	case checksumTypeXxhash128:
		return xxh3.New128(), nil
	default:
		return nil, errors.New("unsupported checksum type")
	}
}
