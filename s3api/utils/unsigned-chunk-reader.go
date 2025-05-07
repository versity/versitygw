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
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"io"
	"math/bits"
	"strconv"
	"strings"

	"github.com/versity/versitygw/s3api/debuglogger"
)

var (
	trailerDelim         = []byte{'\n', '\r', '\n'}
	errMalformedEncoding = errors.New("malformed chunk encoding")
)

type UnsignedChunkReader struct {
	reader           *bufio.Reader
	checksumType     checksumType
	expectedChecksum string
	hasher           hash.Hash
	stash            []byte
	offset           int
}

func NewUnsignedChunkReader(r io.Reader, ct checksumType) (*UnsignedChunkReader, error) {
	hasher, err := getHasher(ct)
	if err != nil {
		debuglogger.Logf("failed to initialize hash calculator: %v", err)
		return nil, err
	}
	debuglogger.Infof("initializing unsigned chunk reader")
	return &UnsignedChunkReader{
		reader:       bufio.NewReader(r),
		checksumType: ct,
		stash:        make([]byte, 0),
		hasher:       hasher,
	}, nil
}

func (ucr *UnsignedChunkReader) Read(p []byte) (int, error) {
	// First read any stashed data
	if len(ucr.stash) != 0 {
		debuglogger.Infof("recovering the stash: (stash length): %v", len(ucr.stash))
		n := copy(p, ucr.stash)
		ucr.offset += n

		if n < len(ucr.stash) {
			ucr.stash = ucr.stash[n:]
			ucr.offset = 0
			return n, nil
		}
	}

	for {
		// Read the chunk size
		chunkSize, err := ucr.extractChunkSize()
		if err != nil {
			return 0, err
		}

		if chunkSize == 0 {
			// Stop reading parsing payloads as 0 sized chunk is reached
			break
		}
		rdr := io.TeeReader(ucr.reader, ucr.hasher)
		payload := make([]byte, chunkSize)
		// Read and cache the payload
		_, err = io.ReadFull(rdr, payload)
		if err != nil {
			debuglogger.Logf("failed to read chunk data: %v", err)
			return 0, err
		}

		// Skip the trailing "\r\n"
		if err := ucr.readAndSkip('\r', '\n'); err != nil {
			debuglogger.Logf("failed to read trailing \\r\\n after chunk data: %v", err)
			return 0, err
		}

		// Copy the payload into the io.Reader buffer
		n := copy(p[ucr.offset:], payload)
		ucr.offset += n

		if int64(n) < chunkSize {
			// stash the remaining data
			ucr.stash = payload[n:]
			debuglogger.Infof("stashing the remaining data: (stash length): %v", len(ucr.stash))
			dataRead := ucr.offset
			ucr.offset = 0
			return dataRead, nil
		}
	}

	// Read and validate trailers
	if err := ucr.readTrailer(); err != nil {
		debuglogger.Logf("failed to read trailer: %v", err)
		return 0, err
	}

	return ucr.offset, io.EOF
}

// Reads and validates the bytes provided from the underlying io.Reader
func (ucr *UnsignedChunkReader) readAndSkip(data ...byte) error {
	for _, d := range data {
		b, err := ucr.reader.ReadByte()
		if err != nil {
			if err == io.EOF {
				return io.ErrUnexpectedEOF
			}
			return err
		}

		if b != d {
			return errMalformedEncoding
		}
	}

	return nil
}

// Extracts the chunk size from the payload
func (ucr *UnsignedChunkReader) extractChunkSize() (int64, error) {
	line, err := ucr.reader.ReadString('\n')
	if err != nil {
		debuglogger.Logf("failed to parse chunk size: %v", err)
		return 0, errMalformedEncoding
	}
	line = strings.TrimSpace(line)

	chunkSize, err := strconv.ParseInt(line, 16, 64)
	if err != nil {
		debuglogger.Logf("failed to convert chunk size: %v", err)
		return 0, errMalformedEncoding
	}

	debuglogger.Infof("chunk size extracted: %v", chunkSize)

	return chunkSize, nil
}

// Reads and validates the trailer at the end
func (ucr *UnsignedChunkReader) readTrailer() error {
	var trailerBuffer bytes.Buffer

	for {
		v, err := ucr.reader.ReadByte()
		if err != nil {
			debuglogger.Logf("failed to read byte: %v", err)
			if err == io.EOF {
				return io.ErrUnexpectedEOF
			}
			return err
		}
		if v != '\r' {
			trailerBuffer.WriteByte(v)
			continue
		}
		var tmp [3]byte
		_, err = io.ReadFull(ucr.reader, tmp[:])
		if err != nil {
			debuglogger.Logf("failed to read chunk ending: \\n\\r\\n: %v", err)
			if err == io.EOF {
				return io.ErrUnexpectedEOF
			}
			return err
		}
		if !bytes.Equal(tmp[:], trailerDelim) {
			debuglogger.Logf("incorrect trailer delimiter: (expected): \\n\\r\\n, (got): %q", tmp[:])
			return errMalformedEncoding
		}
		break
	}

	// Parse the trailer
	trailerHeader := trailerBuffer.String()
	trailerHeader = strings.TrimSpace(trailerHeader)
	trailerHeaderParts := strings.Split(trailerHeader, ":")
	if len(trailerHeaderParts) != 2 {
		debuglogger.Logf("invalid trailer header parts: %v", trailerHeaderParts)
		return errMalformedEncoding
	}

	if trailerHeaderParts[0] != string(ucr.checksumType) {
		debuglogger.Logf("invalid checksum type: %v", trailerHeaderParts[0])
		//TODO: handle the error
		return errMalformedEncoding
	}

	ucr.expectedChecksum = trailerHeaderParts[1]
	debuglogger.Infof("parsed the trailing header:\n%v:%v", trailerHeaderParts[0], trailerHeaderParts[1])

	// Validate checksum
	return ucr.validateChecksum()
}

// Validates the trailing checksum sent at the end
func (ucr *UnsignedChunkReader) validateChecksum() error {
	csum := ucr.hasher.Sum(nil)
	checksum := base64.StdEncoding.EncodeToString(csum)

	if checksum != ucr.expectedChecksum {
		debuglogger.Logf("incorrect checksum: (expected): %v, (got): %v", ucr.expectedChecksum, checksum)
		return fmt.Errorf("actual checksum: %v, expected checksum: %v", checksum, ucr.expectedChecksum)
	}

	return nil
}

// Retruns the hash calculator based on the hash type provided
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
	default:
		return nil, errors.New("unsupported checksum type")
	}
}
