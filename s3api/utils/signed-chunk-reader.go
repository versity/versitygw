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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3api/debuglogger"
	"github.com/versity/versitygw/s3err"
)

// chunked uploads described in:
// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html

const (
	chunkHdrDelim            = "\r\n"
	zeroLenSig               = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	awsV4                    = "AWS4"
	awsS3Service             = "s3"
	awsV4Request             = "aws4_request"
	trailerSignatureHeader   = "x-amz-trailer-signature"
	streamPayloadAlgo        = "AWS4-HMAC-SHA256-PAYLOAD"
	streamPayloadTrailerAlgo = "AWS4-HMAC-SHA256-TRAILER"
)

// ChunkReader reads from chunked upload request body, and returns
// object data stream
type ChunkReader struct {
	r              io.Reader
	signingKey     []byte
	prevSig        string
	parsedSig      string
	chunkDataLeft  int64
	trailer        checksumType
	trailerSig     string
	parsedChecksum string
	stash          []byte
	chunkHash      hash.Hash
	checksumHash   hash.Hash
	isEOF          bool
	isFirstHeader  bool
	region         string
	date           time.Time
}

// NewChunkReader reads from request body io.Reader and parses out the
// chunk metadata in stream. The headers are validated for proper signatures.
// Reading from the chunk reader will read only the object data stream
// without the chunk headers/trailers.
func NewSignedChunkReader(r io.Reader, authdata AuthData, region, secret string, date time.Time, chType checksumType) (io.Reader, error) {
	chRdr := &ChunkReader{
		r:          r,
		signingKey: getSigningKey(secret, region, date),
		// the authdata.Signature is validated in the auth-reader,
		// so we can use that here without any other checks
		prevSig:       authdata.Signature,
		chunkHash:     sha256.New(),
		isFirstHeader: true,
		date:          date,
		region:        region,
		trailer:       chType,
	}

	if chType != "" {
		checksumHasher, err := getHasher(chType)
		if err != nil {
			debuglogger.Logf("failed to initialize hash calculator: %v", err)
			return nil, err
		}

		chRdr.checksumHash = checksumHasher
	}
	if chType == "" {
		debuglogger.Infof("initializing signed chunk reader")
	} else {
		debuglogger.Infof("initializing signed chunk reader with '%v' trailing checksum", chType)
	}
	return chRdr, nil
}

// Read satisfies the io.Reader for this type
func (cr *ChunkReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	if err != nil && err != io.EOF {
		return 0, err
	}

	cr.isEOF = err == io.EOF

	if cr.chunkDataLeft < int64(n) {
		chunkSize := cr.chunkDataLeft
		if chunkSize > 0 {
			cr.chunkHash.Write(p[:chunkSize])
			if cr.checksumHash != nil {
				cr.checksumHash.Write(p[:chunkSize])
			}
		}
		n, err := cr.parseAndRemoveChunkInfo(p[chunkSize:n])
		n += int(chunkSize)
		return n, err
	}

	cr.chunkDataLeft -= int64(n)
	cr.chunkHash.Write(p[:n])
	if cr.checksumHash != nil {
		cr.checksumHash.Write(p[:n])
	}
	return n, err
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html#sigv4-chunked-body-definition
// This part is the same for all chunks,
// only the previous signature and hash of current chunk changes
func (cr *ChunkReader) getStringToSignPrefix(algo string) string {
	credentialScope := fmt.Sprintf("%s/%s/%s/%s",
		cr.date.Format("20060102"),
		cr.region,
		awsS3Service,
		awsV4Request)

	return fmt.Sprintf("%s\n%s\n%s",
		algo,
		cr.date.Format("20060102T150405Z"),
		credentialScope)
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html#sigv4-chunked-body-definition
// signature For each chunk, you calculate the signature using the following
// string to sign. For the first chunk, you use the seed-signature as the
// previous signature.
func (cr *ChunkReader) getChunkStringToSign() string {
	prefix := cr.getStringToSignPrefix(streamPayloadAlgo)
	chunkHash := cr.chunkHash.Sum(nil)
	strToSign := fmt.Sprintf("%s\n%s\n%s\n%s",
		prefix,
		cr.prevSig,
		zeroLenSig,
		hex.EncodeToString(chunkHash))
	debuglogger.PrintInsideHorizontalBorders(debuglogger.Purple, "STRING TO SIGN", strToSign, 64)
	return strToSign
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming-trailers.html#example-signature-calculations-trailing-header
// Builds the final chunk trailing signature string to sign
func (cr *ChunkReader) getTrailerChunkStringToSign() string {
	trailer := fmt.Sprintf("%v:%v\n", cr.trailer, cr.parsedChecksum)
	hsh := sha256.Sum256([]byte(trailer))
	sig := hex.EncodeToString(hsh[:])

	prefix := cr.getStringToSignPrefix(streamPayloadTrailerAlgo)

	strToSign := fmt.Sprintf("%s\n%s\n%s",
		prefix,
		cr.prevSig,
		sig,
	)

	debuglogger.PrintInsideHorizontalBorders(debuglogger.Purple, "TRAILER STRING TO SIGN", strToSign, 64)

	return strToSign
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming-trailers.html#example-signature-calculations-trailing-header
// Calculates and validates the final chunk trailer signature
func (cr *ChunkReader) verifyTrailerSignature() error {
	strToSign := cr.getTrailerChunkStringToSign()
	sig := hex.EncodeToString(hmac256(cr.signingKey, []byte(strToSign)))

	if sig != cr.trailerSig {
		debuglogger.Logf("incorrect trailing signature: (calculated): %v, (got): %v", sig, cr.trailerSig)
		return s3err.GetAPIError(s3err.ErrSignatureDoesNotMatch)
	}

	return nil
}

// Verifies the object checksum
func (cr *ChunkReader) verifyChecksum() error {
	checksumHash := cr.checksumHash.Sum(nil)
	checksum := base64.StdEncoding.EncodeToString(checksumHash)
	if checksum != cr.parsedChecksum {
		algo := types.ChecksumAlgorithm(strings.ToUpper(strings.TrimPrefix(string(cr.trailer), "x-amz-checksum-")))
		debuglogger.Logf("incorrect trailing checksum: (calculated): %v, (got): %v", checksum, cr.parsedChecksum)
		return s3err.GetChecksumBadDigestErr(algo)
	}

	return nil
}

// Calculates and verifies the chunk signature
func (cr *ChunkReader) checkSignature() error {
	sigstr := cr.getChunkStringToSign()
	cr.chunkHash.Reset()
	cr.prevSig = hex.EncodeToString(hmac256(cr.signingKey, []byte(sigstr)))

	if cr.prevSig != cr.parsedSig {
		debuglogger.Logf("incorrect signature: (calculated): %v, (got) %v", cr.prevSig, cr.parsedSig)
		return s3err.GetAPIError(s3err.ErrSignatureDoesNotMatch)
	}
	cr.parsedSig = ""
	return nil
}

// The provided p should have all of the previous chunk data and trailer
// consumed already. The positioning here is expected that p[0] starts the
// new chunk size with the ";chunk-signature=" following. The only exception
// is if we started consuming the trailer, but hit the end of the read buffer.
// In this case, parseAndRemoveChunkInfo is called with skipcheck=true to
// finish consuming the final trailer bytes.
// This parses the chunk metadata in situ without allocating an extra buffer.
// It will just read and validate the chunk metadata and then move the
// following chunk data to overwrite the metadata in the provided buffer.
func (cr *ChunkReader) parseAndRemoveChunkInfo(p []byte) (int, error) {
	n := len(p)

	if cr.parsedSig != "" {
		err := cr.checkSignature()
		if err != nil {
			return 0, err
		}
	}

	chunkSize, sig, bufOffset, err := cr.parseChunkHeaderBytes(p[:n])
	if err == errskipHeader {
		cr.chunkDataLeft = 0
		return 0, nil
	}
	if err != nil {
		debuglogger.Logf("failed to parse chunk headers: %v", err)
		return 0, err
	}
	cr.parsedSig = sig
	// If we hit the final chunk, calculate and validate the final
	// chunk signature and finish reading
	if chunkSize == 0 {
		debuglogger.Infof("final chunk parsed:\nchunk size: %v\nsignature: %v\nbuffer offset: %v", chunkSize, sig, bufOffset)
		cr.chunkHash.Reset()
		err := cr.checkSignature()
		if err != nil {
			return 0, err
		}

		if cr.trailer != "" {
			debuglogger.Infof("final chunk trailers parsed:\nchecksum: %v\ntrailing signature: %v", cr.parsedChecksum, cr.trailerSig)
			err := cr.verifyChecksum()
			if err != nil {
				return 0, err
			}
			err = cr.verifyTrailerSignature()
			if err != nil {
				return 0, err
			}
		}

		return 0, io.EOF
	}
	debuglogger.Infof("chunk headers parsed:\nchunk size: %v\nsignature: %v\nbuffer offset: %v", chunkSize, sig, bufOffset)

	// move data up to remove chunk header
	copy(p, p[bufOffset:n])
	n -= bufOffset

	// if remaining buffer larger than chunk data,
	// parse next header in buffer
	if int64(n) > chunkSize {
		cr.chunkDataLeft = 0
		cr.chunkHash.Write(p[:chunkSize])
		if cr.checksumHash != nil {
			cr.checksumHash.Write(p[:chunkSize])
		}
		n, err := cr.parseAndRemoveChunkInfo(p[chunkSize:n])
		if (chunkSize + int64(n)) > math.MaxInt {
			debuglogger.Logf("exceeding the limit of maximum integer allowed: (value): %v, (limit): %v", chunkSize+int64(n), math.MaxInt)
			return 0, s3err.GetAPIError(s3err.ErrSignatureDoesNotMatch)
		}
		return n + int(chunkSize), err
	}

	cr.chunkDataLeft = chunkSize - int64(n)
	cr.chunkHash.Write(p[:n])
	if cr.checksumHash != nil {
		cr.checksumHash.Write(p[:n])
	}

	return n, nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
// Task 3: Calculate Signature
// https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html#signing-request-intro
func getSigningKey(secret, region string, date time.Time) []byte {
	dateKey := hmac256([]byte(awsV4+secret), []byte(date.Format(yyyymmdd)))
	dateRegionKey := hmac256(dateKey, []byte(region))
	dateRegionServiceKey := hmac256(dateRegionKey, []byte(awsS3Service))
	signingKey := hmac256(dateRegionServiceKey, []byte(awsV4Request))
	debuglogger.Infof("signing key: %s", hex.EncodeToString(signingKey))
	return signingKey
}

func hmac256(key []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

var (
	errInvalidChunkFormat = errors.New("invalid chunk header format")
	errskipHeader         = errors.New("skip to next header")
)

const (
	maxHeaderSize = 1024
)

// This returns the chunk payload size, signature, data start offset, and
// error if any. See the AWS documentation for the chunk header format. The
// header[0] byte is expected to be the first byte of the chunk size here.
func (cr *ChunkReader) parseChunkHeaderBytes(header []byte) (int64, string, int, error) {
	stashLen := len(cr.stash)
	if stashLen > maxHeaderSize {
		debuglogger.Logf("the stash length exceeds the maximum allowed chunk header size: (stash len): %v, (header limit): %v", stashLen, maxHeaderSize)
		return 0, "", 0, errInvalidChunkFormat
	}
	if cr.stash != nil {
		debuglogger.Logf("recovering the stash: (stash len): %v", stashLen)
		tmp := make([]byte, stashLen+len(header))
		copy(tmp, cr.stash)
		copy(tmp[len(cr.stash):], header)
		header = tmp
		cr.stash = nil
	}

	rdr := bufio.NewReader(bytes.NewReader(header))

	// After the first chunk each chunk header should start
	// with "\n\r\n"
	if !cr.isFirstHeader {
		err := readAndSkip(rdr, '\r', '\n')
		if err != nil {
			debuglogger.Logf("failed to read chunk header first 2 bytes: (should be): \\r\\n, (got): %q", header[:2])
			return cr.handleRdrErr(err, header)
		}
	}

	// read and parse the chunk size
	chunkSizeStr, err := readAndTrim(rdr, ';')
	if err != nil {
		debuglogger.Logf("failed to read chunk size: %v", err)
		return cr.handleRdrErr(err, header)
	}
	chunkSize, err := strconv.ParseInt(chunkSizeStr, 16, 64)
	if err != nil {
		debuglogger.Logf("failed to parse chunk size: (size): %v, (err): %v", chunkSizeStr, err)
		return 0, "", 0, errInvalidChunkFormat
	}

	// read the chunk signature
	err = readAndSkip(rdr, 'c', 'h', 'u', 'n', 'k', '-', 's', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e', '=')
	if err != nil {
		debuglogger.Logf("failed to read 'chunk-signature=': %v", err)
		return cr.handleRdrErr(err, header)
	}
	sig, err := readAndTrim(rdr, '\r')
	if err != nil {
		debuglogger.Logf("failed to read '\\r', after chunk signature: %v", err)
		return cr.handleRdrErr(err, header)
	}

	// read and parse the final chunk trailer and checksum
	if chunkSize == 0 {
		if cr.trailer != "" {
			err = readAndSkip(rdr, '\n')
			if err != nil {
				debuglogger.Logf("failed to read \\n before the trailer: %v", err)
				return cr.handleRdrErr(err, header)
			}
			// parse and validate the trailing header
			trailer, err := readAndTrim(rdr, ':')
			if err != nil {
				debuglogger.Logf("failed to read trailer prefix: %v", err)
				return cr.handleRdrErr(err, header)
			}
			if trailer != string(cr.trailer) {
				debuglogger.Logf("incorrect trailer prefix: (expected): %v, (got): %v", cr.trailer, trailer)
				return 0, "", 0, errInvalidChunkFormat
			}

			algo := types.ChecksumAlgorithm(strings.ToUpper(strings.TrimPrefix(trailer, "x-amz-checksum-")))

			// parse the checksum
			checksum, err := readAndTrim(rdr, '\r')
			if err != nil {
				debuglogger.Logf("failed to read checksum value: %v", err)
				return cr.handleRdrErr(err, header)
			}

			if !IsValidChecksum(checksum, algo) {
				debuglogger.Logf("invalid checksum value: %v", checksum)
				return 0, "", 0, s3err.GetInvalidTrailingChecksumHeaderErr(trailer)
			}

			err = readAndSkip(rdr, '\n')
			if err != nil {
				debuglogger.Logf("failed to read \\n after checksum: %v", err)
				return cr.handleRdrErr(err, header)
			}

			// parse the trailing signature
			trailerSigPrefix, err := readAndTrim(rdr, ':')
			if err != nil {
				debuglogger.Logf("failed to read trailing signature prefix: %v", err)
				return cr.handleRdrErr(err, header)
			}

			if trailerSigPrefix != trailerSignatureHeader {
				debuglogger.Logf("invalid trailing signature prefix: (expected): %v, (got): %v", trailerSignatureHeader, trailerSigPrefix)
				return 0, "", 0, errInvalidChunkFormat
			}

			trailerSig, err := readAndTrim(rdr, '\r')
			if err != nil {
				debuglogger.Logf("failed to read trailing signature: %v", err)
				return cr.handleRdrErr(err, header)
			}

			cr.trailerSig = trailerSig
			cr.parsedChecksum = checksum
		}

		// "\r\n\r\n" is followed after the last chunk
		err = readAndSkip(rdr, '\n', '\r', '\n')
		if err != nil {
			debuglogger.Logf("failed to read \\n\\r\\n at the end of chunk header: %v", err)
			return cr.handleRdrErr(err, header)
		}

		return 0, sig, 0, nil
	}

	err = readAndSkip(rdr, '\n')
	if err != nil {
		debuglogger.Logf("failed to read \\n at the end of chunk header: %v", err)
		return cr.handleRdrErr(err, header)
	}

	// find the index of chunk ending: '\r\n'
	// skip the first 2 bytes as it is the starting '\r\n'
	// the first chunk doesn't contain the starting '\r\n', but
	// anyway, trimming the first 2 bytes doesn't pollute the logic.
	ind := bytes.Index(header[2:], []byte{'\r', '\n'})
	cr.isFirstHeader = false

	// the offset is the found index + 4 - the stash length
	// where:
	// ind is the index of '\r\n'
	// 4 specifies the trimmed 2 bytes plus 2 to shift the index at the end of '\r\n'
	offset := ind + 4 - stashLen
	return chunkSize, sig, offset, nil
}

// Stashes the header in cr.stash and returns "errskipHeader"
func (cr *ChunkReader) stashAndSkipHeader(header []byte) (int64, string, int, error) {
	cr.stash = make([]byte, len(header))
	copy(cr.stash, header)
	debuglogger.Logf("stashing the header: (header length): %v", len(header))
	return 0, "", 0, errskipHeader
}

// Returns "errInvalidChunkFormat" if the passed err is "io.EOF" and cr.rdr EOF is reached
// calls "cr.stashAndSkipHeader" if the passed err is "io.EOF" and cr.isEOF is false
// Returns the error otherwise
func (cr *ChunkReader) handleRdrErr(err error, header []byte) (int64, string, int, error) {
	if err == io.EOF {
		if cr.isEOF {
			debuglogger.Logf("incomplete chunk encoding, EOF reached")
			return 0, "", 0, errInvalidChunkFormat
		}
		return cr.stashAndSkipHeader(header)
	}
	return 0, "", 0, err
}

// reads data from the "rdr" and validates the passed data bytes
func readAndSkip(rdr *bufio.Reader, data ...byte) error {
	for _, d := range data {
		b, err := rdr.ReadByte()
		if err != nil {
			return err
		}

		if b != d {
			return errMalformedEncoding
		}
	}

	return nil
}

// reads string by "delim" and trims the delimiter at the end
func readAndTrim(r *bufio.Reader, delim byte) (string, error) {
	str, err := r.ReadString(delim)
	if err != nil {
		return "", err
	}

	return strings.TrimSuffix(str, string(delim)), nil
}
