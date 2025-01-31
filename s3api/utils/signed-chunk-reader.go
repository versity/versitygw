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
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"strconv"
	"time"

	"github.com/versity/versitygw/s3err"
)

// chunked uploads described in:
// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html

const (
	chunkHdrStr       = ";chunk-signature="
	chunkHdrDelim     = "\r\n"
	zeroLenSig        = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	awsV4             = "AWS4"
	awsS3Service      = "s3"
	awsV4Request      = "aws4_request"
	streamPayloadAlgo = "AWS4-HMAC-SHA256-PAYLOAD"
)

// ChunkReader reads from chunked upload request body, and returns
// object data stream
type ChunkReader struct {
	r                io.Reader
	signingKey       []byte
	prevSig          string
	parsedSig        string
	currentChunkSize int64
	chunkDataLeft    int64
	trailerExpected  int
	stash            []byte
	chunkHash        hash.Hash
	strToSignPrefix  string
	skipcheck        bool
}

// NewChunkReader reads from request body io.Reader and parses out the
// chunk metadata in stream. The headers are validated for proper signatures.
// Reading from the chunk reader will read only the object data stream
// without the chunk headers/trailers.
func NewSignedChunkReader(r io.Reader, authdata AuthData, region, secret string, date time.Time) (io.Reader, error) {
	return &ChunkReader{
		r:          r,
		signingKey: getSigningKey(secret, region, date),
		// the authdata.Signature is validated in the auth-reader,
		// so we can use that here without any other checks
		prevSig:         authdata.Signature,
		chunkHash:       sha256.New(),
		strToSignPrefix: getStringToSignPrefix(date, region),
	}, nil
}

// Read satisfies the io.Reader for this type
func (cr *ChunkReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	if err != nil && err != io.EOF {
		return n, err
	}

	if cr.chunkDataLeft < int64(n) {
		chunkSize := cr.chunkDataLeft
		if chunkSize > 0 {
			cr.chunkHash.Write(p[:chunkSize])
		}
		n, err := cr.parseAndRemoveChunkInfo(p[chunkSize:n])
		n += int(chunkSize)
		return n, err
	}

	cr.chunkDataLeft -= int64(n)
	cr.chunkHash.Write(p[:n])
	return n, err
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html#sigv4-chunked-body-definition
// This part is the same for all chunks,
// only the previous signature and hash of current chunk changes
func getStringToSignPrefix(date time.Time, region string) string {
	credentialScope := fmt.Sprintf("%s/%s/%s/%s",
		date.Format("20060102"),
		region,
		awsS3Service,
		awsV4Request)

	return fmt.Sprintf("%s\n%s\n%s",
		streamPayloadAlgo,
		date.Format("20060102T150405Z"),
		credentialScope)
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html#sigv4-chunked-body-definition
// signature For each chunk, you calculate the signature using the following
// string to sign. For the first chunk, you use the seed-signature as the
// previous signature.
func getChunkStringToSign(prefix, prevSig string, chunkHash []byte) string {
	return fmt.Sprintf("%s\n%s\n%s\n%s",
		prefix,
		prevSig,
		zeroLenSig,
		hex.EncodeToString(chunkHash))
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

	if !cr.skipcheck && cr.parsedSig != "" {
		chunkhash := cr.chunkHash.Sum(nil)
		cr.chunkHash.Reset()

		sigstr := getChunkStringToSign(cr.strToSignPrefix, cr.prevSig, chunkhash)
		cr.prevSig = hex.EncodeToString(hmac256(cr.signingKey, []byte(sigstr)))

		if cr.currentChunkSize != 0 && cr.prevSig != cr.parsedSig {
			return 0, s3err.GetAPIError(s3err.ErrSignatureDoesNotMatch)
		}
	}

	if cr.trailerExpected != 0 {
		if len(p) < len(chunkHdrDelim) {
			// This is the special case where we need to consume the
			// trailer, but instead hit the end of the buffer. The
			// subsequent call will finish consuming the trailer.
			cr.chunkDataLeft = 0
			cr.trailerExpected -= len(p)
			cr.skipcheck = true
			return 0, nil
		}
		// move data up to remove trailer
		copy(p, p[cr.trailerExpected:])
		n -= cr.trailerExpected
	}

	cr.skipcheck = false

	chunkSize, sig, bufOffset, err := cr.parseChunkHeaderBytes(p[:n])
	cr.currentChunkSize = chunkSize
	cr.parsedSig = sig
	if err == errskipHeader {
		cr.chunkDataLeft = 0
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if chunkSize == 0 {
		return 0, io.EOF
	}

	cr.trailerExpected = len(chunkHdrDelim)

	// move data up to remove chunk header
	copy(p, p[bufOffset:n])
	n -= bufOffset

	// if remaining buffer larger than chunk data,
	// parse next header in buffer
	if int64(n) > chunkSize {
		cr.chunkDataLeft = 0
		cr.chunkHash.Write(p[:chunkSize])
		n, err := cr.parseAndRemoveChunkInfo(p[chunkSize:n])
		if (chunkSize + int64(n)) > math.MaxInt {
			return 0, s3err.GetAPIError(s3err.ErrSignatureDoesNotMatch)
		}
		return n + int(chunkSize), err
	}

	cr.chunkDataLeft = chunkSize - int64(n)
	cr.chunkHash.Write(p[:n])

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

// Theis returns the chunk payload size, signature, data start offset, and
// error if any. See the AWS documentation for the chunk header format. The
// header[0] byte is expected to be the first byte of the chunk size here.
func (cr *ChunkReader) parseChunkHeaderBytes(header []byte) (int64, string, int, error) {
	stashLen := len(cr.stash)
	if cr.stash != nil {
		tmp := make([]byte, maxHeaderSize)
		copy(tmp, cr.stash)
		copy(tmp[len(cr.stash):], header)
		header = tmp
		cr.stash = nil
	}

	semicolonIndex := bytes.Index(header, []byte(chunkHdrStr))
	if semicolonIndex == -1 {
		cr.stash = make([]byte, len(header))
		copy(cr.stash, header)
		cr.trailerExpected = 0
		return 0, "", 0, errskipHeader
	}

	sigIndex := semicolonIndex + len(chunkHdrStr)
	sigEndIndex := bytes.Index(header[sigIndex:], []byte(chunkHdrDelim))
	if sigEndIndex == -1 {
		cr.stash = make([]byte, len(header))
		copy(cr.stash, header)
		cr.trailerExpected = 0
		return 0, "", 0, errskipHeader
	}

	chunkSizeBytes := header[:semicolonIndex]
	chunkSize, err := strconv.ParseInt(string(chunkSizeBytes), 16, 64)
	if err != nil {
		return 0, "", 0, errInvalidChunkFormat
	}

	signature := string(header[sigIndex:(sigIndex + sigEndIndex)])
	dataStartOffset := sigIndex + sigEndIndex + len(chunkHdrDelim)

	return chunkSize, signature, dataStartOffset - stashLen, nil
}
