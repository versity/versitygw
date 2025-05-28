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
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/s3api/debuglogger"
	"github.com/versity/versitygw/s3err"
)

const (
	maxObjSizeLimit = 5 * 1024 * 1024 * 1024 // 5gb
)

type payloadType string

const (
	payloadTypeUnsigned                 payloadType = "UNSIGNED-PAYLOAD"
	payloadTypeStreamingUnsignedTrailer payloadType = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
	payloadTypeStreamingSigned          payloadType = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	payloadTypeStreamingSignedTrailer   payloadType = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
	payloadTypeStreamingEcdsa           payloadType = "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD"
	payloadTypeStreamingEcdsaTrailer    payloadType = "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER"
)

func getPayloadTypeNotSupportedErr(p payloadType) error {
	return s3err.APIError{
		HTTPStatusCode: http.StatusNotImplemented,
		Code:           "NotImplemented",
		Description:    fmt.Sprintf("The chunk encoding algorithm %v is not supported.", p),
	}
}

var (
	specialValues = map[payloadType]bool{
		payloadTypeUnsigned:                 true,
		payloadTypeStreamingUnsignedTrailer: true,
		payloadTypeStreamingSigned:          true,
		payloadTypeStreamingSignedTrailer:   true,
		payloadTypeStreamingEcdsa:           true,
		payloadTypeStreamingEcdsaTrailer:    true,
	}
)

func (pt payloadType) isValid() bool {
	return pt == payloadTypeUnsigned ||
		pt == payloadTypeStreamingUnsignedTrailer ||
		pt == payloadTypeStreamingSigned ||
		pt == payloadTypeStreamingSignedTrailer ||
		pt == payloadTypeStreamingEcdsa ||
		pt == payloadTypeStreamingEcdsaTrailer
}

type checksumType string

const (
	checksumTypeCrc32     checksumType = "x-amz-checksum-crc32"
	checksumTypeCrc32c    checksumType = "x-amz-checksum-crc32c"
	checksumTypeSha1      checksumType = "x-amz-checksum-sha1"
	checksumTypeSha256    checksumType = "x-amz-checksum-sha256"
	checksumTypeCrc64nvme checksumType = "x-amz-checksum-crc64nvme"
)

func (c checksumType) isValid() bool {
	return c == checksumTypeCrc32 ||
		c == checksumTypeCrc32c ||
		c == checksumTypeSha1 ||
		c == checksumTypeSha256 ||
		c == checksumTypeCrc64nvme
}

// Extracts and validates the checksum type from the 'X-Amz-Trailer' header
func ExtractChecksumType(ctx *fiber.Ctx) (checksumType, error) {
	trailer := ctx.Get("X-Amz-Trailer")
	chType := checksumType(strings.ToLower(trailer))
	if chType != "" && !chType.isValid() {
		debuglogger.Logf("invalid value for 'X-Amz-Trailer': %v", chType)
		return "", s3err.GetAPIError(s3err.ErrTrailerHeaderNotSupported)
	}

	return chType, nil
}

// IsSpecialPayload checks for special authorization types
func IsSpecialPayload(str string) bool {
	return specialValues[payloadType(str)]
}

// Checks if the provided string is unsigned payload trailer type
func IsUnsignedStreamingPayload(str string) bool {
	return payloadType(str) == payloadTypeStreamingUnsignedTrailer
}

// IsChunkEncoding checks for streaming/unsigned authorization types
func IsStreamingPayload(str string) bool {
	pt := payloadType(str)
	return pt == payloadTypeStreamingUnsignedTrailer ||
		pt == payloadTypeStreamingSigned ||
		pt == payloadTypeStreamingSignedTrailer
}

func NewChunkReader(ctx *fiber.Ctx, r io.Reader, authdata AuthData, region, secret string, date time.Time) (io.Reader, error) {
	decContLengthStr := ctx.Get("X-Amz-Decoded-Content-Length")
	if decContLengthStr == "" {
		debuglogger.Logf("missing required header 'X-Amz-Decoded-Content-Length'")
		return nil, s3err.GetAPIError(s3err.ErrMissingContentLength)
	}
	decContLength, err := strconv.ParseInt(decContLengthStr, 10, 64)
	//TODO: not sure if InvalidRequest should be returned in this case
	if err != nil {
		debuglogger.Logf("invalid value for 'X-Amz-Decoded-Content-Length': %v", decContLengthStr)
		return nil, s3err.GetAPIError(s3err.ErrInvalidRequest)
	}

	if decContLength > maxObjSizeLimit {
		debuglogger.Logf("the object size exceeds the allowed limit: (size): %v, (limit): %v", decContLength, maxObjSizeLimit)
		return nil, s3err.GetAPIError(s3err.ErrEntityTooLarge)
	}

	contentSha256 := payloadType(ctx.Get("X-Amz-Content-Sha256"))
	if !contentSha256.isValid() {
		//TODO: Add proper APIError
		debuglogger.Logf("invalid value for 'X-Amz-Content-Sha256': %v", contentSha256)
		return nil, fmt.Errorf("invalid x-amz-content-sha256: %v", string(contentSha256))
	}

	checksumType, err := ExtractChecksumType(ctx)
	if err != nil {
		return nil, err
	}
	if contentSha256 != payloadTypeStreamingSigned && checksumType == "" {
		debuglogger.Logf("empty value for required trailer header 'X-Amz-Trailer': %v", checksumType)
		return nil, s3err.GetAPIError(s3err.ErrTrailerHeaderNotSupported)
	}

	switch contentSha256 {
	case payloadTypeStreamingUnsignedTrailer:
		return NewUnsignedChunkReader(r, checksumType)
	case payloadTypeStreamingSignedTrailer:
		return NewSignedChunkReader(r, authdata, region, secret, date, checksumType)
	case payloadTypeStreamingSigned:
		return NewSignedChunkReader(r, authdata, region, secret, date, "")
	// return not supported for:
	// - STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD
	// - STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER
	default:
		debuglogger.Logf("unsupported chunk reader algorithm: %v", contentSha256)
		return nil, getPayloadTypeNotSupportedErr(contentSha256)
	}
}
