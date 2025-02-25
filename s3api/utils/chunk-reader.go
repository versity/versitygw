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
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/s3err"
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

// IsSpecialPayload checks for special authorization types
func IsSpecialPayload(str string) bool {
	return specialValues[payloadType(str)]
}

// IsChunkEncoding checks for streaming/unsigned authorization types
func IsStreamingPayload(str string) bool {
	pt := payloadType(str)
	return pt == payloadTypeStreamingUnsignedTrailer ||
		pt == payloadTypeStreamingSigned ||
		pt == payloadTypeStreamingSignedTrailer
}

func NewChunkReader(ctx *fiber.Ctx, r io.Reader, authdata AuthData, region, secret string, date time.Time) (io.Reader, error) {
	decContLength := ctx.Get("X-Amz-Decoded-Content-Length")
	if decContLength == "" {
		return nil, s3err.GetAPIError(s3err.ErrMissingDecodedContentLength)
	}
	contentSha256 := payloadType(ctx.Get("X-Amz-Content-Sha256"))
	if !contentSha256.isValid() {
		//TODO: Add proper APIError
		return nil, fmt.Errorf("invalid x-amz-content-sha256: %v", string(contentSha256))
	}

	checksumType := checksumType(ctx.Get("X-Amz-Trailer"))
	if checksumType != "" && !checksumType.isValid() {
		//TODO: Add proper APIError
		return nil, fmt.Errorf("invalid X-Amz-Trailer: %v", checksumType)
	}

	switch contentSha256 {
	case payloadTypeStreamingUnsignedTrailer:
		return NewUnsignedChunkReader(r, checksumType)
		//TODO: Add other chunk readers
	}

	return NewSignedChunkReader(r, authdata, region, secret, date)
}
