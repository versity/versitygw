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
	"crypto/rand"
	"encoding/base64"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/debuglogger"
)

const (
	HeaderAmzRequestID = "x-amz-request-id"
	HeaderAmzID2       = "x-amz-id-2"

	s3RequestIDAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

	s3RequestIDLength = 16
	s3HostIDBytes     = 65
)

// NewS3RequestID returns a request ID, for example
// "5MRQJ97RHWJ4FMX9".
func NewS3RequestID() string {
	return randomBase36(s3RequestIDLength)
}

func randomBase36(length int) string {
	const maxUnbiasedByte = byte(252) // 36 * 7

	out := make([]byte, length)
	buf := make([]byte, length*2)
	for i := 0; i < length; {
		mustReadRandom(buf)
		for _, b := range buf {
			if b >= maxUnbiasedByte {
				continue
			}
			out[i] = s3RequestIDAlphabet[int(b)%len(s3RequestIDAlphabet)]
			i++
			if i == length {
				break
			}
		}
	}

	return string(out)
}

// NewS3HostID generates a new s3-style host ID
func NewS3HostID() string {
	b := make([]byte, s3HostIDBytes)
	mustReadRandom(b)
	return base64.StdEncoding.EncodeToString(b)
}

// EnsureRequestIDs makes sure the request-local IDs exist and are present
// in the response headers. Existing local values are reused so headers and XML
// bodies stay consistent throughout the request.
func EnsureRequestIDs(ctx fiber.Ctx) (requestID, hostID string) {
	requestID = RequestID(ctx)
	if requestID == "" {
		requestID = NewS3RequestID()
		ContextKeyRequestID.Set(ctx, requestID)
	}

	hostID = HostID(ctx)
	if hostID == "" {
		hostID = NewS3HostID()
		ContextKeyHostID.Set(ctx, hostID)
	}

	ctx.Response().Header.Set(HeaderAmzRequestID, requestID)
	ctx.Response().Header.Set(HeaderAmzID2, hostID)

	return requestID, hostID
}

func RequestID(ctx fiber.Ctx) string {
	requestID, _ := ContextKeyRequestID.Get(ctx).(string)
	if requestID != "" {
		return requestID
	}

	return string(ctx.Response().Header.Peek(HeaderAmzRequestID))
}

func HostID(ctx fiber.Ctx) string {
	hostID, _ := ContextKeyHostID.Get(ctx).(string)
	if hostID != "" {
		return hostID
	}

	return string(ctx.Response().Header.Peek(HeaderAmzID2))
}

func mustReadRandom(b []byte) {
	if _, err := rand.Read(b); err != nil {
		debuglogger.Logf("randomize ID bytes: %v", err)
	}
}
