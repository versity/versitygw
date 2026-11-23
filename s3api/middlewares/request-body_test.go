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

package middlewares

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
)

const (
	testBodyLimit = 1024
	// fasthttp reads up to this much of a body before calling the handlers,
	// and waits for it
	fasthttpPrefetchBytes = 8 << 10
)

func TestReadRequestBody_takesBodyWithinLimit(t *testing.T) {
	addr := startBodyReader(t, maxMessageLength(testBodyLimit), "")

	for _, size := range []int{0, 1, testBodyLimit - 1, testBodyLimit} {
		body := bytes.Repeat([]byte("a"), size)
		for name, req := range framings(addr, body) {
			t.Run(fmt.Sprintf("%v/%v", name, size), func(t *testing.T) {
				status, got := roundTrip(t, addr, req, false)
				if status != http.StatusOK {
					t.Fatalf("expected status %v, got %v: %s", http.StatusOK, status, got)
				}
				if !bytes.Equal(got, body) {
					t.Fatalf("the handler got %v body bytes, expected %v", len(got), len(body))
				}
			})
		}
	}
}

func TestReadRequestBody_refusesBodyOverLimit(t *testing.T) {
	limit := maxMessageLength(testBodyLimit)
	addr := startBodyReader(t, limit, "")

	for _, size := range []int{testBodyLimit + 1, 4 * testBodyLimit} {
		body := bytes.Repeat([]byte("a"), size)
		for name, req := range framings(addr, body) {
			t.Run(fmt.Sprintf("%v/%v", name, size), func(t *testing.T) {
				status, got := roundTrip(t, addr, req, false)
				expectS3Error(t, status, got, limit.err)
			})
		}
	}
}

// A body its Content-Length declares too large is refused once one byte past
// the limit arrives: the request below sends only the head of the GiB it
// declares.
func TestReadRequestBody_refusesDeclaredLengthPastTheLimit(t *testing.T) {
	limit := maxMessageLength(testBodyLimit)
	addr := startBodyReader(t, limit, "")

	req := append(putHeaders(addr, 1<<30), bytes.Repeat([]byte("a"), fasthttpPrefetchBytes)...)
	status, got := roundTrip(t, addr, req, false)
	expectS3Error(t, status, got, limit.err)
}

func TestReadRequestBody_verifiesPayloadHash(t *testing.T) {
	limit := maxMessageLength(testBodyLimit)
	body := []byte("payload")
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	wrongSum := sha256.Sum256([]byte("other"))
	wrongHash := hex.EncodeToString(wrongSum[:])

	t.Run("matching hash", func(t *testing.T) {
		addr := startBodyReader(t, limit, hash)
		for name, req := range framings(addr, body) {
			status, got := roundTrip(t, addr, req, false)
			if status != http.StatusOK || !bytes.Equal(got, body) {
				t.Fatalf("%v: expected the body back with status %v, got %v: %s", name, http.StatusOK, status, got)
			}
		}
	})
	t.Run("mismatching hash", func(t *testing.T) {
		addr := startBodyReader(t, limit, wrongHash)
		for _, req := range framings(addr, body) {
			status, got := roundTrip(t, addr, req, false)
			expectS3Error(t, status, got, s3err.GetContentSHA256MismatchErr(wrongHash, hash))
		}
	})
	t.Run("size is checked before the hash", func(t *testing.T) {
		addr := startBodyReader(t, limit, wrongHash)
		for _, req := range framings(addr, bytes.Repeat([]byte("a"), testBodyLimit+1)) {
			status, got := roundTrip(t, addr, req, false)
			expectS3Error(t, status, got, limit.err)
		}
	})
}

func TestReadRequestBody_incompleteBody(t *testing.T) {
	addr := startBodyReader(t, maxMessageLength(8*fasthttpPrefetchBytes), "")

	// the client stops sending past what fasthttp reads ahead of the
	// handlers, and well short of the declared length
	req := append(putHeaders(addr, 4*fasthttpPrefetchBytes), bytes.Repeat([]byte("a"), 2*fasthttpPrefetchBytes)...)
	status, got := roundTrip(t, addr, req, true)
	expectS3Error(t, status, got, s3err.GetAPIError(s3err.ErrIncompleteBody))
}

func TestReadRequestBody_noRequestBody(t *testing.T) {
	addr := startBodyReader(t, NoRequestBody, "")

	t.Run("empty body", func(t *testing.T) {
		for name, req := range framings(addr, nil) {
			status, got := roundTrip(t, addr, req, false)
			if status != http.StatusOK {
				t.Fatalf("%v: expected status %v, got %v: %s", name, http.StatusOK, status, got)
			}
		}
	})
	t.Run("no body framing", func(t *testing.T) {
		req := fmt.Appendf(nil, "PUT /object HTTP/1.1\r\nHost: %s\r\n\r\n", addr)
		status, got := roundTrip(t, addr, req, false)
		if status != http.StatusOK {
			t.Fatalf("expected status %v, got %v: %s", http.StatusOK, status, got)
		}
	})
	t.Run("non-empty body", func(t *testing.T) {
		for _, req := range framings(addr, []byte("a")) {
			status, got := roundTrip(t, addr, req, false)
			expectS3Error(t, status, got, NoRequestBody.err)
		}
	})
}

// startBodyReader serves a fiber app that reads the request body with
// ReadRequestBody and echoes back what the handlers get from ctx.BodyRaw().
// A non-empty hash is stacked on the body reader first, the way the
// authentication middlewares stack the payload hash check.
func startBodyReader(t *testing.T, limit RequestBodyLimit, hash string) string {
	t.Helper()

	app := fiber.New(fiber.Config{StreamRequestBody: true})
	app.Use("*", DrainRequestBody())
	app.Put("/object", func(ctx fiber.Ctx) error {
		if hash != "" {
			var err error
			wrapBodyReader(ctx, func(r io.Reader) io.Reader {
				var hr io.Reader
				hr, err = utils.NewHashReader(r, hash, utils.HashTypeSha256Hex)
				return hr
			})
			if err != nil {
				return err
			}
		}

		if err := ReadRequestBody(limit)(ctx); err != nil {
			serr, ok := err.(s3err.S3Error)
			if !ok {
				return ctx.Status(http.StatusInternalServerError).SendString(err.Error())
			}
			return ctx.Status(serr.StatusCode()).Send(serr.XMLBody("", ""))
		}
		if ctx.Request().IsBodyStream() {
			return ctx.Status(http.StatusInternalServerError).SendString("the body was left a stream")
		}

		return ctx.Send(ctx.BodyRaw())
	})

	return listen(t, app)
}

// framings returns the request carrying body framed with a Content-Length and
// as a chunked one.
func framings(addr string, body []byte) map[string][]byte {
	chunked := fmt.Appendf(nil, "PUT /object HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\n\r\n", addr)
	if len(body) != 0 {
		chunked = fmt.Appendf(chunked, "%x\r\n%s\r\n", len(body), body)
	}
	chunked = append(chunked, "0\r\n\r\n"...)

	return map[string][]byte{
		"content-length": append(putHeaders(addr, len(body)), body...),
		"chunked":        chunked,
	}
}

// roundTrip writes req on a new connection and reads the response. With
// closeWrite, the client half-closes the connection once req is written, the
// way a client that gives up on its body does.
func roundTrip(t *testing.T, addr string, req []byte, closeWrite bool) (int, []byte) {
	t.Helper()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if closeWrite {
		if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
			t.Fatalf("close write: %v", err)
		}
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	return resp.StatusCode, body
}

func expectS3Error(t *testing.T, status int, body []byte, expected error) {
	t.Helper()

	serr := expected.(s3err.S3Error)
	if status != serr.StatusCode() || !bytes.Equal(body, serr.XMLBody("", "")) {
		t.Fatalf("expected %v %s, got %v %s", serr.StatusCode(), serr.XMLBody("", ""), status, body)
	}
}
