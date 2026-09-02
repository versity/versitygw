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
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
)

func TestDrainRequestBody_slowClientFinishesWritingAndReadsTheResponse(t *testing.T) {
	// keep-alive is off by default in the gateway and on with --keep-alive
	for _, disableKeepalive := range []bool{true, false} {
		t.Run(fmt.Sprintf("disableKeepalive=%v", disableKeepalive), func(t *testing.T) {
			slowClientFinishesWriting(t, disableKeepalive)
		})
	}
}

func slowClientFinishesWriting(t *testing.T, disableKeepalive bool) {
	t.Helper()

	addr := startEarlyResponder(t, disableKeepalive)
	// small enough to be drained in full, big enough that it cannot sit in the
	// socket buffers while the server decides to close
	body := bytes.Repeat([]byte("a"), 128<<10)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	if _, err := conn.Write(putHeaders(addr, len(body))); err != nil {
		t.Fatalf("write headers: %v", err)
	}

	// dribble the body out, so the response is decided well before the last byte
	for off := 0; off < len(body); off += 4 << 10 {
		if _, err := conn.Write(body[off:min(off+(4<<10), len(body))]); err != nil {
			t.Fatalf("the server dropped the connection with %v of %v body bytes sent: %v", off, len(body), err)
		}
		time.Sleep(time.Millisecond)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("read response body: %v", err)
	}

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected status %v, got %v", http.StatusBadRequest, resp.StatusCode)
	}
	if disableKeepalive {
		return
	}
	if resp.Close {
		t.Fatal("expected the connection to stay usable after the body was drained")
	}

	// a fully drained body leaves the connection in sync for the next request
	if _, err := conn.Write(putHeaders(addr, 0)); err != nil {
		t.Fatalf("write second request: %v", err)
	}
	resp2, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read second response: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected status %v on the reused connection, got %v", http.StatusBadRequest, resp2.StatusCode)
	}
}

func TestDrainRequestBody_closesConnectionWhenUnreadBodyExceedsTheLimit(t *testing.T) {
	addr := startEarlyResponder(t, false)
	body := bytes.Repeat([]byte("a"), int(maxDrainBytes)*4)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	if _, err := conn.Write(putHeaders(addr, len(body))); err != nil {
		t.Fatalf("write headers: %v", err)
	}
	// the write is expected to fail once the server gives up draining
	go conn.Write(body)

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected status %v, got %v", http.StatusBadRequest, resp.StatusCode)
	}
	if !resp.Close {
		t.Fatal("expected 'Connection: close', the undrained body bytes would desync the next request")
	}
}

func TestDrainRequestBody_givesUpOnAClientThatStopsSending(t *testing.T) {
	idle, total := drainIdleTimeout, drainTotalTimeout
	drainIdleTimeout, drainTotalTimeout = 100*time.Millisecond, 250*time.Millisecond
	t.Cleanup(func() { drainIdleTimeout, drainTotalTimeout = idle, total })

	addr := startEarlyResponder(t, true)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	// announce a body, send only what the handler consumes, then go quiet
	if _, err := conn.Write(putHeaders(addr, 64<<10)); err != nil {
		t.Fatalf("write headers: %v", err)
	}
	if _, err := conn.Write(bytes.Repeat([]byte("a"), handlerReadBytes)); err != nil {
		t.Fatalf("write body: %v", err)
	}

	start := time.Now()
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected status %v, got %v", http.StatusBadRequest, resp.StatusCode)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the drain held the response for %v, the timeout should have cut it short", elapsed)
	}
}

// A chunked body the handler read to its end must not be read again: fasthttp's
// requestStream goes back to the socket for another chunk header past the
// terminating chunk, which would hold the response back until the deadline.
func TestDrainRequestBody_doesNotStallAChunkedBodyTheHandlerFinished(t *testing.T) {
	addr := startFullReader(t)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	body := "PUT /object HTTP/1.1\r\nHost: " + addr + "\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
	if _, err := conn.Write([]byte(body)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	start := time.Now()
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status %v, got %v", http.StatusOK, resp.StatusCode)
	}
	if elapsed := time.Since(start); elapsed > drainIdleTimeout {
		t.Fatalf("the response was held back for %v: the drain re-read a finished chunked body", elapsed)
	}
}

// The same, for a Content-Length body: fasthttp reports EOF idempotently there,
// so it is drained, but a handler that already finished it must not be delayed.
func TestDrainRequestBody_doesNotStallABodyTheHandlerFinished(t *testing.T) {
	addr := startFullReader(t)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	if _, err := conn.Write(append(putHeaders(addr, 5), "hello"...)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	start := time.Now()
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status %v, got %v", http.StatusOK, resp.StatusCode)
	}
	if elapsed := time.Since(start); elapsed > drainIdleTimeout {
		t.Fatalf("the response was held back for %v on a body the handler had finished", elapsed)
	}
}

// fasthttp pre-reads up to 8KB of a declared body before it hands the request to
// the handler, so a test body has to be at least that big to reach the drain.
const handlerReadBytes = 8 << 10

// startEarlyResponder serves a fiber app that reads only the head of the request
// body and then answers, the way the gateway rejects an upload on a bad chunk
// header or a failed authorization long before the client is done sending.
func startEarlyResponder(t *testing.T, disableKeepalive bool) string {
	t.Helper()

	app := fiber.New(fiber.Config{
		StreamRequestBody: true,
		DisableKeepalive:  disableKeepalive,
	})
	app.Use("*", DrainRequestBody())
	app.Put("/object", func(ctx fiber.Ctx) error {
		if body := ctx.Request().BodyStream(); body != nil {
			// consume a little of it, the way the chunk reader parses a chunk
			// header before rejecting the upload
			io.CopyN(io.Discard, body, handlerReadBytes) //nolint:errcheck
		}
		return ctx.Status(http.StatusBadRequest).SendString("rejected")
	})

	return listen(t, app)
}

func listen(t *testing.T, app *fiber.App) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go app.Listener(ln, fiber.ListenConfig{DisableStartupMessage: true}) //nolint:errcheck
	t.Cleanup(func() { app.Shutdown() })                                 //nolint:errcheck

	return ln.Addr().String()
}

func putHeaders(addr string, contentLength int) []byte {
	return fmt.Appendf(nil, "PUT /object HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", addr, contentLength)
}

// startFullReader serves a fiber app whose handler consumes the whole request
// body, so the drain has nothing left to do.
func startFullReader(t *testing.T) string {
	t.Helper()

	app := fiber.New(fiber.Config{StreamRequestBody: true, DisableKeepalive: true})
	app.Use("*", DrainRequestBody())
	app.Put("/object", func(ctx fiber.Ctx) error {
		if body := ctx.Request().BodyStream(); body != nil {
			if _, err := io.Copy(io.Discard, body); err != nil {
				return err
			}
		}
		return ctx.SendStatus(http.StatusOK)
	})

	return listen(t, app)
}
