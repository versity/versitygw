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
	"errors"
	"io"
	"net"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/debuglogger"
)

const (
	// maxDrainBytes caps how much unread request body is read and discarded
	// after the response has been decided. It matches net/http's
	// maxPostHandlerReadBytes: enough to cover request bodies that are rejected
	// early (bad chunk framing, auth failures, missing buckets), small enough
	// that a rejected multi-gigabyte upload is not streamed through the gateway
	// just to be thrown away. A body with more than this still unread is left
	// alone and the connection is closed, so its client can still see a reset.
	maxDrainBytes int64 = 256 << 10
)

// The drain is bounded twice: idle time, so a client that stops sending is cut
// loose quickly, and total time, so a client that trickles cannot hold a worker
// for long.
var (
	drainIdleTimeout  = time.Second
	drainTotalTimeout = 5 * time.Second
)

// DrainRequestBody reads and discards whatever is left of the request body once
// the rest of the handler chain is done with it.
//
// The gateway can decide a response long before the client has finished sending
// the body: an invalid chunk size is detected a few kilobytes into an aws-chunked
// upload, a signature check fails before any payload is read, and so on. fasthttp
// streams request bodies (StreamRequestBody) and does not drain what the handler
// left behind, so the connection is closed with unread bytes still queued in the
// socket. The kernel answers the client's in-flight writes with an RST, and the
// client reports "connection reset by peer" instead of the S3 error the gateway
// took the trouble to produce.
//
// Draining first lets the client finish its write and read the real error. It
// also keeps keep-alive connections in sync: leftover body bytes would otherwise
// be parsed as the start of the next request.
//
// Register it before every route so it wraps all of them. It runs before the
// fiber ErrorHandler, which fiber invokes after the handler chain returns, so
// that handler must not reset the response header the drain may have written to.
func DrainRequestBody() fiber.Handler {
	return func(ctx fiber.Ctx) error {
		// deferred so a panic unwinding through the chain still drains
		defer drainRequestBody(ctx)
		return ctx.Next()
	}
}

func drainRequestBody(ctx fiber.Ctx) {
	stream := ctx.Request().BodyStream()
	if stream == nil {
		// The body was either absent or already buffered in full by fasthttp.
		return
	}

	// fasthttp's requestStream reports EOF idempotently for a Content-Length
	// body, but not for a chunked one: past the terminating chunk it goes back
	// to the socket for another chunk header that will never come. Reading a
	// chunked body the handler already finished would block until the deadline
	// and hold the response back with it, so only Content-Length framing is
	// drained. Nothing is lost for the aws-chunked uploads this exists for --
	// STREAMING-* payloads carry a Content-Length.
	cLength := ctx.Request().Header.ContentLength()
	if cLength <= 0 {
		return
	}

	conn := requestConn(ctx)
	if conn != nil {
		defer conn.SetReadDeadline(time.Time{})
	}
	reader := &drainReader{
		reader:   stream,
		conn:     conn,
		deadline: time.Now().Add(drainTotalTimeout),
	}

	n, err := io.CopyN(io.Discard, reader, maxDrainBytes)
	if err == nil {
		// Filled the cap exactly. One more read tells a body that happened to
		// end there from one with more still to come.
		err = reader.atEOF()
	}
	if errors.Is(err, io.EOF) {
		if n > 0 {
			debuglogger.Logf("discarded %v unread request body bytes before responding", n)
		}
		return
	}

	if err != nil {
		debuglogger.Logf("failed to discard the unread request body after %v bytes: %v", n, err)
	} else {
		debuglogger.Logf("unread request body exceeds the %v byte drain limit: %v bytes discarded", maxDrainBytes, n)
	}

	// The body was not consumed to its end, so the bytes still in flight would
	// be parsed as the start of the next request on a keep-alive connection.
	// Tell fasthttp to close it instead.
	ctx.Response().Header.SetConnectionClose()
}

// drainReader refreshes the connection's read deadline before every read, so a
// client that keeps sending is never cut off mid-drain while one that goes quiet
// is dropped after drainIdleTimeout. deadline caps the whole drain regardless.
type drainReader struct {
	reader   io.Reader
	conn     net.Conn
	deadline time.Time
}

func (dr *drainReader) Read(p []byte) (int, error) {
	if dr.conn != nil {
		next := time.Now().Add(drainIdleTimeout)
		if next.After(dr.deadline) {
			next = dr.deadline
		}
		if err := dr.conn.SetReadDeadline(next); err != nil {
			return 0, err
		}
	}

	return dr.reader.Read(p)
}

// atEOF reports io.EOF when the body ends exactly at the drain limit.
func (dr *drainReader) atEOF() error {
	var b [1]byte
	n, err := dr.Read(b[:])
	if n == 0 && err == nil {
		return nil
	}

	return err
}

func requestConn(ctx fiber.Ctx) net.Conn {
	rctx := ctx.RequestCtx()
	if rctx == nil {
		return nil
	}

	return rctx.Conn()
}
