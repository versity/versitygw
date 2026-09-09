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
	"github.com/versity/versitygw/s3api/utils"
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
// be parsed as the start of the next request, which on a connection shared by an
// upstream proxy mixes requests across tenants.
//
// It wraps the body in a bodyStreamTracker on the way in, which is what tells a
// body the handler finished from one it abandoned. Every reader in the chain
// must therefore take the body from requestBodyStream.
//
// Register it before every route so it wraps all of them. It runs before the
// fiber ErrorHandler, which fiber invokes after the handler chain returns, so
// that handler must not reset the response header the drain may have written to.
func DrainRequestBody() fiber.Handler {
	return func(ctx fiber.Ctx) error {
		var body *bodyStreamTracker
		if stream := ctx.Request().BodyStream(); stream != nil {
			body = &bodyStreamTracker{reader: stream}
			utils.ContextKeyBodyStream.Set(ctx, body)
		}

		// deferred so a panic unwinding through the chain still drains
		defer drainRequestBody(ctx, body)

		return ctx.Next()
	}
}

func drainRequestBody(ctx fiber.Ctx, body *bodyStreamTracker) {
	if body == nil || ctx.Request().BodyStream() == nil {
		// The body was either absent, or buffered in full and released by
		// fasthttp behind the chain's back, the way ctx.Body() does.
		return
	}

	if errors.Is(body.end, io.EOF) {
		// The handler read the body to its end: the socket holds nothing more
		// of it and the connection is already in sync for the next request.
		return
	}

	conn := requestConn(ctx)
	if conn != nil {
		defer conn.SetReadDeadline(time.Time{})
	}

	// The leftovers are read back through the tracker, so a drain that reaches
	// the end of the body records it the same way the handler's reads would.
	src := io.Reader(body)
	if body.end != nil {
		// The framing broke before the body ended, so what is still queued
		// cannot be told apart from the start of the next request and the
		// connection cannot carry one. Draining is still worth attempting: the
		// connection is going away either way, and absorbing the client's
		// in-flight write is what lets it read the S3 error instead of an RST.
		// Only the raw socket can absorb it once the framing is gone.
		ctx.Response().Header.SetConnectionClose()
		if conn == nil {
			return
		}
		src = conn
	}

	reader := &drainReader{
		reader:   src,
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

// requestBodyStream returns the reader the request body must be read through.
// Reading ctx.Request().BodyStream() directly instead hides those reads from
// DrainRequestBody, which then cannot tell a finished body from an abandoned
// one and falls back to closing the connection.
//
// It yields the raw stream where DrainRequestBody is not registered, and nil
// when the request carries no streamed body.
func requestBodyStream(ctx fiber.Ctx) io.Reader {
	if body, ok := utils.ContextKeyBodyStream.Get(ctx).(*bodyStreamTracker); ok {
		return body
	}

	return ctx.Request().BodyStream()
}

// bodyStreamTracker remembers how the request body ended, so the drain can tell
// a body the handler read to its end from one it stopped partway through.
//
// fasthttp cannot be asked a second time. Its requestStream reports EOF
// idempotently for a Content-Length body, but not for a chunked one: past the
// terminating chunk it goes back to the socket for another chunk header that
// will never come, so a read of a body the handler already finished blocks
// until the deadline and holds the response back with it. The first terminal
// result is recorded here and replayed instead.
type bodyStreamTracker struct {
	reader io.Reader
	// end is the first error the stream ended on: nil while it still has more
	// to give, io.EOF once it was read out in full, and the framing error if it
	// broke before that.
	end error
}

func (t *bodyStreamTracker) Read(p []byte) (int, error) {
	if t.end != nil {
		return 0, t.end
	}

	n, err := t.reader.Read(p)
	if err != nil {
		t.end = err
	}

	return n, err
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
