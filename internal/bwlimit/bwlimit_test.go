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

package bwlimit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestParseBytes(t *testing.T) {
	tests := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"", 0, false},
		{"0", 0, false},
		{"0e-999", 0, false},
		{"0x0p-9999", 0, false},
		{"1048576", 1 << 20, false},
		{"64KiB", 64 << 10, false},
		{"1.5 GiB", 3 << 29, false},
		{"500MB", 500_000_000, false},
		{"500MB/s", 500_000_000, false},
		{"10Gbit", 1_250_000_000, false},
		{"100 mbit/S", 12_500_000, false},
		{"2M", 2 << 20, false},
		{"8bit", 1, false},
		// a lowercase b commonly means bits, so it must not mean bytes
		{"10Gb", 0, true},
		{"500mb", 0, true},
		{"64kib", 0, true},
		{"100b", 0, true},
		// non-zero values that round to zero would silently mean unlimited
		{"0.5", 0, true},
		{"4bit", 0, true},
		{"/s", 0, true},
		{"1e-999", 0, true},
		{"0x1p-9999", 0, true},
		{"5e-324bit", 0, true},
		{"-1MiB", 0, true},
		{"fast", 0, true},
		{"MiB", 0, true},
		{"1e30TiB", 0, true},
	}
	for _, tt := range tests {
		got, err := ParseBytes(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseBytes(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseBytes(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestNewLimiterUnlimited(t *testing.T) {
	if NewLimiter(0, 1024) != nil {
		t.Fatal("expected nil limiter for zero rate")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if got := NewListener(ln, nil, nil); got != ln {
		t.Fatal("expected listener to be returned unwrapped when no limits are set")
	}
}

// serve accepts one connection from a listener limited by ingress/egress and
// runs fn on the server side of it, returning the client side.
func serve(t *testing.T, ingress, egress *Limiter, fn func(net.Conn)) net.Conn {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := NewListener(raw, ingress, egress)
	t.Cleanup(func() { ln.Close() })

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		fn(c)
	}()

	c, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

const (
	testRate  = 1 << 20  // 1MiB/s
	testBurst = 64 << 10 // 64KiB
	testSize  = 384 << 10
	// The first burst is free; the remainder must be paced at testRate.
	minElapsed = time.Duration(float64(testSize-testBurst) / testRate * float64(time.Second))
)

func checkElapsed(t *testing.T, elapsed time.Duration) {
	t.Helper()
	if elapsed < minElapsed*9/10 {
		t.Fatalf("transfer took %v, want at least ~%v", elapsed, minElapsed)
	}
	if elapsed > minElapsed*4 {
		t.Fatalf("transfer took %v, want close to %v", elapsed, minElapsed)
	}
}

func TestIngressIsShaped(t *testing.T) {
	payload := bytes.Repeat([]byte("a"), testSize)
	done := make(chan []byte, 1)
	start := time.Now()
	c := serve(t, NewLimiter(testRate, testBurst), nil, func(c net.Conn) {
		got, _ := io.ReadAll(c)
		done <- got
	})

	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	c.(*net.TCPConn).CloseWrite()

	got := <-done
	checkElapsed(t, time.Since(start))
	if !bytes.Equal(got, payload) {
		t.Fatalf("server read %d bytes, want %d intact", len(got), len(payload))
	}
}

func TestConcurrentIngressSharesLimit(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := NewListener(raw, NewLimiter(testRate, testBurst), nil)
	t.Cleanup(func() { ln.Close() })

	const clients = 2
	type pair struct {
		client net.Conn
		server net.Conn
	}
	pairs := make([]pair, clients)
	for i := range pairs {
		client, err := net.Dial("tcp", raw.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		server, err := ln.Accept()
		if err != nil {
			client.Close()
			t.Fatal(err)
		}
		pairs[i] = pair{client: client, server: server}
		defer pairs[i].client.Close()
		defer pairs[i].server.Close()
	}

	start := time.Now()
	done := make(chan error, clients*2)
	payload := bytes.Repeat([]byte("c"), testSize)
	for _, p := range pairs {
		go func(p pair) {
			got := make([]byte, len(payload))
			_, err := io.ReadFull(p.server, got)
			if err == nil && !bytes.Equal(got, payload) {
				err = errors.New("received payload differs")
			}
			done <- err
		}(p)
		go func(p pair) {
			_, err := p.client.Write(payload)
			if err == nil {
				err = p.client.(*net.TCPConn).CloseWrite()
			}
			done <- err
		}(p)
	}

	for range clients * 2 {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent ingress transfer timed out")
		}
	}
	elapsed := time.Since(start)
	want := time.Duration(float64(clients*testSize-testBurst) / testRate * float64(time.Second))
	if elapsed < want*8/10 {
		t.Fatalf("concurrent ingress took %v, want at least about %v at the shared rate", elapsed, want)
	}
}

func TestEgressIsShaped(t *testing.T) {
	payload := bytes.Repeat([]byte("b"), testSize)
	lim := NewLimiter(testRate, testBurst)
	start := time.Now()
	c := serve(t, nil, lim, func(c net.Conn) {
		n, err := c.Write(payload)
		if err != nil || n != len(payload) {
			t.Errorf("Write = %d, %v; want %d, nil", n, err, len(payload))
		}
	})

	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	checkElapsed(t, time.Since(start))
	if !bytes.Equal(got, payload) {
		t.Fatalf("client read %d bytes, want %d intact", len(got), len(payload))
	}
	if w := lim.DrainWaitTime(); w < minElapsed/2 {
		t.Fatalf("WaitTime = %v, want about %v", w, minElapsed)
	}
}

func TestConcurrentEgressSharesLimit(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := NewListener(raw, nil, NewLimiter(testRate, testBurst))
	defer ln.Close()

	const clients = 2
	type pair struct {
		client net.Conn
		server net.Conn
	}
	pairs := make([]pair, clients)
	for i := range pairs {
		client, err := net.Dial("tcp", raw.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		server, err := ln.Accept()
		if err != nil {
			client.Close()
			t.Fatal(err)
		}
		pairs[i] = pair{client: client, server: server}
		defer client.Close()
		defer server.Close()
	}

	payload := bytes.Repeat([]byte("d"), testSize)
	done := make(chan error, clients*2)
	start := time.Now()
	for _, p := range pairs {
		go func(p pair) {
			_, err := p.server.Write(payload)
			done <- err
		}(p)
		go func(p pair) {
			got := make([]byte, len(payload))
			_, err := io.ReadFull(p.client, got)
			if err == nil && !bytes.Equal(got, payload) {
				err = errors.New("received payload differs")
			}
			done <- err
		}(p)
	}
	for range clients * 2 {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent egress transfer timed out")
		}
	}
	want := time.Duration(float64(clients*testSize-testBurst) / testRate * float64(time.Second))
	if elapsed := time.Since(start); elapsed < want*8/10 {
		t.Fatalf("concurrent egress took %v, want at least about %v at the shared rate", elapsed, want)
	}
}

func TestCanceledWaitDoesNotHoldBandwidth(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lim := NewLimiter(MinBurst, MinBurst)
	ln := NewListener(raw, nil, lim)
	defer ln.Close()

	firstClient, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer firstClient.Close()
	first, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	secondClient, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer secondClient.Close()
	second, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	go io.Copy(io.Discard, secondClient)

	payload := make([]byte, MinBurst)
	if _, err := first.Write(payload); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(firstClient, make([]byte, MinBurst)); err != nil {
		t.Fatal(err)
	}
	firstDone := make(chan error, 1)
	go func() {
		_, err := first.Write(payload)
		firstDone <- err
	}()
	until := time.Now().Add(2 * time.Second)
	for lim.DrainWaitTime() == 0 {
		if time.Now().After(until) {
			t.Fatal("first writer did not wait")
		}
		time.Sleep(time.Millisecond)
	}
	if err := second.SetWriteDeadline(time.Now().Add(1600 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	secondDone := make(chan error, 1)
	lim.DrainWaitTime()
	queuedAt := time.Now()
	go func() {
		_, err := second.Write(payload)
		secondDone <- err
	}()
	var wait time.Duration
	queued := false
	for time.Since(queuedAt) < 500*time.Millisecond {
		time.Sleep(5 * time.Millisecond)
		wait += lim.DrainWaitTime()
		if wait > time.Since(queuedAt)*3/2 {
			queued = true
			break
		}
	}
	if !queued {
		t.Fatal("second writer did not join the bandwidth queue")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-firstDone; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("canceled writer error = %v, want net.ErrClosed", err)
	}
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("second writer after cancellation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled writer held the bandwidth queue")
	}
}

func TestCloseReleasesThrottledWriter(t *testing.T) {
	// The requested 1 byte burst is raised to MinBurst, so the first
	// MinBurst bytes go out at once; at 1 byte/s the rest would take hours.
	lim := NewLimiter(1, 1)
	conns := NewConnSet()
	defer conns.CloseAll()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := NewListenerWithConnSet(raw, nil, lim, conns)
	t.Cleanup(func() { ln.Close() })
	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		server, err := ln.Accept()
		if err != nil {
			done <- result{0, err}
			return
		}
		n, err := server.Write(make([]byte, 2*MinBurst))
		done <- result{n, err}
	}()
	client, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := io.ReadFull(client, make([]byte, MinBurst)); err != nil {
		t.Fatal(err)
	}
	var waited time.Duration
	until := time.Now().Add(2 * time.Second)
	for waited == 0 && time.Now().Before(until) {
		waited = lim.DrainWaitTime()
		if waited == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	if waited == 0 {
		t.Fatal("in-progress wait was not reported")
	}
	if err := conns.CloseAll(); err != nil {
		t.Fatal(err)
	}

	select {
	case r := <-done:
		if !errors.Is(r.err, net.ErrClosed) {
			t.Fatalf("Write error = %v, want net.ErrClosed", r.err)
		}
		if r.n != MinBurst {
			t.Fatalf("Write sent %d bytes before blocking, want %d", r.n, MinBurst)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("throttled Write was not released by ConnSet.CloseAll")
	}
	lim.DrainWaitTime()
	if got := lim.DrainWaitTime(); got != 0 {
		t.Fatalf("DrainWaitTime() after final drain = %v, want 0", got)
	}
}

func TestConnSetWaitAndClose(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conns := NewConnSet()
	ln := NewListenerWithConnSet(raw, nil, nil, conns)
	defer ln.Close()
	client, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := conns.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Wait() = %v, want deadline exceeded while connection is open", err)
	}
	lateClient, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer lateClient.Close()
	if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept() after Wait = %v, want net.ErrClosed", err)
	}
	if err := conns.CloseAll(); err != nil {
		t.Fatal(err)
	}
	if err := conns.Wait(context.Background()); err != nil {
		t.Fatalf("Wait() after CloseAll = %v", err)
	}
}

func TestLimitedConnectionSupportsHalfClose(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	egress := NewLimiter(1, MinBurst)
	ln := NewListener(raw, NewLimiter(testRate, testBurst), egress)
	defer ln.Close()
	client, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	halfCloser, ok := server.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("limited TCP connection does not support CloseWrite")
	}
	if _, err := server.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	pending := make(chan error, 1)
	go func() {
		_, err := server.Write(make([]byte, MinBurst))
		pending <- err
	}()
	until := time.Now().Add(2 * time.Second)
	for egress.DrainWaitTime() == 0 {
		if time.Now().After(until) {
			t.Fatal("writer did not wait for bandwidth")
		}
		time.Sleep(time.Millisecond)
	}
	if err := halfCloser.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-pending:
		if err == nil {
			t.Fatal("pending Write() succeeded after CloseWrite")
		}
	case <-time.After(time.Second):
		t.Fatal("CloseWrite did not release a throttled writer")
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(client)
	if err != nil || string(got) != "ping" {
		t.Fatalf("read after CloseWrite = %q, %v; want ping and EOF", got, err)
	}
	if _, err := client.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	got = make([]byte, 4)
	if _, err := io.ReadFull(server, got); err != nil || string(got) != "pong" {
		t.Fatalf("read after half-close = %q, %v; want pong", got, err)
	}

	pipe, peer := net.Pipe()
	defer peer.Close()
	limitedPipe, err := NewListener(&singleConnListener{conn: pipe}, nil, NewLimiter(testRate, testBurst)).Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer limitedPipe.Close()
	if _, ok := limitedPipe.(interface{ CloseWrite() error }); ok {
		t.Fatal("limited connection advertises unsupported CloseWrite")
	}
}

func TestUnixEpochWriteDeadlineExpiresWhileThrottled(t *testing.T) {
	raw, client := net.Pipe()
	defer client.Close()
	ln := NewListener(&singleConnListener{conn: raw}, nil, NewLimiter(1, MinBurst))
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go io.Copy(io.Discard, client)
	if _, err := server.Write(make([]byte, MinBurst)); err != nil {
		t.Fatal(err)
	}
	if err := server.SetWriteDeadline(time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := server.Write([]byte("x"))
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Write() error = %v, want deadline exceeded", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Write() did not honor the expired Unix epoch deadline")
	}
}

type singleConnListener struct {
	conn net.Conn
}

func (l *singleConnListener) Accept() (net.Conn, error) { return l.conn, nil }
func (l *singleConnListener) Close() error              { return l.conn.Close() }
func (l *singleConnListener) Addr() net.Addr            { return l.conn.LocalAddr() }

type terminalReadConn struct {
	net.Conn
	reads int
}

func (c *terminalReadConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.reads++
		if c.reads == 2 && err == nil {
			return n, io.EOF
		}
	}
	return n, err
}

func TestIngressDeadlinePreservesReadData(t *testing.T) {
	first := bytes.Repeat([]byte("a"), MinBurst)
	second := bytes.Repeat([]byte("b"), MinBurst)
	raw, client := net.Pipe()
	defer client.Close()
	ln := NewListener(&singleConnListener{conn: &terminalReadConn{Conn: raw}}, NewLimiter(2*MinBurst, MinBurst), nil)
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	written := make(chan error, 1)
	secondStarted := make(chan struct{})
	go func() {
		_, err := client.Write(first)
		if err == nil {
			close(secondStarted)
			_, err = client.Write(second)
		}
		written <- err
	}()
	buf := make([]byte, MinBurst)
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, first) {
		t.Fatal("first read differs")
	}
	select {
	case <-secondStarted:
	case err := <-written:
		t.Fatalf("first write failed: %v", err)
	case <-time.After(time.Second):
		t.Fatal("second write did not start")
	}
	if err := server.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	n, err := server.Read(buf)
	if n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("deadline read = %d, %v; want 0 and deadline exceeded", n, err)
	}
	select {
	case err := <-written:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("underlying connection did not receive the second read")
	}
	if err := server.SetReadDeadline(time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	if n, err := server.Read(buf); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("buffered read at expired deadline = %d, %v; want 0 and deadline exceeded", n, err)
	}
	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err = server.Read(buf[:MinBurst/2])
	if n != MinBurst/2 || err != nil {
		t.Fatalf("first buffered read = %d, %v; want %d, nil", n, err, MinBurst/2)
	}
	n, err = server.Read(buf[MinBurst/2:])
	if n != MinBurst/2 || !errors.Is(err, io.EOF) {
		t.Fatalf("final buffered read = %d, %v; want %d, EOF", n, err, MinBurst/2)
	}
	if !bytes.Equal(buf, second) {
		t.Fatal("read after deadline differs")
	}
}

type failedWriteListener struct {
	net.Listener
	first   bool
	written int
}

func (l *failedWriteListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if !l.first {
		l.first = true
		return &failedWriteConn{Conn: c, written: l.written}, nil
	}
	return c, nil
}

type failedWriteConn struct {
	net.Conn
	written int
}

func (c *failedWriteConn) Write(p []byte) (int, error) {
	if c.written == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	n, err := c.Conn.Write(p[:c.written])
	if err != nil {
		return n, err
	}
	return n, io.ErrUnexpectedEOF
}

func TestFailedWritesReturnUnusedBandwidth(t *testing.T) {
	for _, written := range []int{0, MinBurst / 2} {
		t.Run(fmt.Sprintf("written-%d", written), func(t *testing.T) {
			raw, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ln := NewListener(&failedWriteListener{Listener: raw, written: written}, nil, NewLimiter(16<<10, MinBurst))
			defer ln.Close()

			firstClient, err := net.Dial("tcp", raw.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer firstClient.Close()
			go io.Copy(io.Discard, firstClient)
			first, err := ln.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer first.Close()
			n, err := first.Write(make([]byte, MinBurst))
			if n != written || !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("failed Write() = %d, %v; want %d, unexpected EOF", n, err, written)
			}
			first.Close()

			secondClient, err := net.Dial("tcp", raw.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer secondClient.Close()
			go io.Copy(io.Discard, secondClient)
			second, err := ln.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer second.Close()
			if err := second.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			remaining := MinBurst - written
			n, err = second.Write(make([]byte, remaining))
			if n != remaining || err != nil {
				t.Fatalf("Write() after failure = %d, %v; want %d, nil", n, err, remaining)
			}
		})
	}
}

func TestDeadlineBoundsWait(t *testing.T) {
	// At 1 byte/s, anything past the first burst would wait for hours, so
	// the deadline must cut the wait short with a timeout error.
	t.Run("write", func(t *testing.T) {
		done := make(chan error, 1)
		c := serve(t, nil, NewLimiter(1, 0), func(c net.Conn) {
			c.SetWriteDeadline(time.Now().Add(time.Second))
			_, err := c.Write(make([]byte, 1<<20))
			done <- err
		})
		go io.Copy(io.Discard, c)
		checkTimeout(t, done)
	})

	t.Run("read", func(t *testing.T) {
		done := make(chan error, 1)
		c := serve(t, NewLimiter(1, 0), nil, func(c net.Conn) {
			c.SetReadDeadline(time.Now().Add(time.Second))
			_, err := io.Copy(io.Discard, c)
			done <- err
		})
		go c.Write(make([]byte, 1<<20))
		checkTimeout(t, done)
	})
}

func checkTimeout(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		var ne net.Error
		if !errors.Is(err, os.ErrDeadlineExceeded) || !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("error = %v, want a timeout", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("throttled I/O ignored its deadline")
	}
}
