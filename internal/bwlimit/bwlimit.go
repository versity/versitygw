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

// Package bwlimit shapes network traffic to a configured bandwidth. Limits are
// token buckets shared by every connection accepted from a wrapped listener,
// so they cap the aggregate throughput of a server rather than each client.
package bwlimit

import (
	"container/list"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// MinRate and MaxRate bound nonzero configured rates in bytes per second.
	MinRate = 64 << 10
	MaxRate = 1 << 40

	// MinBurst is the smallest allowed burst. Reads and writes are split
	// into burst-sized pieces, so a smaller burst would turn each TLS record
	// (up to 16KiB plus overhead) into many system calls.
	MinBurst = 32 << 10
	// MaxBurst is the largest supported burst in bytes.
	MaxBurst = 1<<31 - 1

	// The default burst is 10ms of traffic within these bounds. Every
	// transfer queues up to one burst at a time, so a small burst keeps small
	// requests from queueing far behind concurrent large transfers.
	minDefaultBurst = 64 << 10
	maxDefaultBurst = 1 << 20
)

// Limiter is a byte-rate token bucket. A nil *Limiter is unlimited.
type Limiter struct {
	mu          sync.Mutex
	rate        float64
	burst       int
	tokens      float64
	last        time.Time
	waiters     list.List
	waiting     int64
	waitUpdated time.Time
	waited      int64
}

// BurstSize returns the effective maximum number of bytes available to a
// transfer at once.
func (l *Limiter) BurstSize() int {
	if l == nil {
		return 0
	}
	return l.burst
}

type waiter struct {
	wake chan struct{}
}

// ValidateConfig checks a named direction's rate and burst configuration.
func ValidateConfig(direction string, rate, burst int64) error {
	switch {
	case rate < 0:
		return fmt.Errorf("%s bandwidth rate must not be negative", direction)
	case rate > 0 && rate < MinRate:
		return fmt.Errorf("%s bandwidth rate must be at least %d bytes/s (64KiB/s)", direction, MinRate)
	case rate > MaxRate:
		return fmt.Errorf("%s bandwidth rate must not exceed %d bytes/s (1TiB/s)", direction, int64(MaxRate))
	case burst < 0:
		return fmt.Errorf("%s bandwidth burst must not be negative", direction)
	case burst > 0 && rate == 0:
		return fmt.Errorf("%s bandwidth burst requires a non-zero rate", direction)
	case burst > 0 && burst < MinBurst:
		return fmt.Errorf("%s bandwidth burst must be at least %d bytes (32KiB)", direction, MinBurst)
	case burst > MaxBurst:
		return fmt.Errorf("%s bandwidth burst must not exceed %d bytes", direction, MaxBurst)
	}
	return nil
}

// NewLimiter returns a limiter allowing bytesPerSec bytes per second with
// bursts of up to burst bytes. A non-positive bytesPerSec means unlimited and
// returns nil. A non-positive burst selects a default of 10ms of traffic,
// between 64KiB and 1MiB. A burst below MinBurst is raised to MinBurst and a
// burst above MaxBurst is clamped to MaxBurst.
func NewLimiter(bytesPerSec, burst int64) *Limiter {
	if bytesPerSec <= 0 {
		return nil
	}
	if burst <= 0 {
		burst = min(max(bytesPerSec/100, minDefaultBurst), maxDefaultBurst)
	}
	b := int(min(max(burst, MinBurst), MaxBurst))
	now := time.Now()
	return &Limiter{
		rate:        float64(bytesPerSec),
		burst:       b,
		tokens:      float64(b),
		last:        now,
		waitUpdated: now,
	}
}

// DrainWaitTime returns the time connections spent delayed since the last
// call, including waits still in progress. Delays of concurrent connections
// add up.
func (l *Limiter) DrainWaitTime() time.Duration {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.recordWait(time.Now())
	waited := l.waited
	l.waited = 0
	return time.Duration(waited)
}

func (l *Limiter) recordWait(now time.Time) {
	elapsed := now.Sub(l.waitUpdated)
	if elapsed > 0 && l.waiting > 0 {
		if int64(elapsed) > (math.MaxInt64-l.waited)/l.waiting {
			l.waited = math.MaxInt64
		} else {
			l.waited += int64(elapsed) * l.waiting
		}
	}
	l.waitUpdated = now
}

func (l *Limiter) advance(now time.Time) {
	if elapsed := now.Sub(l.last); elapsed > 0 {
		l.tokens = min(float64(l.burst), l.tokens+elapsed.Seconds()*l.rate)
		l.last = now
	}
}

func (l *Limiter) wakeNext() {
	if head := l.waiters.Front(); head != nil {
		select {
		case head.Value.(*waiter).wake <- struct{}{}:
		default:
		}
	}
}

func (l *Limiter) removeWaiter(elem *list.Element, now time.Time) {
	head := l.waiters.Front() == elem
	l.recordWait(now)
	l.waiting--
	l.waiters.Remove(elem)
	if head {
		l.wakeNext()
	}
}

func (l *Limiter) refund(n int) {
	if n <= 0 {
		return
	}
	l.mu.Lock()
	l.advance(time.Now())
	l.tokens = min(float64(l.burst), l.tokens+float64(n))
	l.wakeNext()
	l.mu.Unlock()
}

// wait charges n bytes when they become available. Waiters are queued so a
// canceled operation does not reserve bandwidth ahead of other connections.
func (l *Limiter) wait(n int, currentDeadline func() (time.Time, <-chan struct{}), closed <-chan struct{}) error {
	if n > l.burst {
		return fmt.Errorf("bwlimit: %d bytes exceeds burst %d", n, l.burst)
	}
	if n <= 0 {
		return nil
	}

	l.mu.Lock()
	now := time.Now()
	deadline, _ := currentDeadline()
	if err := waitError(deadline, closed, now); err != nil {
		l.mu.Unlock()
		return err
	}
	l.advance(now)
	if l.waiters.Len() == 0 && l.tokens >= float64(n) {
		l.tokens -= float64(n)
		l.mu.Unlock()
		return nil
	}

	w := &waiter{wake: make(chan struct{}, 1)}
	elem := l.waiters.PushBack(w)
	l.recordWait(now)
	l.waiting++

	for {
		deadline, deadlineChanged := currentDeadline()
		now = time.Now()
		if err := waitError(deadline, closed, now); err != nil {
			l.removeWaiter(elem, now)
			l.mu.Unlock()
			return err
		}

		head := l.waiters.Front() == elem
		var delay time.Duration
		if head {
			l.advance(now)
			if l.tokens >= float64(n) {
				l.tokens -= float64(n)
				l.removeWaiter(elem, now)
				l.mu.Unlock()
				return nil
			}
			nanos := (float64(n) - l.tokens) / l.rate * float64(time.Second)
			if nanos >= float64(math.MaxInt64) {
				delay = time.Duration(math.MaxInt64)
			} else {
				delay = max(time.Nanosecond, time.Duration(math.Ceil(nanos)))
			}
		}
		l.mu.Unlock()

		var timer *time.Timer
		var timerC <-chan time.Time
		if head {
			timer = time.NewTimer(delay)
			timerC = timer.C
		}
		var deadlineTimer *time.Timer
		var deadlineC <-chan time.Time
		if !deadline.IsZero() {
			deadlineTimer = time.NewTimer(time.Until(deadline))
			deadlineC = deadlineTimer.C
		}
		select {
		case <-timerC:
		case <-deadlineC:
		case <-deadlineChanged:
		case <-closed:
		case <-w.wake:
		}
		if timer != nil {
			timer.Stop()
		}
		if deadlineTimer != nil {
			deadlineTimer.Stop()
		}
		l.mu.Lock()
	}
}

func waitError(deadline time.Time, closed <-chan struct{}, now time.Time) error {
	select {
	case <-closed:
		return net.ErrClosed
	default:
	}
	if !deadline.IsZero() && !now.Before(deadline) {
		return os.ErrDeadlineExceeded
	}
	return nil
}

// NewListener wraps ln so that bytes read from accepted connections are
// limited by ingress and bytes written are limited by egress. Either limiter
// may be nil to leave that direction unlimited; if both are nil, ln is
// returned unchanged.
func NewListener(ln net.Listener, ingress, egress *Limiter) net.Listener {
	if ingress == nil && egress == nil {
		return ln
	}
	return &listener{Listener: ln, ingress: ingress, egress: egress}
}

type listener struct {
	net.Listener
	ingress *Limiter
	egress  *Limiter
}

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	wrapped := &conn{
		Conn:          c,
		ingress:       l.ingress,
		egress:        l.egress,
		readDeadline:  newDeadlineState(),
		writeDeadline: newDeadlineState(),
		closed:        make(chan struct{}),
		writeClosed:   make(chan struct{}),
	}
	if halfCloser, ok := c.(interface{ CloseWrite() error }); ok {
		return &halfCloseConn{conn: wrapped, halfCloser: halfCloser}, nil
	}
	return wrapped, nil
}

// Preserve half-close only when the underlying connection supports it.
type halfCloseConn struct {
	*conn
	halfCloser interface{ CloseWrite() error }
}

func (c *halfCloseConn) CloseWrite() error {
	if err := c.halfCloser.CloseWrite(); err != nil {
		return err
	}
	c.closeWrite()
	return nil
}

type conn struct {
	net.Conn
	ingress       *Limiter
	egress        *Limiter
	readDeadline  deadlineState
	writeDeadline deadlineState
	deadlineMu    sync.Mutex
	readMu        sync.Mutex
	pending       []byte
	pendingErr    error
	// Closing either direction releases its bandwidth waiters.
	closed         chan struct{}
	writeClosed    chan struct{}
	closeOnce      sync.Once
	writeCloseOnce sync.Once
	closeErr       error
	opMu           sync.Mutex
	closing        bool
	ops            sync.WaitGroup
}

// Read charges the ingress limiter after the read rather than before, so an
// idle keep-alive connection blocked in Read holds no tokens. Delaying the
// next Read lets TCP flow control push back on the sender.
func (c *conn) Read(p []byte) (int, error) {
	if !c.beginOp() {
		return 0, net.ErrClosed
	}
	defer c.ops.Done()
	if c.ingress == nil {
		return c.Conn.Read(p)
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.pending) > 0 {
		n := min(len(p), len(c.pending))
		if err := c.ingress.wait(n, c.readDeadline.snapshot, c.closed); err != nil {
			return 0, err
		}
		copy(p, c.pending[:n])
		c.pending = c.pending[n:]
		if len(c.pending) == 0 {
			err := c.pendingErr
			c.pending = nil
			c.pendingErr = nil
			return n, err
		}
		return n, nil
	}
	if len(p) > c.ingress.burst {
		p = p[:c.ingress.burst]
	}
	n, err := c.Conn.Read(p)
	if n > 0 {
		if werr := c.ingress.wait(n, c.readDeadline.snapshot, c.closed); werr != nil {
			if errors.Is(werr, os.ErrDeadlineExceeded) {
				c.pending = append([]byte(nil), p[:n]...)
				c.pendingErr = err
			}
			return 0, werr
		}
	}
	return n, err
}

func (c *conn) Write(p []byte) (int, error) {
	if !c.beginOp() {
		return 0, net.ErrClosed
	}
	defer c.ops.Done()
	if c.egress == nil {
		return c.Conn.Write(p)
	}
	var written int
	for len(p) > 0 {
		chunk := min(len(p), c.egress.burst)
		if err := c.egress.wait(chunk, c.writeDeadline.snapshot, c.writeClosed); err != nil {
			return written, err
		}
		n, err := c.Conn.Write(p[:chunk])
		written += n
		c.egress.refund(chunk - n)
		if err != nil {
			return written, err
		}
		if n != chunk {
			return written, io.ErrShortWrite
		}
		p = p[chunk:]
	}
	return written, nil
}

// ReadFrom preserves the underlying connection's fast path when egress is
// unlimited; otherwise all bytes still pass through the limiter.
func (c *conn) ReadFrom(r io.Reader) (int64, error) {
	if c.egress != nil {
		return io.Copy(connWriter{conn: c}, r)
	}
	if readerFrom, ok := c.Conn.(io.ReaderFrom); ok {
		if c.isClosing() {
			return 0, net.ErrClosed
		}
		return readerFrom.ReadFrom(r)
	}
	return io.Copy(connWriter{conn: c}, r)
}

type connWriter struct {
	conn *conn
}

func (w connWriter) Write(p []byte) (int, error) {
	return w.conn.Write(p)
}

func (c *conn) beginOp() bool {
	c.opMu.Lock()
	defer c.opMu.Unlock()
	if c.closing {
		return false
	}
	c.ops.Add(1)
	return true
}

func (c *conn) isClosing() bool {
	c.opMu.Lock()
	defer c.opMu.Unlock()
	return c.closing
}

func (c *conn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if err := c.Conn.SetDeadline(t); err != nil {
		return err
	}
	c.readDeadline.set(t)
	c.writeDeadline.set(t)
	return nil
}

func (c *conn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if err := c.Conn.SetReadDeadline(t); err != nil {
		return err
	}
	c.readDeadline.set(t)
	return nil
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if err := c.Conn.SetWriteDeadline(t); err != nil {
		return err
	}
	c.writeDeadline.set(t)
	return nil
}

func (c *conn) closeWrite() {
	c.writeCloseOnce.Do(func() { close(c.writeClosed) })
}

func (c *conn) Close() error {
	c.closeOnce.Do(func() {
		c.opMu.Lock()
		c.closing = true
		close(c.closed)
		c.closeWrite()
		c.opMu.Unlock()
		c.closeErr = c.Conn.Close()
		c.ops.Wait()
		c.pending = nil
		c.pendingErr = nil
	})
	return c.closeErr
}

type deadlineState struct {
	mu      sync.Mutex
	when    time.Time
	changed chan struct{}
}

func newDeadlineState() deadlineState {
	return deadlineState{changed: make(chan struct{})}
}

func (d *deadlineState) set(t time.Time) {
	d.mu.Lock()
	d.when = t
	close(d.changed)
	d.changed = make(chan struct{})
	d.mu.Unlock()
}

func (d *deadlineState) snapshot() (time.Time, <-chan struct{}) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.when, d.changed
}

// rateUnits are matched case-insensitively, longest suffix first. "bit" units
// are decimal bits. Byte units must end in an upper-case "B", since a lower-case
// "b" commonly means bits; "iB" units are binary and "B" units decimal.
var rateUnits = []struct {
	suffix string
	mult   float64
}{
	{"tbit", 1e12 / 8}, {"gbit", 1e9 / 8}, {"mbit", 1e6 / 8}, {"kbit", 1e3 / 8}, {"bit", 1.0 / 8},
	{"tib", 1 << 40}, {"gib", 1 << 30}, {"mib", 1 << 20}, {"kib", 1 << 10},
	{"tb", 1e12}, {"gb", 1e9}, {"mb", 1e6}, {"kb", 1e3},
	{"b", 1},
}

// ParseRate parses a non-zero byte rate. Non-zero rates must include an
// explicit unit to avoid unexpectedly low rates caused by missing units.
func ParseRate(s string) (int64, error) {
	v, err := ParseBytes(s)
	if err != nil {
		return 0, err
	}
	str := strings.TrimSpace(s)
	if len(str) >= 2 && strings.EqualFold(str[len(str)-2:], "/s") {
		str = strings.TrimSpace(str[:len(str)-2])
	}
	lower := strings.ToLower(str)
	hasUnit := false
	for _, unit := range rateUnits {
		if strings.HasSuffix(lower, unit.suffix) {
			hasUnit = true
			break
		}
	}
	if v > 0 && !hasUnit {
		return 0, fmt.Errorf("non-zero bandwidth rate %q must include a unit", s)
	}
	return v, nil
}

// ParseBytes parses a byte quantity such as "64KiB", "500MB", "10Gbit", or
// "1048576", with an optional "/s" suffix, and returns it in bytes. An empty
// string parses as 0. A non-zero quantity below one byte is an error, so a
// typo cannot silently disable a limit.
func ParseBytes(s string) (int64, error) {
	str := strings.TrimSpace(s)
	if str == "" {
		return 0, nil
	}
	if len(str) >= 2 && strings.EqualFold(str[len(str)-2:], "/s") {
		str = strings.TrimSpace(str[:len(str)-2])
		if str == "" {
			return 0, fmt.Errorf("invalid byte quantity %q", s)
		}
	}
	lower := strings.ToLower(str)
	mult := 1.0
	hasUnit := false
	for _, u := range rateUnits {
		if !strings.HasSuffix(lower, u.suffix) {
			continue
		}
		if !strings.HasSuffix(u.suffix, "bit") && strings.HasSuffix(u.suffix, "b") && str[len(str)-1] != 'B' {
			return 0, fmt.Errorf("ambiguous unit in %q: use B for bytes (e.g. MB, MiB) or bit for bits (e.g. Mbit)", s)
		}
		mult = u.mult
		str = strings.TrimSpace(str[:len(str)-len(u.suffix)])
		hasUnit = true
		break
	}
	if !hasUnit {
		for _, prefix := range []string{"k", "m", "g", "t"} {
			if strings.HasSuffix(lower, prefix) {
				return 0, fmt.Errorf("ambiguous unit in %q: use an explicit byte or bit unit (e.g. MB, MiB, Mbit)", s)
			}
		}
	}
	if !isDecimal(str) {
		return 0, fmt.Errorf("invalid byte quantity %q", s)
	}
	n, err := strconv.ParseFloat(str, 64)
	if err != nil || n < 0 || math.IsInf(n, 0) || math.IsNaN(n) {
		return 0, fmt.Errorf("invalid byte quantity %q", s)
	}
	v := n * mult
	if v >= math.MaxInt64 {
		return 0, fmt.Errorf("byte quantity %q is too large", s)
	}
	// ParseFloat can underflow a positive decimal to zero.
	if v < 1 && strings.ContainsAny(str, "123456789") {
		return 0, fmt.Errorf("byte quantity %q is less than one byte", s)
	}
	return int64(v), nil
}

func isDecimal(s string) bool {
	beforePoint := 0
	afterPoint := 0
	point := false
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			if point {
				afterPoint++
			} else {
				beforePoint++
			}
		case r == '.' && !point:
			point = true
		default:
			return false
		}
	}
	return beforePoint > 0 && (!point || afterPoint > 0)
}
