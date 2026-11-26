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

package s3event

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/stretchr/testify/require"
)

// fakeOutcome is what the fake broker does with one publish.
type fakeOutcome struct {
	publishErr     error         // Publish fails
	blockPublish   bool          // Publish blocks until its context is done
	nack           bool          // the broker nacks the event
	loseConnection bool          // the connection is lost before the confirm
	confirmErr     error         // WaitContext fails
	release        chan struct{} // if set, the confirm arrives once it is closed
}

// fakeBroker is a scripted broker. It records the publishes of every
// session it dialed.
type fakeBroker struct {
	mu         sync.Mutex
	sessions   []*fakeSession // the initial session first
	dials      int
	dialFails  int  // how many of the next dials fail
	blockDial  bool // dial waits for its context, then returns a session
	attempts   map[string]int
	msgs       map[string][]amqp.Publishing
	ops        []string // "publish <key>" and "wait <key>" in call order
	acked      []string
	closedPubs int // publishes into a closed session
	// outcome decides the n-th (0 based) publish of the event with key.
	// A nil outcome acks every event.
	outcome func(key string, n int) fakeOutcome
}

// fakeSession is an amqpSession of the fake broker.
type fakeSession struct {
	b          *fakeBroker
	lost       bool // the connection was lost
	closeCalls int
}

func newFakeBroker() *fakeBroker {
	return &fakeBroker{attempts: map[string]int{}, msgs: map[string][]amqp.Publishing{}}
}

func (b *fakeBroker) newSession() *fakeSession {
	s := &fakeSession{b: b}
	b.sessions = append(b.sessions, s)
	return s
}

// initialSession returns the session the sender starts with.
func (b *fakeBroker) initialSession(lost bool) *fakeSession {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.newSession()
	s.lost = lost
	return s
}

func (b *fakeBroker) dial(ctx context.Context) (amqpSession, error) {
	b.mu.Lock()
	b.dials++
	block := b.blockDial
	if !block && b.dialFails > 0 {
		b.dialFails--
		b.mu.Unlock()
		return nil, errors.New("dial tcp: connection refused")
	}
	b.mu.Unlock()

	if block {
		// the dial completes just as the sender is closed
		<-ctx.Done()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.newSession(), nil
}

func (b *fakeBroker) setDialFails(n int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.dialFails = n
}

func (s *fakeSession) Publish(ctx context.Context, exchange, key string, msg amqp.Publishing) (amqpConfirmation, error) {
	evKey := eventKey(msg)
	b := s.b

	b.mu.Lock()
	if s.lost || s.closeCalls > 0 {
		b.closedPubs++
		b.mu.Unlock()
		return nil, errRabbitmqClosed
	}
	n := b.attempts[evKey]
	b.attempts[evKey]++
	b.msgs[evKey] = append(b.msgs[evKey], msg)
	b.ops = append(b.ops, "publish "+evKey)
	var o fakeOutcome
	if b.outcome != nil {
		o = b.outcome(evKey, n)
	}
	b.mu.Unlock()

	if o.blockPublish {
		<-ctx.Done()
		return nil, fmt.Errorf("waiting for the broker to unblock publishing: %w", ctx.Err())
	}
	if o.publishErr != nil {
		return nil, o.publishErr
	}
	return &fakeConfirmation{s: s, key: evKey, o: o}, nil
}

func (s *fakeSession) IsClosed() bool {
	s.b.mu.Lock()
	defer s.b.mu.Unlock()
	return s.lost || s.closeCalls > 0
}

func (s *fakeSession) Close() error {
	s.b.mu.Lock()
	defer s.b.mu.Unlock()
	s.closeCalls++
	return nil
}

// snapshot returns a copy of the recorded calls.
func (b *fakeBroker) snapshot() (attempts map[string]int, ops, acked []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	attempts = map[string]int{}
	for k, v := range b.attempts {
		attempts[k] = v
	}
	return attempts, slices.Clone(b.ops), slices.Clone(b.acked)
}

func (b *fakeBroker) published(key string) bool {
	attempts, _, _ := b.snapshot()
	return attempts[key] > 0
}

func (b *fakeBroker) waited(key string) bool {
	_, ops, _ := b.snapshot()
	return slices.Contains(ops, "wait "+key)
}

func (b *fakeBroker) dialed() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dials
}

type fakeConfirmation struct {
	s   *fakeSession
	key string
	o   fakeOutcome
}

func (c *fakeConfirmation) WaitContext(ctx context.Context) (bool, error) {
	b := c.s.b
	b.mu.Lock()
	b.ops = append(b.ops, "wait "+c.key)
	b.mu.Unlock()

	ack, err := c.wait(ctx)

	b.mu.Lock()
	defer b.mu.Unlock()
	if ack {
		b.acked = append(b.acked, c.key)
	}
	if c.o.loseConnection {
		c.s.lost = true
	}
	return ack, err
}

func (c *fakeConfirmation) wait(ctx context.Context) (bool, error) {
	if c.o.release != nil {
		select {
		case <-c.o.release:
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	if c.o.loseConnection {
		return false, errRabbitmqClosed
	}
	if c.o.confirmErr != nil {
		return false, c.o.confirmErr
	}
	return !c.o.nack, nil
}

func eventKey(msg amqp.Publishing) string {
	var ev EventSchema
	if err := json.Unmarshal(msg.Body, &ev); err != nil || len(ev.Records) == 0 {
		// the startup test event
		return "test-event"
	}
	return ev.Records[0].S3.Object.Key
}

func testEvent(key string) EventSchema {
	return EventSchema{Records: []EventRecord{{S3: EventS3Data{Object: EventObjectData{Key: key}}}}}
}

var testRabbitmqConfig = rabbitmqConfig{
	queueSize:      100,
	batchSize:      16,
	retryFor:       time.Minute,
	backoffMin:     time.Millisecond,
	backoffMax:     5 * time.Millisecond,
	flushTimeout:   20 * time.Millisecond,
	reportInterval: time.Hour,
}

// newTestSender starts a sender on the initial session of b.
func newTestSender(t *testing.T, b *fakeBroker, initialLost bool, cfg rabbitmqConfig) *RabbitmqEventSender {
	rs := newRabbitmqEventSender(b.initialSession(initialLost), b.dial, "", "events", nil, cfg)
	t.Cleanup(func() { rs.Close() })
	return rs
}

const (
	waitFor = 5 * time.Second
	tick    = time.Millisecond
)

// closeReturns fails the test if rs.Close does not return quickly.
func closeReturns(t *testing.T, rs *RabbitmqEventSender) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		rs.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(waitFor):
		t.Fatal("Close did not return")
	}
}

func TestRabbitmqSenderPublishesBatches(t *testing.T) {
	b := newFakeBroker()
	release := make(chan struct{})
	b.outcome = func(key string, n int) fakeOutcome {
		if key == "e0" {
			return fakeOutcome{release: release}
		}
		return fakeOutcome{}
	}
	rs := newTestSender(t, b, false, testRabbitmqConfig)

	// e1..e5 queue up while the publisher waits for the confirm of e0
	rs.enqueue(testEvent("e0"))
	require.Eventually(t, func() bool { return b.published("e0") }, waitFor, tick)
	want := []string{"e0"}
	for i := 1; i <= 5; i++ {
		key := fmt.Sprintf("e%v", i)
		rs.enqueue(testEvent(key))
		want = append(want, key)
	}
	close(release)

	require.Eventually(t, func() bool {
		_, _, acked := b.snapshot()
		return len(acked) == len(want)
	}, waitFor, tick)

	attempts, ops, acked := b.snapshot()
	require.Equal(t, want, acked)
	for _, key := range want {
		require.Equal(t, 1, attempts[key], key)
	}
	// the second batch is published before its confirms are awaited
	require.Less(t, slices.Index(ops, "publish e5"), slices.Index(ops, "wait e1"), ops)
	require.Zero(t, b.dialed())
}

func TestRabbitmqSenderRetriesUnconfirmedEvents(t *testing.T) {
	errWrite := errors.New("write: broken pipe")

	tests := []struct {
		name    string
		failure fakeOutcome
		// dials is how many sessions are dialed for the 2 failures
		dials int
	}{
		{name: "broker nack", failure: fakeOutcome{nack: true}},
		{name: "publish error", failure: fakeOutcome{publishErr: errWrite}},
		{name: "connection lost before the confirm", failure: fakeOutcome{loseConnection: true}, dials: 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := newFakeBroker()
			b.outcome = func(key string, n int) fakeOutcome {
				if key == "e0" && n < 2 {
					return tc.failure
				}
				return fakeOutcome{}
			}
			rs := newTestSender(t, b, false, testRabbitmqConfig)

			rs.enqueue(testEvent("e0"))
			rs.enqueue(testEvent("e1"))

			require.Eventually(t, func() bool {
				_, _, acked := b.snapshot()
				return len(acked) == 2
			}, waitFor, tick)

			attempts, _, acked := b.snapshot()
			require.ElementsMatch(t, []string{"e0", "e1"}, acked)
			require.Equal(t, 3, attempts["e0"])
			require.Equal(t, 1, attempts["e1"])

			b.mu.Lock()
			defer b.mu.Unlock()
			// a retry is the same message
			msgs := b.msgs["e0"]
			for _, msg := range msgs[1:] {
				require.Equal(t, msgs[0].MessageId, msg.MessageId)
				require.Equal(t, msgs[0].Timestamp, msg.Timestamp)
			}
			require.Equal(t, tc.dials, b.dials)
			require.Len(t, b.sessions, tc.dials+1)
			for i, s := range b.sessions {
				if i < tc.dials {
					require.Equal(t, 1, s.closeCalls, "a lost session is closed")
				} else {
					require.Zero(t, s.closeCalls, "a failed publish must not close the session")
				}
			}
		})
	}
}

func TestRabbitmqSenderReconnects(t *testing.T) {
	b := newFakeBroker()
	// the connection was lost while no event was sent, and the broker is
	// down for the first two dials
	b.setDialFails(2)
	rs := newTestSender(t, b, true, testRabbitmqConfig)

	rs.enqueue(testEvent("e0"))
	require.Eventually(t, func() bool {
		_, _, acked := b.snapshot()
		return len(acked) == 1
	}, waitFor, tick)
	rs.enqueue(testEvent("e1"))
	require.Eventually(t, func() bool {
		_, _, acked := b.snapshot()
		return len(acked) == 2
	}, waitFor, tick)

	attempts, _, acked := b.snapshot()
	require.Equal(t, []string{"e0", "e1"}, acked)
	require.Equal(t, 1, attempts["e0"])
	require.Equal(t, 1, attempts["e1"])

	b.mu.Lock()
	defer b.mu.Unlock()
	require.Zero(t, b.closedPubs, "published into a closed session")
	// the session dialed on the third try is kept
	require.Equal(t, 3, b.dials)
	require.Len(t, b.sessions, 2)
	require.Equal(t, 1, b.sessions[0].closeCalls)
	require.Zero(t, b.sessions[1].closeCalls)
}

func TestRabbitmqSenderDropsExpiredEvents(t *testing.T) {
	b := newFakeBroker()
	// the broker is down
	b.setDialFails(1 << 30)
	cfg := testRabbitmqConfig
	cfg.retryFor = 20 * time.Millisecond
	rs := newTestSender(t, b, true, cfg)

	rs.enqueue(testEvent("e0"))
	require.Eventually(t, func() bool { return rs.expired.Load() == 1 }, waitFor, tick)
	b.setDialFails(0)
	rs.enqueue(testEvent("e1"))

	require.Eventually(t, func() bool {
		_, _, acked := b.snapshot()
		return len(acked) == 1
	}, waitFor, tick)

	attempts, _, acked := b.snapshot()
	require.Equal(t, []string{"e1"}, acked)
	require.Zero(t, attempts["e0"], "expired event was published")
}

func TestRabbitmqSenderDropsEventsWhenQueueIsFull(t *testing.T) {
	b := newFakeBroker()
	release := make(chan struct{})
	b.outcome = func(key string, n int) fakeOutcome {
		if key == "e0" {
			return fakeOutcome{release: release}
		}
		return fakeOutcome{}
	}
	cfg := testRabbitmqConfig
	cfg.queueSize = 2
	cfg.batchSize = 1
	rs := newTestSender(t, b, false, cfg)

	rs.enqueue(testEvent("e0"))
	require.Eventually(t, func() bool { return b.published("e0") }, waitFor, tick)

	// e1 and e2 fill the queue, e3 and e4 are dropped without blocking
	for i := 1; i <= 4; i++ {
		rs.enqueue(testEvent(fmt.Sprintf("e%v", i)))
	}
	require.EqualValues(t, 2, rs.queueFull.Load())

	close(release)
	require.Eventually(t, func() bool {
		_, _, acked := b.snapshot()
		return len(acked) == 3
	}, waitFor, tick)

	attempts, _, acked := b.snapshot()
	require.Equal(t, []string{"e0", "e1", "e2"}, acked)
	require.Zero(t, attempts["e3"])
	require.Zero(t, attempts["e4"])
}

func TestRabbitmqSenderReportsDropsWhilePublishing(t *testing.T) {
	b := newFakeBroker()
	release := make(chan struct{})
	b.outcome = func(key string, n int) fakeOutcome {
		if key == "e0" {
			return fakeOutcome{release: release}
		}
		return fakeOutcome{}
	}
	cfg := testRabbitmqConfig
	cfg.queueSize = 1
	cfg.batchSize = 1
	cfg.reportInterval = 5 * time.Millisecond
	rs := newTestSender(t, b, false, cfg)

	rs.enqueue(testEvent("e0"))
	require.Eventually(t, func() bool { return b.published("e0") }, waitFor, tick)
	// e1 fills the queue and e2 is dropped
	rs.enqueue(testEvent("e1"))
	rs.enqueue(testEvent("e2"))

	// reported while the publisher still waits for the confirm of e0
	require.Eventually(t, func() bool { return rs.queueFull.Load() == 0 }, waitFor, tick)
	require.Empty(t, func() []string { _, _, acked := b.snapshot(); return acked }())

	close(release)
	require.Eventually(t, func() bool {
		_, _, acked := b.snapshot()
		return len(acked) == 2
	}, waitFor, tick)
	attempts, _, _ := b.snapshot()
	require.Zero(t, attempts["e2"])
}

func TestRabbitmqSenderCloseFlushesQueue(t *testing.T) {
	b := newFakeBroker()
	release := make(chan struct{})
	b.outcome = func(key string, n int) fakeOutcome {
		if key == "e0" {
			return fakeOutcome{release: release}
		}
		return fakeOutcome{}
	}
	cfg := testRabbitmqConfig
	cfg.batchSize = 1
	cfg.flushTimeout = waitFor
	rs := newTestSender(t, b, false, cfg)

	rs.enqueue(testEvent("e0"))
	require.Eventually(t, func() bool { return b.waited("e0") }, waitFor, tick)
	rs.enqueue(testEvent("e1"))
	rs.enqueue(testEvent("e2"))

	closed := make(chan struct{})
	go func() {
		rs.Close()
		close(closed)
	}()
	<-rs.closing
	// events sent after Close are dropped
	rs.enqueue(testEvent("e3"))
	close(release)

	select {
	case <-closed:
	case <-time.After(waitFor):
		t.Fatal("Close did not return")
	}
	attempts, _, acked := b.snapshot()
	require.Equal(t, []string{"e0", "e1", "e2"}, acked)
	require.Zero(t, attempts["e3"])
	b.mu.Lock()
	defer b.mu.Unlock()
	require.Equal(t, 1, b.sessions[0].closeCalls)
}

func TestRabbitmqSenderCloseIsFinal(t *testing.T) {
	tests := []struct {
		name string
		cfg  func(*rabbitmqConfig)
		// outcome of the first publish of e0
		first fakeOutcome
		// initialLost makes the sender dial a session before e0 is sent
		initialLost bool
		dialFails   int
		blockDial   bool
		// ready reports when the publisher reached the point Close must
		// interrupt
		ready func(b *fakeBroker) bool
	}{
		{
			name:  "while sleeping before a retry",
			cfg:   func(c *rabbitmqConfig) { c.backoffMin, c.backoffMax = time.Hour, time.Hour },
			first: fakeOutcome{nack: true},
			ready: func(b *fakeBroker) bool { return b.waited("e0") },
		},
		{
			name:        "while sleeping before a dial",
			cfg:         func(c *rabbitmqConfig) { c.backoffMin, c.backoffMax = time.Hour, time.Hour },
			initialLost: true,
			dialFails:   1,
			ready:       func(b *fakeBroker) bool { return b.dialed() > 0 },
		},
		{
			name:        "while dialing",
			cfg:         func(c *rabbitmqConfig) {},
			initialLost: true,
			blockDial:   true,
			ready:       func(b *fakeBroker) bool { return b.dialed() > 0 },
		},
		{
			name:  "while waiting for a confirm",
			cfg:   func(c *rabbitmqConfig) {},
			first: fakeOutcome{release: make(chan struct{})},
			ready: func(b *fakeBroker) bool { return b.waited("e0") },
		},
		{
			name:  "while the broker blocks publishing",
			cfg:   func(c *rabbitmqConfig) {},
			first: fakeOutcome{blockPublish: true},
			ready: func(b *fakeBroker) bool { return b.published("e0") },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := newFakeBroker()
			b.dialFails = tc.dialFails
			b.blockDial = tc.blockDial
			b.outcome = func(key string, n int) fakeOutcome {
				if n == 0 {
					return tc.first
				}
				return fakeOutcome{}
			}
			cfg := testRabbitmqConfig
			tc.cfg(&cfg)
			rs := newTestSender(t, b, tc.initialLost, cfg)

			rs.enqueue(testEvent("e0"))
			require.Eventually(t, func() bool { return tc.ready(b) }, waitFor, tick)

			closeReturns(t, rs)
			dials := b.dialed()
			// events sent after Close are dropped
			rs.enqueue(testEvent("e1"))
			require.NoError(t, rs.Close())

			b.mu.Lock()
			defer b.mu.Unlock()
			require.Equal(t, dials, b.dials, "dialed after Close")
			for i, s := range b.sessions {
				require.Equal(t, 1, s.closeCalls, "session %v", i)
			}
			require.LessOrEqual(t, b.attempts["e0"], 1)
			require.Zero(t, b.attempts["e1"])
			require.Empty(t, b.acked)
		})
	}
}

func TestSendRabbitmqTestEvent(t *testing.T) {
	noExchange := &amqp.Error{Code: amqp.NotFound, Reason: "NOT_FOUND - no exchange 'events' in vhost '/'", Server: true}
	closedNoExchange := fmt.Errorf("%w: %w", errRabbitmqClosed, noExchange)

	tests := []struct {
		name    string
		outcome fakeOutcome
		wantErr error
	}{
		{name: "confirmed"},
		{name: "nacked, the queue is full", outcome: fakeOutcome{nack: true}},
		{name: "not confirmed in time", outcome: fakeOutcome{release: make(chan struct{})}},
		{name: "broker blocks publishing", outcome: fakeOutcome{blockPublish: true}},
		{name: "channel closed by the broker", outcome: fakeOutcome{confirmErr: closedNoExchange}, wantErr: noExchange},
		{name: "publish error", outcome: fakeOutcome{publishErr: closedNoExchange}, wantErr: noExchange},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := newFakeBroker()
			b.outcome = func(string, int) fakeOutcome { return tc.outcome }

			body, err := generateTestEvent()
			require.NoError(t, err)
			err = sendRabbitmqTestEvent(b.initialSession(false), "events", "", amqp.Publishing{Body: body}, 50*time.Millisecond)
			if tc.wantErr == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tc.wantErr)
			var amqpErr *amqp.Error
			require.ErrorAs(t, err, &amqpErr)
			require.Equal(t, amqp.NotFound, amqpErr.Code)
		})
	}
}

func TestDialRabbitmqGivesUpWhenCanceled(t *testing.T) {
	// a server that never answers the AMQP handshake
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialed := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// the client is in the AMQP handshake once it sent the protocol
		// header
		header := make([]byte, 8)
		if _, err := io.ReadFull(c, header); err != nil {
			return
		}
		cancel()
		<-dialed
	}()

	done := make(chan error, 1)
	go func() {
		_, err := dialRabbitmq(ctx, "amqp://guest:guest@"+ln.Addr().String()+"/")
		done <- err
		dialed <- err
	}()
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(waitFor):
		t.Fatal("dial did not give up when its context was canceled")
	}
}
