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
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
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

// The tests in this file run rabbitmqSession and the sender with the
// amqp091-go client against amqpServer, an in-process fake broker that can
// cut connections, refuse them and block publishing.

func TestRabbitmqSession(t *testing.T) {
	t.Run("confirmed", func(t *testing.T) {
		srv := newAMQPServer(t)
		s := dialTestSession(t, srv.url)
		ack, err := publishAndWait(s, "events")
		require.NoError(t, err)
		require.True(t, ack)
	})

	t.Run("nacked by the broker", func(t *testing.T) {
		srv := newAMQPServer(t)
		s := dialTestSession(t, srv.url)

		srv.setNack(true)
		ack, err := publishAndWait(s, "events")
		require.NoError(t, err, "a broker nack is not a closed channel")
		require.False(t, ack)
		require.False(t, s.IsClosed())

		srv.setNack(false)
		ack, err = publishAndWait(s, "events")
		require.NoError(t, err)
		require.True(t, ack)
	})

	t.Run("connection lost before the confirm", func(t *testing.T) {
		srv := newAMQPServer(t)
		s := dialTestSession(t, srv.url)
		srv.setCut(func(n int, class, method uint16) bool {
			return class == amqpClassBasic && method == amqpMethodBasicPublish
		})

		ack, err := publishAndWait(s, "events")
		require.False(t, ack)
		require.ErrorIs(t, err, errRabbitmqClosed)
		var amqpErr *amqp.Error
		require.ErrorAs(t, err, &amqpErr, "the error carries the reason")
		require.True(t, s.IsClosed())
		require.NoError(t, s.Close())
	})

	t.Run("channel closed by the broker", func(t *testing.T) {
		srv := newAMQPServer(t)
		s := dialTestSession(t, srv.url)

		ack, err := publishAndWait(s, "missing")
		require.False(t, ack)
		require.ErrorIs(t, err, errRabbitmqClosed)
		var amqpErr *amqp.Error
		require.ErrorAs(t, err, &amqpErr)
		require.Equal(t, amqp.NotFound, amqpErr.Code)
		require.True(t, s.IsClosed())

		// the connection is still open and is closed with the session
		require.False(t, s.conn.IsClosed())
		require.NoError(t, s.Close())
		require.True(t, s.conn.IsClosed())
	})

	t.Run("broker blocks publishing", func(t *testing.T) {
		srv := newAMQPServer(t)
		s := dialTestSession(t, srv.url)

		srv.inject(amqpMethodFrame(0, amqpClassConnection, amqpMethodConnectionBlocked, appendShortstr(nil, "low on memory")))
		require.Eventually(t, func() bool { return s.blocked() }, waitFor, tick)

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		_, err := s.Publish(ctx, "events", "events", amqp.Publishing{Body: []byte("{}")})
		require.ErrorIs(t, err, context.DeadlineExceeded)
		_, published := srv.counts()
		require.Zero(t, published, "published while the broker blocks publishing")

		srv.inject(amqpMethodFrame(0, amqpClassConnection, amqpMethodConnectionUnblocked, nil))
		require.Eventually(t, func() bool { return !s.blocked() }, waitFor, tick)
		ack, err := publishAndWait(s, "events")
		require.NoError(t, err)
		require.True(t, ack)
	})

	t.Run("connection lost while the broker blocks publishing", func(t *testing.T) {
		srv := newAMQPServer(t)
		s := dialTestSession(t, srv.url)

		srv.inject(amqpMethodFrame(0, amqpClassConnection, amqpMethodConnectionBlocked, appendShortstr(nil, "low on memory")))
		require.Eventually(t, func() bool { return s.blocked() }, waitFor, tick)
		srv.cutAll()

		ctx, cancel := context.WithTimeout(context.Background(), waitFor)
		defer cancel()
		_, err := s.Publish(ctx, "events", "events", amqp.Publishing{Body: []byte("{}")})
		require.ErrorIs(t, err, errRabbitmqClosed)
	})
}

func TestRabbitmqSenderRecoversConnection(t *testing.T) {
	t.Run("connection lost", func(t *testing.T) {
		srv := newAMQPServer(t)
		rs := newSessionTestSender(t, srv.url)

		rs.enqueue(testEvent("e0"))
		srv.waitForEvents(t, "e0")

		// the broker is unreachable while e1..e5 are sent
		srv.setRefuse(true)
		srv.cutAll()
		var keys []string
		for i := 1; i <= 5; i++ {
			keys = append(keys, fmt.Sprintf("e%v", i))
			rs.enqueue(testEvent(keys[i-1]))
		}
		require.Eventually(t, func() bool {
			accepted, _ := srv.counts()
			return accepted >= 3
		}, waitFor, tick, "the sender does not dial again")
		srv.setRefuse(false)

		srv.waitForEvents(t, keys...)
	})

	t.Run("connection lost while the channel is opened", func(t *testing.T) {
		srv := newAMQPServer(t)
		rs := newSessionTestSender(t, srv.url)

		rs.enqueue(testEvent("e0"))
		srv.waitForEvents(t, "e0")

		// the second connection breaks during channel.open
		srv.setCut(func(n int, class, method uint16) bool {
			return n == 2 && class == amqpClassChannel && method == amqpMethodChannelOpen
		})
		srv.cutAll()
		rs.enqueue(testEvent("e1"))

		srv.waitForEvents(t, "e1")
		accepted, _ := srv.counts()
		require.GreaterOrEqual(t, accepted, 3)
	})

	t.Run("channel closed by the broker", func(t *testing.T) {
		srv := newAMQPServer(t)
		rs := newSessionTestSender(t, srv.url)

		rs.enqueue(testEvent("e0"))
		srv.waitForEvents(t, "e0")

		// publishing to a missing exchange closes the channel, not the
		// connection
		srv.setExchange("events", false)
		rs.enqueue(testEvent("e1"))
		require.Eventually(t, func() bool {
			accepted, published := srv.counts()
			return accepted >= 2 && published >= 3
		}, waitFor, tick, "e1 is not published again on a new connection")
		srv.setExchange("events", true)

		srv.waitForEvents(t, "e1")
	})
}

func TestInitRabbitmqEventServiceMissingExchange(t *testing.T) {
	srv := newAMQPServer(t)

	_, err := InitRabbitmqEventService(srv.url, "missing", "events", nil)
	require.ErrorIs(t, err, errRabbitmqClosed)
	var amqpErr *amqp.Error
	require.ErrorAs(t, err, &amqpErr)
	require.Equal(t, amqp.NotFound, amqpErr.Code)
}

func dialTestSession(t *testing.T, url string) *rabbitmqSession {
	t.Helper()
	s, err := dialRabbitmq(context.Background(), url)
	require.NoError(t, err)
	t.Cleanup(func() { s.Close() })
	return s
}

func publishAndWait(s *rabbitmqSession, exchange string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	c, err := s.Publish(ctx, exchange, "events", amqp.Publishing{Body: []byte("{}")})
	if err != nil {
		return false, err
	}
	return c.WaitContext(ctx)
}

func (s *rabbitmqSession) blocked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unblocked != nil
}

func newSessionTestSender(t *testing.T, url string) *RabbitmqEventSender {
	t.Helper()
	dial := func(ctx context.Context) (amqpSession, error) {
		s, err := dialRabbitmq(ctx, url)
		if err != nil {
			return nil, err
		}
		return s, nil
	}
	s, err := dial(context.Background())
	require.NoError(t, err)

	cfg := testRabbitmqConfig
	cfg.backoffMin = 10 * time.Millisecond
	cfg.backoffMax = 50 * time.Millisecond
	rs := newRabbitmqEventSender(s, dial, "events", "events", nil, cfg)
	t.Cleanup(func() { rs.Close() })
	return rs
}

// AMQP 0-9-1 classes and methods
const (
	amqpClassConnection = 10
	amqpClassChannel    = 20
	amqpClassBasic      = 60
	amqpClassConfirm    = 85

	amqpMethodConnectionStart     = 10
	amqpMethodConnectionStartOk   = 11
	amqpMethodConnectionTune      = 30
	amqpMethodConnectionTuneOk    = 31
	amqpMethodConnectionOpen      = 40
	amqpMethodConnectionOpenOk    = 41
	amqpMethodConnectionClose     = 50
	amqpMethodConnectionCloseOk   = 51
	amqpMethodConnectionBlocked   = 60
	amqpMethodConnectionUnblocked = 61

	amqpMethodChannelOpen    = 10
	amqpMethodChannelOpenOk  = 11
	amqpMethodChannelClose   = 40
	amqpMethodChannelCloseOk = 41

	amqpMethodConfirmSelect   = 10
	amqpMethodConfirmSelectOk = 11

	amqpMethodBasicPublish = 40
	amqpMethodBasicAck     = 80
	amqpMethodBasicNack    = 120
)

// AMQP 0-9-1 framing
const (
	amqpProtocolHeaderSize = 8 // "AMQP" 0 0 9 1
	amqpFrameHeaderSize    = 7 // type, channel and payload size
	amqpFrameMethod        = 1
	amqpFrameHeader        = 2
	amqpFrameBody          = 3
	amqpFrameHeartbeat     = 8
	amqpFrameEnd           = 0xCE
)

// amqpServer speaks just enough AMQP 0-9-1 for one publisher in confirm
// mode: the connection and channel handshakes, confirm.select, basic.publish
// confirmed with basic.ack or basic.nack, channel.close for a publish to a
// missing exchange, and connection.close.
type amqpServer struct {
	t   *testing.T
	ln  net.Listener
	url string

	mu        sync.Mutex
	conns     []*amqpServerConn
	accepted  int             // connections accepted, refused ones included
	refuse    bool            // close new connections at once
	exchanges map[string]bool // the exchanges that exist
	nack      bool            // nack the publishes
	published int             // basic.publish methods received
	delivered [][]byte        // the bodies of the acked publishes
	// cut reports whether to close the n-th (1 based) connection when the
	// client sends the method, instead of answering it
	cut func(n int, class, method uint16) bool
}

type amqpServerConn struct {
	c   net.Conn
	wmu sync.Mutex
}

func (sc *amqpServerConn) send(f []byte) {
	sc.wmu.Lock()
	defer sc.wmu.Unlock()
	sc.c.Write(f)
}

// amqpPublish is a basic.publish whose content is being read.
type amqpPublish struct {
	exchange string
	size     uint64
	body     []byte
}

func newAMQPServer(t *testing.T) *amqpServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := &amqpServer{
		t:         t,
		ln:        ln,
		url:       "amqp://guest:guest@" + ln.Addr().String() + "/",
		exchanges: map[string]bool{"": true, "events": true},
	}
	go srv.serve()
	t.Cleanup(func() {
		ln.Close()
		srv.cutAll()
	})
	return srv
}

func (srv *amqpServer) serve() {
	for {
		c, err := srv.ln.Accept()
		if err != nil {
			return
		}
		srv.mu.Lock()
		srv.accepted++
		n, refuse := srv.accepted, srv.refuse
		sc := &amqpServerConn{c: c}
		if !refuse {
			srv.conns = append(srv.conns, sc)
		}
		srv.mu.Unlock()
		if refuse {
			c.Close()
			continue
		}
		go srv.serveConn(sc, n)
	}
}

// serveConn serves the n-th connection. The client uses one channel.
func (srv *amqpServer) serveConn(sc *amqpServerConn, n int) {
	defer sc.c.Close()
	r := bufio.NewReader(sc.c)
	if _, err := io.ReadFull(r, make([]byte, amqpProtocolHeaderSize)); err != nil {
		return
	}
	start := []byte{0, 9}                           // version 0-9
	start = binary.BigEndian.AppendUint32(start, 0) // no server properties
	start = appendLongstr(start, "PLAIN")
	start = appendLongstr(start, "en_US")
	sc.send(amqpMethodFrame(0, amqpClassConnection, amqpMethodConnectionStart, start))

	var (
		tag     uint64 // delivery tag of the last publish in confirm mode
		confirm bool
		closing bool // the channel was closed and waits for channel.close-ok
		pub     *amqpPublish
	)
	finishPublish := func(channel uint16) {
		p := pub
		pub = nil
		if closing {
			return
		}
		srv.mu.Lock()
		exists, nack := srv.exchanges[p.exchange], srv.nack
		if exists && !nack {
			srv.delivered = append(srv.delivered, p.body)
		}
		srv.mu.Unlock()

		if !exists {
			closing = true
			args := binary.BigEndian.AppendUint16(nil, uint16(amqp.NotFound))
			args = appendShortstr(args, fmt.Sprintf("NOT_FOUND - no exchange '%v' in vhost '/'", p.exchange))
			args = binary.BigEndian.AppendUint16(args, amqpClassBasic)
			args = binary.BigEndian.AppendUint16(args, amqpMethodBasicPublish)
			sc.send(amqpMethodFrame(channel, amqpClassChannel, amqpMethodChannelClose, args))
			return
		}
		if !confirm {
			return
		}
		tag++
		args := binary.BigEndian.AppendUint64(nil, tag)
		args = append(args, 0) // not multiple, not requeued
		method := uint16(amqpMethodBasicAck)
		if nack {
			method = amqpMethodBasicNack
		}
		sc.send(amqpMethodFrame(channel, amqpClassBasic, method, args))
	}

	for {
		f, err := readAMQPFrame(r)
		if err != nil {
			return
		}
		channel := binary.BigEndian.Uint16(f[1:])
		payload := f[amqpFrameHeaderSize : len(f)-1]

		switch f[0] {
		case amqpFrameHeartbeat:
		case amqpFrameHeader:
			if pub != nil {
				// class, weight, then the body size
				pub.size = binary.BigEndian.Uint64(payload[4:])
				if pub.size == 0 {
					finishPublish(channel)
				}
			}
		case amqpFrameBody:
			if pub != nil {
				pub.body = append(pub.body, payload...)
				if uint64(len(pub.body)) >= pub.size {
					finishPublish(channel)
				}
			}
		case amqpFrameMethod:
			class, method := binary.BigEndian.Uint16(payload), binary.BigEndian.Uint16(payload[2:])
			args := payload[4:]
			srv.mu.Lock()
			cut := srv.cut != nil && srv.cut(n, class, method)
			srv.mu.Unlock()
			if cut {
				return
			}

			switch [2]uint16{class, method} {
			case [2]uint16{amqpClassConnection, amqpMethodConnectionStartOk}:
				tune := binary.BigEndian.AppendUint16(nil, 0)     // no channel limit
				tune = binary.BigEndian.AppendUint32(tune, 1<<17) // frame size
				tune = binary.BigEndian.AppendUint16(tune, 0)     // no heartbeat
				sc.send(amqpMethodFrame(0, amqpClassConnection, amqpMethodConnectionTune, tune))
			case [2]uint16{amqpClassConnection, amqpMethodConnectionTuneOk}:
			case [2]uint16{amqpClassConnection, amqpMethodConnectionOpen}:
				sc.send(amqpMethodFrame(0, amqpClassConnection, amqpMethodConnectionOpenOk, appendShortstr(nil, "")))
			case [2]uint16{amqpClassConnection, amqpMethodConnectionClose}:
				sc.send(amqpMethodFrame(0, amqpClassConnection, amqpMethodConnectionCloseOk, nil))
				return
			case [2]uint16{amqpClassChannel, amqpMethodChannelOpen}:
				tag, confirm, closing = 0, false, false
				sc.send(amqpMethodFrame(channel, amqpClassChannel, amqpMethodChannelOpenOk, appendLongstr(nil, "")))
			case [2]uint16{amqpClassChannel, amqpMethodChannelClose}:
				sc.send(amqpMethodFrame(channel, amqpClassChannel, amqpMethodChannelCloseOk, nil))
			case [2]uint16{amqpClassChannel, amqpMethodChannelCloseOk}:
				closing = false
			case [2]uint16{amqpClassConfirm, amqpMethodConfirmSelect}:
				confirm = true
				sc.send(amqpMethodFrame(channel, amqpClassConfirm, amqpMethodConfirmSelectOk, nil))
			case [2]uint16{amqpClassBasic, amqpMethodBasicPublish}:
				srv.mu.Lock()
				srv.published++
				srv.mu.Unlock()
				// reserved short, then the exchange
				exchange := string(args[3 : 3+int(args[2])])
				pub = &amqpPublish{exchange: exchange}
			default:
				srv.t.Errorf("amqpServer: unexpected method %v.%v", class, method)
				return
			}
		}
	}
}

// cutAll closes every connection.
func (srv *amqpServer) cutAll() {
	srv.mu.Lock()
	conns := srv.conns
	srv.conns = nil
	srv.mu.Unlock()
	for _, sc := range conns {
		sc.c.Close()
	}
}

func (srv *amqpServer) setRefuse(refuse bool) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.refuse = refuse
}

func (srv *amqpServer) setNack(nack bool) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.nack = nack
}

func (srv *amqpServer) setExchange(name string, exists bool) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.exchanges[name] = exists
}

func (srv *amqpServer) setCut(cut func(n int, class, method uint16) bool) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.cut = cut
}

func (srv *amqpServer) counts() (accepted, published int) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return srv.accepted, srv.published
}

// inject sends a frame to every client.
func (srv *amqpServer) inject(f []byte) {
	srv.mu.Lock()
	conns := srv.conns
	srv.mu.Unlock()
	for _, sc := range conns {
		sc.send(f)
	}
}

// waitForEvents waits until the events with keys are delivered. Duplicates
// are allowed.
func (srv *amqpServer) waitForEvents(t *testing.T, keys ...string) {
	t.Helper()
	var missing []string
	ok := func() bool {
		srv.mu.Lock()
		defer srv.mu.Unlock()
		missing = missing[:0]
		for _, key := range keys {
			if !slices.ContainsFunc(srv.delivered, func(body []byte) bool {
				var ev EventSchema
				return json.Unmarshal(body, &ev) == nil && len(ev.Records) > 0 && ev.Records[0].S3.Object.Key == key
			}) {
				missing = append(missing, key)
			}
		}
		return len(missing) == 0
	}
	require.Eventually(t, ok, waitFor, tick, "events not delivered: %v", missing)
}

// readAMQPFrame reads a frame: type, channel, payload size, payload and
// frame end.
func readAMQPFrame(r *bufio.Reader) ([]byte, error) {
	header := make([]byte, amqpFrameHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[3:])
	f := make([]byte, amqpFrameHeaderSize+int(size)+1)
	copy(f, header)
	if _, err := io.ReadFull(r, f[amqpFrameHeaderSize:]); err != nil {
		return nil, err
	}
	return f, nil
}

func amqpMethodFrame(channel, class, method uint16, args []byte) []byte {
	payload := binary.BigEndian.AppendUint16(nil, class)
	payload = binary.BigEndian.AppendUint16(payload, method)
	payload = append(payload, args...)
	f := []byte{amqpFrameMethod}
	f = binary.BigEndian.AppendUint16(f, channel)
	f = binary.BigEndian.AppendUint32(f, uint32(len(payload)))
	f = append(f, payload...)
	return append(f, amqpFrameEnd)
}

func appendShortstr(b []byte, s string) []byte {
	return append(append(b, byte(len(s))), s...)
}

func appendLongstr(b []byte, s string) []byte {
	return append(binary.BigEndian.AppendUint32(b, uint32(len(s))), s...)
}
