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
	"io"
	"net"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/stretchr/testify/require"
)

// TestRabbitmqSenderBrokerOutage checks that events published after the
// broker connection was lost are delivered once the broker is reachable
// again. The sender talks to the broker through a local TCP proxy, which
// the test uses to drop connections or make the broker unreachable.
//
// Requires a running broker, e.g.:
//
//	docker run -d -p 5672:5672 rabbitmq:4
//	VGW_TEST_RABBITMQ_URL=amqp://guest:guest@127.0.0.1:5672/ go test ./s3event -run Rabbitmq
func TestRabbitmqSenderBrokerOutage(t *testing.T) {
	brokerURL := os.Getenv("VGW_TEST_RABBITMQ_URL")
	if brokerURL == "" {
		t.Skip("VGW_TEST_RABBITMQ_URL not set")
	}

	tests := []struct {
		name     string
		retryFor time.Duration
		// outage breaks the path to the broker before the event is sent
		outage func(p *tcpProxy)
		// recoverAfter restores the proxy while the event is retried, 0 = never
		recoverAfter  time.Duration
		wantDelivered bool
	}{
		{
			name:          "connection closed by broker",
			retryFor:      10 * time.Second,
			outage:        (*tcpProxy).dropConnections,
			wantDelivered: true,
		},
		{
			name:          "broker unreachable shorter than retry window",
			retryFor:      10 * time.Second,
			outage:        (*tcpProxy).stop,
			recoverAfter:  2 * time.Second,
			wantDelivered: true,
		},
		{
			name:          "broker unreachable longer than retry window",
			retryFor:      2 * time.Second,
			outage:        (*tcpProxy).stop,
			wantDelivered: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// The test reads the queue over its own connection, bypassing the proxy.
			conn, err := amqp.Dial(brokerURL)
			require.NoError(t, err)
			t.Cleanup(func() { conn.Close() })
			ch, err := conn.Channel()
			require.NoError(t, err)
			q, err := ch.QueueDeclare("", false, true, true, false, nil)
			require.NoError(t, err)

			proxy := newTCPProxy(t, brokerURL)
			sender, err := InitRabbitmqEventService(proxy.url, "", q.Name, nil)
			require.NoError(t, err)
			t.Cleanup(func() { sender.Close() })
			rs := sender.(*RabbitmqEventSender)
			rs.retryFor = tc.retryFor

			_, ok, err := ch.Get(q.Name, true)
			require.NoError(t, err)
			require.True(t, ok, "test event from init not delivered")

			tc.outage(proxy)
			if tc.recoverAfter > 0 {
				timer := time.AfterFunc(tc.recoverAfter, proxy.start)
				t.Cleanup(func() { timer.Stop() })
			}

			rs.send(EventSchema{})

			_, delivered, err := ch.Get(q.Name, true)
			require.NoError(t, err)
			require.Equal(t, tc.wantDelivered, delivered)
		})
	}
}

// tcpProxy forwards TCP connections to the broker from rabbitmqURL.
type tcpProxy struct {
	t      *testing.T
	target string
	addr   string
	url    string // rabbitmqURL pointing to the proxy

	mu    sync.Mutex
	ln    net.Listener
	conns []net.Conn
}

func newTCPProxy(t *testing.T, rabbitmqURL string) *tcpProxy {
	u, err := url.Parse(rabbitmqURL)
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	p := &tcpProxy{t: t, target: u.Host, addr: ln.Addr().String(), ln: ln}
	u.Host = p.addr
	p.url = u.String()
	go p.serve(ln)
	t.Cleanup(p.stop)
	return p
}

// start listens again on the same address after stop.
func (p *tcpProxy) start() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ln != nil {
		return
	}
	ln, err := net.Listen("tcp", p.addr)
	if err != nil {
		p.t.Errorf("proxy listen: %v", err)
		return
	}
	p.ln = ln
	go p.serve(ln)
}

// stop closes the listener and all connections: the broker is unreachable.
func (p *tcpProxy) stop() {
	p.mu.Lock()
	if p.ln != nil {
		p.ln.Close()
		p.ln = nil
	}
	p.mu.Unlock()
	p.dropConnections()
}

// dropConnections closes established connections, the listener stays open.
func (p *tcpProxy) dropConnections() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		c.Close()
	}
	p.conns = nil
}

func (p *tcpProxy) serve(ln net.Listener) {
	for {
		client, err := ln.Accept()
		if err != nil {
			return
		}
		broker, err := net.Dial("tcp", p.target)
		if err != nil {
			client.Close()
			continue
		}
		p.mu.Lock()
		p.conns = append(p.conns, client, broker)
		p.mu.Unlock()
		go pipe(client, broker)
		go pipe(broker, client)
	}
}

func pipe(dst, src net.Conn) {
	io.Copy(dst, src)
	dst.Close()
	src.Close()
}
