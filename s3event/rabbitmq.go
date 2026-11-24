// Copyright 2023 Versity Software
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
	"encoding/xml"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/versity/versitygw/s3response"
)

// RabbitmqEventSender sends S3 events to a RabbitMQ exchange/queue.
// It mirrors the behavior of the Kafka and NATS implementations: send a
// test event on initialization to validate configuration, filter events,
// and handle multi-delete payloads.
//
// Events are put in a bounded queue and published by a single goroutine in
// confirm mode. When the broker or the network closes the connection or the
// channel, the publisher dials a new connection for the next events. An
// event the broker does not confirm, because it nacked it or the connection
// was lost before the confirm arrived, is published again with backoff until
// it is confirmed or retryFor has passed since it was queued. amqp091-go
// nacks the pending confirms of a channel as soon as the channel is closed,
// so the retries and their backoff start right away. Delivery is
// at-least-once: an event is duplicated when the connection breaks after the
// broker accepted it but before the confirm arrived.
//
// amqp091-go's own connection recovery is not used: it gets stuck for good
// when the new connection breaks while its channel is reopened.
//
// Events are published as transient messages without the mandatory flag.
// A confirm only means that the broker accepted the event: events still in
// a queue are lost when the broker restarts, and the broker drops events
// that match no queue.
type RabbitmqEventSender struct {
	exchange   string
	routingKey string
	mu         sync.Mutex
	filter     EventFilter

	dial    func(ctx context.Context) (amqpSession, error)
	cfg     rabbitmqConfig
	queue   chan queuedEvent
	closing chan struct{} // closed when Close is called
	// ctx is canceled by Close once the queue is flushed or the flush
	// timed out
	ctx     context.Context
	cancel  context.CancelFunc
	stopped chan struct{} // closed when the publisher goroutine returns

	sessionMu sync.Mutex
	// session is set by the publisher goroutine. It is nil while no
	// connection is dialed.
	session amqpSession

	closeOnce sync.Once
	closeErr  error

	// events dropped since the last report
	queueFull atomic.Uint64 // because the queue was full
	expired   atomic.Uint64 // because they were not delivered within retryFor

	// owned by the publisher goroutine
	failing bool // the last publish attempt failed
}

// amqpSession is one connection with one channel in confirm mode. It is
// not recovered: once it is closed, the sender dials a new one.
type amqpSession interface {
	Publish(ctx context.Context, exchange, key string, msg amqp.Publishing) (amqpConfirmation, error)
	IsClosed() bool
	Close() error
}

// Satisfied by *amqp.DeferredConfirmation.
type amqpConfirmation interface {
	WaitContext(ctx context.Context) (bool, error)
}

type rabbitmqConfig struct {
	// queueSize is how many events wait to be published. When the queue is
	// full, new events are dropped.
	queueSize int
	// batchSize is how many events are published before the publisher
	// waits for their confirms.
	batchSize int
	// retryFor is how long after it was queued an event is still retried.
	// Every event is tried at least once, and a publish that waits for its
	// confirm is not interrupted.
	retryFor   time.Duration
	backoffMin time.Duration
	backoffMax time.Duration
	// flushTimeout bounds how long Close waits for the queued events to be
	// delivered.
	flushTimeout time.Duration
	// reportInterval is how often the number of dropped events is logged.
	reportInterval time.Duration
}

var defaultRabbitmqConfig = rabbitmqConfig{
	queueSize:      10000,
	batchSize:      256,
	retryFor:       2 * time.Minute,
	backoffMin:     500 * time.Millisecond,
	backoffMax:     10 * time.Second,
	flushTimeout:   5 * time.Second,
	reportInterval: time.Minute,
}

const (
	// rabbitmqTestEventTimeout bounds how long the startup waits for the
	// broker to accept and confirm the test event. It does not bound the
	// socket write of the event.
	rabbitmqTestEventTimeout = 10 * time.Second
	// rabbitmqDialTimeout bounds the TCP dial and the TLS and AMQP
	// handshakes, unless the URL sets connection_timeout. It is the default
	// of amqp091-go.
	rabbitmqDialTimeout = 30 * time.Second
	// rabbitmqCloseTimeout bounds the connection close handshake with the
	// broker.
	rabbitmqCloseTimeout = 5 * time.Second
)

var (
	errRabbitmqClosed = errors.New("rabbitmq channel is closed")
	errRabbitmqNacked = errors.New("rabbitmq broker nacked the event")
)

type queuedEvent struct {
	event  EventSchema
	queued time.Time
}

type pendingEvent struct {
	msg    amqp.Publishing
	queued time.Time
}

// InitRabbitmqEventService creates a RabbitMQ sender. If exchange is blank the
// default (empty string) exchange is used. If routingKey is blank we publish
// with an empty routing key; for delete object multi-events we override the
// routing key with the bucket name (object key not suitable as key routinely has '/')
func InitRabbitmqEventService(url, exchange, routingKey string, filter EventFilter) (S3EventSender, error) {
	if url == "" {
		return nil, fmt.Errorf("rabbitmq url should be specified")
	}

	session, err := dialRabbitmq(context.Background(), url)
	if err != nil {
		return nil, err
	}

	// Send a test event to validate publishing works. Use a transient message.
	testMsg, err := generateTestEvent()
	if err != nil {
		session.Close()
		return nil, fmt.Errorf("rabbitmq generate test event: %w", err)
	}

	pub := amqp.Publishing{Timestamp: time.Now(), ContentType: fiber.MIMEApplicationJSON, Body: testMsg, MessageId: uuid.NewString()}
	if err := sendRabbitmqTestEvent(session, exchange, routingKey, pub, rabbitmqTestEventTimeout); err != nil {
		session.Close()
		return nil, fmt.Errorf("rabbitmq publish test event: %w", err)
	}

	dial := func(ctx context.Context) (amqpSession, error) {
		s, err := dialRabbitmq(ctx, url)
		if err != nil {
			return nil, err
		}
		return s, nil
	}
	return newRabbitmqEventSender(session, dial, exchange, routingKey, filter, defaultRabbitmqConfig), nil
}

// sendRabbitmqTestEvent publishes the startup test event and waits for its
// confirm. A broker that nacks the event or does not confirm it in time only
// gets a warning: a full queue or a resource alarm is temporary and must not
// stop the gateway from starting. Other errors, such as a missing exchange,
// are returned.
func sendRabbitmqTestEvent(s amqpSession, exchange, routingKey string, msg amqp.Publishing, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	c, err := s.Publish(ctx, exchange, routingKey, msg)
	if err == nil {
		var ack bool
		ack, err = c.WaitContext(ctx)
		if err == nil && !ack {
			fmt.Fprintf(os.Stderr, "WARNING: rabbitmq broker nacked the test event (is the queue full?), continuing\n")
			return nil
		}
		if err != nil {
			err = fmt.Errorf("waiting for broker confirm: %w", err)
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		fmt.Fprintf(os.Stderr, "WARNING: rabbitmq broker did not confirm the test event within %v (is it blocking publishers?), continuing\n", timeout)
		return nil
	}
	return err
}

// newRabbitmqEventSender starts the publisher goroutine. It publishes on
// session, and on a session from dial once session is closed.
func newRabbitmqEventSender(session amqpSession, dial func(context.Context) (amqpSession, error), exchange, routingKey string, filter EventFilter, cfg rabbitmqConfig) *RabbitmqEventSender {
	ctx, cancel := context.WithCancel(context.Background())
	rs := &RabbitmqEventSender{
		exchange:   exchange,
		routingKey: routingKey,
		filter:     filter,
		dial:       dial,
		session:    session,
		cfg:        cfg,
		queue:      make(chan queuedEvent, cfg.queueSize),
		closing:    make(chan struct{}),
		ctx:        ctx,
		cancel:     cancel,
		stopped:    make(chan struct{}),
	}
	go rs.run()
	go rs.reportDropsEvery()
	return rs
}

func (rs *RabbitmqEventSender) SendEvent(ctx fiber.Ctx, meta EventMeta) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if rs.filter != nil && !rs.filter.Filter(meta.EventName) {
		return
	}

	if meta.EventName == EventObjectRemovedDeleteObjects {
		var dObj s3response.DeleteObjects
		if err := xml.Unmarshal(ctx.BodyRaw(), &dObj); err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse delete objects input payload: %v\n", err.Error())
			return
		}
		for _, obj := range dObj.Objects {
			key := *obj.Key
			schema := createEventSchema(ctx, meta, ConfigurationIdRabbitMQ)
			schema.Records[0].S3.Object.Key = key
			schema.Records[0].S3.Object.VersionId = obj.VersionId
			rs.enqueue(schema)
		}
		return
	}

	schema := createEventSchema(ctx, meta, ConfigurationIdRabbitMQ)
	rs.enqueue(schema)
}

// Close stops taking events and waits up to flushTimeout for the queued
// events to be delivered. Then it stops the publisher, which ends a dial, a
// backoff, or a wait for a confirm or for the broker to unblock publishing,
// and closes the connection. Events that are still queued are dropped.
// Close is final: events sent after it are dropped, and no new connection
// is dialed.
func (rs *RabbitmqEventSender) Close() error {
	rs.closeOnce.Do(func() {
		close(rs.closing)
		flush := time.NewTimer(rs.cfg.flushTimeout)
		select {
		case <-rs.stopped:
		case <-flush.C:
		}
		flush.Stop()

		rs.cancel()
		rs.sessionMu.Lock()
		s := rs.session
		rs.session = nil
		rs.sessionMu.Unlock()
		if s != nil {
			// Close the connection before waiting for the publisher: its
			// deadline also ends a socket write the publisher is stuck in.
			rs.closeErr = s.Close()
		}
		<-rs.stopped
		if n := len(rs.queue); n > 0 {
			fmt.Fprintf(os.Stderr, "rabbitmq event sender closed, dropped %v queued events\n", n)
		}
		rs.reportDrops()
	})
	return rs.closeErr
}

// enqueue hands the event to the publisher goroutine without blocking.
func (rs *RabbitmqEventSender) enqueue(event EventSchema) {
	select {
	case <-rs.closing:
		return
	default:
	}
	select {
	case rs.queue <- queuedEvent{event: event, queued: time.Now()}:
	default:
		if rs.queueFull.Add(1) == 1 {
			fmt.Fprintf(os.Stderr, "rabbitmq event queue is full (%v events), dropping new events\n", cap(rs.queue))
		}
	}
}

// run publishes the queued events in batches until the sender is closed.
func (rs *RabbitmqEventSender) run() {
	defer close(rs.stopped)

	batch := make([]pendingEvent, 0, rs.cfg.batchSize)
	for {
		batch = batch[:0]
		select {
		case <-rs.ctx.Done():
			return
		case ev := <-rs.queue:
			batch = appendPendingEvent(batch, ev)
		case <-rs.closing:
			// Close waits for the queue to be flushed
			select {
			case ev := <-rs.queue:
				batch = appendPendingEvent(batch, ev)
			default:
				return
			}
		}
	fill:
		for len(batch) < rs.cfg.batchSize {
			select {
			case ev := <-rs.queue:
				batch = appendPendingEvent(batch, ev)
			default:
				break fill
			}
		}

		rs.deliver(batch)
	}
}

func appendPendingEvent(batch []pendingEvent, ev queuedEvent) []pendingEvent {
	body, err := json.Marshal(ev.event)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal event data: %v\n", err.Error())
		return batch
	}
	return append(batch, pendingEvent{
		msg: amqp.Publishing{
			Timestamp:   ev.queued,
			ContentType: fiber.MIMEApplicationJSON,
			Body:        body,
			MessageId:   uuid.NewString(),
		},
		queued: ev.queued,
	})
}

// deliver publishes batch and publishes the events that were not confirmed
// again with backoff, until they are confirmed, they expire or the sender is
// closed.
func (rs *RabbitmqEventSender) deliver(batch []pendingEvent) {
	backoff := rs.cfg.backoffMin
	for len(batch) > 0 {
		failed, err := rs.publishBatch(batch)
		if err == nil {
			if rs.failing {
				rs.failing = false
				fmt.Fprintf(os.Stderr, "rabbitmq events are delivered again\n")
			}
			return
		}
		if rs.ctx.Err() != nil {
			return
		}
		if !rs.failing {
			rs.failing = true
			fmt.Fprintf(os.Stderr, "failed to send rabbitmq events, retrying: %v\n", err)
		}

		batch = rs.dropExpired(failed, err)
		if len(batch) == 0 || !rs.sleep(backoff) {
			return
		}
		backoff = min(2*backoff, rs.cfg.backoffMax)
	}
}

// publishBatch publishes the events of batch, then waits for their confirms.
// It returns the events that were not confirmed and the first error.
func (rs *RabbitmqEventSender) publishBatch(batch []pendingEvent) ([]pendingEvent, error) {
	s, err := rs.connect()
	if err != nil {
		return batch, err
	}

	var firstErr error
	confirms := make([]amqpConfirmation, 0, len(batch))
	for _, ev := range batch {
		if rs.ctx.Err() != nil {
			firstErr = rs.ctx.Err()
			break
		}
		c, err := s.Publish(rs.ctx, rs.exchange, rs.routingKey, ev.msg)
		if err != nil {
			firstErr = err
			break
		}
		confirms = append(confirms, c)
	}

	var failed []pendingEvent
	for i, c := range confirms {
		ack, err := c.WaitContext(rs.ctx)
		if err != nil {
			err = fmt.Errorf("waiting for broker confirm: %w", err)
		} else if !ack {
			// A nack does not mean the channel is broken, for example a
			// queue with x-overflow=reject-publish nacks while it is full.
			err = errRabbitmqNacked
		}
		if err != nil {
			failed = append(failed, batch[i])
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	failed = append(failed, batch[len(confirms):]...)
	return failed, firstErr
}

// connect returns the session to publish on. When the broker or the network
// closed the session, it closes what is left of it and dials a new one.
func (rs *RabbitmqEventSender) connect() (amqpSession, error) {
	rs.sessionMu.Lock()
	s := rs.session
	if s != nil && !s.IsClosed() {
		rs.sessionMu.Unlock()
		return s, nil
	}
	rs.session = nil
	rs.sessionMu.Unlock()

	if s != nil {
		// The connection is still open when only the channel was closed,
		// for example because the exchange was deleted.
		s.Close()
	}

	s, err := rs.dial(rs.ctx)
	if err != nil {
		return nil, err
	}
	rs.sessionMu.Lock()
	// Close cancels ctx before it takes the session.
	closed := rs.ctx.Err() != nil
	if !closed {
		rs.session = s
	}
	rs.sessionMu.Unlock()
	if closed {
		s.Close()
		return nil, rs.ctx.Err()
	}

	// While publishing fails, the recovery is logged once the events are
	// delivered again.
	if !rs.failing {
		fmt.Fprintf(os.Stderr, "rabbitmq connection re-established\n")
	}
	return s, nil
}

// dropExpired drops the events that were queued more than retryFor ago.
func (rs *RabbitmqEventSender) dropExpired(batch []pendingEvent, err error) []pendingEvent {
	kept := batch[:0]
	for _, ev := range batch {
		if time.Since(ev.queued) < rs.cfg.retryFor {
			kept = append(kept, ev)
			continue
		}
		if rs.expired.Add(1) == 1 {
			fmt.Fprintf(os.Stderr, "dropping rabbitmq events not delivered within %v: %v\n", rs.cfg.retryFor, err)
		}
	}
	return kept
}

// reportDropsEvery reports the dropped events every reportInterval until
// the sender is closed.
func (rs *RabbitmqEventSender) reportDropsEvery() {
	t := time.NewTicker(rs.cfg.reportInterval)
	defer t.Stop()
	for {
		select {
		case <-rs.ctx.Done():
			return
		case <-t.C:
			rs.reportDrops()
		}
	}
}

// reportDrops logs how many events were dropped since the last report.
func (rs *RabbitmqEventSender) reportDrops() {
	full, expired := rs.queueFull.Swap(0), rs.expired.Swap(0)
	if full == 0 && expired == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "rabbitmq dropped %v events: %v not delivered within %v, %v while the queue was full\n",
		full+expired, expired, rs.cfg.retryFor, full)
}

// sleep waits for d with jitter. It returns false if the sender was closed.
func (rs *RabbitmqEventSender) sleep(d time.Duration) bool {
	if d > 1 {
		d = d/2 + rand.N(d/2)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-rs.ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// dialRabbitmq connects to the broker and opens a channel in confirm mode.
// It gives up when ctx is done, also during the handshakes.
func dialRabbitmq(ctx context.Context, url string) (*rabbitmqSession, error) {
	uri, err := amqp.ParseURI(url)
	if err != nil {
		return nil, fmt.Errorf("rabbitmq connect: %w", err)
	}
	timeout := rabbitmqDialTimeout
	if uri.ConnectionTimeout > 0 {
		timeout = time.Duration(uri.ConnectionTimeout) * time.Millisecond
	}

	// Until stop is called, canceling ctx closes the socket, which ends the
	// TLS and AMQP handshakes and the channel setup.
	var stop func() bool
	defer func() {
		if stop != nil {
			stop()
		}
	}()
	conn, err := amqp.DialConfig(url, amqp.Config{
		Dial: func(network, addr string) (net.Conn, error) {
			c, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			// amqp091-go clears the deadline once the AMQP handshake is done
			if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
				c.Close()
				return nil, err
			}
			stop = context.AfterFunc(ctx, func() { c.Close() })
			return c, nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("rabbitmq connect: %w", err)
	}

	s, err := newRabbitmqSession(conn)
	if err != nil {
		conn.CloseDeadline(time.Now().Add(rabbitmqCloseTimeout))
		return nil, err
	}
	return s, nil
}

// rabbitmqSession is the amqpSession of a RabbitMQ connection.
type rabbitmqSession struct {
	conn     *amqp.Connection
	ch       *amqp.Channel
	chCloses chan *amqp.Error // receives the reason the channel was closed
	closing  atomic.Bool

	mu       sync.Mutex
	closeErr *amqp.Error // read from chCloses
	// unblocked is non-nil while the broker blocks publishing and closed
	// when it stops.
	unblocked chan struct{}
}

func newRabbitmqSession(conn *amqp.Connection) (*rabbitmqSession, error) {
	// Registered before the channel is opened, so that no notification is
	// missed. The watcher starts once the channel is set up.
	connCloses := conn.NotifyClose(make(chan *amqp.Error, 1))
	blocks := conn.NotifyBlocked(make(chan amqp.Blocking, 1))

	ch, err := conn.Channel()
	if err != nil {
		return nil, fmt.Errorf("rabbitmq channel: %w", err)
	}
	chCloses := ch.NotifyClose(make(chan *amqp.Error, 1))
	if err := ch.Confirm(false); err != nil {
		return nil, fmt.Errorf("rabbitmq confirm mode: %w", err)
	}

	s := &rabbitmqSession{conn: conn, ch: ch, chCloses: chCloses}
	go s.watch(connCloses, blocks)
	return s, nil
}

// watch tracks whether the broker blocks publishing until the connection is
// closed, and logs the changes.
func (s *rabbitmqSession) watch(connCloses <-chan *amqp.Error, blocks <-chan amqp.Blocking) {
	for b := range blocks {
		// A blocked connection is not a dead one: wait until the broker
		// unblocks it instead of publishing into it.
		s.setBlocked(b.Active)
		if b.Active {
			fmt.Fprintf(os.Stderr, "rabbitmq broker blocked publishing: %v\n", b.Reason)
		} else {
			fmt.Fprintf(os.Stderr, "rabbitmq broker unblocked publishing\n")
		}
	}

	// amqp091-go closes blocks once the connection is closed, after it sent
	// the reason to connCloses.
	s.setBlocked(false)
	if err := <-connCloses; err != nil && !s.closing.Load() {
		fmt.Fprintf(os.Stderr, "rabbitmq connection lost: %v\n", err)
	}
}

func (s *rabbitmqSession) setBlocked(blocked bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case blocked && s.unblocked == nil:
		s.unblocked = make(chan struct{})
	case !blocked && s.unblocked != nil:
		close(s.unblocked)
		s.unblocked = nil
	}
}

// IsClosed reports whether the connection or the channel is closed. Neither
// is opened again.
func (s *rabbitmqSession) IsClosed() bool {
	return s.conn.IsClosed() || s.ch.IsClosed()
}

// closedError returns errRabbitmqClosed with the reason the channel was
// closed.
func (s *rabbitmqSession) closedError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closeErr == nil {
		select {
		case s.closeErr = <-s.chCloses:
		default:
		}
	}
	if s.closeErr == nil {
		return errRabbitmqClosed
	}
	return fmt.Errorf("%w: %w", errRabbitmqClosed, s.closeErr)
}

func (s *rabbitmqSession) Publish(ctx context.Context, exchange, key string, msg amqp.Publishing) (amqpConfirmation, error) {
	s.mu.Lock()
	unblocked := s.unblocked
	s.mu.Unlock()
	if unblocked != nil {
		select {
		case <-unblocked:
		case <-ctx.Done():
			return nil, fmt.Errorf("waiting for the broker to unblock publishing: %w", ctx.Err())
		}
	}

	dc, err := s.ch.PublishWithDeferredConfirmWithContext(ctx, exchange, key, false, false, msg)
	if errors.Is(err, amqp.ErrClosed) {
		return nil, s.closedError()
	}
	if err != nil {
		return nil, fmt.Errorf("rabbitmq publish: %w", err)
	}
	if dc == nil {
		return nil, errors.New("rabbitmq channel is not in confirm mode")
	}
	return &rabbitmqConfirmation{s: s, dc: dc}, nil
}

// Close closes the connection, which also closes the channel.
func (s *rabbitmqSession) Close() error {
	s.closing.Store(true)
	err := s.conn.CloseDeadline(time.Now().Add(rabbitmqCloseTimeout))
	if errors.Is(err, amqp.ErrClosed) {
		// the connection was lost already
		return nil
	}
	return err
}

// rabbitmqConfirmation tells the nacks amqp091-go makes up for the pending
// confirms of a closed channel from the nacks of the broker.
type rabbitmqConfirmation struct {
	s  *rabbitmqSession
	dc *amqp.DeferredConfirmation
}

func (c *rabbitmqConfirmation) WaitContext(ctx context.Context) (bool, error) {
	ack, err := c.dc.WaitContext(ctx)
	if err != nil || ack {
		return ack, err
	}
	// amqp091-go marks the channel closed and sends the reason to chCloses
	// before it nacks the pending confirms.
	if c.s.IsClosed() {
		return false, c.s.closedError()
	}
	return false, nil
}
