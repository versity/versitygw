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
	"fmt"
	"os"
	"sync"
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
// The connection is re-established when the broker closes it (restart,
// network failure). Events are published in confirm mode and retried with
// backoff for up to retryFor, so a broker restart does not silently drop
// events.
type RabbitmqEventSender struct {
	url        string
	exchange   string
	routingKey string
	connMu     sync.Mutex // guards conn and channel
	conn       *amqp.Connection
	channel    *amqp.Channel
	connected  bool // a connection was established before, next dial is a reconnect
	retryFor   time.Duration
	mu         sync.Mutex
	filter     EventFilter
}

const (
	// how long a single event is retried before it is dropped
	rabbitmqRetryForDefault = 2 * time.Minute
	// timeout of a single publish including the broker confirm
	rabbitmqPublishTimeout = 10 * time.Second
	rabbitmqBackoffMin     = 500 * time.Millisecond
	rabbitmqBackoffMax     = 10 * time.Second
)

// InitRabbitmqEventService creates a RabbitMQ sender. If exchange is blank the
// default (empty string) exchange is used. If routingKey is blank we publish
// with an empty routing key; for delete object multi-events we override the
// routing key with the bucket name (object key not suitable as key routinely has '/')
func InitRabbitmqEventService(url, exchange, routingKey string, filter EventFilter) (S3EventSender, error) {
	if url == "" {
		return nil, fmt.Errorf("rabbitmq url should be specified")
	}

	rs := &RabbitmqEventSender{
		url:        url,
		exchange:   exchange,
		routingKey: routingKey,
		retryFor:   rabbitmqRetryForDefault,
		filter:     filter,
	}

	// Send a test event to validate publishing works. Use a transient message.
	testMsg, err := generateTestEvent()
	if err != nil {
		return nil, fmt.Errorf("rabbitmq generate test event: %w", err)
	}

	pub := amqp.Publishing{Timestamp: time.Now(), ContentType: fiber.MIMEApplicationJSON, Body: testMsg, MessageId: uuid.NewString()}
	if err := rs.publish(pub); err != nil {
		rs.Close()
		return nil, fmt.Errorf("rabbitmq publish test event: %w", err)
	}

	return rs, nil
}

// getChannel returns an open channel in confirm mode, reconnecting if the
// previous connection or channel was closed.
func (rs *RabbitmqEventSender) getChannel() (*amqp.Channel, error) {
	rs.connMu.Lock()
	defer rs.connMu.Unlock()

	if rs.conn != nil && !rs.conn.IsClosed() && rs.channel != nil && !rs.channel.IsClosed() {
		return rs.channel, nil
	}
	rs.closeLocked()

	conn, err := amqp.Dial(rs.url)
	if err != nil {
		return nil, fmt.Errorf("rabbitmq connect: %w", err)
	}
	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("rabbitmq channel: %w", err)
	}
	if err := ch.Confirm(false); err != nil {
		ch.Close()
		conn.Close()
		return nil, fmt.Errorf("rabbitmq confirm mode: %w", err)
	}

	rs.conn, rs.channel = conn, ch
	if rs.connected {
		fmt.Fprintf(os.Stderr, "rabbitmq event connection re-established\n")
	}
	rs.connected = true
	return ch, nil
}

// invalidate drops the connection if ch is still the current channel, so the
// next publish reconnects.
func (rs *RabbitmqEventSender) invalidate(ch *amqp.Channel) {
	rs.connMu.Lock()
	defer rs.connMu.Unlock()
	if rs.channel == ch {
		rs.closeLocked()
	}
}

func (rs *RabbitmqEventSender) closeLocked() error {
	var firstErr error
	if rs.channel != nil {
		if err := rs.channel.Close(); err != nil && !rs.channel.IsClosed() {
			firstErr = err
		}
	}
	if rs.conn != nil && !rs.conn.IsClosed() {
		if err := rs.conn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	rs.conn, rs.channel = nil, nil
	return firstErr
}

// publish sends one message and waits for the broker confirm.
func (rs *RabbitmqEventSender) publish(msg amqp.Publishing) error {
	ch, err := rs.getChannel()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), rabbitmqPublishTimeout)
	defer cancel()

	dc, err := ch.PublishWithDeferredConfirmWithContext(ctx, rs.exchange, rs.routingKey, false, false, msg)
	if err == nil {
		var acked bool
		acked, err = dc.WaitContext(ctx)
		if err == nil && !acked {
			if ch.IsClosed() {
				err = fmt.Errorf("rabbitmq connection closed before publish was confirmed")
			} else {
				err = fmt.Errorf("rabbitmq nacked the message")
			}
		}
	}
	if err != nil {
		rs.invalidate(ch)
		return err
	}
	return nil
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
			go rs.send(schema)
		}
		return
	}

	schema := createEventSchema(ctx, meta, ConfigurationIdRabbitMQ)
	go rs.send(schema)
}

func (rs *RabbitmqEventSender) Close() error {
	rs.connMu.Lock()
	defer rs.connMu.Unlock()
	return rs.closeLocked()
}

func (rs *RabbitmqEventSender) send(event EventSchema) {
	body, err := json.Marshal(event)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal event data: %v\n", err.Error())
		return
	}

	msg := amqp.Publishing{
		Timestamp:   time.Now(),
		ContentType: fiber.MIMEApplicationJSON,
		Body:        body,
		MessageId:   uuid.NewString(),
	}

	deadline := time.Now().Add(rs.retryFor)
	backoff := rabbitmqBackoffMin
	for attempt := 1; ; attempt++ {
		err := rs.publish(msg)
		if err == nil {
			if attempt > 1 {
				fmt.Fprintf(os.Stderr, "rabbitmq event %v sent after %v attempts\n", msg.MessageId, attempt)
			}
			return
		}
		if time.Now().Add(backoff).After(deadline) {
			fmt.Fprintf(os.Stderr, "failed to send rabbitmq event %v, dropped after %v attempts: %v\n", msg.MessageId, attempt, err.Error())
			return
		}
		if attempt == 1 {
			fmt.Fprintf(os.Stderr, "failed to send rabbitmq event %v, retrying: %v\n", msg.MessageId, err.Error())
		}
		time.Sleep(backoff)
		backoff = min(backoff*2, rabbitmqBackoffMax)
	}
}
