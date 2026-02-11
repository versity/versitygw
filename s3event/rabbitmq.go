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
type RabbitmqEventSender struct {
	url        string
	exchange   string
	routingKey string
	conn       *amqp.Connection
	channel    *amqp.Channel
	mu         sync.Mutex
	filter     EventFilter
}

// InitRabbitmqEventService creates a RabbitMQ sender. If exchange is blank the
// default (empty string) exchange is used. If routingKey is blank we publish
// with an empty routing key; for delete object multi-events we override the
// routing key with the bucket name (object key not suitable as key routinely has '/')
func InitRabbitmqEventService(url, exchange, routingKey string, filter EventFilter) (S3EventSender, error) {
	if url == "" {
		return nil, fmt.Errorf("rabbitmq url should be specified")
	}

	conn, err := amqp.Dial(url)
	if err != nil {
		return nil, fmt.Errorf("rabbitmq connect: %w", err)
	}

	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("rabbitmq channel: %w", err)
	}

	// Send a test event to validate publishing works. Use a transient message.
	testMsg, err := generateTestEvent()
	if err != nil {
		ch.Close()
		conn.Close()
		return nil, fmt.Errorf("rabbitmq generate test event: %w", err)
	}

	pub := amqp.Publishing{Timestamp: time.Now(), ContentType: fiber.MIMEApplicationJSON, Body: testMsg, MessageId: uuid.NewString()}
	if err := ch.Publish(exchange, routingKey, false, false, pub); err != nil {
		ch.Close()
		conn.Close()
		return nil, fmt.Errorf("rabbitmq publish test event: %w", err)
	}

	return &RabbitmqEventSender{
		url:        url,
		exchange:   exchange,
		routingKey: routingKey,
		conn:       conn,
		channel:    ch,
		filter:     filter,
	}, nil
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
	var firstErr error
	if rs.channel != nil {
		if err := rs.channel.Close(); err != nil {
			firstErr = err
		}
	}
	if rs.conn != nil {
		if err := rs.conn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
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

	if err := rs.channel.Publish(rs.exchange, rs.routingKey, false, false, msg); err != nil {
		fmt.Fprintf(os.Stderr, "failed to send rabbitmq event: %v\n", err.Error())
	}
}
