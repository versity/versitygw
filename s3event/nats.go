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
	"fmt"
	"os"
	"sync"

	"github.com/gofiber/fiber/v2"
	"github.com/nats-io/nats.go"
)

type NatsEventSender struct {
	topic  string
	client *nats.Conn
	mu     sync.Mutex
}

func InitNatsEventService(url, topic string) (S3EventSender, error) {
	if topic == "" {
		return nil, fmt.Errorf("nats message topic should be specified")
	}

	client, err := nats.Connect(url)
	if err != nil {
		return nil, err
	}

	msg, err := generateTestEvent()
	if err != nil {
		return nil, fmt.Errorf("nats generate test event: %w", err)
	}

	err = client.Publish(topic, msg)
	if err != nil {
		return nil, fmt.Errorf("nats publish test event: %v", err)
	}

	return &NatsEventSender{
		topic:  topic,
		client: client,
	}, nil
}

func (ns *NatsEventSender) SendEvent(ctx *fiber.Ctx, meta EventMeta) {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	schema, err := createEventSchema(ctx, meta, ConfigurationIdNats)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create nats event: %v\n", err.Error())
		return
	}

	go ns.send(schema)
}

func (ns *NatsEventSender) Close() error {
	ns.client.Close()
	return nil
}

func (ns *NatsEventSender) send(event []byte) {
	err := ns.client.Publish(ns.topic, event)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to send nats event: %v\n", err.Error())
	}
}
