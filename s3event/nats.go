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

	"github.com/gofiber/fiber/v2"
	"github.com/nats-io/nats.go"
	"github.com/versity/versitygw/s3response"
)

type NatsEventSender struct {
	topic  string
	client *nats.Conn
	mu     sync.Mutex
	filter EventFilter
}

func InitNatsEventService(url, topic string, filter EventFilter) (S3EventSender, error) {
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
		filter: filter,
	}, nil
}

func (ns *NatsEventSender) SendEvent(ctx *fiber.Ctx, meta EventMeta) {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	if ns.filter != nil && !ns.filter.Filter(meta.EventName) {
		return
	}

	if meta.EventName == EventObjectRemovedDeleteObjects {
		var dObj s3response.DeleteObjects

		if err := xml.Unmarshal(ctx.Body(), &dObj); err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse delete objects input payload: %v\n", err.Error())
			return
		}

		// Events aren't send in correct order
		for _, obj := range dObj.Objects {
			key := *obj.Key
			schema := createEventSchema(ctx, meta, ConfigurationIdWebhook)
			schema.Records[0].S3.Object.Key = key
			schema.Records[0].S3.Object.VersionId = obj.VersionId

			go ns.send(schema)
		}

		return
	}

	schema := createEventSchema(ctx, meta, ConfigurationIdWebhook)

	go ns.send(schema)
}

func (ns *NatsEventSender) Close() error {
	ns.client.Close()
	return nil
}

func (ns *NatsEventSender) send(event EventSchema) {
	eventBytes, err := json.Marshal(event)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse event data: %v\n", err.Error())
		return
	}
	err = ns.client.Publish(ns.topic, eventBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to send nats event: %v\n", err.Error())
	}
}
