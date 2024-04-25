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

	"github.com/gofiber/fiber/v2"
	"github.com/segmentio/kafka-go"
	"github.com/versity/versitygw/s3response"
)

var sequencer = 0

type Kafka struct {
	key    string
	writer *kafka.Writer
	filter EventFilter
	mu     sync.Mutex
}

func InitKafkaEventService(url, topic, key string, filter EventFilter) (S3EventSender, error) {
	if topic == "" {
		return nil, fmt.Errorf("kafka message topic should be specified")
	}

	w := kafka.NewWriter(kafka.WriterConfig{
		Brokers:      []string{url},
		Topic:        topic,
		Balancer:     &kafka.LeastBytes{},
		BatchTimeout: 5 * time.Millisecond,
	})

	msg, err := generateTestEvent()
	if err != nil {
		return nil, fmt.Errorf("kafka generate test event: %w", err)
	}

	message := kafka.Message{
		Key:   []byte(key),
		Value: msg,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	err = w.WriteMessages(ctx, message)
	cancel()
	if err != nil {
		return nil, err
	}

	return &Kafka{
		key:    key,
		writer: w,
		filter: filter,
	}, nil
}

func (ks *Kafka) SendEvent(ctx *fiber.Ctx, meta EventMeta) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.filter != nil && !ks.filter.Filter(meta.EventName) {
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

			go ks.send(schema)
		}

		return
	}

	schema := createEventSchema(ctx, meta, ConfigurationIdWebhook)

	go ks.send(schema)
}

func (ks *Kafka) Close() error {
	return ks.writer.Close()
}

func (ks *Kafka) send(event EventSchema) {
	eventBytes, err := json.Marshal(event)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse event data: %v\n", err.Error())
		return
	}

	message := kafka.Message{
		Key:   []byte(ks.key),
		Value: eventBytes,
	}

	ctx := context.Background()
	err = ks.writer.WriteMessages(ctx, message)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to send kafka event: %v\n", err.Error())
	}
}

func genSequencer() string {
	sequencer = sequencer + 1
	return fmt.Sprintf("%X", sequencer)
}
