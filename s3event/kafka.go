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
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/segmentio/kafka-go"
)

var sequencer = 0

type Kafka struct {
	key    string
	writer *kafka.Writer
	mu     sync.Mutex
}

func InitKafkaEventService(url, topic, key string) (S3EventSender, error) {
	if topic == "" {
		return nil, fmt.Errorf("kafka message topic should be specified")
	}

	w := kafka.NewWriter(kafka.WriterConfig{
		Brokers:      []string{url},
		Topic:        topic,
		Balancer:     &kafka.LeastBytes{},
		BatchTimeout: 5 * time.Millisecond,
	})

	msg := map[string]string{
		"Service": "S3",
		"Event":   "s3:TestEvent",
		"Time":    time.Now().Format(time.RFC3339),
		"Bucket":  "Test-Bucket",
	}

	msgJSON, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	message := kafka.Message{
		Key:   []byte(key),
		Value: msgJSON,
	}

	ctx := context.Background()

	err = w.WriteMessages(ctx, message)
	if err != nil {
		return nil, err
	}

	return &Kafka{
		key:    key,
		writer: w,
	}, nil
}

func (ks *Kafka) SendEvent(ctx *fiber.Ctx, meta EventMeta) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	path := strings.Split(ctx.Path(), "/")
	bucket, object := path[1], strings.Join(path[2:], "/")

	schema := EventSchema{
		EventVersion: "2.2",
		EventSource:  "aws:s3",
		AwsRegion:    ctx.Locals("region").(string),
		EventTime:    time.Now().Format(time.RFC3339),
		EventName:    meta.EventName,
		UserIdentity: EventUserIdentity{
			PrincipalId: ctx.Locals("access").(string),
		},
		RequestParameters: EventRequestParams{
			SourceIPAddress: ctx.IP(),
		},
		ResponseElements: EventResponseElements{
			RequestId: ctx.Get("X-Amz-Request-Id"),
			HostId:    ctx.Get("X-Amx-Id-2"),
		},
		S3: EventS3Data{
			S3SchemaVersion: "1.0",
			// This field will come up after implementing per bucket notifications
			ConfigurationId: "kafka-global",
			Bucket: EventS3BucketData{
				Name: bucket,
				OwnerIdentity: EventUserIdentity{
					PrincipalId: ctx.Locals("access").(string),
				},
				Arn: fmt.Sprintf("arn:aws:s3:::%v", strings.Join(path, "/")),
			},
			Object: EventObjectData{
				Key:       object,
				Size:      meta.ObjectSize,
				ETag:      meta.ObjectETag,
				VersionId: meta.VersionId,
				Sequencer: genSequencer(),
			},
		},
		GlacierEventData: EventGlacierData{
			// Not supported
			RestoreEventData: EventRestoreData{},
		},
	}

	ks.send([]EventSchema{schema})
}

func (ks *Kafka) send(evnt []EventSchema) {
	msg, err := json.Marshal(evnt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nfailed to parse the event data: %v", err.Error())
		return
	}

	message := kafka.Message{
		Key:   []byte(ks.key),
		Value: msg,
	}

	ctx := context.Background()
	err = ks.writer.WriteMessages(ctx, message)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nfailed to send kafka event: %v", err.Error())
	}
}

func genSequencer() string {
	sequencer = sequencer + 1
	return fmt.Sprintf("%X", sequencer)
}
