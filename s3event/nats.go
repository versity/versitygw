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
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

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

	return &NatsEventSender{
		topic:  topic,
		client: client,
	}, nil
}

func (ns *NatsEventSender) SendEvent(ctx *fiber.Ctx, meta EventMeta) {
	ns.mu.Lock()
	defer ns.mu.Unlock()

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
			ConfigurationId: "nats-global",
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

	ns.send([]EventSchema{schema})
}

func (ns *NatsEventSender) send(evnt []EventSchema) {
	msg, err := json.Marshal(evnt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse the event data: %v\n", err.Error())
	}

	err = ns.client.Publish(ns.topic, msg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to send nats event: %v\n", err.Error())
	}
}
