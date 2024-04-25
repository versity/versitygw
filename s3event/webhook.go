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
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/s3response"
)

type Webhook struct {
	url    string
	client *http.Client
	filter EventFilter
	mu     sync.Mutex
}

func InitWebhookEventSender(url string, filter EventFilter) (S3EventSender, error) {
	if url == "" {
		return nil, fmt.Errorf("webhook url should be specified")
	}

	client := &http.Client{
		Timeout: time.Second * 1,
	}

	testEv, err := generateTestEvent()
	if err != nil {
		return nil, fmt.Errorf("webhook generate test event: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(testEv))
	if err != nil {
		return nil, fmt.Errorf("create webhook http request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	_, err = client.Do(req)
	if err != nil {
		if err, ok := err.(net.Error); ok && !err.Timeout() {
			return nil, fmt.Errorf("send webhook test event: %w", err)
		}
	}

	return &Webhook{
		client: &http.Client{
			Timeout: 3 * time.Second,
		},
		url:    url,
		filter: filter,
	}, nil
}

func (w *Webhook) SendEvent(ctx *fiber.Ctx, meta EventMeta) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.filter != nil && !w.filter.Filter(meta.EventName) {
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

			go w.send(schema)
		}

		return
	}

	schema := createEventSchema(ctx, meta, ConfigurationIdWebhook)

	go w.send(schema)
}

func (w *Webhook) Close() error {
	return nil
}

func (w *Webhook) send(event EventSchema) {
	eventBytes, err := json.Marshal(event)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse event data: %v\n", err.Error())
		return
	}

	req, err := http.NewRequest(http.MethodPost, w.url, bytes.NewReader(eventBytes))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create webhook event request: %v\n", err.Error())
		return
	}

	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	_, err = w.client.Do(req)
	if err != nil {
		if err, ok := err.(net.Error); ok && !err.Timeout() {
			fmt.Fprintf(os.Stderr, "failed to send webhook event: %v\n", err.Error())
		}
	}
}
