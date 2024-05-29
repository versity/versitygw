// Copyright 2024 Versity Software
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

package metrics

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/s3err"
)

var (
	// max size of data items to buffer before dropping
	// new incoming data items
	dataItemCount = 100000
)

// Tag is added metadata for metrics
type Tag struct {
	// Key is tag name
	Key string
	// Value is tag data
	Value string
}

// Manager is a manager of metrics plugins
type Manager struct {
	wg  sync.WaitGroup
	ctx context.Context

	config Config

	publishers  []publisher
	addDataChan chan datapoint
}

type Config struct {
	ServiceName      string
	StatsdServers    string
	DogStatsdServers string
}

// NewManager initializes metrics plugins and returns a new metrics manager
func NewManager(ctx context.Context, conf Config) (*Manager, error) {
	if len(conf.StatsdServers) == 0 && len(conf.DogStatsdServers) == 0 {
		return nil, nil
	}

	if conf.ServiceName == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("failed to get hostname: %w", err)
		}
		conf.ServiceName = hostname
	}

	addDataChan := make(chan datapoint, dataItemCount)

	mgr := &Manager{
		addDataChan: addDataChan,
		ctx:         ctx,
		config:      conf,
	}

	// setup statsd endpoints
	if len(conf.StatsdServers) > 0 {
		statsdServers := strings.Split(conf.StatsdServers, ",")

		for _, server := range statsdServers {
			statsd, err := newStatsd(server, conf.ServiceName)
			if err != nil {
				return nil, err
			}
			mgr.publishers = append(mgr.publishers, statsd)
		}
	}

	// setup dogstatsd endpoints
	if len(conf.DogStatsdServers) > 0 {
		dogStatsdServers := strings.Split(conf.DogStatsdServers, ",")

		for _, server := range dogStatsdServers {
			dogStatsd, err := newDogStatsd(server, conf.ServiceName)
			if err != nil {
				return nil, err
			}
			mgr.publishers = append(mgr.publishers, dogStatsd)
		}
	}

	mgr.wg.Add(1)
	go mgr.addForwarder(addDataChan)

	return mgr, nil
}

func (m *Manager) Send(ctx *fiber.Ctx, err error, action string, count int64, status int) {
	// In case of Authentication failures, url parsing ...
	if action == "" {
		action = ActionUndetected
	}

	a := ActionMap[action]
	reqTags := []Tag{
		{Key: "method", Value: ctx.Method()},
		{Key: "api", Value: a.Service},
		{Key: "action", Value: a.Name},
	}

	reqStatus := status

	if err != nil {
		var apierr s3err.APIError
		if errors.As(err, &apierr) {
			reqStatus = apierr.HTTPStatusCode
		} else {
			reqStatus = http.StatusInternalServerError
		}
	}
	if reqStatus == 0 {
		reqStatus = http.StatusOK
	}

	reqTags = append(reqTags, Tag{
		Key:   "status",
		Value: fmt.Sprintf("%v", reqStatus),
	})

	if err != nil {
		m.increment("failed_count", reqTags...)
	} else {
		m.increment("success_count", reqTags...)
	}

	switch action {
	case ActionPutObject:
		m.add("bytes_written", count, reqTags...)
		m.increment("object_created_count", reqTags...)
	case ActionCompleteMultipartUpload:
		m.increment("object_created_count", reqTags...)
	case ActionUploadPart:
		m.add("bytes_written", count, reqTags...)
	case ActionGetObject:
		m.add("bytes_read", count, reqTags...)
	case ActionDeleteObject:
		m.increment("object_removed_count", reqTags...)
	case ActionDeleteObjects:
		m.add("object_removed_count", count, reqTags...)
	}
}

// increment increments the key by one
func (m *Manager) increment(key string, tags ...Tag) {
	m.add(key, 1, tags...)
}

// add adds value to key
func (m *Manager) add(key string, value int64, tags ...Tag) {
	if m.ctx.Err() != nil {
		return
	}

	d := datapoint{
		key:   key,
		value: value,
		tags:  tags,
	}

	select {
	case m.addDataChan <- d:
	default:
		// channel full, drop the updates
	}
}

// Close closes metrics channels, waits for data to complete, closes all plugins
func (m *Manager) Close() {
	// drain the datapoint channels
	close(m.addDataChan)
	m.wg.Wait()

	// close all publishers
	for _, p := range m.publishers {
		p.Close()
	}
}

// publisher is the interface for interacting with the metrics plugins
type publisher interface {
	Add(key string, value int64, tags ...Tag)
	Close()
}

func (m *Manager) addForwarder(addChan <-chan datapoint) {
	for data := range addChan {
		for _, s := range m.publishers {
			s.Add(data.key, data.value, data.tags...)
		}
	}
	m.wg.Done()
}

type datapoint struct {
	key   string
	value int64
	tags  []Tag
}
