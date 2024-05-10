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
	"fmt"
	"os"
	"strings"
	"sync"
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

	publishers    []publisher
	addDataChan   chan datapoint
	gaugeDataChan chan datapoint
}

type Config struct {
	StatsdServers string
}

// NewManager initializes metrics plugins and returns a new metrics manager
func NewManager(ctx context.Context, conf Config) (*Manager, error) {
	if len(conf.StatsdServers) == 0 {
		return nil, nil
	}
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("failed to get hostname: %w", err)
	}

	addDataChan := make(chan datapoint, dataItemCount)
	gaugeDataChan := make(chan datapoint, dataItemCount)

	mgr := &Manager{
		addDataChan:   addDataChan,
		gaugeDataChan: gaugeDataChan,
		ctx:           ctx,
	}

	statsdServers := strings.Split(conf.StatsdServers, ",")

	for _, server := range statsdServers {
		statsd, err := NewStatsd(server, hostname)
		if err != nil {
			return nil, err
		}
		mgr.publishers = append(mgr.publishers, statsd)
	}

	mgr.wg.Add(1)
	go mgr.addForwarder(addDataChan)
	mgr.wg.Add(1)
	go mgr.gaugeForwarder(gaugeDataChan)

	return mgr, nil
}

func (m *Manager) Send(err error, action string, objSize int64, objCount int64) {
	// In case of Authentication failures, url parsing ...
	if action == "" {
		action = "s3:UnDetected"
	}
	if err != nil {
		m.Increment(action, "failed_count")
	}
	m.Increment(action, "success_count")

	switch action {
	case "s3:PutObject":
		m.Add(action, "bytes_written", objSize)
		m.Increment(action, "object_created_count")
	case "s3:CompleteMultipartUpload":
		m.Increment(action, "object_created_count")
	case "s3:UploadPart":
		m.Add(action, "bytes_written", objSize)
	case "s3:GetObject":
		m.Add(action, "bytes_read", objSize)
	case "s3:DeleteObject":
		m.Increment(action, "object_removed_count")
	case "s3:DeleteObjects":
		m.Add(action, "object_removed_count", objCount)
	}
	//TODO: Handle UploadPartCopy case
	//TODO: Handle CopyObject case
}

// Increment increments the key by one
func (m *Manager) Increment(module, key string, tags ...Tag) {
	m.Add(module, key, 1, tags...)
}

// Add adds value to key
func (m *Manager) Add(module, key string, value int64, tags ...Tag) {
	if m.ctx.Err() != nil {
		return
	}

	d := datapoint{
		module: module,
		key:    key,
		value:  value,
		tags:   tags,
	}

	select {
	case m.addDataChan <- d:
	default:
		// channel full, drop the updates
	}
}

// Gauge sets key to value
func (m *Manager) Gauge(module, key string, value int64, tags ...Tag) {
	if m.ctx.Err() != nil {
		return
	}

	d := datapoint{
		module: module,
		key:    key,
		value:  value,
		tags:   tags,
	}

	select {
	case m.gaugeDataChan <- d:
	default:
		// channel full, drop the updates
	}
}

// Close closes metrics channels, waits for data to complete, closes all plugins
func (m *Manager) Close() {
	// drain the datapoint channels
	close(m.addDataChan)
	close(m.gaugeDataChan)
	m.wg.Wait()

	// close all publishers
	for _, p := range m.publishers {
		p.Close()
	}
}

// publisher is the interface for interacting with the metrics plugins
type publisher interface {
	Add(module, key string, value int64, tags ...Tag)
	Gauge(module, key string, value int64, tags ...Tag)
	Close()
}

func (m *Manager) addForwarder(addChan <-chan datapoint) {
	for data := range addChan {
		for _, s := range m.publishers {
			s.Add(data.module, data.key, data.value, data.tags...)
		}
	}
	m.wg.Done()
}

func (m *Manager) gaugeForwarder(gaugeChan <-chan datapoint) {
	for data := range gaugeChan {
		for _, s := range m.publishers {
			s.Gauge(data.module, data.key, data.value, data.tags...)
		}
	}
	m.wg.Done()
}

type datapoint struct {
	module string
	key    string
	value  int64
	tags   []Tag
}
