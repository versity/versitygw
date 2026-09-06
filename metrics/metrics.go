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
	"sync/atomic"

	"github.com/gofiber/fiber/v3"
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

// Manager is the interface definition for metrics manager
type Manager interface {
	Send(ctx fiber.Ctx, err error, action string, count int64, status int)
	// SendWithBucket is Send with the bucket dimension stated
	// by the caller. The S3 middleware derives the bucket from
	// the matched route, which synthesized contexts (RDMA
	// operational records) cannot reproduce: they pass the
	// captured bucket explicitly instead.
	SendWithBucket(ctx fiber.Ctx, err error, action string, count int64, status int, bucket string)
	Close()
}

// manager is a manager of metrics plugins
type manager struct {
	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc

	config Config

	publishers  []publisher
	addDataChan chan datapoint
	// closed gates senders against Close: the datapoint channel
	// is closed to drain the forwarder, and a send on a closed
	// channel panics. Producers that lose this race (an S3
	// handler still finishing after the shutdown timeout) drop
	// their update instead of taking the process down.
	closed atomic.Bool
}

type Config struct {
	ServiceName      string
	StatsdServers    string
	DogStatsdServers string
}

// NewManager initializes metrics plugins and returns a new metrics manager
func NewManager(ctx context.Context, conf Config) (Manager, error) {
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

	// Derive a cancellable child of the caller context: closing
	// the manager cancels it itself (a standalone user of the
	// API has no external cancellation to rely on), while the
	// gateway shutdown path keeps its own context propagation.
	mctx, mcancel := context.WithCancel(ctx)
	mgr := &manager{
		addDataChan: addDataChan,
		ctx:         mctx,
		cancel:      mcancel,
		config:      conf,
	}

	// setup statsd endpoints
	if len(conf.StatsdServers) > 0 {
		statsdServers := strings.SplitSeq(conf.StatsdServers, ",")

		for server := range statsdServers {
			statsd, err := newStatsd(server, conf.ServiceName)
			if err != nil {
				return nil, err
			}
			mgr.publishers = append(mgr.publishers, statsd)
		}
	}

	// setup dogstatsd endpoints
	if len(conf.DogStatsdServers) > 0 {
		dogStatsdServers := strings.SplitSeq(conf.DogStatsdServers, ",")

		for server := range dogStatsdServers {
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

func (m *manager) Send(ctx fiber.Ctx, err error, action string, count int64, status int) {
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

	// add tag bucket=<bucketname> if the request specifies a bucket
	bucket := ctx.Params("bucket")
	if bucket != "" {
		reqTags = append(reqTags, Tag{Key: "bucket", Value: bucket})
	}

	m.send(ctx, err, action, count, status, reqTags)
}

// SendWithBucket reports with the bucket dimension supplied by the
// caller; see the Manager interface.
func (m *manager) SendWithBucket(ctx fiber.Ctx, err error, action string, count int64, status int, bucket string) {
	if action == "" {
		action = ActionUndetected
	}
	a := ActionMap[action]
	reqTags := []Tag{
		{Key: "method", Value: ctx.Method()},
		{Key: "api", Value: a.Service},
		{Key: "action", Value: a.Name},
	}
	if bucket != "" {
		reqTags = append(reqTags, Tag{Key: "bucket", Value: bucket})
	}
	m.send(ctx, err, action, count, status, reqTags)
}

func (m *manager) send(ctx fiber.Ctx, err error, action string, count int64, status int, reqTags []Tag) {
	reqStatus := status

	if err != nil {
		var apierr s3err.S3Error
		if errors.As(err, &apierr) {
			reqStatus = apierr.StatusCode()
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
func (m *manager) increment(key string, tags ...Tag) {
	m.add(key, 1, tags...)
}

// add adds value to key
func (m *manager) add(key string, value int64, tags ...Tag) {
	if m.ctx.Err() != nil || m.closed.Load() {
		return
	}

	d := datapoint{
		key:   key,
		value: value,
		tags:  tags,
	}

	// The send races Close for last-producer position: the
	// closed check above and the channel close in Close are not
	// atomic, so the send below can still observe a closed
	// channel. Recovering here turns that race into a dropped
	// datapoint, which is the documented contract for late
	// producers.
	defer func() { _ = recover() }()
	select {
	case m.addDataChan <- d:
	default:
		// channel full, drop the updates
	}
}

// Close stops the manager: producers drop new datapoints, the
// forwarder drains the buffered ones and exits through the
// canceled context, and the publishers flush and close. The
// datapoint channel itself is never closed - a producer racing
// the closure would panic - so the closed flag and the context
// cancellation carry the shutdown instead.
func (m *manager) Close() {
	m.closed.Store(true)
	// Self-owned cancellation terminates the forwarder wherever
	// it is waiting; the external context is only a second path.
	m.cancel()
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

func (m *manager) addForwarder(addChan <-chan datapoint) {
	defer m.wg.Done()
	for {
		select {
		case data, ok := <-addChan:
			if !ok {
				return
			}
			for _, s := range m.publishers {
				s.Add(data.key, data.value, data.tags...)
			}
		case <-m.ctx.Done():
			// The channel is never closed (producers race its
			// closure otherwise); termination is the context.
			// Drain whatever the buffer still holds so late
			// datapoints are not lost, then exit.
			for {
				select {
				case data, ok := <-addChan:
					if !ok {
						return
					}
					for _, s := range m.publishers {
						s.Add(data.key, data.value, data.tags...)
					}
				default:
					return
				}
			}
		}
	}
}

type datapoint struct {
	key   string
	value int64
	tags  []Tag
}
