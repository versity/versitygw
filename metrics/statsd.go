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
	"fmt"

	"github.com/smira/go-statsd"
)

// Statsd metrics type
type Statsd struct {
	c *statsd.Client
}

// NewStatsd takes a server address and returns a statsd merics
// Supply service name to be used as a tag to identify the spcific
// gateway instance, this may typically be the gateway hostname
func NewStatsd(server string, service string) (*Statsd, error) {
	c := statsd.NewClient(
		server,
		statsd.MaxPacketSize(1400),
		statsd.MetricPrefix("versitygw."),
		statsd.TagStyle(statsd.TagFormatInfluxDB),
		statsd.DefaultTags(statsd.StringTag("service", service)),
	)
	return &Statsd{c: c}, nil
}

// Close closes statsd connections
func (s *Statsd) Close() {
	s.c.Close()
}

// Add adds value to key
func (s *Statsd) Add(module, key string, value int64, tags ...Tag) {
	stags := make([]statsd.Tag, len(tags))
	for i, t := range tags {
		stags[i] = statsd.StringTag(t.Key, t.Value)
	}
	s.c.Incr(fmt.Sprintf("%v.%v", module, key), value, stags...)
}

// Gauge sets key to value
func (s *Statsd) Gauge(module, key string, value int64, tags ...Tag) {
	stags := make([]statsd.Tag, len(tags))
	for i, t := range tags {
		stags[i] = statsd.StringTag(t.Key, t.Value)
	}
	s.c.Gauge(fmt.Sprintf("%v.%v", module, key), int64(value), stags...)
}
