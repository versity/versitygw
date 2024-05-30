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
	"github.com/smira/go-statsd"
)

// vgwStatsd metrics type
type vgwStatsd struct {
	c *statsd.Client
}

// newStatsd takes a server address and returns a statsd merics
// Supply service name to be used as a tag to identify the spcific
// gateway instance, this may typically be the gateway hostname
func newStatsd(server string, service string) (*vgwStatsd, error) {
	c := statsd.NewClient(
		server,
		statsd.MetricPrefix("versitygw."),
		statsd.TagStyle(statsd.TagFormatInfluxDB),
		statsd.DefaultTags(statsd.StringTag("service", service)),
	)
	return &vgwStatsd{c: c}, nil
}

// Close closes statsd connections
func (s *vgwStatsd) Close() {
	s.c.Close()
}

// Add adds value to key
func (s *vgwStatsd) Add(key string, value int64, tags ...Tag) {
	stags := make([]statsd.Tag, len(tags))
	for i, t := range tags {
		stags[i] = statsd.StringTag(t.Key, t.Value)
	}
	s.c.Incr(key, value, stags...)
}
