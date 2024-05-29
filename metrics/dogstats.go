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

	dogstats "github.com/DataDog/datadog-go/v5/statsd"
)

// vgwDogStatsd metrics type
type vgwDogStatsd struct {
	c *dogstats.Client
}

var (
	rateSampleAlways = 1.0
)

// newDogStatsd takes a server address and returns a statsd merics
func newDogStatsd(server string, service string) (*vgwDogStatsd, error) {
	c, err := dogstats.New(server,
		dogstats.WithMaxMessagesPerPayload(1000),
		dogstats.WithNamespace("versitygw"),
		dogstats.WithTags([]string{
			"service:" + service,
		}))
	if err != nil {
		return nil, err
	}
	return &vgwDogStatsd{c: c}, nil
}

// Close closes statsd connections
func (s *vgwDogStatsd) Close() {
	s.c.Close()
}

func (t Tag) ddString() string {
	if t.Value == "" {
		return t.Key
	}
	return fmt.Sprintf("%v:%v", t.Key, t.Value)
}

// Add adds value to key
func (s *vgwDogStatsd) Add(key string, value int64, tags ...Tag) {
	stags := make([]string, len(tags))
	for i, t := range tags {
		stags[i] = t.ddString()
	}
	s.c.Count(key, value, stags, rateSampleAlways)
}
