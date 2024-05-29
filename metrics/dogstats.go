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
func (s *vgwDogStatsd) Add(module, key string, value int64, tags ...Tag) {
	stags := make([]string, len(tags))
	for i, t := range tags {
		stags[i] = t.ddString()
	}
	s.c.Count(fmt.Sprintf("%v.%v", module, key), value, stags, rateSampleAlways)
}
