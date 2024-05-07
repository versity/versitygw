package s3event

import (
	"strings"
	"testing"
)

func TestFilterWildcardCreated(t *testing.T) {
	filterString := `{"s3:ObjectCreated:*": true}`
	strReader := strings.NewReader(filterString)

	ef, err := parseEventFilters(strReader)
	if err != nil {
		t.Fatalf("failed to parse event filter: %v", err)
	}

	created := []string{
		"s3:ObjectCreated:Put",
		"s3:ObjectCreated:Post",
		"s3:ObjectCreated:Copy",
		"s3:ObjectCreated:CompleteMultipartUpload",
	}

	for _, event := range created {
		allowed := ef.Filter(EventType(event))
		if !allowed {
			t.Errorf("expected event to be allowed: %s", event)
		}
	}
}

func TestFilterWildcardRemoved(t *testing.T) {
	filterString := `{"s3:ObjectRemoved:*": true}`
	strReader := strings.NewReader(filterString)

	ef, err := parseEventFilters(strReader)
	if err != nil {
		t.Fatalf("failed to parse event filter: %v", err)
	}

	removed := []string{
		"s3:ObjectRemoved:Delete",
		"s3:ObjectRemoved:DeleteObjects",
	}

	for _, event := range removed {
		allowed := ef.Filter(EventType(event))
		if !allowed {
			t.Errorf("expected event to be allowed: %s", event)
		}
	}
}
