package command

import (
	"encoding/xml"
	"fmt"
	"strconv"
)

type Tag struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

type TagSet struct {
	Tags []Tag `xml:"Tag"`
}

type Tagging struct {
	XMLName      xml.Name `xml:"Tagging"`
	XMLNamespace string   `xml:"xmlns,attr"`
	TagSet       TagSet   `xml:"TagSet"`
}

type TaggingFields struct {
	TagCount  int
	TagKeys   []string
	TagValues []string
}

func (p *Tagging) AddTags(keys, values []string) error {
	p.TagSet.Tags = make([]Tag, 0, len(keys))
	for idx, key := range keys {
		unquotedKey, err := strconv.Unquote(`"` + key + `"`)
		if err != nil {
			return fmt.Errorf("error unquoting key: %w", err)
		}
		unquotedValue, err := strconv.Unquote(`"` + values[idx] + `"`)
		if err != nil {
			return fmt.Errorf("error unquoting key: %w", err)
		}
		p.TagSet.Tags = append(p.TagSet.Tags, Tag{
			Key:   unquotedKey,
			Value: unquotedValue,
		})
	}
	return nil
}

func (p *Tagging) GenerateKeyValuePairs(count int) {
	p.TagSet.Tags = make([]Tag, 0, count)
	for idx := 1; idx <= count; idx++ {
		key := fmt.Sprintf("key%d", idx)
		value := fmt.Sprintf("value%d", idx)
		p.TagSet.Tags = append(p.TagSet.Tags, Tag{
			Key:   key,
			Value: value,
		})
	}
}
