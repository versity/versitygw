package command

import (
	"encoding/xml"
	"errors"
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

type PutBucketTaggingTags struct {
	XMLName      xml.Name `xml:"Tagging"`
	XMLNamespace string   `xml:"xmlns,attr"`
	TagSet       TagSet   `xml:"TagSet"`
}

type PutBucketTaggingFields struct {
	TagCount  int
	TagKeys   []string
	TagValues []string
}

type PutBucketTaggingCommand struct {
	*S3Command
	TagCount *int
	Tags     *PutBucketTaggingTags
}

func NewPutBucketTaggingCommand(s3Command *S3Command, fields *PutBucketTaggingFields) (*PutBucketTaggingCommand, error) {
	if s3Command.BucketName == "" {
		return nil, errors.New("PutBucketTagging must have bucket name")
	}
	s3Command.Method = "PUT"
	s3Command.Query = "tagging="
	command := &PutBucketTaggingCommand{
		S3Command: s3Command,
	}
	if len(fields.TagKeys) != len(fields.TagValues) {
		return nil, errors.New("must be same number of tag keys and tag values")
	}
	if fields.TagCount > 0 && len(fields.TagKeys) != 0 {
		return nil, errors.New("tagCount can not be set simultaneously with tagKeys or tagValues")
	}
	command.Tags = &PutBucketTaggingTags{
		XMLNamespace: "http://s3.amazonaws.com/doc/2006-03-01/",
	}
	if fields.TagCount > 0 {
		command.Tags.GenerateKeyValuePairs(fields.TagCount)

	} else if len(fields.TagKeys) != 0 {
		if err := command.Tags.AddTags(fields.TagKeys, fields.TagValues); err != nil {
			return nil, fmt.Errorf("error adding keys and/or values to payload: %w", err)
		}
	}
	xmlData, err := xml.Marshal(command.Tags)
	if err != nil {
		return nil, fmt.Errorf("error marshalling XML: %w", err)
	}
	command.Payload = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" + string(xmlData)
	return command, nil
}

func (p *PutBucketTaggingTags) GenerateKeyValuePairs(count int) {
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

func (p *PutBucketTaggingTags) AddTags(keys, values []string) error {
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
