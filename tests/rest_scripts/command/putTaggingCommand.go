package command

import (
	"encoding/xml"
	"errors"
	"fmt"
)

type PutTaggingCommand struct {
	*S3Command
	TagCount *int
	Tags     *Tagging
}

func (p *PutTaggingCommand) createTaggingPayload(fields *TaggingFields) error {
	p.Method = "PUT"
	p.Query = "tagging="
	if len(fields.TagKeys) != len(fields.TagValues) {
		return errors.New("must be same number of tag keys and tag values")
	}
	if fields.TagCount > 0 && len(fields.TagKeys) != 0 {
		return errors.New("tagCount can not be set simultaneously with tagKeys or tagValues")
	}
	p.Tags = &Tagging{
		XMLNamespace: "https://s3.amazonaws.com/doc/2006-03-01/",
	}
	if fields.TagCount > 0 {
		p.Tags.GenerateKeyValuePairs(fields.TagCount)

	} else if len(fields.TagKeys) != 0 {
		if err := p.Tags.AddTags(fields.TagKeys, fields.TagValues); err != nil {
			return fmt.Errorf("error adding keys and/or values to payload: %w", err)
		}
	}
	xmlData, err := xml.Marshal(p.Tags)
	if err != nil {
		return fmt.Errorf("error marshalling XML: %w", err)
	}
	p.Payload = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" + string(xmlData)
	return nil
}
