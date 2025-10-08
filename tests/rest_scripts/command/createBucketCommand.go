package command

import (
	"encoding/xml"
	"errors"
	"fmt"
)

type CreateBucketCommandXML struct {
	XMLName            xml.Name `xml:"CreateBucketConfiguration"`
	XMLNamespace       string   `xml:"xmlns,attr"`
	LocationConstraint string   `xml:"LocationConstraint"`
}

type CreateBucketCommand struct {
	*S3Command
	Config *CreateBucketCommandXML
}

func NewCreateBucketCommand(s3Command *S3Command, locationConstraint string, constraintSet bool) (*CreateBucketCommand, error) {
	if s3Command.BucketName == "" {
		return nil, errors.New("CreateBucket must have bucket name")
	}
	s3Command.Method = "PUT"
	s3Command.Query = ""
	var config *CreateBucketCommandXML = nil
	if constraintSet {
		config = &CreateBucketCommandXML{
			XMLNamespace:       "http://s3.amazonaws.com/doc/2006-03-01/",
			LocationConstraint: locationConstraint,
		}
	}
	command := &CreateBucketCommand{
		S3Command: s3Command,
		Config:    config,
	}
	if constraintSet {
		xmlData, err := xml.Marshal(command.Config)
		if err != nil {
			return nil, fmt.Errorf("error marshalling XML: %w", err)
		}
		command.Payload = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" + string(xmlData)
	}
	return command, nil
}
