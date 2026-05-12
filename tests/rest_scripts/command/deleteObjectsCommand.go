package command

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
)

const (
	ETag             = "eTag"
	Key              = "key"
	LastModifiedTime = "lastModifiedTime"
	Size             = "size"
	VersionId        = "versionId"
)

type Object struct {
	XMLName          xml.Name `xml:"Object"`
	ETag             string   `xml:"ETag,omitempty"`
	Key              string   `xml:"Key"`
	LastModifiedTime string   `xml:"LastModifiedTime,omitempty"`
	Size             string   `xml:"Size,omitempty"`
	VersionId        string   `xml:"VersionId,omitempty"`
}

type Delete struct {
	XMLName      xml.Name `xml:"Delete"`
	XMLNamespace string   `xml:"xmlns,attr"`
	Objects      []*Object
	Quiet        bool `xml:"Quiet,omitempty"`
}

func NewDeleteObjectsCommand(command *S3RequestBuilder, objectStrings []string, quietMode bool) (*S3RequestBuilder, error) {
	command.Config.Method = "POST"
	command.Config.Query = "delete"
	deleteCommand := &Delete{
		XMLNamespace: "https://s3.amazonaws.com/doc/2006-03-01/",
	}
	for _, objectString := range objectStrings {
		var object *Object
		var err error
		if object, err = assembleObject(objectString); err != nil {
			return nil, fmt.Errorf("error assembling object for DeleteObjects command: %w", err)
		}
		deleteCommand.Objects = append(deleteCommand.Objects, object)
	}
	deleteCommand.Quiet = quietMode
	xmlData, err := xml.Marshal(deleteCommand)
	if err != nil {
		return nil, fmt.Errorf("error marshalling XML: %w", err)
	}
	command.Config.Payload = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" + string(xmlData)
	return command, nil
}

func assembleObject(objectString string) (*Object, error) {
	object := &Object{}
	objectStrings := strings.SplitSeq(objectString, ";")
	for singleObjectString := range objectStrings {
		keyValuePair := strings.Split(singleObjectString, "=")
		switch keyValuePair[0] {
		case ETag:
			object.ETag = keyValuePair[1]
		case Key:
			object.Key = keyValuePair[1]
		case LastModifiedTime:
			object.LastModifiedTime = keyValuePair[1]
		case Size:
			object.Size = keyValuePair[1]
		case VersionId:
			object.VersionId = keyValuePair[1]
		default:
			return nil, errors.New("invalid object key for DeleteObjects command: " + keyValuePair[0])
		}
	}
	return object, nil
}
