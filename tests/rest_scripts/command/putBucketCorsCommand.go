package command

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
)

const (
	AllowedMethods = "allowedMethods"
	AllowedOrigins = "allowedOrigins"
	AllowedHeaders = "allowedHeaders"
	ExposedHeaders = "exposedHeaders"
	ID             = "id"
	MaxAgeSeconds  = "maxAgeSeconds"
)

type CORSRule struct {
	XMLName       xml.Name `xml:"CORSRule"`
	AllowedMethod []string `xml:"AllowedMethod"`
	AllowedOrigin []string `xml:"AllowedOrigin"`
	AllowedHeader []string `xml:"AllowedHeader,omitempty"`
	ExposeHeader  []string `xml:"ExposeHeader,omitempty"`
	ID            string   `xml:"ID,omitempty"`
	MaxAgeSeconds string   `xml:"MaxAgeSeconds,omitempty"`
}

type CORSConfiguration struct {
	XMLName      xml.Name `xml:"CORSConfiguration"`
	XMLNamespace string   `xml:"xmlns,attr"`
	CORSRules    []*CORSRule
}

func NewPutBucketCORSCommand(command *S3Command, ruleStrings []string) (*S3Command, error) {
	command.Method = "PUT"
	command.Query = "cors"
	corsConfiguration := &CORSConfiguration{
		XMLNamespace: "https://s3.amazonaws.com/doc/2006-03-01/",
	}
	for _, ruleString := range ruleStrings {
		var corsRule *CORSRule
		var err error
		if corsRule, err = assembleCORSRule(ruleString); err != nil {
			return nil, fmt.Errorf("error assembling CORS rule: %w", err)
		}
		corsConfiguration.CORSRules = append(corsConfiguration.CORSRules, corsRule)
	}
	xmlData, err := xml.Marshal(corsConfiguration)
	if err != nil {
		return nil, fmt.Errorf("error marshalling XML: %w", err)
	}
	command.Payload = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" + string(xmlData)
	return command, nil
}

func assembleCORSRule(ruleString string) (*CORSRule, error) {
	corsRule := &CORSRule{}
	ruleComponents := strings.Split(ruleString, ";")
	for _, component := range ruleComponents {
		componentSegments := strings.Split(component, "=")
		switch componentSegments[0] {
		case AllowedMethods:
			corsRule.AllowedMethod = strings.Split(componentSegments[1], ",")
		case AllowedOrigins:
			corsRule.AllowedOrigin = strings.Split(componentSegments[1], ",")
		case AllowedHeaders:
			corsRule.AllowedHeader = strings.Split(componentSegments[1], ",")
		case ExposedHeaders:
			corsRule.ExposeHeader = strings.Split(componentSegments[1], ",")
		case ID:
			corsRule.ID = componentSegments[1]
		case MaxAgeSeconds:
			corsRule.MaxAgeSeconds = componentSegments[1]
		default:
			return nil, errors.New("invalid CORSRule component type: " + componentSegments[0])
		}
	}
	return corsRule, nil
}
