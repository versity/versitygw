package command

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
)

type ErrorDocument struct {
	Key string `xml:"Key,omitempty" json:"key,omitempty"`
}

type IndexDocument struct {
	Suffix string `xml:"Suffix,omitempty" json:"suffix,omitempty"`
}

type RedirectAllRequestsTo struct {
	HostName string `xml:"HostName,omitempty" json:"hostName,omitempty"`
	Protocol string `xml:"Protocol,omitempty" json:"protocol,omitempty"`
}

type Condition struct {
	HttpErrorCodeReturnedEquals string `xml:"HttpErrorCodeReturnedEquals,omitempty" json:"httpErrorCodeReturnedEquals,omitempty"`
	KeyPrefixEquals             string `xml:"KeyPrefixEquals,omitempty" json:"keyPrefixEquals,omitempty"`
}

type Redirect struct {
	HostName             string `xml:"HostName,omitempty" json:"hostName,omitempty"`
	HttpRedirectCode     string `xml:"HttpRedirectCode,omitempty" json:"httpRedirectCode,omitempty"`
	Protocol             string `xml:"Protocol,omitempty" json:"protocol,omitempty"`
	ReplaceKeyPrefixWith string `xml:"ReplaceKeyPrefixWith,omitempty" json:"replaceKeyPrefixWith,omitempty"`
	ReplaceKeyWith       string `xml:"ReplaceKeyWith,omitempty" json:"replaceKeyWith,omitempty"`
}

type RoutingRule struct {
	Condition *Condition `xml:"Condition,omitempty" json:"condition,omitempty"`
	Redirect  *Redirect  `xml:"Redirect,omitempty" json:"redirect,omitempty"`
}

type RoutingRules struct {
	RoutingRule []RoutingRule `xml:"RoutingRule,omitempty" json:"routingRule,omitempty"`
}

type WebsiteConfiguration struct {
	XMLName               xml.Name               `xml:"WebsiteConfiguration,omitempty" json:"-"`
	XMLNamespace          string                 `xml:"xmlns,attr" json:"xmlNamespace,omitempty"`
	ErrorDocument         *ErrorDocument         `xml:"ErrorDocument,omitempty" json:"errorDocument,omitempty"`
	IndexDocument         *IndexDocument         `xml:"IndexDocument,omitempty" json:"indexDocument,omitempty"`
	RedirectAllRequestsTo *RedirectAllRequestsTo `xml:"RedirectAllRequestsTo,omitempty" json:"redirectAllRequestsTo,omitempty"`
	RoutingRules          *RoutingRules          `xml:"RoutingRules,omitempty" json:"routingRules,omitempty"`
}

func NewPutBucketWebsiteCommand(command *S3RequestBuilder, websiteString string) (*S3RequestBuilder, error) {
	command.Config.Method = "PUT"
	command.Config.Query = "website"
	xmlData, err := convertWebsiteJsonToXml(websiteString)
	if err != nil {
		return nil, fmt.Errorf("error assembling website configuration: %w", err)
	}
	command.Config.Payload = xml.Header + string(xmlData)
	return command, nil
}

func convertWebsiteJsonToXml(websiteString string) ([]byte, error) {
	websiteConfiguration := WebsiteConfiguration{
		XMLNamespace: "https://s3.amazonaws.com/doc/2006-03-01/",
	}
	if err := json.Unmarshal([]byte(websiteString), &websiteConfiguration); err != nil {
		return nil, fmt.Errorf("error unmarshaling website string: %w", err)
	}
	xmlData, err := xml.Marshal(websiteConfiguration)
	if err != nil {
		return nil, fmt.Errorf("error marshalling XML: %w", err)
	}
	return xmlData, nil
}
