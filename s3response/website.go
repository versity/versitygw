// Copyright 2023 Versity Software
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

package s3response

import (
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/versity/versitygw/s3err"
)

const maxRoutingRules = 50

// WebsiteConfiguration represents the S3 bucket website configuration.
type WebsiteConfiguration struct {
	XMLName               xml.Name               `xml:"WebsiteConfiguration"`
	IndexDocument         *IndexDocument         `xml:"IndexDocument,omitempty"`
	ErrorDocument         *ErrorDocument         `xml:"ErrorDocument,omitempty"`
	RedirectAllRequestsTo *RedirectAllRequestsTo `xml:"RedirectAllRequestsTo,omitempty"`
	RoutingRules          []RoutingRule          `xml:"RoutingRules>RoutingRule,omitempty"`
}

// IndexDocument specifies the default object served for directory-like requests.
type IndexDocument struct {
	Suffix string `xml:"Suffix"`
}

// ErrorDocument specifies the object served when an error occurs.
type ErrorDocument struct {
	Key string `xml:"Key"`
}

// RedirectAllRequestsTo redirects all requests to another host.
type RedirectAllRequestsTo struct {
	HostName string `xml:"HostName"`
	Protocol string `xml:"Protocol,omitempty"`
}

// RoutingRule specifies a redirect rule with an optional condition.
type RoutingRule struct {
	Condition *RoutingRuleCondition `xml:"Condition,omitempty"`
	Redirect  Redirect              `xml:"Redirect"`
}

// RoutingRuleCondition specifies when a routing rule applies.
type RoutingRuleCondition struct {
	HttpErrorCodeReturnedEquals string `xml:"HttpErrorCodeReturnedEquals,omitempty"`
	KeyPrefixEquals             string `xml:"KeyPrefixEquals,omitempty"`
}

// Redirect specifies where to redirect matching requests.
type Redirect struct {
	HostName             string `xml:"HostName,omitempty"`
	HttpRedirectCode     string `xml:"HttpRedirectCode,omitempty"`
	Protocol             string `xml:"Protocol,omitempty"`
	ReplaceKeyPrefixWith string `xml:"ReplaceKeyPrefixWith,omitempty"`
	ReplaceKeyWith       string `xml:"ReplaceKeyWith,omitempty"`
}

// Validate checks the website configuration for S3-compatible validity.
func (c *WebsiteConfiguration) Validate() error {
	if c.RedirectAllRequestsTo != nil {
		if c.IndexDocument != nil || c.ErrorDocument != nil || len(c.RoutingRules) > 0 {
			return s3err.GetAPIError(s3err.ErrInvalidWebsiteConfiguration)
		}
		if c.RedirectAllRequestsTo.HostName == "" {
			return s3err.GetAPIError(s3err.ErrInvalidWebsiteConfiguration)
		}
		if err := validateProtocol(c.RedirectAllRequestsTo.Protocol); err != nil {
			return err
		}
		return nil
	}

	if c.IndexDocument == nil {
		return s3err.GetAPIError(s3err.ErrInvalidWebsiteConfiguration)
	}
	if c.IndexDocument.Suffix == "" {
		return s3err.GetAPIError(s3err.ErrInvalidWebsiteSuffix)
	}
	if strings.Contains(c.IndexDocument.Suffix, "/") {
		return s3err.GetAPIError(s3err.ErrInvalidWebsiteSuffix)
	}

	if c.ErrorDocument != nil && c.ErrorDocument.Key == "" {
		return s3err.GetAPIError(s3err.ErrInvalidWebsiteConfiguration)
	}

	if len(c.RoutingRules) > maxRoutingRules {
		return s3err.GetAPIError(s3err.ErrInvalidWebsiteConfiguration)
	}

	for i, rule := range c.RoutingRules {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("routing rule %d: %w", i, err)
		}
	}

	return nil
}

// Validate checks a single routing rule for validity.
func (r *RoutingRule) Validate() error {
	if r.Redirect.ReplaceKeyWith != "" && r.Redirect.ReplaceKeyPrefixWith != "" {
		return s3err.GetAPIError(s3err.ErrInvalidWebsiteConfiguration)
	}

	if err := validateProtocol(r.Redirect.Protocol); err != nil {
		return err
	}

	if r.Redirect.HttpRedirectCode != "" {
		code := r.Redirect.HttpRedirectCode
		if len(code) != 3 || code[0] != '3' {
			return s3err.GetAPIError(s3err.ErrInvalidWebsiteRedirectCode)
		}
	}

	return nil
}

func validateProtocol(protocol string) error {
	if protocol != "" && protocol != "http" && protocol != "https" {
		return s3err.GetAPIError(s3err.ErrInvalidWebsiteConfiguration)
	}
	return nil
}

// ParseWebsiteConfigOutput parses raw bytes into a WebsiteConfiguration.
func ParseWebsiteConfigOutput(data []byte) (*WebsiteConfiguration, error) {
	var config WebsiteConfiguration
	err := xml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse website config: %w", err)
	}

	return &config, nil
}
