// Copyright 2026 Versity Software
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
	"strconv"
	"strings"

	"github.com/versity/versitygw/debuglogger"
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
	Redirect  *Redirect             `xml:"Redirect"`
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
			debuglogger.Logf("website redirect conflicts with config")
			return s3err.GetAPIError(s3err.ErrMalformedXML)
		}
		if c.RedirectAllRequestsTo.HostName == "" {
			debuglogger.Logf("website redirect hostname is empty")
			return s3err.GetAPIError(s3err.ErrMalformedXML)
		}
		if err := validateProtocol(c.RedirectAllRequestsTo.Protocol); err != nil {
			return err
		}
		return nil
	}

	if c.IndexDocument == nil {
		debuglogger.Logf("website index document is missing")
		return s3err.GetAPIError(s3err.ErrMalformedXML)
	}
	if c.IndexDocument.Suffix == "" {
		debuglogger.Logf("website index suffix is empty")
		return s3err.GetInvalidArgumentErr(s3err.InvalidArgIndexDocumentSuffix, c.IndexDocument.Suffix)
	}
	if strings.Contains(c.IndexDocument.Suffix, "/") {
		debuglogger.Logf("website index suffix contains slash")
		return s3err.GetInvalidArgumentErr(s3err.InvalidArgIndexDocumentSuffix, c.IndexDocument.Suffix)
	}

	if c.ErrorDocument != nil && c.ErrorDocument.Key == "" {
		debuglogger.Logf("website error document key is empty")
		return s3err.GetInvalidArgumentErr(s3err.InvalidArgErrorDocumentKey, "")
	}

	if len(c.RoutingRules) > maxRoutingRules {
		debuglogger.Logf("too many website routing rules: %d", len(c.RoutingRules))
		return s3err.GetWebsiteRoutingRulesLimitedErr(len(c.RoutingRules))
	}

	for _, rule := range c.RoutingRules {
		if err := rule.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// Validate checks a single routing rule for validity.
func (r *RoutingRule) Validate() error {
	if err := r.Redirect.Validate(); err != nil {
		return err
	}

	if err := r.Condition.Validate(); err != nil {
		return err
	}

	return nil
}

func (c *RoutingRuleCondition) Validate() error {
	if c == nil {
		return nil
	}

	if c.HttpErrorCodeReturnedEquals == "" && c.KeyPrefixEquals == "" {
		debuglogger.Logf("website routing rule condition is empty")
		return s3err.GetAPIError(s3err.ErrMalformedXML)
	}

	return isValidHTTPCode(c.HttpErrorCodeReturnedEquals, validateErrorCode)
}

func (r *Redirect) Validate() error {
	if r == nil {
		return nil
	}

	if r.HostName == "" &&
		r.HttpRedirectCode == "" &&
		r.Protocol == "" &&
		r.ReplaceKeyPrefixWith == "" &&
		r.ReplaceKeyWith == "" {
		debuglogger.Logf("website routing rule redirect is empty")
		return s3err.GetAPIError(s3err.ErrMalformedXML)
	}

	if r.ReplaceKeyWith != "" && r.ReplaceKeyPrefixWith != "" {
		debuglogger.Logf("website redirect has both key replacements")
		return s3err.GetAPIError(s3err.ErrBothReplaceKeyAndPrefix)
	}

	if err := validateProtocol(r.Protocol); err != nil {
		return err
	}

	if err := isValidHTTPCode(r.HttpRedirectCode, validateRedirectCode); err != nil {
		return err
	}

	return nil
}

type httpCodeValidator func(code int) error

func isValidHTTPCode(input string, validateCode httpCodeValidator) error {
	if input == "" {
		return nil
	}

	code, err := strconv.Atoi(input)
	if err != nil {
		return s3err.GetAPIError(s3err.ErrMalformedXML)
	}

	return validateCode(code)
}

// isValidErrorCode checks if the provided code is a valid
// HTTP error code: S3 considers 400-417 and 500-505 as valid
func validateErrorCode(code int) error {
	if (code >= 400 && code <= 417) || (code >= 500 && code <= 505) {
		return nil
	}

	debuglogger.Logf("invalid website error code: %d", code)
	return s3err.GetInvalidHTTPErrorCodeErr(code)
}

// validateRedirectCode check if the provided code
// is a valid HTTP redirect code
func validateRedirectCode(code int) error {
	switch code {
	case 301, 302, 303, 304, 305, 307, 308:
		return nil
	}

	debuglogger.Logf("invalid website redirect code: %d", code)
	return s3err.GetInvalidRedirectCodeErr(code)
}

func validateProtocol(protocol string) error {
	if protocol != "" && protocol != "http" && protocol != "https" {
		debuglogger.Logf("invalid website redirect protocol: %q", protocol)
		return s3err.GetAPIError(s3err.ErrInvalidWebsiteRedirectProtocol)
	}
	return nil
}

// ParseWebsiteConfigOutput parses raw bytes into a WebsiteConfiguration.
func ParseWebsiteConfigOutput(data []byte) (*WebsiteConfiguration, error) {
	var config WebsiteConfiguration
	err := xml.Unmarshal(data, &config)
	if err != nil {
		debuglogger.Logf("failed to parse website config: %v", err)
		return nil, fmt.Errorf("failed to parse website config: %w", err)
	}

	return &config, nil
}

// MatchPrefetchRoutingRule returns the first rule that can be evaluated before
// attempting an object read. Only prefix-only conditions participate in this
// phase.
func (c *WebsiteConfiguration) MatchPrefetchRoutingRule(key string) *RoutingRule {
	for i := range c.RoutingRules {
		rule := &c.RoutingRules[i]
		condition := rule.Condition
		if condition == nil ||
			condition.KeyPrefixEquals == "" ||
			condition.HttpErrorCodeReturnedEquals != "" {
			continue
		}

		if condition.KeyPrefixEquals != "" && strings.HasPrefix(key, condition.KeyPrefixEquals) {
			return rule
		}
	}

	return nil
}

// MatchPostErrorRoutingRule returns the first rule that matches after a 4xx
// object-read error. Prefix-only rules are skipped because they have already
// been evaluated in the pre-fetch phase.
func (c *WebsiteConfiguration) MatchPostErrorRoutingRule(key string, statusCode int) *RoutingRule {
	for i := range c.RoutingRules {
		rule := &c.RoutingRules[i]
		condition := rule.Condition
		if condition != nil && condition.HttpErrorCodeReturnedEquals == "" {
			continue
		}

		if condition.Matches(key, statusCode) {
			return rule
		}
	}

	return nil
}

// Matches reports whether all configured condition fields match.
func (c *RoutingRuleCondition) Matches(key string, statusCode int) bool {
	if c == nil {
		return true
	}

	if c.KeyPrefixEquals != "" && !strings.HasPrefix(key, c.KeyPrefixEquals) {
		return false
	}

	if c.HttpErrorCodeReturnedEquals != "" &&
		strconv.Itoa(statusCode) != c.HttpErrorCodeReturnedEquals {
		return false
	}

	return true
}
