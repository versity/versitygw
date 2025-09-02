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

package auth

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/s3err"
)

// headerRegex is the regexp to validate http header names
var headerRegex = regexp.MustCompile(`^[!#$%&'*+\-.^_` + "`" + `|~0-9A-Za-z]+$`)

type CORSHeader string
type CORSHTTPMethod string

// IsValid validates the CORS http header
// the rules are based on http RFC
// https://datatracker.ietf.org/doc/html/rfc7230#section-3.2
//
// Empty values are considered as valid
func (ch CORSHeader) IsValid() bool {
	return ch == "" || headerRegex.MatchString(ch.String())
}

// String converts the header value to 'string'
func (ch CORSHeader) String() string {
	return string(ch)
}

// ToLower converts the header to lower case
func (ch CORSHeader) ToLower() string {
	return strings.ToLower(string(ch))
}

// IsValid validates the cors http request method:
// the methods are case sensitive
func (cm CORSHTTPMethod) IsValid() bool {
	return cm.IsEmpty() || cm == http.MethodGet || cm == http.MethodHead || cm == http.MethodPut ||
		cm == http.MethodPost || cm == http.MethodDelete
}

// IsEmpty checks if the cors method is an empty string
func (cm CORSHTTPMethod) IsEmpty() bool {
	return cm == ""
}

// String converts the method value to 'string'
func (cm CORSHTTPMethod) String() string {
	return string(cm)
}

type CORSConfiguration struct {
	Rules []CORSRule `xml:"CORSRule"`
}

// Validate validates the cors configuration rules
func (cc *CORSConfiguration) Validate() error {
	if cc == nil || cc.Rules == nil {
		debuglogger.Logf("invalid CORS configuration")
		return s3err.GetAPIError(s3err.ErrMalformedXML)
	}

	if len(cc.Rules) == 0 {
		debuglogger.Logf("empty CORS config rules")
		return s3err.GetAPIError(s3err.ErrMalformedXML)
	}

	// validate each CORS rule
	for _, rule := range cc.Rules {
		if err := rule.Validate(); err != nil {
			return err
		}
	}

	return nil
}

type CORSAllowanceConfig struct {
	Origin           string
	Methods          string
	ExposedHeaders   string
	AllowCredentials string
	AllowHeaders     string
	MaxAge           *int32
}

// IsAllowed walks through the CORS rules and finds the first one allowing access.
// If no rule grants access, returns 'AccessForbidden'
func (cc *CORSConfiguration) IsAllowed(origin string, method CORSHTTPMethod, headers []CORSHeader) (*CORSAllowanceConfig, error) {
	// if method is empty, anyways cors is forbidden
	// skip, without going through the rules
	if method.IsEmpty() {
		debuglogger.Logf("empty Access-Control-Request-Method")
		return nil, s3err.GetAPIError(s3err.ErrCORSForbidden)
	}
	for _, rule := range cc.Rules {
		// find the first rule granting access
		if isAllowed, wilcardOrigin := rule.Match(origin, method, headers); isAllowed {
			o := origin
			allowCredentials := "true"
			if wilcardOrigin {
				o = "*"
				allowCredentials = "false"
			}

			return &CORSAllowanceConfig{
				Origin:           o,
				AllowCredentials: allowCredentials,
				Methods:          rule.GetAllowedMethods(),
				ExposedHeaders:   rule.GetExposeHeaders(),
				AllowHeaders:     buildAllowedHeaders(headers),
				MaxAge:           rule.MaxAgeSeconds,
			}, nil
		}
	}

	// if no matching rule is found, return AccessForbidden
	return nil, s3err.GetAPIError(s3err.ErrCORSForbidden)
}

type CORSRule struct {
	AllowedMethods []CORSHTTPMethod `xml:"AllowedMethod"`
	AllowedHeaders []CORSHeader     `xml:"AllowedHeader"`
	ExposeHeaders  []CORSHeader     `xml:"ExposeHeader"`
	AllowedOrigins []string         `xml:"AllowedOrigin"`
	ID             *string
	MaxAgeSeconds  *int32
}

// Validate validates and returns error if CORS configuration has invalid rule
func (cr *CORSRule) Validate() error {
	// validate CORS allowed headers
	for _, header := range cr.AllowedHeaders {
		if !header.IsValid() {
			debuglogger.Logf("invalid CORS allowed header: %s", header)
			return s3err.GetInvalidCORSHeaderErr(header.String())
		}
	}
	// validate CORS allowed methods
	for _, method := range cr.AllowedMethods {
		if !method.IsValid() {
			debuglogger.Logf("invalid CORS allowed method: %s", method)
			return s3err.GetUnsopportedCORSMethodErr(method.String())
		}
	}
	// validate CORS expose headers
	for _, header := range cr.ExposeHeaders {
		if !header.IsValid() {
			debuglogger.Logf("invalid CORS exposed header: %s", header)
			return s3err.GetInvalidCORSHeaderErr(header.String())
		}
	}

	return nil
}

// Match matches the provided origin, method and headers with the
// CORS configuration rule
// if the matching origin is "*", it returns true as the first argument
func (cr *CORSRule) Match(origin string, method CORSHTTPMethod, headers []CORSHeader) (bool, bool) {
	wildcardOrigin := false
	originFound := false

	// check if the provided origin exists in CORS AllowedOrigins
	for _, or := range cr.AllowedOrigins {
		if wildcardMatch(or, origin) {
			originFound = true
			if or == "*" {
				// mark wildcardOrigin as true, if "*" is found in AllowedOrigins
				wildcardOrigin = true
			}
			break
		}
	}

	if !originFound {
		return false, false
	}

	// cache the CORS AllowedMethods in a map
	allowedMethods := cacheCORSMethods(cr.AllowedMethods)
	// check if the provided method exists in CORS AllowedMethods
	if _, ok := allowedMethods[method]; !ok {
		return false, false
	}

	// check is CORS rule allowed headers match
	// with the requested allowed headers
	for _, reqHeader := range headers {
		match := false
		for _, header := range cr.AllowedHeaders {
			if wildcardMatch(header.ToLower(), reqHeader.ToLower()) {
				match = true
				break
			}
		}

		if !match {
			return false, false
		}
	}

	return true, wildcardOrigin
}

// GetExposeHeaders returns comma separated CORS expose headers
func (cr *CORSRule) GetExposeHeaders() string {
	var result strings.Builder

	for i, h := range cr.ExposeHeaders {
		if i > 0 {
			result.WriteString(", ")
		}
		result.WriteString(h.String())
	}

	return result.String()
}

// buildAllowedHeaders builds a comma separated string from []CORSHeader
func buildAllowedHeaders(headers []CORSHeader) string {
	var result strings.Builder

	for i, h := range headers {
		if i > 0 {
			result.WriteString(", ")
		}
		result.WriteString(h.ToLower())
	}

	return result.String()
}

// GetAllowedMethods returns comma separated CORS allowed methods
func (cr *CORSRule) GetAllowedMethods() string {
	var result strings.Builder

	for i, m := range cr.AllowedMethods {
		if i > 0 {
			result.WriteString(", ")
		}
		result.WriteString(m.String())
	}

	return result.String()
}

// ParseCORSOutput parses raw bytes to 'CORSConfiguration'
func ParseCORSOutput(data []byte) (*CORSConfiguration, error) {
	var config CORSConfiguration
	err := xml.Unmarshal(data, &config)
	if err != nil {
		debuglogger.Logf("unmarshal cors output: %v", err)
		return nil, fmt.Errorf("failed to parse cors config: %w", err)
	}

	return &config, nil
}

func cacheCORSMethods(input []CORSHTTPMethod) map[CORSHTTPMethod]struct{} {
	result := make(map[CORSHTTPMethod]struct{}, len(input))
	for _, el := range input {
		result[el] = struct{}{}
	}

	return result
}

// ParseCORSHeaders parses/validates Access-Control-Request-Headers
// and returns []CORSHeaders
func ParseCORSHeaders(headers string) ([]CORSHeader, error) {
	result := []CORSHeader{}
	if headers == "" {
		return result, nil
	}

	headersSplitted := strings.Split(headers, ",")
	for _, h := range headersSplitted {
		corsHeader := CORSHeader(strings.TrimSpace(h))
		if corsHeader == "" || !corsHeader.IsValid() {
			debuglogger.Logf("invalid access control header: %s", h)
			return nil, s3err.GetInvalidCORSRequestHeaderErr(h)
		}
		result = append(result, corsHeader)
	}

	return result, nil
}

func wildcardMatch(pattern, input string) bool {
	pIdx, sIdx := 0, 0
	starIdx, matchIdx := -1, 0

	for sIdx < len(input) {
		if pIdx < len(pattern) && pattern[pIdx] == input[sIdx] {
			// exact match of current char
			sIdx++
			pIdx++
		} else if pIdx < len(pattern) && pattern[pIdx] == '*' {
			// remember star position
			starIdx = pIdx
			matchIdx = sIdx
			pIdx++
		} else if starIdx != -1 {
			// backtrack: try to match more characters with '*'
			pIdx = starIdx + 1
			matchIdx++
			sIdx = matchIdx
		} else {
			return false
		}
	}

	// skip trailing stars
	for pIdx < len(pattern) && pattern[pIdx] == '*' {
		pIdx++
	}

	return pIdx == len(pattern)
}
