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
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/versity/versitygw/s3err"
)

func TestCORSOrigin_Validate(t *testing.T) {
	tests := []struct {
		name  string
		input string
		err   error
	}{
		{"invalid double wildcard", "*hello*", s3err.GetMultipleWildcardCORSOriginErr("*hello*")},
		{"invalid double wildcard 2", "something**", s3err.GetMultipleWildcardCORSOriginErr("something**")},
		{"invalid double wildcard 3", "som*eth*ing", s3err.GetMultipleWildcardCORSOriginErr("som*eth*ing")},
		{"invalid multiple wildcard", "http://*.example.com/*/path/*", s3err.GetMultipleWildcardCORSOriginErr("http://*.example.com/*/path/*")},
		{"invalid multiple wildcard 2", "http://example.com/*/so/*/much/*/wildcards/*/in/*/this/*/path", s3err.GetMultipleWildcardCORSOriginErr("http://example.com/*/so/*/much/*/wildcards/*/in/*/this/*/path")},
		{"no wildcard", "http://127.0.0.1:8080", nil},
		{"one wildcard", "http://127.0.0.1:8080/*", nil},
		// empty string - valid
		{"empty origin", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			co := CORSOrigin(tt.input)
			gotErr := co.Validate()
			assert.Equal(t, tt.err, gotErr)
		})
	}
}

func TestCORSHeader_IsValid(t *testing.T) {
	tests := []struct {
		name   string
		header CORSHeader
		want   bool
	}{
		{"empty", "", true},
		{"valid", "X-Custom-Header", true},
		{"invalid_1", "Invalid Header", false},
		{"invalid_2", "invalid/header", false},
		{"invalid_3", "Invalid\tHeader", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.header.IsValid(); got != tt.want {
				t.Errorf("IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCORSHTTPMethod_IsValid(t *testing.T) {
	tests := []struct {
		name   string
		method CORSHTTPMethod
		want   bool
	}{
		{"empty invalid", "", false},
		{"GET valid", http.MethodGet, true},
		{"HEAD valid", http.MethodHead, true},
		{"PUT valid", http.MethodPut, true},
		{"POST valid", http.MethodPost, true},
		{"DELETE valid", http.MethodDelete, true},
		{"get valid", "get", false},
		{"put valid", "put", false},
		{"post valid", "post", false},
		{"head valid", "head", false},
		{"invalid", "FOO", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.method.IsValid(); got != tt.want {
				t.Errorf("IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCORSHeader_ToLower(t *testing.T) {
	tests := []struct {
		name   string
		header CORSHeader
		want   string
	}{
		{
			name:   "already lowercase",
			header: CORSHeader("content-type"),
			want:   "content-type",
		},
		{
			name:   "mixed case",
			header: CORSHeader("X-CuStOm-HeAdEr"),
			want:   "x-custom-header",
		},
		{
			name:   "uppercase",
			header: CORSHeader("AUTHORIZATION"),
			want:   "authorization",
		},
		{
			name:   "empty string",
			header: CORSHeader(""),
			want:   "",
		},
		{
			name:   "numeric and symbols",
			header: CORSHeader("X-123-HEADER"),
			want:   "x-123-header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.header.ToLower()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCORSHTTPMethod_IsEmpty(t *testing.T) {
	tests := []struct {
		name   string
		method CORSHTTPMethod
		want   bool
	}{
		{
			name:   "empty string is empty",
			method: CORSHTTPMethod(""),
			want:   true,
		},
		{
			name:   "GET method is not empty",
			method: CORSHTTPMethod("GET"),
			want:   false,
		},
		{
			name:   "random string is not empty",
			method: CORSHTTPMethod("FOO"),
			want:   false,
		},
		{
			name:   "lowercase get is not empty (case sensitive)",
			method: CORSHTTPMethod("get"),
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.method.IsEmpty()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCORSConfiguration_Validate(t *testing.T) {
	tests := []struct {
		name string
		cfg  *CORSConfiguration
		want error
	}{
		{"nil config", nil, s3err.GetAPIError(s3err.ErrMalformedXML)},
		{"nil rules", &CORSConfiguration{}, s3err.GetAPIError(s3err.ErrMalformedXML)},
		{"empty rules", &CORSConfiguration{Rules: []CORSRule{}}, s3err.GetAPIError(s3err.ErrMalformedXML)},
		{"invalid rule", &CORSConfiguration{Rules: []CORSRule{{
			AllowedHeaders: []CORSHeader{"Invalid Header"},
			AllowedOrigins: []CORSOrigin{"origin"},
			AllowedMethods: []CORSHTTPMethod{http.MethodPut},
		}}}, s3err.GetInvalidCORSHeaderErr("Invalid Header")},
		{"valid rule", &CORSConfiguration{Rules: []CORSRule{{
			AllowedOrigins: []CORSOrigin{"origin"},
			AllowedHeaders: []CORSHeader{"X-Test"},
			AllowedMethods: []CORSHTTPMethod{http.MethodGet},
			ExposeHeaders:  []CORSHeader{"X-Expose"},
		}}}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			assert.EqualValues(t, tt.want, err)
		})
	}
}

func TestCORSConfiguration_IsAllowed(t *testing.T) {
	type input struct {
		cfg     *CORSConfiguration
		origin  string
		method  CORSHTTPMethod
		headers []CORSHeader
	}
	type output struct {
		result *CORSAllowanceConfig
		err    error
	}
	tests := []struct {
		name   string
		input  input
		output output
	}{
		{
			name: "allowed exact origin",
			input: input{
				cfg: &CORSConfiguration{Rules: []CORSRule{{
					AllowedOrigins: []CORSOrigin{"http://allowed.com"},
					AllowedMethods: []CORSHTTPMethod{http.MethodGet},
					AllowedHeaders: []CORSHeader{"X-Test"},
				}}},
				origin:  "http://allowed.com",
				method:  http.MethodGet,
				headers: []CORSHeader{"X-Test"},
			},
			output: output{
				result: &CORSAllowanceConfig{
					Origin:           "http://allowed.com",
					AllowCredentials: "true",
					Methods:          http.MethodGet,
					AllowHeaders:     "x-test",
					ExposedHeaders:   "",
					MaxAge:           nil,
				},
				err: nil,
			},
		},
		{
			name: "allowed wildcard origin",
			input: input{
				cfg: &CORSConfiguration{Rules: []CORSRule{{
					AllowedOrigins: []CORSOrigin{"*"},
					AllowedMethods: []CORSHTTPMethod{http.MethodGet},
					AllowedHeaders: []CORSHeader{"X-Test"},
				}}},
				origin:  "anything",
				method:  http.MethodGet,
				headers: []CORSHeader{"X-Test"},
			},
			output: output{
				result: &CORSAllowanceConfig{
					Origin:           "*",
					AllowCredentials: "false",
					AllowHeaders:     "x-test",
					Methods:          http.MethodGet,
					ExposedHeaders:   "",
					MaxAge:           nil,
				},
				err: nil,
			},
		},
		{
			name: "forbidden no matching origin",
			input: input{
				cfg: &CORSConfiguration{Rules: []CORSRule{{
					AllowedOrigins: []CORSOrigin{"http://nope.com"},
				}}},
				origin: "http://not-allowed.com",
				method: http.MethodGet,
			},
			output: output{
				result: nil,
				err:    s3err.GetAPIError(s3err.ErrCORSForbidden),
			},
		},
		{
			name: "forbidden method not allowed",
			input: input{
				cfg: &CORSConfiguration{Rules: []CORSRule{{
					AllowedOrigins: []CORSOrigin{"http://allowed.com"},
					AllowedMethods: []CORSHTTPMethod{http.MethodPost},
					AllowedHeaders: []CORSHeader{"X-Test"},
				}}},
				origin:  "http://allowed.com",
				method:  http.MethodGet,
				headers: []CORSHeader{"X-Test"},
			},
			output: output{
				result: nil,
				err:    s3err.GetAPIError(s3err.ErrCORSForbidden),
			},
		},
		{
			name: "forbidden header not allowed",
			input: input{
				cfg: &CORSConfiguration{Rules: []CORSRule{{
					AllowedOrigins: []CORSOrigin{"http://allowed.com"},
					AllowedMethods: []CORSHTTPMethod{http.MethodGet},
					AllowedHeaders: []CORSHeader{"X-Test"},
				}}},
				origin:  "http://allowed.com",
				method:  http.MethodGet,
				headers: []CORSHeader{"X-Nope"},
			},
			output: output{
				result: nil,
				err:    s3err.GetAPIError(s3err.ErrCORSForbidden),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.input.cfg.IsAllowed(tt.input.origin, tt.input.method, tt.input.headers)
			assert.EqualValues(t, tt.output.err, err)
			assert.EqualValues(t, tt.output.result, got)
		})
	}
}

func TestCORSRule_Validate(t *testing.T) {
	tests := []struct {
		name string
		rule CORSRule
		want error
	}{
		{
			name: "valid rule",
			rule: CORSRule{
				AllowedOrigins: []CORSOrigin{"http://allowed.com"},
				AllowedMethods: []CORSHTTPMethod{http.MethodGet},
				AllowedHeaders: []CORSHeader{"X-Test"},
			},
			want: nil,
		},
		{
			name: "empty allowed origins",
			rule: CORSRule{
				AllowedOrigins: []CORSOrigin{},
				AllowedMethods: []CORSHTTPMethod{http.MethodPost},
				AllowedHeaders: []CORSHeader{"X-Test"},
			},
			want: s3err.GetAPIError(s3err.ErrMalformedXML),
		},
		{
			name: "invalid allowed origins",
			rule: CORSRule{
				AllowedOrigins: []CORSOrigin{"http://allowed*/*"},
				AllowedMethods: []CORSHTTPMethod{http.MethodGet},
				AllowedHeaders: []CORSHeader{"X-Test"},
			},
			want: s3err.GetMultipleWildcardCORSOriginErr("http://allowed*/*"),
		},
		{
			name: "invalid allowed methods",
			rule: CORSRule{
				AllowedOrigins: []CORSOrigin{"http://allowed.com"},
				AllowedMethods: []CORSHTTPMethod{"invalid_method"},
				AllowedHeaders: []CORSHeader{"X-Test"},
			},
			want: s3err.GetUnsopportedCORSMethodErr("invalid_method"),
		},
		{
			name: "empty allowed methods",
			rule: CORSRule{
				AllowedOrigins: []CORSOrigin{"http://allowed.com"},
				AllowedMethods: []CORSHTTPMethod{},
				AllowedHeaders: []CORSHeader{"X-Test"},
			},
			want: s3err.GetAPIError(s3err.ErrMalformedXML),
		},
		{
			name: "invalid allowed header",
			rule: CORSRule{
				AllowedOrigins: []CORSOrigin{"http://allowed.com"},
				AllowedMethods: []CORSHTTPMethod{http.MethodGet},
				AllowedHeaders: []CORSHeader{"Invalid Header"},
			},
			want: s3err.GetInvalidCORSHeaderErr("Invalid Header"),
		},
		{
			name: "invalid allowed header",
			rule: CORSRule{
				AllowedOrigins: []CORSOrigin{"http://allowed.com"},
				AllowedMethods: []CORSHTTPMethod{http.MethodGet},
				AllowedHeaders: []CORSHeader{"Content-Length"},
				ExposeHeaders:  []CORSHeader{"Content-Encoding", "invalid header"},
			},
			want: s3err.GetInvalidCORSHeaderErr("invalid header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			assert.EqualValues(t, tt.want, err)
		})
	}
}

func TestCORSRule_Match(t *testing.T) {
	type input struct {
		rule    CORSRule
		origin  string
		method  CORSHTTPMethod
		headers []CORSHeader
	}
	type output struct {
		isAllowed  bool
		isWildcard bool
	}
	tests := []struct {
		name   string
		input  input
		output output
	}{
		{
			name: "exact origin and method match",
			input: input{
				rule: CORSRule{
					AllowedOrigins: []CORSOrigin{"http://allowed.com"},
					AllowedMethods: []CORSHTTPMethod{http.MethodGet},
					AllowedHeaders: []CORSHeader{"X-Test"},
				},
				origin:  "http://allowed.com",
				method:  http.MethodGet,
				headers: []CORSHeader{"X-Test"},
			},
			output: output{isAllowed: true, isWildcard: false},
		},
		{
			name: "wildcard origin match",
			input: input{
				rule: CORSRule{
					AllowedOrigins: []CORSOrigin{"*"},
					AllowedMethods: []CORSHTTPMethod{http.MethodPost},
					AllowedHeaders: []CORSHeader{"X-Test"},
				},
				origin:  "http://random.com",
				method:  http.MethodPost,
				headers: []CORSHeader{"X-Test"},
			},
			output: output{isAllowed: true, isWildcard: true},
		},
		{
			name: "wildcard containing origin match",
			input: input{
				rule: CORSRule{
					AllowedOrigins: []CORSOrigin{"http://random*"},
					AllowedMethods: []CORSHTTPMethod{http.MethodPost},
					AllowedHeaders: []CORSHeader{"X-Test"},
				},
				origin:  "http://random.com",
				method:  http.MethodPost,
				headers: []CORSHeader{"X-Test"},
			},
			output: output{isAllowed: true, isWildcard: false},
		},
		{
			name: "wildcard allowed headers match",
			input: input{
				rule: CORSRule{
					AllowedOrigins: []CORSOrigin{"http://something.com"},
					AllowedMethods: []CORSHTTPMethod{http.MethodPost},
					AllowedHeaders: []CORSHeader{"X-*"},
				},
				origin:  "http://something.com",
				method:  http.MethodPost,
				headers: []CORSHeader{"X-Test", "X-Something", "X-Anyting"},
			},
			output: output{isAllowed: true, isWildcard: false},
		},
		{
			name: "origin mismatch",
			input: input{
				rule: CORSRule{
					AllowedOrigins: []CORSOrigin{"http://allowed.com"},
					AllowedMethods: []CORSHTTPMethod{http.MethodGet},
					AllowedHeaders: []CORSHeader{"X-Test"},
				},
				origin:  "http://notallowed.com",
				method:  http.MethodGet,
				headers: []CORSHeader{"X-Test"},
			},
			output: output{isAllowed: false, isWildcard: false},
		},
		{
			name: "method mismatch",
			input: input{
				rule: CORSRule{
					AllowedOrigins: []CORSOrigin{"http://allowed.com"},
					AllowedMethods: []CORSHTTPMethod{http.MethodPost},
					AllowedHeaders: []CORSHeader{"X-Test"},
				},
				origin:  "http://allowed.com",
				method:  http.MethodGet,
				headers: []CORSHeader{"X-Test"},
			},
			output: output{isAllowed: false, isWildcard: false},
		},
		{
			name: "header mismatch",
			input: input{
				rule: CORSRule{
					AllowedOrigins: []CORSOrigin{"http://allowed.com"},
					AllowedMethods: []CORSHTTPMethod{http.MethodGet},
					AllowedHeaders: []CORSHeader{"X-Test"},
				},
				origin:  "http://allowed.com",
				method:  http.MethodGet,
				headers: []CORSHeader{"X-Other"},
			},
			output: output{isAllowed: false, isWildcard: false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isAllowed, wild := tt.input.rule.Match(tt.input.origin, tt.input.method, tt.input.headers)
			assert.Equal(t, tt.output.isAllowed, isAllowed)
			assert.Equal(t, tt.output.isWildcard, wild)
		})
	}
}

func TestGetExposeHeaders(t *testing.T) {
	tests := []struct {
		name string
		rule CORSRule
		want string
	}{
		{"multiple headers", CORSRule{ExposeHeaders: []CORSHeader{"Content-Length", "Content-Type", "Content-Encoding"}}, "Content-Length, Content-Type, Content-Encoding"},
		{"single header", CORSRule{ExposeHeaders: []CORSHeader{"Authorization"}}, "Authorization"},
		{"no headers", CORSRule{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.rule.GetExposeHeaders()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBuildAllowedHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers []CORSHeader
		want    string
	}{
		{
			name:    "empty slice returns empty string",
			headers: []CORSHeader{},
			want:    "",
		},
		{
			name:    "single header lowercase",
			headers: []CORSHeader{"Content-Type"},
			want:    "content-type",
		},
		{
			name:    "multiple headers lowercased with commas",
			headers: []CORSHeader{"Content-Type", "X-Custom-Header", "Authorization"},
			want:    "content-type, x-custom-header, authorization",
		},
		{
			name:    "already lowercase header",
			headers: []CORSHeader{"accept"},
			want:    "accept",
		},
		{
			name:    "mixed case headers",
			headers: []CORSHeader{"ACCEPT", "x-Powered-By"},
			want:    "accept, x-powered-by",
		},
		{
			name:    "empty header value",
			headers: []CORSHeader{""},
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildAllowedHeaders(tt.headers)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetAllowedMethods(t *testing.T) {
	tests := []struct {
		name string
		rule CORSRule
		want string
	}{
		{"multiple methods", CORSRule{AllowedMethods: []CORSHTTPMethod{http.MethodGet, http.MethodPost, http.MethodPut}}, "GET, POST, PUT"},
		{"single method", CORSRule{AllowedMethods: []CORSHTTPMethod{http.MethodGet}}, "GET"},
		{"no methods", CORSRule{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.rule.GetAllowedMethods()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseCORSOutput(t *testing.T) {
	tests := []struct {
		name string
		data string
		want bool
	}{
		{"valid", `<CORSConfiguration><CORSRule></CORSRule></CORSConfiguration>`, true},
		{"invalid xml", `<CORSConfiguration><CORSRule>`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseCORSOutput([]byte(tt.data))
			if (err == nil) != tt.want {
				t.Errorf("ParseCORSOutput() err = %v, want success=%v", err, tt.want)
			}
			if tt.want && cfg == nil {
				t.Errorf("Expected non-nil config")
			}
		})
	}
}

func TestCacheCORSProps(t *testing.T) {
	tests := []struct {
		name string
		in   []CORSHTTPMethod
		want map[string]struct{}
	}{
		{
			name: "empty CORSHTTPMethod slice",
			in:   []CORSHTTPMethod{},
			want: map[string]struct{}{},
		},
		{
			name: "single CORSHTTPMethod",
			in:   []CORSHTTPMethod{http.MethodGet},
			want: map[string]struct{}{http.MethodGet: {}},
		},
		{
			name: "multiple CORSHTTPMethods",
			in:   []CORSHTTPMethod{http.MethodGet, http.MethodPost, http.MethodPut},
			want: map[string]struct{}{
				http.MethodGet:  {},
				http.MethodPost: {},
				http.MethodPut:  {},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cacheCORSMethods(tt.in)
			assert.Equal(t, len(tt.want), len(got))
			for key := range tt.want {
				_, ok := got[CORSHTTPMethod(key)]
				assert.True(t, ok)
			}
		})
	}
}

func TestParseCORSHeaders(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []CORSHeader
		err  error
	}{
		{
			name: "empty string",
			in:   "",
			want: []CORSHeader{},
			err:  nil,
		},
		{
			name: "single valid header",
			in:   "X-Test",
			want: []CORSHeader{"X-Test"},
			err:  nil,
		},
		{
			name: "multiple valid headers with spaces",
			in:   "X-Test, Content-Type, Authorization",
			want: []CORSHeader{"X-Test", "Content-Type", "Authorization"},
			err:  nil,
		},
		{
			name: "header with leading/trailing spaces",
			in:   "   X-Test   ",
			want: []CORSHeader{"X-Test"},
			err:  nil,
		},
		{
			name: "contains invalid header",
			in:   "X-Test, Invalid Header, Content-Type",
			want: nil,
			err:  s3err.GetInvalidCORSRequestHeaderErr(" Invalid Header"),
		},
		{
			name: "only invalid header",
			in:   "Invalid Header",
			want: nil,
			err:  s3err.GetInvalidCORSRequestHeaderErr("Invalid Header"),
		},
		{
			name: "multiple commas in a row",
			in:   "X-Test,,Content-Type",
			want: nil,
			err:  s3err.GetInvalidCORSRequestHeaderErr(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCORSHeaders(tt.in)
			assert.EqualValues(t, tt.err, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWildcardMatch(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		input   string
		want    bool
	}{
		// Exact match, no wildcards
		{"exact match", "hello", "hello", true},
		{"exact mismatch", "hello", "hell", false},
		// Single '*' matching zero chars
		{"star matches zero chars", "he*lo", "helo", true},
		// Single '*' matching multiple chars
		{"star matches multiple chars", "he*o", "heyyyyyo", true},
		// '*' at start
		{"star at start", "*world", "hello world", true},
		// '*' at end
		{"star at end", "hello*", "hello there", true},
		// '*' matches whole string
		{"only star", "*", "anything", true},
		{"only star empty", "*", "", true},
		// Multiple '*'s
		{"multiple stars", "a*b*c", "axxxbzzzzyc", true},
		{"multiple stars no match", "a*b*c", "axxxbzzzzy", false},
		// Backtracking needed
		{"backtracking required", "a*b*c", "ab123c", true},
		// No match with star present
		{"star but mismatch", "he*world", "hey there", false},
		// Trailing stars in pattern
		{"trailing stars match", "abc**", "abc", true},
		{"trailing stars match longer", "abc**", "abccc", true},
		// Empty pattern cases
		{"empty pattern and empty input", "", "", true},
		{"empty pattern non-empty input", "", "a", false},
		{"only stars pattern with empty input", "***", "", true},
		// Pattern longer than input
		{"pattern longer no star", "abcd", "abc", false},
		// Input longer but no star
		{"input longer no star", "abc", "abcd", false},
		// Complex interleaved match
		{"complex interleaved", "*a*b*cd*", "xxaYYbZZcd123", true},
		// Star match at the end after mismatch
		{"mismatch then star match", "ab*xyz", "abzzzxyz", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wildcardMatch(tt.pattern, tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}
