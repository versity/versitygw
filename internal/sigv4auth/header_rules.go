// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sigv4auth

import "strings"

// rule reports whether a header name adheres to some signing policy — which
// headers are excluded from signing, which must be signed when present, and
// which are eligible for query-string hoisting on a presigned request.
type rule interface {
	IsValid(value string) bool
}

// rules is a set of rule; IsValid reports whether any rule in the set
// matches (nested/composable rules).
type rules []rule

func (r rules) IsValid(value string) bool {
	for _, rl := range r {
		if rl.IsValid(value) {
			return true
		}
	}
	return false
}

// mapRule is a case-insensitive set-membership rule.
type mapRule map[string]struct{}

func (m mapRule) IsValid(value string) bool {
	for key := range m {
		if strings.EqualFold(key, value) {
			return true
		}
	}
	return false
}

// allowList and excludeList wrap another rule, only for readability at the
// table-definition call site — allowList is a no-op wrapper, excludeList
// inverts.
type allowList struct{ rule }

func (w allowList) IsValid(value string) bool { return w.rule.IsValid(value) }

type excludeList struct{ rule }

func (b excludeList) IsValid(value string) bool { return !b.rule.IsValid(value) }

// patterns matches by case-insensitive prefix.
type patterns []string

func (p patterns) IsValid(value string) bool {
	for _, pattern := range p {
		if hasPrefixFold(value, pattern) {
			return true
		}
	}
	return false
}

// inclusiveRules requires every rule in the set to match.
type inclusiveRules []rule

func (r inclusiveRules) IsValid(value string) bool {
	for _, rl := range r {
		if !rl.IsValid(value) {
			return false
		}
	}
	return true
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[0:len(prefix)], prefix)
}

// ignoredHeaders is excluded from signing regardless of SignedHeaders.
var ignoredHeaders = rules{
	excludeList{
		mapRule{
			"Authorization":     struct{}{},
			"User-Agent":        struct{}{},
			"X-Amzn-Trace-Id":   struct{}{},
			"Expect":            struct{}{},
			"Transfer-Encoding": struct{}{},
		},
	},
}

// requiredSignedHeadersRule is the header-auth SignedHeaders policy: which
// request headers, if present, must appear in SignedHeaders.
var requiredSignedHeadersRule = rules{
	allowList{
		mapRule{
			"Host": struct{}{},
		},
	},
	patterns{"X-Amz-"},
}

// allowedQueryHoisting selects which unsigned headers a presigned request
// may hoist into the query string.
var allowedQueryHoisting = inclusiveRules{
	excludeList{requiredSignedHeadersRule},
	patterns{"X-Amz-"},
}

// IsIgnoredHeader reports whether a header is normally excluded from signing.
func IsIgnoredHeader(header string) bool {
	return !ignoredHeaders.IsValid(header)
}

// IsRequiredSignedHeader reports whether a header must be signed when it is
// present on an incoming request.
func IsRequiredSignedHeader(header string) bool {
	return requiredSignedHeadersRule.IsValid(header)
}
