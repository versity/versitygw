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
	"encoding/json"
	"strings"
)

type Resources map[string]struct{}

const ResourceArnPrefix = "arn:aws:s3:::"

// Override UnmarshalJSON method to decode both []string and string properties
func (r *Resources) UnmarshalJSON(data []byte) error {
	ss := []string{}
	var err error
	if err = json.Unmarshal(data, &ss); err == nil {
		if len(ss) == 0 {
			return policyErrInvalidResource
		}
		*r = make(Resources)
		for _, s := range ss {
			err = r.Add(s)
			if err != nil {
				return err
			}
		}
	} else {
		var s string
		if err = json.Unmarshal(data, &s); err == nil {
			if s == "" {
				return policyErrInvalidResource
			}
			*r = make(Resources)
			err = r.Add(s)
			if err != nil {
				return err
			}
		}
	}

	return err
}

// Adds and validates a new resource to Resources map
func (r Resources) Add(rc string) error {
	ok, pattern := isValidResource(rc)
	if !ok {
		return policyErrInvalidResource
	}

	r[pattern] = struct{}{}

	return nil
}

// Checks if the resources contain object pattern
func (r Resources) ContainsObjectPattern() bool {
	for resource := range r {
		if resource == "*" || strings.Contains(resource, "/") {
			return true
		}
	}

	return false
}

// Checks if the resources contain bucket pattern
func (r Resources) ContainsBucketPattern() bool {
	for resource := range r {
		if resource == "*" || !strings.Contains(resource, "/") {
			return true
		}
	}

	return false
}

// Bucket resources should start with bucket name: arn:aws:s3:::MyBucket/*
func (r Resources) Validate(bucket string) error {
	for resource := range r {
		if !strings.HasPrefix(resource, bucket) {
			return policyErrInvalidResource
		}
	}

	return nil
}

func (r Resources) FindMatch(resource string) bool {
	for res := range r {
		if r.Match(res, resource) {
			return true
		}
	}

	return false
}

// Match checks if the input string matches the given pattern with wildcards (`*`, `?`).
// - `?` matches exactly one occurrence of any character.
// - `*` matches arbitrary many (including zero) occurrences of any character.
func (r Resources) Match(pattern, input string) bool {
	pIdx, sIdx := 0, 0
	starIdx, matchIdx := -1, 0

	for sIdx < len(input) {
		if pIdx < len(pattern) && (pattern[pIdx] == '?' || pattern[pIdx] == input[sIdx]) {
			sIdx++
			pIdx++
		} else if pIdx < len(pattern) && pattern[pIdx] == '*' {
			starIdx = pIdx
			matchIdx = sIdx
			pIdx++
		} else if starIdx != -1 {
			pIdx = starIdx + 1
			matchIdx++
			sIdx = matchIdx
		} else {
			return false
		}
	}

	for pIdx < len(pattern) && pattern[pIdx] == '*' {
		pIdx++
	}

	return pIdx == len(pattern)
}

// Checks the resource to have arn prefix and not starting with /
func isValidResource(rc string) (isValid bool, pattern string) {
	if !strings.HasPrefix(rc, ResourceArnPrefix) {
		return false, ""
	}

	res := strings.TrimPrefix(rc, ResourceArnPrefix)
	if res == "" {
		return false, ""
	}
	// The resource can't start with / (bucket name comes first)
	if strings.HasPrefix(res, "/") {
		return false, ""
	}

	return true, res
}
