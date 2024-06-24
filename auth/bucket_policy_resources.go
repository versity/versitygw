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
			return errInvalidResource
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
				return errInvalidResource
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
		return errInvalidResource
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
			return errInvalidResource
		}
	}

	return nil
}

func (r Resources) FindMatch(resource string) bool {
	for res := range r {
		if strings.HasSuffix(res, "*") {
			pattern := strings.TrimSuffix(res, "*")
			if strings.HasPrefix(resource, pattern) {
				return true
			}
		} else {
			if res == resource {
				return true
			}
		}
	}

	return false
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
