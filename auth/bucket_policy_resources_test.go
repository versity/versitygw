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
	"testing"
)

func TestUnmarshalJSON(t *testing.T) {
	var r Resources

	cases := []struct {
		input    string
		expected int
		wantErr  bool
	}{
		{`"arn:aws:s3:::my-bucket/*"`, 1, false},
		{`["arn:aws:s3:::my-bucket/*", "arn:aws:s3:::other-bucket"]`, 2, false},
		{`""`, 0, true},
		{`[]`, 0, true},
		{`["invalid-bucket"]`, 0, true},
	}

	for _, tc := range cases {
		r = Resources{}
		err := json.Unmarshal([]byte(tc.input), &r)
		if (err != nil) != tc.wantErr {
			t.Errorf("Unexpected error status for input %s: %v", tc.input, err)
		}
		if len(r) != tc.expected {
			t.Errorf("Expected %d resources, got %d", tc.expected, len(r))
		}
	}
}

func TestAdd(t *testing.T) {
	r := Resources{}

	cases := []struct {
		input   string
		wantErr bool
	}{
		{"arn:aws:s3:::valid-bucket/*", false},
		{"arn:aws:s3:::valid-bucket/object", false},
		{"invalid-bucket/*", true},
		{"/invalid-start", true},
	}

	for _, tc := range cases {
		err := r.Add(tc.input)
		if (err != nil) != tc.wantErr {
			t.Errorf("Unexpected error status for input %s: %v", tc.input, err)
		}
	}
}

func TestContainsObjectPattern(t *testing.T) {
	cases := []struct {
		resources []string
		expected  bool
	}{
		{[]string{"arn:aws:s3:::my-bucket/my-object"}, true},
		{[]string{"arn:aws:s3:::my-bucket/*"}, true},
		{[]string{"arn:aws:s3:::my-bucket"}, false},
	}

	for _, tc := range cases {
		r := Resources{}
		for _, res := range tc.resources {
			r.Add(res)
		}
		if r.ContainsObjectPattern() != tc.expected {
			t.Errorf("Expected object pattern to be %v for %v", tc.expected, tc.resources)
		}
	}
}

func TestContainsBucketPattern(t *testing.T) {
	cases := []struct {
		resources []string
		expected  bool
	}{
		{[]string{"arn:aws:s3:::my-bucket"}, true},
		{[]string{"arn:aws:s3:::my-bucket/*"}, false},
		{[]string{"arn:aws:s3:::my-bucket/object"}, false},
	}

	for _, tc := range cases {
		r := Resources{}
		for _, res := range tc.resources {
			r.Add(res)
		}
		if r.ContainsBucketPattern() != tc.expected {
			t.Errorf("Expected bucket pattern to be %v for %v", tc.expected, tc.resources)
		}
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		resources []string
		bucket    string
		expected  bool
	}{
		{[]string{"arn:aws:s3:::valid-bucket/*"}, "valid-bucket", true},
		{[]string{"arn:aws:s3:::wrong-bucket/*"}, "valid-bucket", false},
		{[]string{"arn:aws:s3:::valid-bucket/*", "arn:aws:s3:::valid-bucket/object/*"}, "valid-bucket", true},
	}

	for _, tc := range cases {
		r := Resources{}
		for _, res := range tc.resources {
			r.Add(res)
		}
		if (r.Validate(tc.bucket) == nil) != tc.expected {
			t.Errorf("Expected validation to be %v for bucket %s", tc.expected, tc.bucket)
		}
	}
}

func TestFindMatch(t *testing.T) {
	cases := []struct {
		resources []string
		input     string
		expected  bool
	}{
		{[]string{"arn:aws:s3:::my-bucket/*"}, "my-bucket/my-object", true},
		{[]string{"arn:aws:s3:::my-bucket/object"}, "other-bucket/my-object", false},
		{[]string{"arn:aws:s3:::my-bucket/object"}, "my-bucket/object", true},
		{[]string{"arn:aws:s3:::my-bucket/*", "arn:aws:s3:::other-bucket/*"}, "other-bucket/something", true},
	}

	for _, tc := range cases {
		r := Resources{}
		for _, res := range tc.resources {
			r.Add(res)
		}
		if r.FindMatch(tc.input) != tc.expected {
			t.Errorf("Expected FindMatch to be %v for input %s", tc.expected, tc.input)
		}
	}
}

func TestMatch(t *testing.T) {
	r := Resources{}
	cases := []struct {
		pattern  string
		input    string
		expected bool
	}{
		{"my-bucket/*", "my-bucket/object", true},
		{"my-bucket/?bject", "my-bucket/object", true},
		{"my-bucket/*", "other-bucket/object", false},
		{"*", "any-bucket/object", true},
		{"my-bucket/*", "my-bucket/subdir/object", true},
		{"my-bucket/*", "other-bucket", false},
		{"my-bucket/*/*", "my-bucket/hello", false},
		{"my-bucket/*/*", "my-bucket/hello/world", true},
		{"foo/???/bar", "foo/qux/bar", true},
		{"foo/???/bar", "foo/quxx/bar", false},
		{"foo/???/bar/*/?", "foo/qux/bar/hello/g", true},
		{"foo/???/bar/*/?", "foo/qux/bar/hello/smth", false},
	}
	for _, tc := range cases {
		if r.Match(tc.pattern, tc.input) != tc.expected {
			t.Errorf("Match(%s, %s) failed, expected %v", tc.pattern, tc.input, tc.expected)
		}
	}
}
