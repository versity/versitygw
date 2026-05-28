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
	posixNormalizer := testNormalizeObjectKey

	cases := []struct {
		name       string
		resources  []string
		input      string
		normalizer objectKeyNormalizer
		expected   bool
	}{
		{
			name:      "wildcard object match without normalizer",
			resources: []string{"arn:aws:s3:::my-bucket/*"},
			input:     "my-bucket/my-object",
			expected:  true,
		},
		{
			name:      "wrong bucket without normalizer",
			resources: []string{"arn:aws:s3:::my-bucket/object"},
			input:     "other-bucket/my-object",
			expected:  false,
		},
		{
			name:      "exact object match without normalizer",
			resources: []string{"arn:aws:s3:::my-bucket/object"},
			input:     "my-bucket/object",
			expected:  true,
		},
		{
			name:      "second resource matches without normalizer",
			resources: []string{"arn:aws:s3:::my-bucket/*", "arn:aws:s3:::other-bucket/*"},
			input:     "other-bucket/something",
			expected:  true,
		},
		{
			name:       "normalized private key does not match public prefix",
			resources:  []string{"arn:aws:s3:::my-bucket/public/*"},
			input:      "my-bucket/private.txt",
			normalizer: posixNormalizer,
			expected:   false,
		},
		{
			name:       "policy resource parent segment normalizes before matching",
			resources:  []string{"arn:aws:s3:::my-bucket/public/../private.txt"},
			input:      "my-bucket/private.txt",
			normalizer: posixNormalizer,
			expected:   true,
		},
		{
			name:       "policy resource escaping bucket does not normalize inside bucket",
			resources:  []string{"arn:aws:s3:::my-bucket/../private.txt"},
			input:      "my-bucket/private.txt",
			normalizer: posixNormalizer,
			expected:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Resources{}
			for _, res := range tc.resources {
				if err := r.Add(res); err != nil {
					t.Fatalf("Add(%q): %v", res, err)
				}
			}
			if r.FindMatch(tc.input, tc.normalizer) != tc.expected {
				t.Errorf("Expected FindMatch to be %v for input %s", tc.expected, tc.input)
			}
		})
	}
}

func TestMatch(t *testing.T) {
	r := Resources{}
	posixNormalizer := testNormalizeObjectKey

	cases := []struct {
		name       string
		pattern    string
		input      string
		normalizer objectKeyNormalizer
		expected   bool
	}{
		{
			name:     "wildcard object",
			pattern:  "my-bucket/*",
			input:    "my-bucket/object",
			expected: true,
		},
		{
			name:     "single char wildcard",
			pattern:  "my-bucket/?bject",
			input:    "my-bucket/object",
			expected: true,
		},
		{
			name:     "wrong bucket",
			pattern:  "my-bucket/*",
			input:    "other-bucket/object",
			expected: false,
		},
		{
			name:     "global wildcard",
			pattern:  "*",
			input:    "any-bucket/object",
			expected: true,
		},
		{
			name:     "wildcard nested object",
			pattern:  "my-bucket/*",
			input:    "my-bucket/subdir/object",
			expected: true,
		},
		{
			name:     "bucket only does not match object wildcard",
			pattern:  "my-bucket/*",
			input:    "other-bucket",
			expected: false,
		},
		{
			name:     "missing nested segment",
			pattern:  "my-bucket/*/*",
			input:    "my-bucket/hello",
			expected: false,
		},
		{
			name:     "nested segment",
			pattern:  "my-bucket/*/*",
			input:    "my-bucket/hello/world",
			expected: true,
		},
		{
			name:     "three char segment",
			pattern:  "foo/???/bar",
			input:    "foo/qux/bar",
			expected: true,
		},
		{
			name:     "too long for single char wildcards",
			pattern:  "foo/???/bar",
			input:    "foo/quxx/bar",
			expected: false,
		},
		{
			name:     "mixed wildcards",
			pattern:  "foo/???/bar/*/?",
			input:    "foo/qux/bar/hello/g",
			expected: true,
		},
		{
			name:     "mixed wildcards final segment too long",
			pattern:  "foo/???/bar/*/?",
			input:    "foo/qux/bar/hello/smth",
			expected: false,
		},
		{
			name:       "raw traversal key matches public prefix without normalization",
			pattern:    "my-bucket/public/*",
			input:      "my-bucket/public/../private.txt",
			normalizer: nil,
			expected:   true,
		},
		{
			name:       "normalized traversal key does not match public prefix",
			pattern:    "my-bucket/public/*",
			input:      "my-bucket/private.txt",
			normalizer: posixNormalizer,
			expected:   false,
		},
		{
			name:       "policy resource traversal normalizes to private object",
			pattern:    "my-bucket/public/../private.txt",
			input:      "my-bucket/private.txt",
			normalizer: posixNormalizer,
			expected:   true,
		},
		{
			name:       "policy resource traversal escaping bucket does not match bucket object",
			pattern:    "my-bucket/../private.txt",
			input:      "my-bucket/private.txt",
			normalizer: posixNormalizer,
			expected:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if r.Match(tc.pattern, tc.input, tc.normalizer) != tc.expected {
				t.Errorf("Match(%s, %s) failed, expected %v", tc.pattern, tc.input, tc.expected)
			}
		})
	}
}
