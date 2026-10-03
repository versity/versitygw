// Copyright 2026 Versity Software
// Copyright 2026 Gluesys Inc. and Jihyeon Gim
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.  See the License for the specific language governing
// permissions and limitations under the License.

//go:build linux && amd64 && cgo && rdma

package rcroutes

import (
	"errors"
	"testing"
)

func TestSplitTargetQuery(t *testing.T) {
	cases := []struct {
		name   string
		target string
		bucket string
		key    string
		query  string
		ok     bool
	}{
		{"plain", "/b/k", "b", "k", "", true},
		{"query preserved", "/b/k?uploadId=1", "b", "k", "uploadId=1", true},
		{"multi key query", "/b/k?uploadId=1&partNumber=2", "b", "k",
			"uploadId=1&partNumber=2", true},
		{"question mark only", "/b/k?", "b", "k", "", true},
		{"percent decoded", "/b%20/k%2Fone", "b ", "k/one", "", true},
		{"query with encoded slash", "/b/k?a=%2F", "b", "k", "a=%2F", true},
		{"no key", "/b", "", "", "", false},
		{"empty key", "/b/", "", "", "", false},
		{"no bucket", "/k", "", "", "", false},
		{"empty", "", "", "", "", false},
		{"no leading slash", "b/k", "", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, k, q, ok := splitTarget(tc.target)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if b != tc.bucket || k != tc.key || q != tc.query {
				t.Fatalf("got (%q,%q,%q), want (%q,%q,%q)",
					b, k, q, tc.bucket, tc.key, tc.query)
			}
		})
	}
}

func TestValidatePlainQuery(t *testing.T) {
	if err := validatePlainQuery(""); err != nil {
		t.Fatalf("empty query rejected: %v", err)
	}
	for _, query := range []string{
		"uploadId=abc",
		"partNumber=1",
		"uploadId=abc&partNumber=1",
		"checksumCRC32=1",
		"unknown=1",
		"a=%zz", // malformed percent-encoding
	} {
		err := validatePlainQuery(query)
		if err == nil {
			t.Fatalf("query %q accepted", query)
		}
		var bad errRouteBadRequest
		if !errors.As(err, &bad) {
			t.Fatalf("query %q: error is not bad-request class: %v",
				query, err)
		}
	}
}
