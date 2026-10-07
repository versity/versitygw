// Copyright 2026 Versity Software
// Copyright 2026 Gluesys Inc. and Jihyeon Gim
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
// either express or implied.
// See the License for the specific language governing permissions
// and limitations under the License.

package rcroutes

import (
	"errors"
	"testing"
)

func TestClassifyRCTarget(t *testing.T) {
	const part = "/stack/payload?uploadId=up-1&partNumber=2"

	got, err := classifyRCTarget(true, part)
	if err != nil || !got.partPut || got.uploadID != "up-1" || got.number != 2 {
		t.Fatalf("part put: %+v %v", got, err)
	}

	cases := []struct {
		name  string
		isPut bool
		raw   string
	}{
		{"get part", false, part},
		{"upload id only", true, "/stack/payload?uploadId=up-1"},
		{"part only", true, "/stack/payload?partNumber=2"},
		{"empty id", true, "/stack/payload?uploadId=&partNumber=2"},
		{"zero", true, "/stack/payload?uploadId=up-1&partNumber=0"},
		{"above max", true, "/stack/payload?uploadId=up-1&partNumber=10001"},
		{"not a number", true, "/stack/payload?uploadId=up-1&partNumber=1x"},
		{"extra key", true, "/stack/payload?uploadId=up-1&partNumber=2&versionId=1"},
		{"duplicate", true, "/stack/payload?uploadId=up-1&uploadId=up-2&partNumber=2"},
		{"empty query", true, "/stack/payload?"},
		{"other query", true, "/stack/payload?versionId=1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := classifyRCTarget(tc.isPut, tc.raw)
			if !errors.Is(err, errUnsupportedRCQuery) || got.partPut {
				t.Fatalf("got %+v %v", got, err)
			}
		})
	}

	for _, raw := range []string{"/stack/payload", "/stack/a%2Fb"} {
		for _, isPut := range []bool{false, true} {
			got, err := classifyRCTarget(isPut, raw)
			if err != nil || got.partPut {
				t.Fatalf("%s put=%v: %+v %v", raw, isPut, got, err)
			}
		}
	}

	edges := []struct {
		raw string
		n   int32
	}{
		{"/b/k?partNumber=1&uploadId=id", 1},
		{"/b/k?uploadId=id&partNumber=10000", 10000},
		{"/b/k?uploadId=a%2Bb&partNumber=3", 3},
	}
	for _, tc := range edges {
		got, err := classifyRCTarget(true, tc.raw)
		if err != nil || !got.partPut || got.number != tc.n {
			t.Fatalf("%s: %+v %v", tc.raw, got, err)
		}
		if tc.raw == edges[2].raw && got.uploadID != "a+b" {
			t.Fatalf("decoded id %q", got.uploadID)
		}
	}
}
