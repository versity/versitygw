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

package backend

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/versity/versitygw/s3err"
)

func TestEvaluateObjectDeletePreconditions(t *testing.T) {
	const etag = `"b1946ac92492d2347c6235b4d2611184"`
	modTime := time.Date(2026, 10, 7, 6, 20, 25, 0, time.UTC)
	size := int64(6)
	str := func(s string) *string { return &s }
	i64 := func(n int64) *int64 { return &n }
	tm := func(t time.Time) *time.Time { return &t }

	errIfMatch := s3err.GetPreconditionFailedErr(s3err.ConditionIfMatch)
	errSize := s3err.GetPreconditionFailedErr(s3err.ConditionIfMatchSize)
	errModTime := s3err.GetPreconditionFailedErr(s3err.ConditionIfMatchLastModTime)

	for _, tc := range []struct {
		name string
		pre  ObjectDeletePreconditions
		want error
	}{
		{"none", ObjectDeletePreconditions{}, nil},
		{"etag quoted", ObjectDeletePreconditions{IfMatch: str(etag)}, nil},
		{"etag unquoted", ObjectDeletePreconditions{IfMatch: str(strings.Trim(etag, `"`))}, nil},
		{"etag wildcard", ObjectDeletePreconditions{IfMatch: str("*")}, nil},
		{"etag quoted wildcard", ObjectDeletePreconditions{IfMatch: str(`"*"`)}, nil},
		{"etag wildcard with size", ObjectDeletePreconditions{IfMatch: str("*"), IfMatchSize: i64(size)}, nil},
		{"etag wildcard with wrong size", ObjectDeletePreconditions{IfMatch: str("*"), IfMatchSize: i64(size + 1)}, errSize},
		{"etag mismatch", ObjectDeletePreconditions{IfMatch: str("abc")}, errIfMatch},
		{"etag prefix of wildcard", ObjectDeletePreconditions{IfMatch: str("**")}, errIfMatch},
		{"size match", ObjectDeletePreconditions{IfMatchSize: i64(size)}, nil},
		{"mod time match", ObjectDeletePreconditions{IfMatchLastModTime: tm(modTime)}, nil},
		{"mod time mismatch", ObjectDeletePreconditions{IfMatchLastModTime: tm(modTime.Add(time.Hour))}, errModTime},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := EvaluateObjectDeletePreconditions(etag, modTime, size, tc.pre)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
