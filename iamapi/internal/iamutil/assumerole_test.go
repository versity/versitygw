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

package iamutil

import (
	"errors"
	"strings"
	"testing"

	"github.com/versity/versitygw/iamapi/iamerr"
)

func TestValidateExternalID(t *testing.T) {
	tests := []struct {
		name       string
		externalID string
		wantErr    error
	}{
		{"shortest allowed", "ab", nil},
		{"longest allowed", strings.Repeat("a", 1224), nil},
		{"every allowed special character", "a_+=,.@:/-Z9", nil},
		{"empty", "", iamerr.ValueTooShort("externalId", 2)},
		{"one character", "a", iamerr.ValueTooShort("externalId", 2)},
		{"too long", strings.Repeat("a", 1225), iamerr.ValueTooLong("externalId", 1224)},
		{"space", "a b", iamerr.InvalidExternalID("a b")},
		{"hash", "a#b", iamerr.InvalidExternalID("a#b")},
		{"non-ascii letter", "séc", iamerr.InvalidExternalID("séc")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateExternalID(tt.externalID)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("ValidateExternalID = %v, want nil", err)
				}
				return
			}
			var got iamerr.Error
			if !errors.As(err, &got) || got != tt.wantErr {
				t.Fatalf("ValidateExternalID = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsArnShaped(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"arn:aws:iam::000000000000:role/reader", true},
		{"arn:aws:iam::000000000000:role/team/reader", true},
		{"arn:aws:iam:::role/reader", true},
		{"arn:aws:sts::000000000000:assumed-role/reader/session", true},
		{"arn:aws:iam::000000000000:xxxxxxxx", true},
		{"arn:aws:s3:::bucket/key:with:colons", true},
		{"arn:aws:iam:000000000000:role/reader", false},
		{"urn:aws:iam::000000000000:role/reader", false},
		{" arn:aws:iam::000000000000:role/reader", false},
		{"arn:xxxxxxxxxxxxxxxxxxxxxxxx", false},
		{"reader-role-by-its-name", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsArnShaped(tt.value); got != tt.want {
			t.Errorf("IsArnShaped(%q) = %v, want %v", tt.value, got, tt.want)
		}
	}
}
