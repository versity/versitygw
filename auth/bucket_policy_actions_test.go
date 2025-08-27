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

	"github.com/stretchr/testify/assert"
)

func TestAction_IsValid(t *testing.T) {
	tests := []struct {
		name    string
		action  Action
		wantErr bool
	}{
		{"valid exact action", GetObjectAction, false},
		{"valid all actions", AllActions, false},
		{"invalid prefix", "invalid:Action", true},
		{"unsupported action 1", "s3:Unsupported", true},
		{"unsupported action 2", "s3:HeadObject", true},
		{"valid wildcard match 1", "s3:Get*", false},
		{"valid wildcard match 2", "s3:*Object*", false},
		{"valid wildcard match 3", "s3:*Multipart*", false},
		{"any char match 1", "s3:Get?bject", false},
		{"any char match 2", "s3:Get??bject", true},
		{"any char match 3", "s3:???", true},
		{"mixed match 1", "s3:Get?*", false},
		{"mixed match 2", "s3:*Object?????", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.action.IsValid()
			if tt.wantErr {
				assert.EqualValues(t, policyErrInvalidAction, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAction_String(t *testing.T) {
	a := Action("s3:TestAction")
	assert.Equal(t, "s3:TestAction", a.String())
}

func TestAction_Match(t *testing.T) {
	tests := []struct {
		name    string
		action  Action
		pattern Action
		want    bool
	}{
		{"exact match", "s3:GetObject", "s3:GetObject", true},
		{"wildcard match", "s3:GetObject", "s3:Get*", true},
		{"wildcard mismatch", "s3:PutObject", "s3:Get*", false},
		{"any character match", "s3:Get1", "s3:Get?", true},
		{"any character mismatch", "s3:Get12", "s3:Get?", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.action.Match(tt.pattern)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAction_IsObjectAction(t *testing.T) {
	tests := []struct {
		name   string
		action Action
		want   *bool
	}{
		{"all actions", AllActions, nil},
		{"object action exact", GetObjectAction, getBoolPtr(true)},
		{"object action wildcard", "s3:Get*", getBoolPtr(true)},
		{"non object action", GetBucketAclAction, getBoolPtr(false)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.action.IsObjectAction()
			if tt.want == nil {
				assert.Nil(t, got)
			} else {
				assert.NotNil(t, got)
				assert.Equal(t, *tt.want, *got)
			}
		})
	}
}

func TestActions_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid slice", `["s3:GetObject","s3:PutObject"]`, false},
		{"empty slice", `[]`, true},
		{"invalid action in slice", `["s3:Invalid"]`, true},
		{"valid string", `"s3:GetObject"`, false},
		{"empty string", `""`, true},
		{"invalid string", `"s3:Invalid"`, true},
		{"invalid json", `{}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var a Actions
			err := json.Unmarshal([]byte(tt.input), &a)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestActions_Add(t *testing.T) {
	tests := []struct {
		name    string
		action  string
		wantErr bool
	}{
		{"valid add", "s3:GetObject", false},
		{"invalid add", "s3:InvalidAction", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := make(Actions)
			err := a.Add(tt.action)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				_, ok := a[Action(tt.action)]
				assert.True(t, ok)
			}
		})
	}
}

func TestActions_FindMatch(t *testing.T) {
	tests := []struct {
		name    string
		actions Actions
		check   Action
		want    bool
	}{
		{"all actions present", Actions{AllActions: {}}, GetObjectAction, true},
		{"exact match", Actions{GetObjectAction: {}}, GetObjectAction, true},
		{"wildcard match", Actions{"s3:Get*": {}}, GetObjectAction, true},
		{"no match", Actions{"s3:Put*": {}}, GetObjectAction, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.actions.FindMatch(tt.check)
			assert.Equal(t, tt.want, got)
		})
	}
}
