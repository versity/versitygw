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

func TestPrincipals_Add(t *testing.T) {
	p := make(Principals)
	p.Add("user1")
	_, ok := p["user1"]
	assert.True(t, ok)
}

func TestPrincipals_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Principals
		wantErr bool
	}{
		{"valid slice", `["user1","user2"]`, Principals{"user1": {}, "user2": {}}, false},
		{"empty slice", `[]`, nil, true},
		{"valid string", `"user1"`, Principals{"user1": {}}, false},
		{"empty string", `""`, nil, true},
		{"valid AWS object", `{"AWS":"user1"}`, Principals{"user1": {}}, false},
		{"empty AWS object", `{"AWS":""}`, nil, true},
		{"valid AWS array", `{"AWS":["user1","user2"]}`, Principals{"user1": {}, "user2": {}}, false},
		{"empty AWS array", `{"AWS":[]}`, nil, true},
		{"invalid json", `{invalid}`, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p Principals
			err := json.Unmarshal([]byte(tt.input), &p)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, p)
			}
		})
	}
}

func TestPrincipals_ToSlice(t *testing.T) {
	p := Principals{"user1": {}, "user2": {}, "*": {}}
	got := p.ToSlice()
	assert.Contains(t, got, "user1")
	assert.Contains(t, got, "user2")
	assert.NotContains(t, got, "*")
}

func TestPrincipals_Validate(t *testing.T) {
	iamSingle := NewIAMServiceSingle(Account{
		Access: "user1",
	})
	tests := []struct {
		name       string
		principals Principals
		mockIAM    IAMService
		err        error
	}{
		{"only wildcard", Principals{"*": {}}, iamSingle, nil},
		{"wildcard and user", Principals{"*": {}, "user1": {}}, iamSingle, policyErrInvalidPrincipal},
		{"accounts exist returns err", Principals{"user2": {}, "user3": {}}, iamSingle, policyErrInvalidPrincipal},
		{"accounts exist non-empty", Principals{"user1": {}}, iamSingle, nil},
		{"accounts valid", Principals{"user1": {}}, iamSingle, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.principals.Validate(tt.mockIAM)
			assert.EqualValues(t, tt.err, err)
		})
	}
}

func TestPrincipals_Contains(t *testing.T) {
	p := Principals{"user1": {}}
	assert.True(t, p.Contains("user1"))
	assert.False(t, p.Contains("user2"))

	p = Principals{"*": {}}
	assert.True(t, p.Contains("anyuser"))
}

func TestPrincipals_isPublic(t *testing.T) {
	assert.True(t, Principals{"*": {}}.isPublic())
	assert.False(t, Principals{"user1": {}}.isPublic())
}
