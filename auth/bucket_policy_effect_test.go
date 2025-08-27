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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBucketPolicyAccessType_Validate(t *testing.T) {
	tests := []struct {
		name    string
		input   BucketPolicyAccessType
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid allow",
			input:   BucketPolicyAccessTypeAllow,
			wantErr: false,
		},
		{
			name:    "valid deny",
			input:   BucketPolicyAccessTypeDeny,
			wantErr: false,
		},
		{
			name:    "invalid type",
			input:   BucketPolicyAccessType("InvalidValue"),
			wantErr: true,
			errMsg:  "Invalid effect: InvalidValue",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()
			if tt.wantErr {
				assert.EqualError(t, err, tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
