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

package middlewares

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_isValidMD5(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{"invalid", "hello world", false},
		{"valid base64", "aGVsbCBzLGRham5mamFuc2Zhc2RmZHNhZmRzYWY=", false},
		{"valid 1", "CY9rzUYh03PK3k6DJie09g==", true},
		{"valid 2", "uU0nuZNNPgilLlLX2n2r+s==", true},
		{"valid 3", "7Qdih1MuhjZehB6Sv8UNjA==", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidMD5(tt.s)
			assert.Equal(t, tt.want, got)
		})
	}
}
