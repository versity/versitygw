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

func TestPolicyVersion_isValid(t *testing.T) {
	tests := []struct {
		name  string // description of this test case
		value string
		want  bool
	}{
		{"valid 2008", "2008-10-17", true},
		{"valid 2012", "2012-10-17", true},
		{"invalid empty", "", false},
		{"invalid 1", "invalid", false},
		{"invalid 2", "2010-10-17", false},
		{"invalid 3", "2006-00-12", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PolicyVersion(tt.value).isValid()
			assert.Equal(t, tt.want, got)
		})
	}
}
