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

package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeClientIPHeader(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		want    string
		wantErr bool
	}{
		{name: "disabled", header: "", want: ""},
		{name: "blank is disabled", header: "  ", want: ""},
		{name: "x-forwarded-for", header: "X-Forwarded-For", want: ClientIPHeaderForwardedFor},
		{name: "x-forwarded-for lowercase", header: "x-forwarded-for", want: ClientIPHeaderForwardedFor},
		{name: "x-real-ip", header: "X-Real-Ip", want: ClientIPHeaderRealIP},
		{name: "x-real-ip uppercase", header: "X-REAL-IP", want: ClientIPHeaderRealIP},
		{name: "surrounding spaces", header: " X-Real-Ip ", want: ClientIPHeaderRealIP},
		{name: "unknown header", header: "Forwarded", wantErr: true},
		{name: "typo", header: "X-Forward-For", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeClientIPHeader(tt.header)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "invalid client IP header")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
