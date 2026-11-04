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

package azblobclient

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("testkey"))

	tests := []struct {
		name                       string
		account, key, url, sas     string
		wantURL                    string
		wantSAS, wantKey, wantDflt bool
	}{
		{
			name:    "sas and account without url",
			account: "acct",
			sas:     "sv=2024-01-01&sig=abc",
			wantURL: "https://acct.blob.core.windows.net/",
			wantSAS: true,
		},
		{
			name:    "account and key",
			account: "acct",
			key:     key,
			wantURL: "https://acct.blob.core.windows.net/",
			wantKey: true,
		},
		{
			name:     "account only",
			account:  "acct",
			wantURL:  "https://acct.blob.core.windows.net/",
			wantDflt: true,
		},
		{
			name:     "key without account",
			key:      key,
			url:      "https://example.com/",
			wantURL:  "https://example.com/",
			wantDflt: true,
		},
		{
			name:    "explicit url wins",
			account: "acct",
			key:     key,
			url:     "http://127.0.0.1:10000/acct",
			wantURL: "http://127.0.0.1:10000/acct",
			wantKey: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// AZURE_CLIENT_ID must not be taken as the account name
			t.Setenv("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000000")

			client, creds, err := New(tt.account, tt.key, tt.url, tt.sas)
			if !assert.NoError(t, err) {
				return
			}
			assert.NotNil(t, client)
			assert.Equal(t, tt.wantURL, creds.ServiceURL)
			assert.Equal(t, tt.wantSAS, creds.SASToken != "")
			assert.Equal(t, tt.wantKey, creds.SharedKey != nil)
			assert.Equal(t, tt.wantDflt, creds.Default != nil)
			if tt.wantKey {
				assert.Equal(t, tt.account, creds.SharedKey.AccountName())
			}
		})
	}
}
