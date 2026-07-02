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

package embedgw

import (
	"context"
	"strings"
	"testing"
)

func TestRunIAMAPIValidatesConfig(t *testing.T) {
	base := IAMConfig{
		RootUserAccess: "root",
		RootUserSecret: "secret",
		Ports:          []string{"127.0.0.1:0"},
		MaxConnections: 1,
		MaxRequests:    1,
		IAMDir:         t.TempDir(),
		Quiet:          true,
	}

	tests := []struct {
		name    string
		mutate  func(*IAMConfig)
		wantErr string
	}{
		{
			name: "missing root access",
			mutate: func(cfg *IAMConfig) {
				cfg.RootUserAccess = ""
			},
			wantErr: "root access key is required",
		},
		{
			name: "missing root secret",
			mutate: func(cfg *IAMConfig) {
				cfg.RootUserSecret = ""
			},
			wantErr: "root secret key is required",
		},
		{
			name: "missing ports",
			mutate: func(cfg *IAMConfig) {
				cfg.Ports = nil
			},
			wantErr: "no ports specified",
		},
		{
			name: "invalid max connections",
			mutate: func(cfg *IAMConfig) {
				cfg.MaxConnections = 0
			},
			wantErr: "max-connections must be positive",
		},
		{
			name: "invalid max requests",
			mutate: func(cfg *IAMConfig) {
				cfg.MaxRequests = 0
			},
			wantErr: "max-requests must be positive",
		},
		{
			name: "missing storer",
			mutate: func(cfg *IAMConfig) {
				cfg.IAMDir = ""
			},
			wantErr: "no IAM storer config specified",
		},
		{
			name: "invalid socket permission",
			mutate: func(cfg *IAMConfig) {
				cfg.SocketPerm = "nope"
			},
			wantErr: "invalid SocketPerm value",
		},
		{
			name: "missing tls cert",
			mutate: func(cfg *IAMConfig) {
				cfg.CertFile = ""
				cfg.KeyFile = "server.key"
			},
			wantErr: "TLS key specified without cert file",
		},
		{
			name: "missing tls key",
			mutate: func(cfg *IAMConfig) {
				cfg.CertFile = "server.crt"
				cfg.KeyFile = ""
			},
			wantErr: "TLS cert specified without key file",
		},
		{
			name: "multiple storers",
			mutate: func(cfg *IAMConfig) {
				cfg.VaultEndpointURL = "https://vault.example.com"
			},
			wantErr: "multiple IAM storer configs specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			cfg.IAMDir = t.TempDir()
			tt.mutate(&cfg)

			err := RunIAMAPI(context.Background(), &cfg)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestRunIAMAPIRejectsNilConfig(t *testing.T) {
	err := RunIAMAPI(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "iam config is required") {
		t.Fatalf("error = %q", err)
	}
}
