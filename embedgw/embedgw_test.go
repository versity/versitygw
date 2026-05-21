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
	"testing"
)

func TestValidatePortConflicts(t *testing.T) {
	tests := []struct {
		name        string
		ports       []string
		admPorts    []string
		webuiPorts  []string
		expectError bool
		description string
	}{
		{
			name:        "bare port conflict with bare port",
			ports:       []string{":7071"},
			admPorts:    []string{},
			webuiPorts:  []string{":7071"},
			expectError: true,
			description: "should fail: bare :7071 conflicts with bare :7071",
		},
		{
			name:        "bare port conflict with IP:port",
			ports:       []string{":7071"},
			admPorts:    []string{},
			webuiPorts:  []string{"127.0.0.1:7071"},
			expectError: true,
			description: "should fail: bare :7071 conflicts with 127.0.0.1:7071",
		},
		{
			name:        "IP:port conflict with bare port",
			ports:       []string{"127.0.0.1:7071"},
			admPorts:    []string{},
			webuiPorts:  []string{":7071"},
			expectError: true,
			description: "should fail: 127.0.0.1:7071 conflicts with bare :7071",
		},
		{
			name:        "same IP:port allowed",
			ports:       []string{"127.0.0.1:7071"},
			admPorts:    []string{},
			webuiPorts:  []string{"127.0.0.1:7071"},
			expectError: false,
			description: "should pass: identical IP:port specs are allowed",
		},
		{
			name:        "different IP:port no conflict",
			ports:       []string{"127.0.0.1:7071"},
			admPorts:    []string{},
			webuiPorts:  []string{"127.0.0.1:7072"},
			expectError: false,
			description: "should pass: different ports don't conflict",
		},
		{
			name:        "different IP same port no conflict when both have IP",
			ports:       []string{"127.0.0.1:7071"},
			admPorts:    []string{},
			webuiPorts:  []string{"192.168.1.1:7071"},
			expectError: false,
			description: "should pass: different IPs with same port are okay",
		},
		{
			name:        "admin port conflict with s3 port",
			ports:       []string{":7070"},
			admPorts:    []string{"127.0.0.1:7070"},
			webuiPorts:  []string{},
			expectError: true,
			description: "should fail: admin port conflicts with s3 port",
		},
		{
			name:        "all three conflict",
			ports:       []string{":8080"},
			admPorts:    []string{"127.0.0.1:8080"},
			webuiPorts:  []string{"192.168.1.1:8080"},
			expectError: true,
			description: "should fail: bare port conflicts with both admin and webui",
		},
		{
			name:        "no conflicts",
			ports:       []string{":7070"},
			admPorts:    []string{":8080"},
			webuiPorts:  []string{":9090"},
			expectError: false,
			description: "should pass: all different ports",
		},
		{
			name:        "IPv6 bare port conflict with IPv4 specified",
			ports:       []string{":7071"},
			admPorts:    []string{},
			webuiPorts:  []string{"[::1]:7071"},
			expectError: true,
			description: "should fail: bare :7071 conflicts with [::1]:7071",
		},
		{
			name:        "multiple ports with one conflict",
			ports:       []string{":7070", ":8080"},
			admPorts:    []string{":9090"},
			webuiPorts:  []string{"127.0.0.1:8080"},
			expectError: true,
			description: "should fail: :8080 conflicts with 127.0.0.1:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePortConflicts(tt.ports, tt.admPorts, tt.webuiPorts)
			if tt.expectError && err == nil {
				t.Errorf("%s: expected error but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("%s: expected no error but got: %v", tt.description, err)
			}
		})
	}
}
