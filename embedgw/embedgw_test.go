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
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3api"
)

func TestValidatePortConflicts(t *testing.T) {
	tests := []struct {
		name         string
		ports        []string
		admPorts     []string
		webuiPorts   []string
		websitePorts []string
		expectError  bool
		description  string
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
		{
			name:         "website bare port conflict with s3 port",
			ports:        []string{"127.0.0.1:8080"},
			admPorts:     []string{},
			webuiPorts:   []string{},
			websitePorts: []string{":8080"},
			expectError:  true,
			description:  "should fail: website bare :8080 conflicts with s3 127.0.0.1:8080",
		},
		{
			name:         "website no conflict",
			ports:        []string{":7070"},
			admPorts:     []string{":8080"},
			webuiPorts:   []string{":9090"},
			websitePorts: []string{":8081"},
			expectError:  false,
			description:  "should pass: website uses a distinct port",
		},
		{
			name:         "duplicate website unix socket conflict",
			ports:        []string{"/tmp/versitygw.sock"},
			admPorts:     []string{},
			webuiPorts:   []string{},
			websitePorts: []string{"/tmp/versitygw.sock"},
			expectError:  true,
			description:  "should fail: duplicate unix socket path conflicts across s3 and website",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePortConflicts(tt.ports, tt.admPorts, tt.webuiPorts, tt.websitePorts)
			if tt.expectError && err == nil {
				t.Errorf("%s: expected error but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("%s: expected no error but got: %v", tt.description, err)
			}
		})
	}
}

func TestValidateAdminPathPrefix(t *testing.T) {
	tests := []struct {
		prefix  string
		wantErr bool
	}{
		{prefix: "", wantErr: false},
		{prefix: "/admin", wantErr: false},
		{prefix: "/vgw-admin_1.0~x", wantErr: false},
		{prefix: "admin", wantErr: true},
		{prefix: "/", wantErr: true},
		{prefix: "/admin/", wantErr: true},
		{prefix: "/api/admin", wantErr: true},
		{prefix: "/.", wantErr: true},
		{prefix: "/..", wantErr: true},
		{prefix: "/ad min", wantErr: true},
		{prefix: "/:bucket", wantErr: true},
		{prefix: "/admin*", wantErr: true},
		{prefix: "/admin%20", wantErr: true},
		{prefix: "/admin?x", wantErr: true},
		{prefix: " /admin", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			err := validateAdminPathPrefix(tt.prefix)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateAdminPathPrefix(%q) = %v, wantErr %v", tt.prefix, err, tt.wantErr)
			}
		})
	}
}

func TestAppendPathPrefix(t *testing.T) {
	urls := []string{"http://127.0.0.1:7070", "https://s3.example.com/"}

	got := appendPathPrefix(urls, "/admin")
	want := []string{"http://127.0.0.1:7070/admin", "https://s3.example.com/admin"}
	if !slices.Equal(got, want) {
		t.Fatalf("appendPathPrefix = %v, want %v", got, want)
	}
	if urls[0] != "http://127.0.0.1:7070" {
		t.Fatalf("appendPathPrefix modified its input: %v", urls)
	}
	if got := appendPathPrefix(urls, ""); !slices.Equal(got, urls) {
		t.Fatalf("appendPathPrefix without prefix = %v, want %v", got, urls)
	}
}

func TestRunVersityGWValidatesAdminPathPrefix(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name: "invalid prefix",
			mutate: func(cfg *Config) {
				cfg.AdminPathPrefix = "/api/admin"
			},
			wantErr: "invalid AdminPathPrefix",
		},
		{
			name: "same as webui s3 prefix",
			mutate: func(cfg *Config) {
				cfg.AdminPathPrefix = "/ui"
				cfg.WebuiS3Prefix = "/UI"
			},
			wantErr: "must differ from WebuiS3Prefix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				RootUserAccess:    "root",
				RootUserSecret:    "secret",
				Ports:             []string{"127.0.0.1:0"},
				MaxConnections:    1,
				MaxRequests:       1,
				MultipartMaxParts: 1,
				Quiet:             true,
			}
			tt.mutate(&cfg)

			err := RunVersityGW(context.Background(), backend.BackendUnsupported{}, &cfg)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestRunVersityGWValidatesClientIPHeader(t *testing.T) {
	cfg := Config{
		RootUserAccess:    "root",
		RootUserSecret:    "secret",
		Ports:             []string{"127.0.0.1:0"},
		MaxConnections:    1,
		MaxRequests:       1,
		MultipartMaxParts: 1,
		Quiet:             true,
		ClientIPHeader:    "Forwarded",
	}

	err := RunVersityGW(context.Background(), backend.BackendUnsupported{}, &cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid client IP header") {
		t.Fatalf("error = %q, want substring %q", err, "invalid client IP header")
	}
}

// TestRunVersityGWRequiresTrustedProxies pins the review requirement that a
// configured client IP header cannot silently degrade into trusting every
// peer.
func TestRunVersityGWRequiresTrustedProxies(t *testing.T) {
	cfg := Config{
		RootUserAccess:    "root",
		RootUserSecret:    "secret",
		Ports:             []string{"127.0.0.1:0"},
		MaxConnections:    1,
		MaxRequests:       1,
		MultipartMaxParts: 1,
		Quiet:             true,
		ClientIPHeader:    "X-Forwarded-For",
	}

	err := RunVersityGW(context.Background(), backend.BackendUnsupported{}, &cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "trusted-proxies is empty") {
		t.Fatalf("error = %q, want substring %q", err, "trusted-proxies is empty")
	}
}

func TestRunVersityGWRejectsInvalidTrustedProxies(t *testing.T) {
	cfg := Config{
		RootUserAccess:    "root",
		RootUserSecret:    "secret",
		Ports:             []string{"127.0.0.1:0"},
		MaxConnections:    1,
		MaxRequests:       1,
		MultipartMaxParts: 1,
		Quiet:             true,
		ClientIPHeader:    "X-Forwarded-For",
		TrustedProxies:    "10.0.0.0/8, nope",
	}

	err := RunVersityGW(context.Background(), backend.BackendUnsupported{}, &cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid trusted proxy") {
		t.Fatalf("error = %q, want substring %q", err, "invalid trusted proxy")
	}
}

// policyEvaluatorIAM stands in for an IAM service that evaluates identity
// policies.
type policyEvaluatorIAM struct{ auth.IAMService }

func (policyEvaluatorIAM) EvaluatePolicy(string, string, []auth.Action, []string, map[string][]string) (auth.PolicyEvaluation, error) {
	return auth.PolicyEvaluation{}, nil
}

// fixedOwnerIAM stands in for an IAM service that fixes bucket ownership.
type fixedOwnerIAM struct{ auth.IAMService }

func (fixedOwnerIAM) BucketOwner() auth.Account { return auth.Account{Access: "owner"} }

func TestRunVersityGWValidatesListBucketsScope(t *testing.T) {
	single := auth.NewIAMServiceSingle(auth.Account{Access: "root", Secret: "secret", Role: auth.RoleAdmin})
	tests := []struct {
		name    string
		scope   string
		iam     auth.IAMService
		wantErr string
	}{
		{name: "invalid value", scope: "shared", wantErr: "invalid list buckets scope"},
		{name: "accessible with a policy evaluator", scope: "accessible", iam: policyEvaluatorIAM{single}, wantErr: "not supported with an IAM service"},
		{name: "all with a policy evaluator", scope: "all", iam: policyEvaluatorIAM{single}, wantErr: "not supported with an IAM service"},
		{name: "accessible with a fixed owner", scope: "accessible", iam: fixedOwnerIAM{single}, wantErr: "not supported with an IAM service"},
		{name: "all with a fixed owner", scope: "all", iam: fixedOwnerIAM{single}, wantErr: "not supported with an IAM service"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				RootUserAccess:    "root",
				RootUserSecret:    "secret",
				Ports:             []string{"127.0.0.1:0"},
				MaxConnections:    1,
				MaxRequests:       1,
				MultipartMaxParts: 1,
				Quiet:             true,
				ListBucketsScope:  tt.scope,
				IAMService:        tt.iam,
			}

			err := RunVersityGW(context.Background(), backend.BackendUnsupported{}, &cfg)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestRunVersityGWBannerUsesEffectiveBandwidthOptions(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		RootUserAccess:       "root",
		RootUserSecret:       "secret",
		Ports:                []string{port},
		MaxConnections:       1,
		MaxRequests:          1,
		MultipartMaxParts:    1,
		EgressBandwidthLimit: 1 << 20,
		S3Options:            []s3api.Option{s3api.WithBandwidthLimit(0, 0, 1_250_000_000, 1<<20)},
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	originalStdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = originalStdout }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- RunVersityGW(ctx, backend.BackendUnsupported{}, &cfg) }()
	var response *http.Response
	deadline := time.Now().Add(5 * time.Second)
	for {
		response, err = http.Get("http://" + port + "/")
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		cancel()
		<-runDone
		t.Fatalf("gateway did not start: %v", err)
	}
	_ = response.Body.Close()
	cancel()
	var runErr error
	select {
	case runErr = <-runDone:
	case <-time.After(5 * time.Second):
		t.Fatal("gateway did not stop after cancellation")
	}
	_ = w.Close()
	output, readErr := io.ReadAll(r)
	_ = r.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if runErr != nil {
		t.Fatalf("RunVersityGW() = %v", runErr)
	}
	if !strings.Contains(string(output), "egress: 1.25 GB/s (10 Gbit/s), burst 1 MiB") {
		t.Fatalf("banner did not show effective S3 option: %s", output)
	}
	if strings.Contains(string(output), "egress: 1 MB/s (8 Mbit/s), burst 64 KiB") {
		t.Fatalf("banner showed the overridden config value: %s", output)
	}
	if cfg.EgressBandwidthLimit != 1<<20 || cfg.EgressBandwidthBurst != 0 {
		t.Fatalf("RunVersityGW() changed caller bandwidth config: rate=%d burst=%d",
			cfg.EgressBandwidthLimit, cfg.EgressBandwidthBurst)
	}
}
