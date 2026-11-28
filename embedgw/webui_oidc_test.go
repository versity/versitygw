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
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/webui"
)

var testWebuiOIDC = webui.OIDCConfig{
	Issuer:   "https://auth.example.com/realms/main",
	ClientID: "versitygw-webui",
	RoleArn:  "arn:aws:iam::000000000000:role/webui-users",
}

func TestRunVersityGWValidatesWebuiOIDC(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name: "standalone webui without iam gateways",
			mutate: func(cfg *Config) {
				cfg.WebuiPorts = []string{"127.0.0.1:0"}
				cfg.WebuiOIDC = testWebuiOIDC
			},
			wantErr: "requires webui-iam-gateways",
		},
		{
			name: "s3-port webui without client id",
			mutate: func(cfg *Config) {
				cfg.WebuiS3Prefix = "/ui"
				cfg.WebuiIAMGateways = []string{"https://iam.example.com"}
				cfg.WebuiOIDC = testWebuiOIDC
				cfg.WebuiOIDC.ClientID = ""
			},
			wantErr: "webui-oidc-client-id is required",
		},
		{
			name: "http issuer without opt-in",
			mutate: func(cfg *Config) {
				cfg.WebuiS3Prefix = "/ui"
				cfg.WebuiIAMGateways = []string{"https://iam.example.com"}
				cfg.WebuiOIDC = testWebuiOIDC
				cfg.WebuiOIDC.Issuer = "http://127.0.0.1:9000"
			},
			wantErr: "webui-oidc-allow-http",
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

// TestRunVersityGWServesWebuiOIDCConfig checks that both WebUI modes the S3
// gateway hosts put the SSO settings on their login page.
func TestRunVersityGWServesWebuiOIDCConfig(t *testing.T) {
	sockDir := shortSocketDir(t)
	s3Sock := filepath.Join(sockDir, "s3.sock")
	webSock := filepath.Join(sockDir, "web.sock")

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- RunVersityGW(ctx, backend.BackendUnsupported{}, &Config{
			RootUserAccess:    "root",
			RootUserSecret:    "secret",
			Ports:             []string{s3Sock},
			MaxConnections:    16,
			MaxRequests:       16,
			MultipartMaxParts: 1,
			Quiet:             true,
			CORSAllowOrigin:   "*",
			WebuiPorts:        []string{webSock},
			WebuiS3Prefix:     "/ui",
			WebuiIAMGateways:  []string{"https://iam.example.com"},
			WebuiOIDC:         testWebuiOIDC,
		})
	}()
	t.Cleanup(func() { stopServer(t, "RunVersityGW", cancel, errCh) })

	for _, page := range []struct{ sock, path string }{{webSock, "/"}, {s3Sock, "/ui/"}} {
		oidc := pageOIDCConfig(t, page.sock, page.path)
		if oidc["issuer"] != testWebuiOIDC.Issuer || oidc["clientId"] != testWebuiOIDC.ClientID || oidc["roleArn"] != testWebuiOIDC.RoleArn {
			t.Fatalf("%s%s: oidc config = %v", filepath.Base(page.sock), page.path, oidc)
		}
	}
}

func TestRunIAMAPIValidatesWebuiOIDC(t *testing.T) {
	oidc := testWebuiOIDC
	oidc.RoleArn = ""

	err := RunIAMAPI(context.Background(), &IAMConfig{
		RootUserAccess: "root",
		RootUserSecret: "secret",
		Ports:          []string{"127.0.0.1:0"},
		MaxConnections: 1,
		MaxRequests:    1,
		IAMDir:         t.TempDir(),
		Quiet:          true,
		WebuiPorts:     []string{"127.0.0.1:0"},
		WebuiOIDC:      oidc,
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if want := "webui-oidc-role-arn or webui-oidc-role-claim is required"; !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want substring %q", err, want)
	}
}

// TestRunIAMAPIServesWebuiOIDCConfig checks the WebUI the IAM service hosts.
// Its IAM endpoint is its own address, detected from Ports, so SSO needs no
// WebuiIAMGateways there.
func TestRunIAMAPIServesWebuiOIDCConfig(t *testing.T) {
	webSock := filepath.Join(shortSocketDir(t), "web.sock")

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- RunIAMAPI(ctx, &IAMConfig{
			RootUserAccess:  "root",
			RootUserSecret:  "secret",
			Ports:           []string{"127.0.0.1:0"},
			MaxConnections:  16,
			MaxRequests:     16,
			IAMDir:          t.TempDir(),
			Quiet:           true,
			CORSAllowOrigin: "*",
			WebuiPorts:      []string{webSock},
			WebuiOIDC:       testWebuiOIDC,
		})
	}()
	t.Cleanup(func() { stopServer(t, "RunIAMAPI", cancel, errCh) })

	oidc := pageOIDCConfig(t, webSock, "/")
	if oidc["issuer"] != testWebuiOIDC.Issuer || oidc["label"] != webui.DefaultOIDCLabel || oidc["scopes"] != webui.DefaultOIDCScopes {
		t.Fatalf("oidc config = %v", oidc)
	}
}

// shortSocketDir returns a directory for unix sockets. A socket path is
// limited to ~104 bytes on macOS, which t.TempDir() can exceed once it
// embeds the test name.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "vgw-oidc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// stopServer cancels a server started in the background and waits for it.
func stopServer(t *testing.T, name string, cancel context.CancelFunc, errCh <-chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			t.Errorf("%s: %v", name, err)
		}
	case <-time.After(15 * time.Second):
		t.Errorf("%s did not return after cancel", name)
	}
}

// pageOIDCConfig fetches the login page at path over the unix socket sock,
// retrying until the server is up, and returns the oidc object of its
// injected window.__VGWCONFIG__.
func pageOIDCConfig(t *testing.T, sock, path string) map[string]any {
	t.Helper()

	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			},
		},
	}

	var resp *http.Response
	var err error
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		resp, err = client.Get("http://webui" + path)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("GET %s on %s: %v", path, sock, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s on %s: status %d", path, sock, resp.StatusCode)
	}

	_, rest, found := strings.Cut(string(body), "window.__VGWCONFIG__ = ")
	if !found {
		t.Fatalf("GET %s on %s: page has no injected config", path, sock)
	}
	raw, _, _ := strings.Cut(rest, ";</script>")

	var cfg struct {
		OIDC map[string]any `json:"oidc"`
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("decode injected config: %v", err)
	}
	if cfg.OIDC == nil {
		t.Fatalf("GET %s on %s: no oidc config in %s", path, sock, raw)
	}
	return cfg.OIDC
}
