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

package webui

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testIAMGateways = []string{"https://iam.example.com"}

func validOIDCConfig() OIDCConfig {
	return OIDCConfig{
		Issuer:   "https://auth.example.com/realms/main",
		ClientID: "versitygw-webui",
		RoleArn:  "arn:aws:iam::000000000000:role/webui-users",
	}
}

func TestOIDCConfigValidate(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(*OIDCConfig)
		iamGateways []string
		wantErr     string
	}{
		{name: "valid", mutate: func(*OIDCConfig) {}},
		{
			name:   "role claim alone",
			mutate: func(c *OIDCConfig) { c.RoleArn = ""; c.RoleClaim = "vgw_roles" },
		},
		{
			name: "issuer with trailing slash, port and path",
			mutate: func(c *OIDCConfig) {
				c.Issuer = "https://authentik.example.com:9443/application/o/versitygw/"
			},
		},
		{
			name: "all optional settings",
			mutate: func(c *OIDCConfig) {
				c.RoleClaim = "vgw_roles"
				c.Scopes = "openid email offline_access"
				c.Label = "Sign in with Keycloak"
				c.SessionDuration = 7200
				c.RedirectURI = "http://localhost:8080/ui/"
			},
		},
		{
			name:   "http issuer with opt-in",
			mutate: func(c *OIDCConfig) { c.Issuer = "http://127.0.0.1:9000"; c.AllowHTTP = true },
		},
		{
			name:        "disabled",
			mutate:      func(c *OIDCConfig) { *c = OIDCConfig{} },
			iamGateways: []string{},
		},
		{
			name:    "settings without issuer",
			mutate:  func(c *OIDCConfig) { c.Issuer = "" },
			wantErr: "webui-oidc-issuer is not",
		},
		{
			name:    "http issuer without opt-in",
			mutate:  func(c *OIDCConfig) { c.Issuer = "http://auth.example.com" },
			wantErr: "plain http needs webui-oidc-allow-http",
		},
		{
			name:    "relative issuer",
			mutate:  func(c *OIDCConfig) { c.Issuer = "auth.example.com" },
			wantErr: "must be an absolute https URL",
		},
		{
			name:    "issuer with query",
			mutate:  func(c *OIDCConfig) { c.Issuer = "https://auth.example.com/?tenant=a" },
			wantErr: "must not contain a query",
		},
		{
			name:    "issuer with fragment",
			mutate:  func(c *OIDCConfig) { c.Issuer = "https://auth.example.com/#x" },
			wantErr: "must not contain a fragment",
		},
		{
			name:    "issuer with credentials",
			mutate:  func(c *OIDCConfig) { c.Issuer = "https://user:pass@auth.example.com" },
			wantErr: "must not contain credentials",
		},
		{
			name:    "missing client id",
			mutate:  func(c *OIDCConfig) { c.ClientID = "" },
			wantErr: "webui-oidc-client-id is required",
		},
		{
			name:    "client id with whitespace",
			mutate:  func(c *OIDCConfig) { c.ClientID = "web ui" },
			wantErr: "invalid webui-oidc-client-id",
		},
		{
			name:    "no role",
			mutate:  func(c *OIDCConfig) { c.RoleArn = "" },
			wantErr: "webui-oidc-role-arn or webui-oidc-role-claim is required",
		},
		{
			name:    "malformed role arn",
			mutate:  func(c *OIDCConfig) { c.RoleArn = "arn:aws:iam::000000000000:user/alice" },
			wantErr: "invalid webui-oidc-role-arn",
		},
		{
			name:    "scopes without openid",
			mutate:  func(c *OIDCConfig) { c.Scopes = "profile email" },
			wantErr: "must include openid",
		},
		{
			name:    "session duration too short",
			mutate:  func(c *OIDCConfig) { c.SessionDuration = 899 },
			wantErr: "must be between 900 and 43200",
		},
		{
			name:    "session duration too long",
			mutate:  func(c *OIDCConfig) { c.SessionDuration = 43201 },
			wantErr: "must be between 900 and 43200",
		},
		{
			name:    "relative redirect uri",
			mutate:  func(c *OIDCConfig) { c.RedirectURI = "/ui/" },
			wantErr: "invalid webui-oidc-redirect-uri",
		},
		{
			name:    "redirect uri with fragment",
			mutate:  func(c *OIDCConfig) { c.RedirectURI = "https://ui.example.com/#cb" },
			wantErr: "must not contain a fragment",
		},
		{
			name:        "no iam gateways",
			mutate:      func(*OIDCConfig) {},
			iamGateways: []string{},
			wantErr:     "requires webui-iam-gateways",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validOIDCConfig()
			tt.mutate(&cfg)
			iamGateways := tt.iamGateways
			if iamGateways == nil {
				iamGateways = testIAMGateways
			}

			err := cfg.Validate(iamGateways)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestIndexHTMLInjectsOIDCConfig(t *testing.T) {
	oidc := validOIDCConfig()
	oidc.RoleClaim = "vgw_roles"
	oidc.Scopes = "  openid   email offline_access "
	oidc.SessionDuration = 7200
	oidc.RedirectURI = "https://ui.example.com/"
	oidc.AllowHTTP = true

	server, err := NewServer(&ServerConfig{IAMGateways: testIAMGateways, OIDC: oidc}, WithQuiet())
	require.NoError(t, err)

	cfg := fetchPageConfig(t, server.app, "/")
	assert.Equal(t, map[string]any{
		"issuer":          oidc.Issuer,
		"clientId":        oidc.ClientID,
		"roleArn":         oidc.RoleArn,
		"roleClaim":       "vgw_roles",
		"scopes":          "openid email offline_access",
		"label":           DefaultOIDCLabel,
		"sessionDuration": float64(7200),
		"redirectUri":     "https://ui.example.com/",
	}, cfg["oidc"])
}

func TestIndexHTMLOIDCDefaults(t *testing.T) {
	oidc := validOIDCConfig()
	oidc.RoleArn = ""
	oidc.RoleClaim = "vgw_roles"

	server, err := NewServer(&ServerConfig{IAMGateways: testIAMGateways, OIDC: oidc}, WithQuiet())
	require.NoError(t, err)

	got, ok := fetchPageConfig(t, server.app, "/index.html")["oidc"].(map[string]any)
	require.True(t, ok, "oidc config missing from page")
	assert.Equal(t, DefaultOIDCScopes, got["scopes"])
	assert.Equal(t, DefaultOIDCLabel, got["label"])
	for _, key := range []string{"roleArn", "sessionDuration", "redirectUri", "AllowHTTP", "allowHttp"} {
		assert.NotContains(t, got, key)
	}
}

func TestIndexHTMLOmitsOIDCConfigWhenDisabled(t *testing.T) {
	server, err := NewServer(&ServerConfig{IAMGateways: testIAMGateways}, WithQuiet())
	require.NoError(t, err)

	assert.NotContains(t, fetchPageConfig(t, server.app, "/"), "oidc")
}

func TestNewServerRejectsInvalidOIDCConfig(t *testing.T) {
	_, err := NewServer(&ServerConfig{OIDC: validOIDCConfig()}, WithQuiet())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires webui-iam-gateways")
}

// TestMountOnInjectsOIDCConfig covers the WebUI the S3 gateway serves on
// its own port, whose login page is under the mount prefix.
func TestMountOnInjectsOIDCConfig(t *testing.T) {
	app := fiber.New()
	require.NoError(t, MountOn(app, "/ui", &ServerConfig{IAMGateways: testIAMGateways, OIDC: validOIDCConfig()}))

	got, ok := fetchPageConfig(t, app, "/ui/")["oidc"].(map[string]any)
	require.True(t, ok, "oidc config missing from page")
	assert.Equal(t, validOIDCConfig().Issuer, got["issuer"])
}

func TestMountOnRejectsInvalidOIDCConfig(t *testing.T) {
	oidc := validOIDCConfig()
	oidc.Scopes = "email"

	err := MountOn(fiber.New(), "/ui", &ServerConfig{IAMGateways: testIAMGateways, OIDC: oidc})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must include openid")
}

// fetchPageConfig requests the login page at path and decodes the
// window.__VGWCONFIG__ object injected into it.
func fetchPageConfig(t *testing.T, app *fiber.App, path string) map[string]any {
	t.Helper()

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, path, nil))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	const marker = "window.__VGWCONFIG__ = "
	_, rest, found := strings.Cut(string(body), marker)
	require.True(t, found, "page has no injected config")
	raw, _, found := strings.Cut(rest, ";</script>")
	require.True(t, found, "injected config is not terminated")

	var cfg map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &cfg))
	return cfg
}
