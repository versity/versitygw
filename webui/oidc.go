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
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

const (
	// DefaultOIDCScopes is the scope list requested when none is configured.
	DefaultOIDCScopes = "openid profile email"
	// DefaultOIDCLabel is the sign-in button text when none is configured.
	DefaultOIDCLabel = "Sign in with SSO"

	// MinOIDCSessionDuration and MaxOIDCSessionDuration are the
	// DurationSeconds bounds AssumeRoleWithWebIdentity accepts.
	MinOIDCSessionDuration = 900
	MaxOIDCSessionDuration = 43200
)

var oidcRoleArnPattern = regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:role/\S+$`)

// OIDCConfig turns on single sign-on through an OpenID Connect provider on
// the WebUI login page. The browser runs the authorization code flow with
// PKCE as a public client and trades the ID token for temporary credentials
// with AssumeRoleWithWebIdentity on the standalone IAM service.
//
// Every field except AllowHTTP is sent to the browser, so none of it may be
// secret. There is deliberately no client secret.
type OIDCConfig struct {
	// Issuer is the provider's issuer URL, exactly as its discovery document
	// and the IAM service's registered OIDC provider name it. Setting it
	// turns SSO on; empty leaves the login page key-only.
	Issuer string `json:"issuer"`
	// ClientID is the public client registered at the provider for the
	// WebUI. It is also the audience the IAM service checks.
	ClientID string `json:"clientId"`
	// RoleArn is the role assumed when RoleClaim is unset, absent from the
	// token, or names no role.
	RoleArn string `json:"roleArn,omitempty"`
	// RoleClaim names an ID token claim holding one or more role ARNs. Several
	// let the user choose a role for the session.
	RoleClaim string `json:"roleClaim,omitempty"`
	// Scopes is the space-separated scope list; it must include "openid".
	// Empty means DefaultOIDCScopes.
	Scopes string `json:"scopes"`
	// Label is the sign-in button text. Empty means DefaultOIDCLabel.
	Label string `json:"label"`
	// SessionDuration is sent as DurationSeconds. Zero leaves it to the IAM
	// service's default of one hour.
	SessionDuration int `json:"sessionDuration,omitempty"`
	// RedirectURI overrides the redirect URI the browser otherwise derives
	// from the login page's own URL.
	RedirectURI string `json:"redirectUri,omitempty"`
	// AllowHTTP permits a plain http Issuer, for test providers. The IAM
	// service needs its own --oidc-allow-insecure-transport to accept the
	// same issuer.
	AllowHTTP bool `json:"-"`
}

// Enabled reports whether SSO is configured.
func (c OIDCConfig) Enabled() bool {
	return c.Issuer != ""
}

// Validate checks the settings for a WebUI whose login page offers
// iamGateways as its standalone IAM service endpoints. SSO signs in through
// that service, so it needs at least one of them.
func (c OIDCConfig) Validate(iamGateways []string) error {
	if !c.Enabled() {
		if c.ClientID != "" || c.RoleArn != "" || c.RoleClaim != "" || c.RedirectURI != "" || c.SessionDuration != 0 {
			return errors.New("webui-oidc settings are set but webui-oidc-issuer is not; the issuer is what turns WebUI single sign-on on")
		}
		return nil
	}

	if err := validateOIDCURL("webui-oidc-issuer", c.Issuer, c.AllowHTTP); err != nil {
		return err
	}
	// OpenID Connect Discovery forbids a query in the issuer identifier.
	if strings.Contains(c.Issuer, "?") {
		return fmt.Errorf("invalid webui-oidc-issuer %q: must not contain a query", c.Issuer)
	}
	if c.ClientID == "" {
		return errors.New("webui-oidc-client-id is required when webui-oidc-issuer is set")
	}
	if strings.ContainsFunc(c.ClientID, isSpace) {
		return fmt.Errorf("invalid webui-oidc-client-id %q: must not contain whitespace", c.ClientID)
	}
	if c.RoleArn == "" && c.RoleClaim == "" {
		return errors.New("webui-oidc-role-arn or webui-oidc-role-claim is required when webui-oidc-issuer is set")
	}
	if c.RoleArn != "" && !oidcRoleArnPattern.MatchString(c.RoleArn) {
		return fmt.Errorf("invalid webui-oidc-role-arn %q: must be a role ARN such as arn:aws:iam::000000000000:role/name", c.RoleArn)
	}
	if strings.ContainsFunc(c.RoleClaim, isSpace) {
		return fmt.Errorf("invalid webui-oidc-role-claim %q: must not contain whitespace", c.RoleClaim)
	}
	if c.Scopes != "" && !slices.Contains(strings.Fields(c.Scopes), "openid") {
		return fmt.Errorf("invalid webui-oidc-scopes %q: must include openid", c.Scopes)
	}
	if c.SessionDuration != 0 && (c.SessionDuration < MinOIDCSessionDuration || c.SessionDuration > MaxOIDCSessionDuration) {
		return fmt.Errorf("invalid webui-oidc-session-duration %d: must be between %d and %d seconds", c.SessionDuration, MinOIDCSessionDuration, MaxOIDCSessionDuration)
	}
	if c.RedirectURI != "" {
		// The redirect URI is the WebUI's own address, and a WebUI served
		// over plain http (local, or behind a TLS-terminating proxy) is a
		// supported setup, so http needs no opt-in here.
		if err := validateOIDCURL("webui-oidc-redirect-uri", c.RedirectURI, true); err != nil {
			return err
		}
	}
	if len(iamGateways) == 0 {
		return errors.New("webui-oidc-issuer requires webui-iam-gateways: WebUI single sign-on exchanges the provider's token at the standalone IAM service")
	}

	return nil
}

// withDefaults fills the fields that have a default.
func (c OIDCConfig) withDefaults() OIDCConfig {
	if strings.TrimSpace(c.Scopes) == "" {
		c.Scopes = DefaultOIDCScopes
	}
	c.Scopes = strings.Join(strings.Fields(c.Scopes), " ")
	if strings.TrimSpace(c.Label) == "" {
		c.Label = DefaultOIDCLabel
	}
	return c
}

// validateOIDCURL checks that raw is an absolute https URL, or http when
// allowHTTP is set, with a host and no credentials or fragment.
func validateOIDCURL(option, raw string, allowHTTP bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid %s %q: %w", option, raw, err)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && allowHTTP:
	case u.Scheme == "http":
		return fmt.Errorf("invalid %s %q: must be an https URL (plain http needs webui-oidc-allow-http)", option, raw)
	default:
		return fmt.Errorf("invalid %s %q: must be an absolute https URL", option, raw)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid %s %q: missing host", option, raw)
	}
	if u.User != nil {
		return fmt.Errorf("invalid %s %q: must not contain credentials", option, raw)
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("invalid %s %q: must not contain a fragment", option, raw)
	}
	return nil
}

func isSpace(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\r'
}
