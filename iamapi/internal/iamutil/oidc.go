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

package iamutil

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/iamapi/iamerr"
)

const (
	MinOIDCProviderArnLen         = 20
	MaxOIDCProviderArnLen         = 2048
	MaxOIDCProviderURLLen         = 255
	MaxOIDCClientIDLen            = 255
	MaxThumbprintsPerOIDCProvider = 5
	OIDCThumbprintLen             = 40

	oidcProviderResourceType = "oidc-provider"
)

var oidcHostLabelPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// insecureOIDCScheme is the plaintext scheme an OIDC provider Url may carry
// only when OIDCEndpointPolicy.AllowInsecureTransport is set.
const insecureOIDCScheme = "http://"

// OIDCEndpointPolicy relaxes the endpoint checks applied to an OIDC
// provider's Url and to every outbound fetch made against it (thumbprint
// auto-fetch at CreateOpenIDConnectProvider time, and the discovery
// document plus JWKS at AssumeRoleWithWebIdentity time).
//
// The zero value is the default, AWS-matching posture for an
// internet-facing IdP: https only, on the implicit :443, at a publicly
// routable address, with full hostname and chain verification against the
// system trust store (or a registered ThumbprintList). That posture makes
// the IAM API unusable with an IdP that is deliberately unreachable from
// the public internet — a SPIFFE/SPIRE OIDC discovery provider on a
// cluster-internal Service, or one bound to loopback as a sidecar in the
// gateway's own pod — because every address such an IdP can have is
// rejected outright, and no combination of the other settings can express
// "this private address is the IdP".
type OIDCEndpointPolicy struct {
	// AllowPrivateEndpoints permits a provider Url that resolves to a
	// loopback, private, link-local, unspecified, or multicast address, and
	// permits an explicit port in that Url (an IdP on an internal network
	// rarely gets to own :443 on its host). Transport is otherwise
	// unchanged: still https, still fully verified.
	//
	// This necessarily also re-permits cloud metadata endpoints
	// (e.g. 169.254.169.254) as fetch targets, so enable it only
	// where registering an OIDC provider is already a trusted,
	// administrator-only operation.
	AllowPrivateEndpoints bool

	// AllowInsecureTransport permits a plaintext http:// provider Url —
	// along with the http discovery/JWKS endpoints and redirects that
	// implies — and disables TLS certificate verification, ThumbprintList
	// pinning included, for https ones. It makes the network path itself
	// the only thing authenticating the IdP, so it belongs only where that
	// path is trustworthy on its own, such as a sidecar bound to loopback
	// inside the gateway's own pod.
	AllowInsecureTransport bool
}

// IsInsecureOIDCProviderURL reports whether providerURL, a stored provider
// Url, names a plaintext http endpoint.
//
// An https provider is stored scheme-stripped, the canonical form AWS uses;
// an http one (creatable only under AllowInsecureTransport) deliberately
// keeps its scheme in storage, in its ARN, and in the iss claim it is
// matched against, so "http://host" and "https://host" can never be taken
// for one another — the same reason WebIdentityIssuer strips only "https://".
func IsInsecureOIDCProviderURL(providerURL string) bool {
	return strings.HasPrefix(providerURL, insecureOIDCScheme)
}

// OIDCEndpointURL restores the full endpoint URL of a stored provider Url:
// the "https://" ValidateOIDCProviderURL stripped, or the "http://" it
// deliberately kept.
func OIDCEndpointURL(providerURL string) string {
	if IsInsecureOIDCProviderURL(providerURL) {
		return providerURL
	}
	return "https://" + providerURL
}

// ParseStringList reads flat indexed list members "<paramName>.member.1",
// "<paramName>.member.2", ... — the AWS Query-protocol wire form for a bare
// []string (distinct from ParseTags's Key/Value-pair member form, used by
// ClientIDList/ThumbprintList) — stopping at the first missing index.
// Returns nil if no entries are present.
func ParseStringList(ctx fiber.Ctx, paramName string) []string {
	var values []string
	for i := 1; ; i++ {
		value, ok := RequestParam(ctx, fmt.Sprintf("%s.member.%d", paramName, i))
		if !ok {
			break
		}
		values = append(values, value)
	}
	return values
}

// BuildOIDCProviderArn constructs the ARN for an IAM OIDC identity
// provider. url must already be in ValidateOIDCProviderURL's canonical
// stored form: an https provider with its scheme stripped, an http one
// (AllowInsecureTransport only) with its scheme intact.
func BuildOIDCProviderArn(accountID, url string) string {
	return fmt.Sprintf("arn:aws:iam::%s:oidc-provider/%s", accountID, url)
}

// ParseOIDCProviderArn validates arn's overall length and structural shape
// (arn:aws:iam::<account>:<resource-type>/<resource>) and, on success,
// returns the resource segment — the provider's Url exactly as stored (see
// BuildOIDCProviderArn for that form). The account-id segment must match
// DefaultAccountID; any other value is rejected with AccessDenied, matching
// real AWS's behavior for a well-formed ARN referencing a foreign account.
//
// Beyond the length and account-id checks, real AWS produces several more
// specific messages for structurally-malformed ARNs this function does not
// reproduce byte-for-byte — e.g. "Invalid service in ARN" for a non-iam
// service segment (a check this function does not perform at all), and a
// bare "Invalid ARN" (no echoed value) for a present-but-empty resource —
// this function falls back to a generic "Invalid ARN: %s" for those cases
// instead.
func ParseOIDCProviderArn(arn string) (string, error) {
	if len(arn) < MinOIDCProviderArnLen {
		debuglogger.Logf("invalid OpenIDConnectProviderArn length: %d", len(arn))
		return "", iamerr.ValueTooShort("openIDConnectProviderArn", MinOIDCProviderArnLen)
	}
	if len(arn) > MaxOIDCProviderArnLen {
		debuglogger.Logf("invalid OpenIDConnectProviderArn length: %d", len(arn))
		return "", iamerr.ValueTooLong("openIDConnectProviderArn", MaxOIDCProviderArnLen)
	}

	const prefix = "arn:aws:iam::"
	if !strings.HasPrefix(arn, prefix) {
		debuglogger.Logf("malformed OpenIDConnectProviderArn: %q", arn)
		return "", iamerr.ValidationError(fmt.Sprintf("Invalid ARN: %s", arn))
	}

	rest := strings.SplitN(arn[len(prefix):], ":", 2)
	if len(rest) != 2 || rest[0] == "" {
		debuglogger.Logf("malformed OpenIDConnectProviderArn: %q", arn)
		return "", iamerr.ValidationError(fmt.Sprintf("Invalid ARN: %s", arn))
	}
	if rest[0] != DefaultAccountID {
		debuglogger.Logf("OpenIDConnectProviderArn account id mismatch: %q", arn)
		return "", iamerr.AccessDeniedOIDCProvider(DefaultAccountID, arn)
	}

	resourceType, resource, ok := strings.Cut(rest[1], "/")
	if !ok || resource == "" {
		debuglogger.Logf("malformed OpenIDConnectProviderArn: %q", arn)
		return "", iamerr.ValidationError(fmt.Sprintf("Invalid ARN: %s", arn))
	}
	if resourceType != oidcProviderResourceType {
		debuglogger.Logf("wrong resource type in ARN: %q", arn)
		return "", iamerr.ValidationError("Invalid resource type in ARN")
	}

	return resource, nil
}

// GetOIDCProviderArn resolves the OpenIDConnectProviderArn request
// parameter, validates its shape via ParseOIDCProviderArn, and returns the
// ARN exactly as supplied by the caller (used verbatim in NoSuchEntity
// messages, which echo the full ARN, not just the url). A missing
// parameter is rejected with iamerr.MissingValue — every OIDC action
// taking this parameter reports it identically.
func GetOIDCProviderArn(ctx fiber.Ctx, operation string) (string, error) {
	arn, ok := RequestParam(ctx, "OpenIDConnectProviderArn")
	if !ok || arn == "" {
		debuglogger.Logf("missing required %s parameter: OpenIDConnectProviderArn", operation)
		return "", iamerr.MissingValue("openIDConnectProviderArn")
	}
	if _, err := ParseOIDCProviderArn(arn); err != nil {
		return "", err
	}
	return arn, nil
}

// ValidateOIDCProviderURL validates the Url parameter of
// CreateOpenIDConnectProvider and returns its canonical stored form — the
// form used for ARN construction, storage keys, iss-claim matching, and
// GetOpenIDConnectProvider's own Url response field.
//
// This implements a pragmatic subset of AWS's real validation: scheme must
// be exactly "https", no userinfo/port/query/fragment, host must be a
// syntactically plausible RFC-1123-ish hostname or IP literal, overall
// length <= MaxOIDCProviderURLLen. It does not attempt to reproduce every
// hostname-shape check AWS performs; it returns clear InvalidInput/
// ValidationError messages instead of chasing every malformed edge case.
//
// policy relaxes two of those rules for non-public IdPs:
// AllowPrivateEndpoints additionally accepts an explicit port, and
// AllowInsecureTransport additionally accepts an "http://" scheme.
//
// An https Url is returned scheme-stripped, as AWS canonicalizes it; an
// http one keeps its scheme, so that it stays distinguishable from the same
// host over https everywhere the stored form is used (see
// IsInsecureOIDCProviderURL).
func ValidateOIDCProviderURL(rawURL string, policy OIDCEndpointPolicy) (string, error) {
	if rawURL == "" {
		return "", iamerr.MissingValue("url")
	}
	if len(rawURL) > MaxOIDCProviderURLLen {
		return "", iamerr.ValueTooLong("url", MaxOIDCProviderURLLen)
	}
	// A URL with no scheme delimiter at all (e.g. "example.com") is
	// rejected as ValidationError; one with a scheme the policy doesn't
	// permit (e.g. "http://example.com" by default) is rejected as
	// InvalidInput — distinct error codes for distinct malformed inputs.
	if !strings.Contains(rawURL, "://") {
		return "", iamerr.ValidationError("Invalid Open ID Connect Provider URL")
	}
	insecure := policy.AllowInsecureTransport && strings.HasPrefix(rawURL, insecureOIDCScheme)
	if !insecure && !strings.HasPrefix(rawURL, "https://") {
		return "", iamerr.InvalidInput("Invalid Open ID Connect Provider URL. The URL must begin with https://.")
	}

	wantScheme := "https"
	if insecure {
		wantScheme = "http"
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != wantScheme || parsed.Host == "" {
		return "", iamerr.ValidationError("Invalid Open ID Connect Provider URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", iamerr.InvalidInput("Invalid Open ID Connect Provider URL.")
	}
	if parsed.Port() != "" && !policy.AllowPrivateEndpoints {
		return "", iamerr.InvalidInput("Invalid Open ID Connect Provider URL.")
	}
	if !isValidOIDCHostname(parsed.Hostname()) {
		return "", iamerr.InvalidInput("Invalid Open ID Connect Provider URL.")
	}

	if insecure {
		return rawURL, nil
	}
	return strings.TrimPrefix(rawURL, "https://"), nil
}

func isValidOIDCHostname(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !oidcHostLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

// ValidateThumbprintList validates a parsed ThumbprintList: at most
// MaxThumbprintsPerOIDCProvider entries, each exactly OIDCThumbprintLen
// characters (no hex-charset check — any 40-char string is accepted). If
// required is true, an empty list is rejected
// (UpdateOpenIDConnectProviderThumbprint, no auto-fetch fallback exists
// there); if false, an empty list passes through untouched
// (CreateOpenIDConnectProvider, whose caller handles empty via auto-fetch
// before calling this).
func ValidateThumbprintList(thumbprints []string, required bool) error {
	if required && len(thumbprints) == 0 {
		return iamerr.ThumbprintListEmpty()
	}
	if len(thumbprints) > MaxThumbprintsPerOIDCProvider {
		return iamerr.ThumbprintListTooLong(MaxThumbprintsPerOIDCProvider)
	}
	for _, tp := range thumbprints {
		if len(tp) != OIDCThumbprintLen {
			return iamerr.InvalidInput(fmt.Sprintf("Thumbprint must be exactly %d characters.", OIDCThumbprintLen))
		}
	}
	return nil
}

// NormalizeThumbprintList lowercases every entry: AWS stores/returns
// thumbprints lowercased regardless of submitted case.
func NormalizeThumbprintList(thumbprints []string) []string {
	out := make([]string, len(thumbprints))
	for i, tp := range thumbprints {
		out[i] = strings.ToLower(tp)
	}
	return out
}
