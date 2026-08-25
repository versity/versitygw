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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/iamapi/policy"
	"golang.org/x/sync/singleflight"
)

const (
	MinRoleSessionNameLen = 2
	MaxRoleSessionNameLen = 64

	MinWebIdentityTokenLen = 4
	MaxWebIdentityTokenLen = 20000

	MinRoleArnLen = 20
	MaxRoleArnLen = 2048

	MinDurationSeconds     = 900
	MaxDurationSeconds     = 43200
	DefaultDurationSeconds = 3600

	// webIdentityExpLeeway is AWS's observed clock-skew allowance for a web
	// identity token's exp claim: a token expired by less than this is
	// still accepted.
	webIdentityExpLeeway = 5 * time.Minute

	oidcFetchTimeout      = 8 * time.Second
	maxOIDCFetchBodyBytes = 1 << 20 // 1 MiB; well beyond any real discovery doc or JWKS.

	// maxJWKSKeysPerType is AWS's documented OIDC provider JWKS limit: at
	// most 100 RSA and 100 EC keys. A JWKS response exceeding either bound
	// is rejected outright rather than accepted into the cache and iterated
	// over on every verification.
	maxJWKSKeysPerType = 100

	// jwksMinForcedRefreshInterval rate-limits how often a token with an
	// unrecognized kid can force a JWKS refresh for the same issuer, on top
	// of jwksCacheTTL's normal expiry. Without this, anyone who knows a
	// trusted issuer/audience/role ARN could send unlimited tokens carrying
	// unique, made-up kid values and force a fresh discovery-document-plus-
	// JWKS fetch against the real IdP for every single one, before any
	// signature or authentication check ever runs.
	jwksMinForcedRefreshInterval = 30 * time.Second

	// maxOIDCFetchRedirects bounds how many redirects a discovery-document
	// or JWKS fetch will follow. net/http's own default client stops after
	// 10 redirects, but that default is implemented by its CheckRedirect
	// func - replacing CheckRedirect (as ssrfSafeHTTPClient does, to add the
	// https-only and SSRF checks) silently loses that cap entirely unless
	// the replacement enforces its own.
	maxOIDCFetchRedirects = 5
)

var roleSessionNamePattern = regexp.MustCompile(`^[\w+=,.@-]*$`)

// ValidateRoleSessionName checks RoleSessionName against STS's length and
// charset constraints.
func ValidateRoleSessionName(name string) error {
	if len(name) < MinRoleSessionNameLen {
		debuglogger.Logf("RoleSessionName too short: %q", name)
		return iamerr.ValueTooShort("roleSessionName", MinRoleSessionNameLen)
	}
	if len(name) > MaxRoleSessionNameLen {
		debuglogger.Logf("RoleSessionName too long: %q", name)
		return iamerr.ValueTooLong("roleSessionName", MaxRoleSessionNameLen)
	}
	if !roleSessionNamePattern.MatchString(name) {
		debuglogger.Logf("invalid RoleSessionName characters: %q", name)
		return iamerr.InvalidRoleSessionName(name)
	}
	return nil
}

// ValidateWebIdentityTokenLength checks WebIdentityToken against STS's
// length constraints (content/structure is validated separately by
// ParseWebIdentityClaims).
func ValidateWebIdentityTokenLength(token string) error {
	if len(token) < MinWebIdentityTokenLen {
		debuglogger.Logf("WebIdentityToken too short: length=%d", len(token))
		return iamerr.ValueTooShort("webIdentityToken", MinWebIdentityTokenLen)
	}
	if len(token) > MaxWebIdentityTokenLen {
		debuglogger.Logf("WebIdentityToken too long: length=%d", len(token))
		return iamerr.ValueTooLong("webIdentityToken", MaxWebIdentityTokenLen)
	}
	return nil
}

// ValidateRoleArnLength checks RoleArn against STS's length constraints.
func ValidateRoleArnLength(arn string) error {
	if len(arn) < MinRoleArnLen {
		debuglogger.Logf("RoleArn too short: %q", arn)
		return iamerr.ValueTooShort("roleArn", MinRoleArnLen)
	}
	if len(arn) > MaxRoleArnLen {
		debuglogger.Logf("RoleArn too long: length=%d", len(arn))
		return iamerr.ValueTooLong("roleArn", MaxRoleArnLen)
	}
	return nil
}

// ParseDurationSeconds parses AssumeRoleWithWebIdentity's optional
// DurationSeconds request parameter, returning DefaultDurationSeconds
// (always 1 hour, regardless of the role's own MaxSessionDuration) when
// absent.
func ParseDurationSeconds(ctx fiber.Ctx) (int32, error) {
	raw, ok := RequestParam(ctx, "DurationSeconds")
	if !ok || raw == "" {
		return DefaultDurationSeconds, nil
	}

	parsed, err := strconv.ParseInt(raw, 10, 32)
	if err != nil {
		debuglogger.Logf("malformed DurationSeconds value %q", raw)
		return 0, iamerr.MalformedInput()
	}
	if parsed < MinDurationSeconds {
		debuglogger.Logf("DurationSeconds too low: %s", raw)
		return 0, iamerr.DurationSecondsTooLow(raw)
	}
	if parsed > MaxDurationSeconds {
		debuglogger.Logf("DurationSeconds too high: %s", raw)
		return 0, iamerr.DurationSecondsTooHigh(raw)
	}

	return int32(parsed), nil
}

// RoleNameFromAssumeArn extracts the role name from a RoleArn of the shape
// arn:aws:iam::<account>:role/<path/><name>, for an assumed-role account
// matching accountID. Any other shape (wrong account, wrong resource type,
// not even ARN-shaped) reports ok=false: AssumeRoleWithWebIdentity treats
// all such cases identically (AccessDenied), never distinguishing "no such
// role" from "malformed ARN" the way other IAM actions do, so no error
// value is returned here.
func RoleNameFromAssumeArn(arn, accountID string) (roleName string, ok bool) {
	const prefix = "arn:aws:iam::"
	if !strings.HasPrefix(arn, prefix) {
		return "", false
	}
	rest := strings.TrimPrefix(arn, prefix)

	acct, rest, found := strings.Cut(rest, ":")
	if !found || acct != accountID {
		return "", false
	}

	resourceType, resource, found := strings.Cut(rest, "/")
	if !found || resourceType != "role" || resource == "" {
		return "", false
	}

	if idx := strings.LastIndex(resource, "/"); idx >= 0 {
		resource = resource[idx+1:]
	}
	if resource == "" {
		return "", false
	}
	return resource, true
}

// ParseWebIdentityClaims parses tokenString as a JWT without verifying its
// signature, returning its claims. This is the first step of
// AssumeRoleWithWebIdentity validation: the token's iss claim must be read
// before it's known which OIDC provider (and therefore which signing keys)
// to verify against.
func ParseWebIdentityClaims(tokenString string) (jwt.MapClaims, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		debuglogger.Logf("web identity token is not a valid JWT: %v", err)
		return nil, iamerr.InvalidIdentityTokenMalformed()
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, iamerr.InvalidIdentityTokenMalformed()
	}
	return claims, nil
}

// WebIdentityIssuer returns claims' iss value, scheme-stripped to match the
// stored form of a registered OIDC provider's Url.
//
// Only an "https://" prefix is stripped — OIDC issuer identifiers are
// compared exactly, scheme included, and CreateOpenIDConnectProvider already
// requires every registered provider's Url to be https. An iss using any
// other scheme (or none at all) therefore can never legitimately equal a
// registered provider; returning it unstripped in that case (rather than
// also trimming a bare "http://") guarantees it stays distinguishable from a
// same-host https issuer instead of being silently treated as equivalent.
func WebIdentityIssuer(claims jwt.MapClaims) (string, bool) {
	iss, ok := claims["iss"].(string)
	if !ok || iss == "" {
		return "", false
	}
	if stripped, ok := strings.CutPrefix(iss, "https://"); ok {
		return stripped, true
	}
	return iss, true
}

// WebIdentityAudience resolves a web identity token's "effective audience"
// (the value AWS maps to the <provider>:aud trust-policy condition key)
// along with its original aud claim value(s) (mapped to <provider>:oaud
// whenever azp overrides them).
//
// Whenever azp (authorized party) is present, it is always the effective
// audience — regardless of whether aud itself carries one value or many —
// and the original aud claim value(s) are additionally returned for the
// oaud mapping; this matters for Google hybrid clients, where aud names the
// backend project and azp names the actual OAuth client that requested the
// token. A multi-valued aud with no azp is rejected — per OpenID Connect
// Core, a multi-audience ID token must carry azp to disambiguate which
// audience the token was issued for, and AWS enforces this as a hard
// requirement rather than a recommendation.
func WebIdentityAudience(claims jwt.MapClaims) (audience string, original []string, err error) {
	var auds []string
	switch v := claims["aud"].(type) {
	case string:
		if v != "" {
			auds = []string{v}
		}
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok && s != "" {
				auds = append(auds, s)
			}
		}
	}

	if len(auds) == 0 {
		debuglogger.Logf("web identity token has no aud claim")
		return "", nil, iamerr.InvalidIdentityTokenClaims()
	}

	if azp, _ := claims["azp"].(string); azp != "" {
		return azp, auds, nil
	}

	if len(auds) > 1 {
		debuglogger.Logf("web identity token has multiple audiences %v but no azp claim", auds)
		return "", nil, iamerr.InvalidIdentityTokenMultipleAudiences()
	}
	return auds[0], nil, nil
}

// wellKnownClaims are excluded from ExtractClaimContext: they're either
// handled specially (iss/aud/azp/sub) or aren't meaningful as trust-policy
// Condition context (exp/iat/nbf are timestamps, not strings).
var wellKnownClaims = map[string]bool{
	"iss": true, "aud": true, "azp": true, "sub": true,
	"exp": true, "iat": true, "nbf": true,
}

// ExtractClaimContext projects every other top-level scalar or
// scalar-array claim from a web identity token into a plain map, for
// trust-policy Condition keys beyond the well-known "aud"/"sub" (e.g. a
// custom "amr" or "groups" claim, or a Bool/Numeric/Date condition against a
// custom "admin"/"tier"/"level" claim).
func ExtractClaimContext(claims jwt.MapClaims) map[string][]string {
	out := make(map[string][]string, len(claims))
	for name, value := range claims {
		if wellKnownClaims[name] {
			continue
		}
		switch v := value.(type) {
		case []any:
			var values []string
			for _, e := range v {
				if s, ok := claimScalarString(e); ok {
					values = append(values, s)
				}
			}
			if len(values) > 0 {
				out[name] = values
			}
		default:
			if s, ok := claimScalarString(v); ok {
				out[name] = []string{s}
			}
		}
	}
	return out
}

// claimScalarString converts a single decoded JWT claim value to its
// Condition-context string form. golang-jwt decodes every JSON number as
// float64 and every JSON bool as bool (standard encoding/json behavior for
// an interface{} target) - without this, a claim like "tier": 3 or "admin":
// true would never reach the Condition context at all (the key would always
// look "absent"), silently defeating a Bool/Numeric/Date condition guarding
// it. 'f', -1 gives the shortest round-tripping decimal form (3.0 -> "3",
// 4.5 -> "4.5"), matching how a policy author would hand-write the value.
func claimScalarString(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(v), true
	default:
		return "", false
	}
}

// BuildAssumedRoleArn constructs the ARN a role's temporary session
// credentials are identified by. Unlike the role's own ARN
// (arn:aws:iam::...:role/...), an assumed session uses the sts service.
func BuildAssumedRoleArn(accountID, roleName, roleSessionName string) string {
	return fmt.Sprintf("arn:aws:sts::%s:assumed-role/%s/%s", accountID, roleName, roleSessionName)
}

// PackedPolicySize reports the percentage of policy.MaxSessionPolicyBytes
// sessionPolicy consumes, or nil if no session Policy parameter was
// supplied at all — matching how AWS omits PackedPolicySize entirely in
// that case rather than reporting 0%.
func PackedPolicySize(sessionPolicy string) *int64 {
	if sessionPolicy == "" {
		return nil
	}
	pct := int64(len(sessionPolicy) * 100 / policy.MaxSessionPolicyBytes)
	return &pct
}

// VerifyWebIdentityExpiration checks claims' exp against now, allowing
// webIdentityExpLeeway of clock skew.
func VerifyWebIdentityExpiration(claims jwt.MapClaims, now time.Time) error {
	expFloat, ok := claims["exp"].(float64)
	if !ok {
		debuglogger.Logf("web identity token has no exp claim")
		return iamerr.InvalidIdentityTokenClaims()
	}
	exp := int64(expFloat)
	if now.After(time.Unix(exp, 0).Add(webIdentityExpLeeway)) {
		debuglogger.Logf("web identity token expired: now=%d exp=%d", now.Unix(), exp)
		return iamerr.ExpiredWebIdentityToken(now.Unix(), exp)
	}
	return nil
}

// VerifyWebIdentityRequiredClaims checks claims for AWS's other mandatory
// web identity token claims beyond exp (already checked separately by
// VerifyWebIdentityExpiration): iat and sub must both be present, and nbf
// (if present) must not be in the future beyond webIdentityExpLeeway of
// clock skew. A token with exp but no iat, or with iat but no sub, is
// rejected with InvalidIdentityToken "Missing a required claim:
// <iat|sub>." — without this check, such a token would otherwise obtain
// credentials whenever the role's trust policy doesn't itself require sub
// via Condition.
func VerifyWebIdentityRequiredClaims(claims jwt.MapClaims, now time.Time) error {
	if _, ok := claims["iat"].(float64); !ok {
		debuglogger.Logf("web identity token has no iat claim")
		return iamerr.InvalidIdentityTokenMissingClaim("iat")
	}
	if sub, ok := claims["sub"].(string); !ok || sub == "" {
		debuglogger.Logf("web identity token has no sub claim")
		return iamerr.InvalidIdentityTokenMissingClaim("sub")
	}
	if nbfFloat, ok := claims["nbf"].(float64); ok {
		nbf := time.Unix(int64(nbfFloat), 0)
		if now.Before(nbf.Add(-webIdentityExpLeeway)) {
			debuglogger.Logf("web identity token not yet valid: now=%d nbf=%d", now.Unix(), int64(nbfFloat))
			return iamerr.InvalidIdentityTokenClaims()
		}
	}
	return nil
}

// VerifyWebIdentitySignature fetches issuerURL's OIDC discovery document
// and JWKS (from cache when a fresh-enough entry exists), then verifies
// tokenString's signature against the matching key. On success it returns
// the token's verified claims (exp/nbf/iat are not re-checked here —
// callers that need those checks perform them separately with AWS-matching
// messages and leeway).
//
// thumbprints is the OIDC provider's registered ThumbprintList, used as a
// pinned-certificate fallback when the JWKS endpoint's TLS certificate
// doesn't chain to a trusted root (self-signed/private-CA providers).
//
// If the cached key set doesn't contain the token's kid, the cache is
// bypassed for one forced refresh before giving up — the provider may have
// rotated its signing key since the cache entry was fetched.
func VerifyWebIdentitySignature(ctx context.Context, tokenString, issuerURL string, thumbprints []string) (jwt.MapClaims, error) {
	keys, err := cachedJWKS(ctx, issuerURL, thumbprints)
	if err != nil {
		debuglogger.Logf("failed to fetch JWKS for web identity provider %q: %v", issuerURL, err)
		return nil, iamerr.InvalidIdentityTokenIDPCommunicationError()
	}

	claims, err := verifySignatureWithKeys(tokenString, keys)
	if err != nil && errors.Is(err, errUnknownKID) {
		keys, refreshErr := forceRefreshJWKSCache(ctx, issuerURL, thumbprints)
		if refreshErr != nil {
			debuglogger.Logf("failed to refresh JWKS for web identity provider %q: %v", issuerURL, refreshErr)
			return nil, iamerr.InvalidIdentityTokenIDPCommunicationError()
		}
		claims, err = verifySignatureWithKeys(tokenString, keys)
	}
	if err != nil {
		debuglogger.Logf("web identity token signature verification failed: %v", err)
		return nil, iamerr.InvalidIdentityTokenClaims()
	}
	return claims, nil
}

// errUnknownKID is keyFunc's error when a token's kid names no key in the
// set — the signal VerifyWebIdentitySignature uses to force one cache
// refresh (the provider may have rotated its signing key) before giving up.
var errUnknownKID = errors.New("no matching JWKS key for kid")

// verifySignatureWithKeys is VerifyWebIdentitySignature's network-free core,
// split out so it can be exercised directly against an in-memory key set
// (the SSRF guard in fetchJWKS's dialer means it can never itself be
// exercised against a same-process test server — the same split
// FetchThumbprint/ThumbprintFromChain use). The returned error is the raw
// parse/verification failure (not yet converted to an iamerr), so callers
// can distinguish errUnknownKID from every other failure.
func verifySignatureWithKeys(tokenString string, keys *jwkSet) (jwt.MapClaims, error) {
	parser := jwt.NewParser(
		jwt.WithoutClaimsValidation(),
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}),
	)
	token, err := parser.Parse(tokenString, keys.keyFunc)
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("web identity token failed signature verification")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("web identity token claims are not a JSON object")
	}
	return claims, nil
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// keyFunc resolves a token's verification key by matching its header kid
// against the set. A set with exactly one key is used regardless of kid
// (or its absence) — a common pattern for single-key providers.
func (s *jwkSet) keyFunc(token *jwt.Token) (any, error) {
	kid, _ := token.Header["kid"].(string)

	if len(s.Keys) == 1 && (kid == "" || s.Keys[0].Kid == kid || s.Keys[0].Kid == "") {
		return s.Keys[0].publicKey()
	}
	for _, k := range s.Keys {
		if k.Kid == kid {
			return k.publicKey()
		}
	}
	return nil, fmt.Errorf("%w: %q", errUnknownKID, kid)
}

func (k jwk) publicKey() (any, error) {
	switch k.Kty {
	case "RSA":
		nb, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("decode RSA modulus: %w", err)
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("decode RSA exponent: %w", err)
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(nb),
			E: int(new(big.Int).SetBytes(eb).Int64()),
		}, nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve %q", k.Crv)
		}
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("decode EC x: %w", err)
		}
		yb, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, fmt.Errorf("decode EC y: %w", err)
		}
		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xb),
			Y:     new(big.Int).SetBytes(yb),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported JWK key type %q", k.Kty)
	}
}

type oidcDiscoveryDoc struct {
	Issuer  string `json:"issuer"`
	JWKSUri string `json:"jwks_uri"`
}

// validateDiscoveryIssuer reports an error unless doc's issuer exactly
// matches issuerURL's provider Url: both the OIDC discovery spec and
// AWS's own documentation require an exact match, not merely a document
// reachable from the provider's own URL — otherwise a provider could return,
// or be redirected/misdirected to, an entirely different issuer's metadata.
func validateDiscoveryIssuer(doc oidcDiscoveryDoc, issuerURL string) error {
	want := "https://" + issuerURL
	if doc.Issuer != want {
		return fmt.Errorf("discovery document for %q has mismatched issuer %q", issuerURL, doc.Issuer)
	}
	return nil
}

// jwksCacheTTL bounds how long a fetched key set is reused before
// VerifyWebIdentitySignature fetches it again, so that a burst of
// AssumeRoleWithWebIdentity calls for the same provider doesn't turn into a
// discovery-document-plus-JWKS fetch per call (latency, rate-limiting, and —
// since this fetch happens before the caller is authenticated — anonymous
// request amplification against the IdP).
const jwksCacheTTL = 5 * time.Minute

type jwksCacheEntry struct {
	keys      *jwkSet
	expiresAt time.Time
	// lastForcedRefresh is when an unknown-kid lookup last bypassed
	// expiresAt to force a fetch for this issuer, gated by
	// jwksMinForcedRefreshInterval.
	lastForcedRefresh time.Time
}

var (
	jwksCacheMu sync.Mutex
	jwksCache   = map[string]jwksCacheEntry{}

	// jwksFetchGroup coalesces concurrent fetches for the same issuerURL —
	// from cache-expiry and forced unknown-kid refreshes alike — into a
	// single outbound discovery-document-plus-JWKS request, so a burst of
	// simultaneous AssumeRoleWithWebIdentity calls (e.g. many callers'
	// caches expiring at once) doesn't turn into one fetch per caller.
	jwksFetchGroup singleflight.Group
)

// jwksCacheKey builds cachedJWKS's cache key from issuerURL and the
// provider's current ThumbprintList, so that changing a provider's
// thumbprints (e.g. after a signing-key or CA compromise) or recreating the
// provider at the same URL with a different ThumbprintList invalidates any
// previously cached key set immediately instead of leaving it reachable for
// up to jwksCacheTTL more. Every call site always supplies the provider's
// current ThumbprintList (freshly read from storage for the request being
// verified), so a changed configuration always maps to a different key here;
// thumbprints are sorted first since storage doesn't guarantee list order is
// stable across reads of an unchanged provider.
func jwksCacheKey(issuerURL string, thumbprints []string) string {
	sorted := slices.Clone(thumbprints)
	slices.Sort(sorted)
	return issuerURL + "|" + strings.Join(sorted, ",")
}

// cachedJWKS returns issuerURL's key set from cache if a fresh-enough entry
// exists for the current thumbprints, otherwise fetches and caches a fresh
// one.
func cachedJWKS(ctx context.Context, issuerURL string, thumbprints []string) (*jwkSet, error) {
	key := jwksCacheKey(issuerURL, thumbprints)
	jwksCacheMu.Lock()
	entry, ok := jwksCache[key]
	jwksCacheMu.Unlock()
	if ok && time.Now().Before(entry.expiresAt) {
		return entry.keys, nil
	}
	return fetchAndCacheJWKS(ctx, issuerURL, thumbprints)
}

// forceRefreshJWKSCache is VerifyWebIdentitySignature's fallback when a
// token's kid matches no cached key: the provider may have rotated its
// signing key since the cache entry was fetched. This bypasses
// expiresAt but not jwksMinForcedRefreshInterval — within that window of a
// previous forced refresh attempt for the same issuer, the still-cached (and
// still non-matching) key set is returned unchanged rather than fetching
// again. Without this gate, an unknown kid alone (no valid signature or
// authentication required to reach this code) would let anyone who knows a
// trusted issuer force one outbound fetch per token by simply varying kid.
//
// lastForcedRefresh is recorded *before* the fetch is attempted, not after a
// success: gating only on success left a failing or slow/unreachable
// issuer with no negative-caching at all — every unknown-kid token would
// re-trigger a fresh outbound fetch (and wait out its own timeout) with no
// backoff, since a failed attempt never set the timestamp that would have
// gated the next one. Recording the attempt up front bounds retries to one
// per jwksMinForcedRefreshInterval regardless of whether the fetch succeeds.
func forceRefreshJWKSCache(ctx context.Context, issuerURL string, thumbprints []string) (*jwkSet, error) {
	key := jwksCacheKey(issuerURL, thumbprints)
	jwksCacheMu.Lock()
	entry, ok := jwksCache[key]
	if ok && time.Since(entry.lastForcedRefresh) < jwksMinForcedRefreshInterval {
		jwksCacheMu.Unlock()
		if entry.keys == nil {
			// The gate is active but there's no key material to fall back
			// on — either this is the very first forced refresh for key
			// and it hasn't completed yet, or every attempt so far has
			// failed. Fail closed instead of returning a nil key set for
			// the caller to dereference.
			return nil, fmt.Errorf("no cached JWKS available for %q and a recent refresh attempt is still rate-limited", issuerURL)
		}
		return entry.keys, nil
	}
	entry.lastForcedRefresh = time.Now()
	jwksCache[key] = entry
	jwksCacheMu.Unlock()

	return fetchAndCacheJWKS(ctx, issuerURL, thumbprints)
}

// fetchAndCacheJWKS fetches issuerURL's key set and, on success, replaces
// its cache entry, coalescing concurrent callers for the same issuerURL AND
// thumbprints via jwksFetchGroup (keyed identically to jwksCache, so a
// caller mid-fetch for one thumbprint configuration never receives a result
// coalesced from a differently-configured concurrent caller).
func fetchAndCacheJWKS(ctx context.Context, issuerURL string, thumbprints []string) (*jwkSet, error) {
	key := jwksCacheKey(issuerURL, thumbprints)
	v, err, _ := jwksFetchGroup.Do(key, func() (any, error) {
		keys, err := fetchJWKS(ctx, issuerURL, thumbprints)
		if err != nil {
			return nil, err
		}
		jwksCacheMu.Lock()
		entry := jwksCache[key]
		entry.keys = keys
		entry.expiresAt = time.Now().Add(jwksCacheTTL)
		jwksCache[key] = entry
		jwksCacheMu.Unlock()
		return keys, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*jwkSet), nil
}

// fetchJWKS retrieves issuerURL's OIDC discovery document, then the JWKS it
// points to. issuerURL is the provider's stored Url (scheme stripped).
// thumbprints, if non-empty, lets the fetch's TLS connections succeed
// against a self-signed/private-CA certificate whose chain matches one of
// them, the same trust-pinning fallback real AWS documents for OIDC
// providers.
func fetchJWKS(ctx context.Context, issuerURL string, thumbprints []string) (*jwkSet, error) {
	client := ssrfSafeHTTPClient(thumbprints)
	base := "https://" + issuerURL

	var doc oidcDiscoveryDoc
	if err := fetchJSON(ctx, client, strings.TrimRight(base, "/")+"/.well-known/openid-configuration", &doc); err != nil {
		return nil, err
	}
	if err := validateDiscoveryIssuer(doc, issuerURL); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(doc.JWKSUri, "https://") {
		return nil, fmt.Errorf("discovery document for %q has non-https jwks_uri %q", issuerURL, doc.JWKSUri)
	}

	var keys jwkSet
	if err := fetchJSON(ctx, client, doc.JWKSUri, &keys); err != nil {
		return nil, err
	}
	if len(keys.Keys) == 0 {
		return nil, fmt.Errorf("no keys published at %q", doc.JWKSUri)
	}
	if err := enforceJWKSKeyLimits(keys.Keys); err != nil {
		return nil, fmt.Errorf("JWKS at %q: %w", doc.JWKSUri, err)
	}
	return &keys, nil
}

// enforceJWKSKeyLimits rejects a key set exceeding AWS's documented OIDC
// provider limits (100 RSA and 100 EC keys) before it's cached or iterated
// over by keyFunc on every verification — an oversized or malicious JWKS
// response should fail fast rather than being accepted as a large key set to
// scan on every request.
func enforceJWKSKeyLimits(keys []jwk) error {
	var rsaCount, ecCount int
	for _, k := range keys {
		switch k.Kty {
		case "RSA":
			rsaCount++
		case "EC":
			ecCount++
		}
	}
	if rsaCount > maxJWKSKeysPerType {
		return fmt.Errorf("%d RSA keys exceeds the %d-key limit", rsaCount, maxJWKSKeysPerType)
	}
	if ecCount > maxJWKSKeysPerType {
		return fmt.Errorf("%d EC keys exceeds the %d-key limit", ecCount, maxJWKSKeysPerType)
	}
	return nil
}

func fetchJSON(ctx context.Context, client *http.Client, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d from %q", resp.StatusCode, url)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOIDCFetchBodyBytes))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

// ssrfSafeHTTPClient returns an http.Client whose transport resolves each
// dial target's DNS once and rejects loopback/private/link-local/multicast
// addresses before connecting, mirroring FetchThumbprint's SSRF guard. It
// applies to every connection the client makes — including ones a redirect
// points at — since Transport.DialContext runs per underlying TCP
// connection, not just for the original request URL. CheckRedirect further
// refuses to follow any redirect whose target isn't https, since Go's
// default client would otherwise happily follow a discovery document (or
// its own redirect chain) down to plaintext http.
//
// TLS certificate verification is replaced with verifyOIDCConnection, which
// accepts a chain that matches one of thumbprints (AWS's documented
// trust-pinning fallback for self-signed/private-CA providers) even when
// standard CA-based verification would otherwise reject it, and falls back
// to ordinary hostname+CA verification against the system root pool
// whenever thumbprints is empty or doesn't match.
func ssrfSafeHTTPClient(thumbprints []string) *http.Client {
	dialer := &net.Dialer{}
	return &http.Client{
		Timeout: oidcFetchTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxOIDCFetchRedirects {
				return fmt.Errorf("stopped after %d redirects", maxOIDCFetchRedirects)
			}
			if req.URL.Scheme != "https" {
				return fmt.Errorf("refusing to follow non-https redirect to %q", req.URL)
			}
			return nil
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
				if err != nil || len(ips) == 0 {
					return nil, fmt.Errorf("dns lookup failed for %q", host)
				}
				for _, ip := range ips {
					if isDisallowedFetchTarget(ip) {
						return nil, fmt.Errorf("refusing to dial disallowed address %q for host %q", ip, host)
					}
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
			},
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // verified ourselves via VerifyConnection below
				VerifyConnection: func(cs tls.ConnectionState) error {
					return verifyOIDCConnection(cs, thumbprints)
				},
			},
		},
	}
}

// verifyOIDCConnection accepts cs's peer certificate chain if the top
// (topmost/intermediate CA) certificate's thumbprint matches any of
// thumbprints AND that certificate, used as the sole trust root, validates
// a signature path to the presented leaf for cs.ServerName — AWS's
// documented trust-pinning fallback trusts certificates *issued by* the
// pinned CA for the expected host, not merely any chain that happens to end
// in a certificate with that thumbprint. Thumbprint equality alone is never
// sufficient: an attacker can append the (non-secret) pinned certificate to
// an unrelated, unsigned chain, so the pinned certificate must also
// cryptographically issue the leaf and the leaf must match cs.ServerName.
// Falls back to standard hostname+CA verification against the system root
// pool whenever thumbprints is empty or none matches.
func verifyOIDCConnection(cs tls.ConnectionState, thumbprints []string) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("iamutil: no certificate presented")
	}

	if len(thumbprints) > 0 {
		top := cs.PeerCertificates[len(cs.PeerCertificates)-1]
		topThumbprint, err := ThumbprintFromChain(cs.PeerCertificates)
		if err != nil {
			return err
		}
		for _, pinned := range thumbprints {
			if !strings.EqualFold(pinned, topThumbprint) {
				continue
			}
			roots := x509.NewCertPool()
			roots.AddCert(top)
			opts := x509.VerifyOptions{
				DNSName:       cs.ServerName,
				Roots:         roots,
				Intermediates: x509.NewCertPool(),
			}
			if n := len(cs.PeerCertificates); n > 1 {
				for _, cert := range cs.PeerCertificates[1 : n-1] {
					opts.Intermediates.AddCert(cert)
				}
			}
			if _, err := cs.PeerCertificates[0].Verify(opts); err == nil {
				return nil
			}
			break
		}
	}

	opts := x509.VerifyOptions{
		DNSName:       cs.ServerName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range cs.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}
	_, err := cs.PeerCertificates[0].Verify(opts)
	return err
}
