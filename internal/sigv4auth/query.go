// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sigv4auth

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/debuglogger"
)

const (
	AlgorithmECDSAP256SHA256 = "AWS4-ECDSA-P256-SHA256"

	QueryAlgorithm     = "X-Amz-Algorithm"
	QueryCredential    = "X-Amz-Credential"
	QueryDate          = "X-Amz-Date"
	QueryExpires       = "X-Amz-Expires"
	QuerySignedHeaders = "X-Amz-SignedHeaders"
	QuerySignature     = "X-Amz-Signature"
	QuerySecurityToken = "X-Amz-Security-Token"

	maxQueryExpirationSeconds = 604800
)

type QueryErrorKind string

const (
	ErrQueryMissingRequiredParams QueryErrorKind = "missing_required_query_parameters"
	ErrQueryUnsupportedAlgorithm  QueryErrorKind = "unsupported_query_algorithm"
	ErrQueryUnsupportedECDSA      QueryErrorKind = "unsupported_query_ecdsa"
	ErrQueryInvalidDateFormat     QueryErrorKind = "invalid_query_date_format"
	ErrQueryDateMismatch          QueryErrorKind = "query_date_mismatch"
	ErrQueryIncorrectRegion       QueryErrorKind = "query_incorrect_region"
	ErrQueryExpiresNumber         QueryErrorKind = "query_expires_number"
	ErrQueryExpiresNegative       QueryErrorKind = "query_expires_negative"
	ErrQueryExpiresTooLarge       QueryErrorKind = "query_expires_too_large"
	ErrQueryExpired               QueryErrorKind = "query_expired"
	ErrQuerySecurityToken         QueryErrorKind = "query_security_token"
)

type QueryError struct {
	Kind       QueryErrorKind
	Value      string
	Expected   string
	Actual     string
	Expires    int
	ExpiresAt  time.Time
	ServerTime time.Time
}

func (e *QueryError) Error() string {
	if e == nil {
		return ""
	}
	switch e.Kind {
	case ErrQueryIncorrectRegion:
		return fmt.Sprintf("sigv4 query %s: expected %q, got %q", e.Kind, e.Expected, e.Actual)
	case ErrQueryDateMismatch:
		return fmt.Sprintf("sigv4 query %s: expected %q, got %q", e.Kind, e.Expected, e.Actual)
	case ErrQueryExpired:
		return fmt.Sprintf("sigv4 query %s: expired at %s", e.Kind, e.ExpiresAt.Format(time.RFC3339))
	case ErrQueryUnsupportedAlgorithm, ErrQueryUnsupportedECDSA, ErrQueryExpiresNumber:
		return fmt.Sprintf("sigv4 query %s: %q", e.Kind, e.Value)
	default:
		return string(e.Kind)
	}
}

type QueryAuthOptions struct {
	Service string
	Region  string
	// RequireExpiration enables the X-Amz-Expires validation required by S3
	// presigned URLs. Other SigV4 query-auth services, including IAM, leave it
	// disabled.
	RequireExpiration bool
	Now               func() time.Time
}

type QueryAuthDetails struct {
	SigningTime time.Time
	Expires     int
	ExpiresAt   time.Time
	ServerTime  time.Time
}

// ParseQueryAuthorization parses and validates AWS SigV4 query-string
// authentication parameters. The credential scope service must match
// opts.Service. If opts.Region is set, the credential scope region must match
// it as well.
func ParseQueryAuthorization(ctx fiber.Ctx, opts QueryAuthOptions) (AuthData, QueryAuthDetails, error) {
	a := AuthData{}
	details := QueryAuthDetails{}

	if err := ValidateQueryAlgorithm(ctx.Query(QueryAlgorithm)); err != nil {
		return a, details, err
	}

	credsQuery := ctx.Query(QueryCredential)
	if credsQuery == "" {
		return a, details, missingQueryParameterError(QueryCredential)
	}

	creds, err := ParseCredentials(credsQuery, opts.Service)
	if err != nil {
		return a, details, err
	}

	// A security token in the query string is only ever legitimate alongside
	// a temporary (ASIA…) access key. Reject it outright for root or any
	// long-term (AKIA…) credential before any signature work, rather than
	// letting it fall through to a signature mismatch once the tampered or
	// unsigned token parameter invalidates the canonical query string.
	if ctx.Request().URI().QueryArgs().Has(QuerySecurityToken) && !IsTempAccessKeyID(creds.Access) {
		return a, details, &QueryError{Kind: ErrQuerySecurityToken}
	}

	if opts.Region != "" && creds.Region != opts.Region {
		return a, details, &QueryError{
			Kind:     ErrQueryIncorrectRegion,
			Expected: opts.Region,
			Actual:   creds.Region,
		}
	}

	date := ctx.Query(QueryDate)
	if date == "" {
		return a, details, missingQueryParameterError(QueryDate)
	}

	tdate, err := time.Parse(ISO8601Format, date)
	if err != nil {
		return a, details, &QueryError{Kind: ErrQueryInvalidDateFormat, Value: date}
	}

	if date[:8] != creds.Date {
		return a, details, &QueryError{
			Kind:     ErrQueryDateMismatch,
			Expected: creds.Date,
			Actual:   date[:8],
		}
	}

	signature := ctx.Query(QuerySignature)
	if signature == "" {
		return a, details, missingQueryParameterError(QuerySignature)
	}

	signedHdrs := ctx.Query(QuerySignedHeaders)
	if signedHdrs == "" {
		return a, details, missingQueryParameterError(QuerySignedHeaders)
	}

	expiration := QueryExpiration{}
	if opts.RequireExpiration {
		now := time.Now().UTC()
		if opts.Now != nil {
			now = opts.Now().UTC()
		}
		expiration, err = ValidateQueryExpiration(ctx.Query(QueryExpires), tdate, now)
		if err != nil {
			return a, details, err
		}
	}

	a = AuthData{
		Algorithm:     ctx.Query(QueryAlgorithm),
		Access:        creds.Access,
		Region:        creds.Region,
		Service:       creds.Service,
		SignedHeaders: signedHdrs,
		Signature:     signature,
		Date:          date,
	}
	details = QueryAuthDetails{
		SigningTime: tdate,
		Expires:     expiration.Expires,
		ExpiresAt:   expiration.ExpiresAt,
		ServerTime:  expiration.ServerTime,
	}

	return a, details, nil
}

func ValidateQueryAlgorithm(algo string) error {
	switch algo {
	case "":
		return missingQueryParameterError(QueryAlgorithm)
	case AlgorithmHMACSHA256:
		return nil
	case AlgorithmECDSAP256SHA256:
		return &QueryError{Kind: ErrQueryUnsupportedECDSA, Value: algo}
	default:
		return &QueryError{Kind: ErrQueryUnsupportedAlgorithm, Value: algo}
	}
}

type QueryExpiration struct {
	Expires    int
	ExpiresAt  time.Time
	ServerTime time.Time
}

func ValidateQueryExpiration(str string, date, now time.Time) (QueryExpiration, error) {
	if str == "" {
		return QueryExpiration{}, missingQueryParameterError(QueryExpires)
	}

	exp, err := strconv.Atoi(str)
	if err != nil {
		return QueryExpiration{}, &QueryError{Kind: ErrQueryExpiresNumber, Value: str}
	}

	if exp < 0 {
		return QueryExpiration{}, &QueryError{Kind: ErrQueryExpiresNegative, Value: str}
	}

	if exp > maxQueryExpirationSeconds {
		return QueryExpiration{}, &QueryError{Kind: ErrQueryExpiresTooLarge, Value: str}
	}

	now = now.UTC()
	expiresAt := date.Add(time.Duration(exp) * time.Second)
	expiration := QueryExpiration{
		Expires:    exp,
		ExpiresAt:  expiresAt,
		ServerTime: now,
	}

	if expiresAt.Before(now) {
		return expiration, &QueryError{
			Kind:       ErrQueryExpired,
			Expires:    exp,
			ExpiresAt:  expiresAt,
			ServerTime: now,
		}
	}

	return expiration, nil
}

func missingQueryParameterError(parameter string) *QueryError {
	return &QueryError{Kind: ErrQueryMissingRequiredParams, Value: parameter}
}

// CheckQuerySignature rebuilds a SigV4 query-auth request — reading
// everything it needs straight from ctx, with no intermediate
// *http.Request — and compares the generated query signature to the
// signature presented by the client. derivedKey is the request's kSigning
// value — either computed locally via DeriveKey from a known secret, or
// obtained from a standalone IAM service that never reveals the secret
// itself.
func CheckQuerySignature(ctx fiber.Ctx, auth AuthData, derivedKey []byte, payloadHash string, tdate time.Time, contentLen int64, opts CheckOptions) (*CheckResult, error) {
	service := opts.Service
	if service == "" {
		service = auth.Service
	}
	signedHdrs := strings.Split(auth.SignedHeaders, ";")

	in, err := signingInputFromCtx(ctx, signedHdrs, contentLen, opts.RequiredSignedHeaders, true)
	if err != nil {
		return nil, err
	}
	in.AccessKeyID = auth.Access
	in.CredentialScope = BuildCredentialScope(tdate.Format(YYYYMMDD), auth.Region, service)
	in.SignedHdrs = signedHdrs
	in.PayloadHash = payloadHash
	in.SigningTime = tdate
	in.DisableURIPathEscaping = opts.DisableURIPathEscaping

	result := BuildAndSign(derivedKey, in)

	// See the identical comment in verify.go's CheckSignature: this dumps a
	// complete, replayable signed query string unredacted, so it may only
	// run at LevelUnsafe.
	if debuglogger.IsUnsafeEnabled() {
		debuglogger.Logf("Request Signature:\n"+
			"---[ CANONICAL STRING  ]-----------------------------\n%s\n"+
			"---[ STRING TO SIGN ]--------------------------------\n%s\n"+
			"---[ SIGNED QUERY ]-----------------------------------\n%s\n"+
			"-----------------------------------------------------",
			result.CanonicalString, result.StringToSign, result.RawQuery)
	}

	if !SecureCompare(result.Signature, auth.Signature) {
		return nil, &SignatureMismatchError{
			AccessKeyID:           auth.Access,
			StringToSign:          result.StringToSign,
			SignatureProvided:     auth.Signature,
			StringToSignBytes:     HexBytes(result.StringToSign),
			CanonicalRequest:      result.CanonicalString,
			CanonicalRequestBytes: HexBytes(result.CanonicalString),
		}
	}

	return &CheckResult{
		CanonicalString: result.CanonicalString,
		StringToSign:    result.StringToSign,
	}, nil
}

var generatedQueryAuthParams = map[string]struct{}{
	QueryAlgorithm:     {},
	QueryCredential:    {},
	QueryDate:          {},
	QuerySignedHeaders: {},
	QuerySignature:     {},
}

// IsQueryAuth determines if a request uses SigV4 query-string auth.
func IsQueryAuth(ctx fiber.Ctx) bool {
	algo := ctx.Query(QueryAlgorithm)
	creds := ctx.Query(QueryCredential)
	date := ctx.Query(QueryDate)
	signature := ctx.Query(QuerySignature)
	signedHeaders := ctx.Query(QuerySignedHeaders)

	return !allEmpty(algo, creds, date, signature, signedHeaders)
}

// IsQueryAuthV2 determines if a request is query-string signed with the legacy
// AWS Signature Version 2 signer.
func IsQueryAuthV2(ctx fiber.Ctx) bool {
	expires := ctx.Query("Expires")
	access := ctx.Query("AWSAccessKeyId")
	signature := ctx.Query("Signature")

	return anyNonEmpty(expires, access, signature)
}

func allEmpty(args ...string) bool {
	for _, a := range args {
		if a != "" {
			return false
		}
	}

	return true
}

func anyNonEmpty(args ...string) bool {
	for _, a := range args {
		if a != "" {
			return true
		}
	}

	return false
}
