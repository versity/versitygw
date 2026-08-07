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

package iammiddleware

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/iamapi/internal/iamutil"
	"github.com/versity/versitygw/iamapi/types"
	"github.com/versity/versitygw/internal/httpctx"
	"github.com/versity/versitygw/internal/sigv4auth"
)

const (
	SigningRegion  = "us-east-1"
	timeExpiration = 15 * time.Minute
)

// requiredSignedHeaders is the header-auth SignedHeaders policy for a
// permanent (root or AKIA…) credential. requiredTempSignedHeaders is the
// counterpart for a temporary (ASIA…) session credential: it additionally
// requires the session-token header be signed whenever it's present,
// matching standard AWS SDK behavior — defense in depth on top of the
// independent, access-key-bound SessionToken equality check in
// resolveSessionIdentity, so the header can't be silently dropped from the
// canonical request and left unbound to the signature.
//
// This only applies to header auth. Query-string (presigned) auth carries
// the token as a query parameter instead, which createPresignedHTTPRequestFromCtx
// already includes in the signed canonical query string regardless of
// SignedHeaders, so requiredSignedHeaders (unconditionally "host") is used
// for both root/permanent and session query-auth requests.
var (
	requiredSignedHeaders     = []string{"host"}
	requiredTempSignedHeaders = []string{"host", sigv4auth.HeaderSecurityToken}
)

// requiredHeaderAuthSignedHeaders returns the SignedHeaders policy
// checkSignature enforces for header-based auth, based on whether accessKey
// is a temporary (ASIA…) session credential.
func requiredHeaderAuthSignedHeaders(accessKey string) []string {
	if iamutil.IsTempAccessKeyID(accessKey) {
		return requiredTempSignedHeaders
	}
	return requiredSignedHeaders
}

type RootCredentials struct {
	Access string
	Secret string
}

// IdentityStore resolves an access key id to the session or long-term user
// that owns it, and resolves named resources for policy evaluation.
// storage.Storer satisfies this directly.
type IdentityStore interface {
	GetSession(ctx context.Context, accessKeyID string) (*types.Session, error)
	GetRole(ctx context.Context, roleName string) (*types.Role, error)
	GetUserByAccessKeyID(ctx context.Context, accessKeyID string) (*types.User, error)
	GetUser(ctx context.Context, username string) (*types.User, error)
	GetOIDCProvider(ctx context.Context, arn string) (*types.OIDCProvider, error)
	RecordAccessKeyUsage(ctx context.Context, accessKeyID, service, region string, when time.Time) error
}

// VerifyIAMAuth authenticates a request against service (sigv4auth.ServiceIAM
// or sigv4auth.ServiceSTS).
//
// Three kinds of credential are accepted: the configured root user, a
// long-term (AKIA…) IAM user access key, or a temporary (ASIA…) session
// minted by AssumeRoleWithWebIdentity. Whichever it is, the resolved
// identity (and, for a user/session, its policy documents) is stored via
// httpctx.ContextKeyCallerIdentity for the policy middleware and controllers
// to read back. Root bypasses the policy middleware entirely
func VerifyIAMAuth(service string, root *RootCredentials, store IdentityStore) fiber.Handler {
	return func(ctx fiber.Ctx) error {
		authData, tdate, queryAuth, err := parseIAMAuth(ctx, service)
		if err != nil {
			return err
		}

		// A security token in the query string is only ever legitimate
		// alongside a temporary (ASIA…) access key — reject it outright for
		// root or any long-term (AKIA…) credential before any signature
		// work, the same way for both, rather than letting it fall through
		// to a signature-mismatch error once a tampered/unsigned token
		// param invalidates the canonical query string.
		if queryAuth && !iamutil.IsTempAccessKeyID(authData.Access) &&
			ctx.Request().URI().QueryArgs().Has(sigv4auth.QuerySecurityToken) {
			return iamerr.GetAPIError(iamerr.ErrInvalidClientTokenID)
		}

		if authData.Access == root.Access {
			if err := checkSignature(ctx, authData, root.Secret, tdate, queryAuth, service); err != nil {
				return err
			}
			httpctx.ContextKeyCallerIdentity.Set(ctx, types.Identity{IsRoot: true})
			return nil
		}

		identity, secret, err := resolveIdentity(ctx, store, authData, queryAuth)
		if err != nil {
			return err
		}

		if err := checkSignature(ctx, authData, secret, tdate, queryAuth, service); err != nil {
			return err
		}
		httpctx.ContextKeyCallerIdentity.Set(ctx, *identity)

		if identity.User != nil {
			recordAccessKeyUsage(ctx.Context(), store, authData.Access, service)
		}
		return nil
	}
}

// recordAccessKeyUsage best-effort-updates a permanent access key's
// GetAccessKeyLastUsed metadata (service, region, and timestamp) after it
// successfully authenticates a request, matching real IAM's behavior. A
// failure is only logged, never returned, since this is purely
// informational metadata and a lost update under concurrent use is
// immaterial. Called synchronously: a Storer implementation for which this
// update is network-bound (e.g. Vault) is expected to make it non-blocking
// itself rather than adding that latency to every authenticated request
func recordAccessKeyUsage(reqCtx context.Context, store IdentityStore, accessKeyID, service string) {
	if err := store.RecordAccessKeyUsage(reqCtx, accessKeyID, service, SigningRegion, time.Now().UTC()); err != nil {
		debuglogger.Logf("failed to record access key last-used metadata for %q: %v", accessKeyID, err)
	}
}

// resolveIdentity resolves authData.Access to a session or long-term user,
// by its AKIA…/ASIA… prefix, and returns the generic identity the rest of
// the request pipeline uses along with the secret VerifyIAMAuth checks the
// signature against. It does not itself verify the SigV4 signature — the
// caller does that next, so a stolen/guessed access key or session token
// alone is never sufficient.
//
// A temporary session can be used via query-string (presigned URL)
// authentication — real AWS accepts X-Amz-Security-Token as a query
// parameter for exactly this (confirmed live: a genuine presigned
// sts:GetCallerIdentity request signed with temporary/session credentials,
// carrying X-Amz-Security-Token in the query string, succeeds against real
// AWS). VerifyIAMAuth already rejects a security token paired with any
// non-temporary credential (root included) before this is ever reached.
func resolveIdentity(ctx fiber.Ctx, store IdentityStore, authData sigv4auth.AuthData, queryAuth bool) (*types.Identity, string, error) {
	if store == nil {
		return nil, "", iamerr.GetAPIError(iamerr.ErrInvalidClientTokenID)
	}

	if iamutil.IsTempAccessKeyID(authData.Access) {
		return resolveSessionIdentity(ctx, store, authData, queryAuth)
	}
	return resolveUserIdentity(ctx, store, authData)
}

func resolveSessionIdentity(ctx fiber.Ctx, store IdentityStore, authData sigv4auth.AuthData, queryAuth bool) (*types.Identity, string, error) {
	session, err := store.GetSession(ctx.Context(), authData.Access)
	if err != nil {
		return nil, "", iamerr.GetAPIError(iamerr.ErrInvalidClientTokenID)
	}

	token := ctx.Get(sigv4auth.HeaderSecurityToken)
	if queryAuth {
		token = ctx.Query(sigv4auth.QuerySecurityToken)
	}
	if token == "" || !sigv4auth.SecureCompare(token, session.SessionToken) {
		return nil, "", iamerr.GetAPIError(iamerr.ErrInvalidClientTokenID)
	}

	// A signature-valid, unexpired session still authenticates even if its
	// role has since been deleted — real STS credentials are self-contained
	// and don't re-check role existence on every call. What such a session
	// can no longer do is get any IAM action past the policy middleware:
	// with Role/IdentityPolicies left unset, EvaluateIdentityPolicies denies
	// by default, same effective outcome as an explicit rejection here would
	// have had for every pipeline except GetCallerIdentity, which needs
	// none of this and must keep working regardless.
	//
	// The reloaded role must also still be the *same* role the session was
	// originally minted against — RoleID and Arn, both captured in the
	// session at AssumeRoleWithWebIdentity time, must match the freshly
	// loaded role's own values. Without this check, deleting a role and
	// recreating one of the same name (necessarily getting a new RoleID)
	// would let every pre-existing session for the old role silently
	// inherit whatever policies the new role happens to carry.
	identity := &types.Identity{
		Session:       session,
		SessionPolicy: session.Policy,
	}
	if role, err := store.GetRole(ctx.Context(), session.RoleName); err == nil &&
		role.RoleID == session.RoleID && role.Arn == session.RoleArn {
		identity.Role = role
		identity.IdentityPolicies = role.Policies.Inline
	}
	return identity, session.SecretAccessKey, nil
}

func resolveUserIdentity(ctx fiber.Ctx, store IdentityStore, authData sigv4auth.AuthData) (*types.Identity, string, error) {
	user, err := store.GetUserByAccessKeyID(ctx.Context(), authData.Access)
	if err != nil {
		return nil, "", iamerr.GetAPIError(iamerr.ErrInvalidClientTokenID)
	}

	var keyEntry *types.AccessKeyEntry
	for i := range user.AccessKeys {
		if user.AccessKeys[i].AccessKeyId == authData.Access {
			keyEntry = &user.AccessKeys[i]
			break
		}
	}
	if keyEntry == nil || keyEntry.Status != iamutil.AccessKeyStatusActive {
		return nil, "", iamerr.GetAPIError(iamerr.ErrInvalidClientTokenID)
	}

	identity := &types.Identity{
		User:             user,
		IdentityPolicies: user.Policies.Inline,
	}
	return identity, keyEntry.SecretAccessKey, nil
}

func checkSignature(ctx fiber.Ctx, authData sigv4auth.AuthData, secret string, tdate time.Time, queryAuth bool, service string) error {
	contentLength, err := parseContentLength(ctx.Get("Content-Length"))
	if err != nil {
		return err
	}

	payloadHash := sigv4auth.PayloadSHA256Hex(ctx.BodyRaw())
	if queryAuth {
		_, err = sigv4auth.CheckQuerySignature(ctx, authData, secret, payloadHash, tdate, contentLength, sigv4auth.CheckOptions{
			Service:               service,
			RequiredSignedHeaders: requiredSignedHeaders,
		})
	} else {
		_, err = sigv4auth.CheckSignature(ctx, authData, secret, payloadHash, tdate, contentLength, sigv4auth.CheckOptions{
			Service:               service,
			RequiredSignedHeaders: requiredHeaderAuthSignedHeaders(authData.Access),
		})
	}
	if err != nil {
		return mapIAMSigV4Error(err, service)
	}
	return nil
}

func parseIAMAuth(ctx fiber.Ctx, expectedService string) (sigv4auth.AuthData, time.Time, bool, error) {
	if sigv4auth.IsQueryAuth(ctx) {
		return parseIAMQueryAuth(ctx, expectedService)
	}
	if sigv4auth.IsQueryAuthV2(ctx) {
		return sigv4auth.AuthData{}, time.Time{}, false, iamerr.GetAPIError(iamerr.ErrUnsupportedSignatureVersion)
	}

	return parseIAMHeaderAuth(ctx, expectedService)
}

func parseIAMHeaderAuth(ctx fiber.Ctx, expectedService string) (sigv4auth.AuthData, time.Time, bool, error) {
	authData := sigv4auth.AuthData{}

	authorization := ctx.Get("Authorization")
	if authorization == "" {
		return authData, time.Time{}, false, iamerr.GetAPIError(iamerr.ErrMissingAuthenticationToken)
	}

	date := ctx.Get("X-Amz-Date")
	if date == "" {
		date = ctx.Get("Date")
	}
	if date == "" {
		return authData, time.Time{}, false, iamerr.IncompleteSignatureMissingDate(authorization)
	}

	tdate, err := time.Parse(sigv4auth.ISO8601Format, date)
	if err != nil {
		return authData, time.Time{}, false, iamerr.IncompleteSignatureInvalidXAmzDate(date)
	}
	if err := ValidateDateAt(tdate, time.Now().UTC()); err != nil {
		return authData, time.Time{}, false, err
	}

	authData, err = sigv4auth.ParseAuthorization(authorization, expectedService)
	if err != nil {
		return authData, time.Time{}, false, mapIAMSigV4Error(err, expectedService, authorization)
	}

	if authData.Region != SigningRegion {
		return authData, time.Time{}, false, iamerr.GetAPIError(iamerr.ErrInvalidRegion)
	}
	if date[:8] != authData.Date {
		return authData, time.Time{}, false, iamerr.GetAPIError(iamerr.ErrInvalidCredentialDate)
	}

	return authData, tdate, false, nil
}

// parseIAMQueryAuth parses SigV4 query-string (presigned URL) authentication
// parameters. Unlike S3 (see s3api/utils/presign-auth-reader.go), IAM/STS
// query-auth does not use X-Amz-Expires at all: confirmed live (niksis02
// profile) against real IAM's ListUsers — a presigned request with
// X-Amz-Expires omitted, non-numeric ("abc"), negative ("-5"), or far
// beyond the 604800-second S3 maximum ("9999999") is accepted every time,
// while a request merely signed too long ago is rejected with
// SignatureDoesNotMatch ("Signature expired: ... is now earlier than ...
// (... - 15 min.)") — byte-for-byte the same message this codebase's own
// SignatureDoesNotMatchExpired already produces. So X-Amz-Expires is
// neither required nor validated here, and the same fixed ±timeExpiration
// freshness window header auth uses applies to query auth too.
func parseIAMQueryAuth(ctx fiber.Ctx, expectedService string) (sigv4auth.AuthData, time.Time, bool, error) {
	authData, details, err := sigv4auth.ParseQueryAuthorization(ctx, sigv4auth.QueryAuthOptions{
		Service: expectedService,
		Region:  SigningRegion,
	})
	if err != nil {
		return authData, time.Time{}, true, mapIAMSigV4Error(err, expectedService)
	}
	if err := ValidateDateAt(details.SigningTime, time.Now().UTC()); err != nil {
		return authData, time.Time{}, true, err
	}

	return authData, details.SigningTime, true, nil
}

func parseContentLength(contentLengthStr string) (int64, error) {
	if contentLengthStr == "" {
		return 0, nil
	}

	contentLength, err := strconv.ParseInt(contentLengthStr, 10, 64)
	if err != nil {
		return 0, iamerr.GetAPIError(iamerr.ErrInvalidContentLength)
	}

	return contentLength, nil
}

// ValidateDateAt checks that date is within the allowed window relative to now.
// Exported so tests can exercise it directly.
func ValidateDateAt(date, now time.Time) error {
	if date.After(now.Add(timeExpiration)) {
		return iamerr.SignatureDoesNotMatchNotYetCurrent(date, now, timeExpiration)
	}
	if date.Before(now.Add(-timeExpiration)) {
		return iamerr.SignatureDoesNotMatchExpired(date, now, timeExpiration)
	}
	return nil
}

func mapIAMSigV4Error(err error, expectedService string, authorization ...string) error {
	var queryErr *sigv4auth.QueryError
	if errors.As(err, &queryErr) {
		return mapIAMQueryError(queryErr)
	}

	var parseErr *sigv4auth.ParseError
	if errors.As(err, &parseErr) {
		authHeader := ""
		if len(authorization) > 0 {
			authHeader = authorization[0]
		}
		return mapIAMParseError(parseErr, expectedService, authHeader)
	}

	var headersErr *sigv4auth.HeadersNotSignedError
	if errors.As(err, &headersErr) {
		if len(headersErr.Headers) == 1 && headersErr.Headers[0] == "host" {
			return iamerr.GetAPIError(iamerr.ErrMissingHostSignedHeader)
		}
		return iamerr.IncompleteSignatureHeadersNotSigned(headersErr.Headers)
	}

	var sigErr *sigv4auth.SignatureMismatchError
	if errors.As(err, &sigErr) {
		return iamerr.GetAPIError(iamerr.ErrSignatureDoesNotMatch)
	}

	return err
}

func mapIAMQueryError(err *sigv4auth.QueryError) error {
	switch err.Kind {
	case sigv4auth.ErrQueryMissingRequiredParams:
		switch err.Value {
		case sigv4auth.QueryAlgorithm:
			return iamerr.GetAPIError(iamerr.ErrMissingAuthenticationToken)
		case sigv4auth.QueryCredential, sigv4auth.QueryDate, sigv4auth.QuerySignedHeaders, sigv4auth.QuerySignature:
			return iamerr.IncompleteSignatureMissingQueryParameter(err.Value)
		default:
			return iamerr.GetAPIError(iamerr.ErrIncompleteSignature)
		}
	case sigv4auth.ErrQueryUnsupportedAlgorithm, sigv4auth.ErrQueryUnsupportedECDSA:
		return iamerr.GetAPIError(iamerr.ErrUnsupportedQueryAlgorithm)
	case sigv4auth.ErrQueryInvalidDateFormat:
		return iamerr.IncompleteSignatureInvalidXAmzDate(err.Value)
	case sigv4auth.ErrQueryDateMismatch:
		return iamerr.GetAPIError(iamerr.ErrInvalidCredentialDate)
	case sigv4auth.ErrQueryIncorrectRegion:
		return iamerr.GetAPIError(iamerr.ErrInvalidRegion)
	case sigv4auth.ErrQuerySecurityToken:
		return iamerr.GetAPIError(iamerr.ErrInvalidClientTokenID)
	default:
		return iamerr.GetAPIError(iamerr.ErrIncompleteSignature)
	}
}

func mapIAMParseError(err *sigv4auth.ParseError, expectedService, authorization string) error {
	if authorization == "" {
		authorization = err.Input
	}

	switch err.Kind {
	case sigv4auth.ErrInvalidAuthorizationHeader:
		return iamerr.GetAPIError(iamerr.ErrMissingAuthenticationToken)
	case sigv4auth.ErrUnsupportedAuthorizationVersion:
		return iamerr.GetAPIError(iamerr.ErrUnsupportedSignatureVersion)
	case sigv4auth.ErrInvalidAuthorizationType:
		return iamerr.GetAPIError(iamerr.ErrMissingAuthenticationToken)
	case sigv4auth.ErrMissingComponents:
		return iamerr.GetAPIError(iamerr.ErrMissingAuthorizationComponents)
	case sigv4auth.ErrMissingCredential:
		return iamerr.IncompleteSignatureMissingAuthorizationComponent("Credential", authorization)
	case sigv4auth.ErrMissingSignedHeaders:
		return iamerr.IncompleteSignatureMissingAuthorizationComponent("SignedHeaders", authorization)
	case sigv4auth.ErrMissingSignature:
		return iamerr.IncompleteSignatureMissingAuthorizationComponent("Signature", authorization)
	case sigv4auth.ErrMalformedComponent:
		return iamerr.IncompleteSignatureMalformedComponent(err.Value)
	case sigv4auth.ErrMalformedCredential:
		return iamerr.IncompleteSignatureMalformedCredential(err.Input)
	case sigv4auth.ErrIncorrectService:
		return iamerr.IncorrectServiceScope(expectedService)
	case sigv4auth.ErrIncorrectTerminal:
		return iamerr.GetAPIError(iamerr.ErrInvalidTerminal)
	case sigv4auth.ErrInvalidDateFormat:
		return iamerr.GetAPIError(iamerr.ErrInvalidCredentialDate)
	default:
		return iamerr.GetAPIError(iamerr.ErrIncompleteSignature)
	}
}
