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
	"errors"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/internal/sigv4auth"
)

const (
	SigningRegion  = "us-east-1"
	timeExpiration = 15 * time.Minute
)

var requiredSignedHeaders = []string{"host"}

type RootCredentials struct {
	Access string
	Secret string
}

func VerifyIAMAuth(root *RootCredentials) fiber.Handler {
	return func(ctx fiber.Ctx) error {
		authData, tdate, queryAuth, err := parseIAMAuth(ctx)
		if err != nil {
			return err
		}

		if authData.Access != root.Access {
			return iamerr.GetAPIError(iamerr.ErrInvalidClientTokenID)
		}

		contentLength, err := parseContentLength(ctx.Get("Content-Length"))
		if err != nil {
			return err
		}

		payloadHash := sigv4auth.PayloadSHA256Hex(ctx.BodyRaw())
		if queryAuth {
			_, err = sigv4auth.CheckQuerySignature(ctx, authData, root.Secret, payloadHash, tdate, contentLength, sigv4auth.CheckOptions{
				Service:               sigv4auth.ServiceIAM,
				RequiredSignedHeaders: requiredSignedHeaders,
			})
		} else {
			_, err = sigv4auth.CheckSignature(ctx, authData, root.Secret, payloadHash, tdate, contentLength, sigv4auth.CheckOptions{
				Service:               sigv4auth.ServiceIAM,
				RequiredSignedHeaders: requiredSignedHeaders,
			})
		}
		if err != nil {
			return mapIAMSigV4Error(err)
		}

		return nil
	}
}

func parseIAMAuth(ctx fiber.Ctx) (sigv4auth.AuthData, time.Time, bool, error) {
	if sigv4auth.IsQueryAuth(ctx) {
		return parseIAMQueryAuth(ctx)
	}
	if sigv4auth.IsQueryAuthV2(ctx) {
		return sigv4auth.AuthData{}, time.Time{}, false, iamerr.GetAPIError(iamerr.ErrUnsupportedSignatureVersion)
	}

	return parseIAMHeaderAuth(ctx)
}

func parseIAMHeaderAuth(ctx fiber.Ctx) (sigv4auth.AuthData, time.Time, bool, error) {
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

	authData, err = sigv4auth.ParseAuthorization(authorization, sigv4auth.ServiceIAM)
	if err != nil {
		return authData, time.Time{}, false, mapIAMSigV4Error(err, authorization)
	}

	if authData.Region != SigningRegion {
		return authData, time.Time{}, false, iamerr.GetAPIError(iamerr.ErrInvalidRegion)
	}
	if date[:8] != authData.Date {
		return authData, time.Time{}, false, iamerr.GetAPIError(iamerr.ErrInvalidCredentialDate)
	}

	return authData, tdate, false, nil
}

func parseIAMQueryAuth(ctx fiber.Ctx) (sigv4auth.AuthData, time.Time, bool, error) {
	if ctx.Request().URI().QueryArgs().Has(sigv4auth.QuerySecurityToken) {
		return sigv4auth.AuthData{}, time.Time{}, true, mapIAMSigV4Error(&sigv4auth.QueryError{Kind: sigv4auth.ErrQuerySecurityToken})
	}

	authData, details, err := sigv4auth.ParseQueryAuthorization(ctx, sigv4auth.QueryAuthOptions{
		Service: sigv4auth.ServiceIAM,
		Region:  SigningRegion,
	})
	if err != nil {
		return authData, time.Time{}, true, mapIAMSigV4Error(err)
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

func mapIAMSigV4Error(err error, authorization ...string) error {
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
		return mapIAMParseError(parseErr, authHeader)
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

func mapIAMParseError(err *sigv4auth.ParseError, authorization string) error {
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
		return iamerr.GetAPIError(iamerr.ErrIncorrectService)
	case sigv4auth.ErrIncorrectTerminal:
		return iamerr.GetAPIError(iamerr.ErrInvalidTerminal)
	case sigv4auth.ErrInvalidDateFormat:
		return iamerr.GetAPIError(iamerr.ErrInvalidCredentialDate)
	default:
		return iamerr.GetAPIError(iamerr.ErrIncompleteSignature)
	}
}
