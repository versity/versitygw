// Copyright 2023 Versity Software
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

package utils

import (
	"errors"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/internal/sigv4auth"
	"github.com/versity/versitygw/s3err"
)

const (
	unsignedPayload string = "UNSIGNED-PAYLOAD"
)

// CheckPresignedSignature validates presigned request signature
func CheckPresignedSignature(ctx fiber.Ctx, auth AuthData, secret string) error {
	var contentLength int64
	var err error
	contentLengthStr := ctx.Get("Content-Length")
	if contentLengthStr != "" {
		contentLength, err = strconv.ParseInt(contentLengthStr, 10, 64)
		if err != nil {
			return s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
	}

	date, _ := time.Parse(iso8601Format, auth.Date)

	_, err = sigv4auth.CheckQuerySignature(ctx, auth, secret, unsignedPayload, date, contentLength, sigv4auth.CheckOptions{
		Service:                service,
		DisableURIPathEscaping: true,
	})
	if err != nil {
		return mapSigV4Error(err)
	}

	return nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
//
// # ParsePresignedURIParts parses and validates request URL query parameters
//
// ?X-Amz-Algorithm=AWS4-HMAC-SHA256
// &X-Amz-Credential=access-key-id/20130721/us-east-1/s3/aws4_request
// &X-Amz-Date=20130721T201207Z
// &X-Amz-Expires=86400
// &X-Amz-SignedHeaders=host
// &X-Amz-Signature=1e68ad45c1db540284a4a1eca3884c293ba1a0ff63ab9db9a15b5b29dfa02cd8
func ParsePresignedURIParts(ctx fiber.Ctx, region string) (AuthData, error) {
	auth, _, err := sigv4auth.ParseQueryAuthorization(ctx, sigv4auth.QueryAuthOptions{
		Service:           service,
		Region:            region,
		RequireExpiration: true,
	})
	if err != nil {
		return AuthData{}, mapQueryAuthError(err)
	}

	return auth, nil
}

func validateExpiration(str string, date time.Time) error {
	_, err := sigv4auth.ValidateQueryExpiration(str, date, time.Now().UTC())
	return mapQueryAuthError(err)
}

// validateAlgorithm validates the algorithm
// for AWS4-ECDSA-P256-SHA256 it returns a custom non AWS error
// currently only AWS4-HMAC-SHA256 algorithm is supported
func validateAlgorithm(algo string) error {
	return mapQueryAuthError(sigv4auth.ValidateQueryAlgorithm(algo))
}

// IsPresignedURLAuth determines if the request is presigned:
// which is authorization with query params
func IsPresignedURLAuth(ctx fiber.Ctx) bool {
	return sigv4auth.IsQueryAuth(ctx) || ctx.Query(sigv4auth.QueryExpires) != "" || IsPresignedURLAuthV2(ctx)
}

// IsPresignedURLAuthV2 determines if the request is
// query-string signed with aws v2 signer
func IsPresignedURLAuthV2(ctx fiber.Ctx) bool {
	return sigv4auth.IsQueryAuthV2(ctx)
}

func mapQueryAuthError(err error) error {
	if err == nil {
		return nil
	}

	var queryErr *sigv4auth.QueryError
	if errors.As(err, &queryErr) {
		switch queryErr.Kind {
		case sigv4auth.ErrQueryMissingRequiredParams:
			return s3err.QueryAuthErrors.MissingRequiredParams()
		case sigv4auth.ErrQueryUnsupportedAlgorithm:
			return s3err.QueryAuthErrors.UnsupportedAlgorithm()
		case sigv4auth.ErrQueryUnsupportedECDSA:
			return s3err.QueryAuthErrors.OnlyHMACSupported()
		case sigv4auth.ErrQueryInvalidDateFormat:
			return s3err.QueryAuthErrors.InvalidXAmzDateFormat()
		case sigv4auth.ErrQueryDateMismatch:
			return s3err.QueryAuthErrors.DateMismatch(queryErr.Expected, queryErr.Actual)
		case sigv4auth.ErrQueryIncorrectRegion:
			return s3err.QueryAuthErrors.IncorrectRegion(queryErr.Expected, queryErr.Actual)
		case sigv4auth.ErrQueryExpiresNumber:
			return s3err.QueryAuthErrors.ExpiresNumber()
		case sigv4auth.ErrQueryExpiresNegative:
			return s3err.QueryAuthErrors.ExpiresNegative()
		case sigv4auth.ErrQueryExpiresTooLarge:
			return s3err.QueryAuthErrors.ExpiresTooLarge()
		case sigv4auth.ErrQueryExpired:
			return s3err.GetExpiredPresignedURLError(
				queryErr.Expires,
				queryErr.ExpiresAt.Format(time.RFC3339),
				queryErr.ServerTime.Format(time.RFC3339),
			)
		case sigv4auth.ErrQuerySecurityToken:
			return s3err.QueryAuthErrors.SecurityTokenNotSupported()
		}
	}

	var parseErr *sigv4auth.ParseError
	if errors.As(err, &parseErr) {
		return mapCredentialsParseError(parseErr, s3err.QueryAuthErrors)
	}

	return err
}
