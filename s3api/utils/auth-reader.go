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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/internal/sigv4auth"
	"github.com/versity/versitygw/s3err"
)

const (
	iso8601Format = sigv4auth.ISO8601Format
	yyyymmdd      = sigv4auth.YYYYMMDD
)

func HexBytes(s string) string {
	return sigv4auth.HexBytes(s)
}

const (
	service = sigv4auth.ServiceS3
)

// CheckValidSignature validates the ctx v4 auth signature
func CheckValidSignature(ctx fiber.Ctx, auth AuthData, secret, checksum string, tdate time.Time, contentLen int64) (string, error) {
	result, err := sigv4auth.CheckSignature(ctx, auth, secret, checksum, tdate, contentLen, sigv4auth.CheckOptions{
		Service:                service,
		DisableURIPathEscaping: true,
	})
	if err != nil {
		return "", mapSigV4Error(err)
	}

	return result.CanonicalString, nil
}

// AuthData is the parsed authorization data from the header.
type AuthData = sigv4auth.AuthData

// ParseAuthorization returns the parsed fields for the aws v4 auth header
// example authorization string from aws docs:
// Authorization: AWS4-HMAC-SHA256
// Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,
// SignedHeaders=host;range;x-amz-date,
// Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024
func ParseAuthorization(authorization string) (AuthData, error) {
	authData, err := sigv4auth.ParseAuthorization(authorization, service)
	if err != nil {
		return AuthData{}, mapSigV4Error(err)
	}
	return authData, nil
}

type CredentialsScope = sigv4auth.CredentialsScope

type CredsError interface {
	MalformedCredential(string) s3err.S3Error
	IncorrectService(string, string) s3err.S3Error
	IncorrectTerminal(string, string) s3err.S3Error
	InvalidDateFormat(string, string) s3err.S3Error
}

func ParseCredentials(input string, errHandler CredsError) (*CredentialsScope, error) {
	creds, err := sigv4auth.ParseCredentials(input, service)
	if err != nil {
		return nil, mapCredentialsError(input, err, errHandler)
	}
	return creds, nil
}

func SignPostPolicy(base64Policy, yyyymmdd, region, secretKey string) (string, error) {
	signingKey := deriveSigningKey(secretKey, yyyymmdd, region)
	sig := hmacSHA256(signingKey, []byte(base64Policy))
	return hex.EncodeToString(sig), nil
}

func deriveSigningKey(secretKey, yyyymmdd, region string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(yyyymmdd))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	return kSigning
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func mapSigV4Error(err error) error {
	var parseErr *sigv4auth.ParseError
	if errors.As(err, &parseErr) {
		return mapAuthParseError(parseErr)
	}

	var headersErr *sigv4auth.HeadersNotSignedError
	if errors.As(err, &headersErr) {
		return s3err.GetHeadersNotSignedErr(headersErr.Headers)
	}

	var sigErr *sigv4auth.SignatureMismatchError
	if errors.As(err, &sigErr) {
		return s3err.GetSignatureDoesNotMatchErr(
			sigErr.AccessKeyID,
			sigErr.StringToSign,
			sigErr.SignatureProvided,
			sigErr.StringToSignBytes,
			sigErr.CanonicalRequest,
			sigErr.CanonicalRequestBytes,
		)
	}

	return err
}

func mapAuthParseError(err *sigv4auth.ParseError) error {
	switch err.Kind {
	case sigv4auth.ErrInvalidAuthorizationHeader:
		return s3err.GetInvalidArgumentErr(s3err.InvalidArgAuthHeader, err.Input)
	case sigv4auth.ErrUnsupportedAuthorizationVersion:
		return s3err.GetAPIError(s3err.ErrUnsupportedAuthorizationMechanism)
	case sigv4auth.ErrInvalidAuthorizationType:
		return s3err.GetInvalidArgumentErr(s3err.InvalidArgAuthorizationType, err.Value)
	case sigv4auth.ErrMissingComponents:
		return s3err.MalformedAuth.MissingComponents()
	case sigv4auth.ErrMissingCredential:
		return s3err.MalformedAuth.MissingCredential()
	case sigv4auth.ErrMissingSignedHeaders:
		return s3err.MalformedAuth.MissingSignedHeaders()
	case sigv4auth.ErrMissingSignature:
		return s3err.MalformedAuth.MissingSignature()
	case sigv4auth.ErrMalformedComponent:
		return s3err.MalformedAuth.MalformedComponent(err.Value)
	default:
		return mapCredentialsParseError(err, s3err.MalformedAuth)
	}
}

func mapCredentialsError(input string, err error, errHandler CredsError) error {
	var parseErr *sigv4auth.ParseError
	if !errors.As(err, &parseErr) {
		return err
	}
	if parseErr.Input == "" {
		parseErr.Input = input
	}
	return mapCredentialsParseError(parseErr, errHandler)
}

func mapCredentialsParseError(err *sigv4auth.ParseError, errHandler CredsError) error {
	switch err.Kind {
	case sigv4auth.ErrMalformedCredential:
		return errHandler.MalformedCredential(err.Input)
	case sigv4auth.ErrIncorrectService:
		return errHandler.IncorrectService(err.Input, err.Actual)
	case sigv4auth.ErrIncorrectTerminal:
		return errHandler.IncorrectTerminal(err.Input, err.Actual)
	case sigv4auth.ErrInvalidDateFormat:
		return errHandler.InvalidDateFormat(err.Input, err.Value)
	default:
		return err
	}
}
