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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode"
)

const (
	AlgorithmHMACSHA256 = "AWS4-HMAC-SHA256"
	Terminal            = "aws4_request"
	ServiceS3           = "s3"
	ServiceIAM          = "iam"

	ISO8601Format = "20060102T150405Z"
	YYYYMMDD      = "20060102"
)

type ParseErrorKind string

const (
	ErrInvalidAuthorizationHeader      ParseErrorKind = "invalid_authorization_header"
	ErrUnsupportedAuthorizationVersion ParseErrorKind = "unsupported_authorization_version"
	ErrInvalidAuthorizationType        ParseErrorKind = "invalid_authorization_type"
	ErrMissingComponents               ParseErrorKind = "missing_components"
	ErrMissingCredential               ParseErrorKind = "missing_credential"
	ErrMissingSignedHeaders            ParseErrorKind = "missing_signed_headers"
	ErrMissingSignature                ParseErrorKind = "missing_signature"
	ErrMalformedComponent              ParseErrorKind = "malformed_component"
	ErrMalformedCredential             ParseErrorKind = "malformed_credential"
	ErrIncorrectService                ParseErrorKind = "incorrect_service"
	ErrIncorrectTerminal               ParseErrorKind = "incorrect_terminal"
	ErrInvalidDateFormat               ParseErrorKind = "invalid_date_format"
)

type ParseError struct {
	Kind     ParseErrorKind
	Input    string
	Value    string
	Expected string
	Actual   string
}

func (e *ParseError) Error() string {
	if e == nil {
		return ""
	}
	switch e.Kind {
	case ErrIncorrectService, ErrIncorrectTerminal:
		return fmt.Sprintf("sigv4 %s: expected %q, got %q", e.Kind, e.Expected, e.Actual)
	case ErrInvalidAuthorizationType, ErrMalformedComponent, ErrInvalidDateFormat:
		return fmt.Sprintf("sigv4 %s: %q", e.Kind, e.Value)
	default:
		return string(e.Kind)
	}
}

// AuthData is the parsed authorization data from an AWS SigV4 Authorization header.
type AuthData struct {
	Algorithm     string
	Access        string
	Region        string
	Service       string
	SignedHeaders string
	Signature     string
	Date          string
}

type CredentialsScope struct {
	Access  string
	Date    string
	Region  string
	Service string
}

// HexBytes returns the hex byte representation used by AWS-style diagnostic
// signature mismatch errors.
func HexBytes(s string) string {
	b := []byte(s)

	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02x", v)
	}

	return strings.Join(parts, " ")
}

func PayloadSHA256Hex(payload []byte) string {
	hashedPayload := sha256.Sum256(payload)
	return hex.EncodeToString(hashedPayload[:])
}

// ParseAuthorization parses and validates an AWS SigV4 Authorization header.
// The credential scope service must match expectedService.
func ParseAuthorization(authorization, expectedService string) (AuthData, error) {
	a := AuthData{}

	authParts := strings.SplitN(authorization, " ", 2)
	for i, el := range authParts {
		if strings.Contains(el, " ") {
			authParts[i] = removeSpace(el)
		}
	}

	if len(authParts) < 2 {
		return a, &ParseError{Kind: ErrInvalidAuthorizationHeader, Input: authorization}
	}

	algo := authParts[0]
	if algo == "AWS" {
		return a, &ParseError{Kind: ErrUnsupportedAuthorizationVersion, Value: algo}
	}
	if algo != AlgorithmHMACSHA256 {
		return a, &ParseError{Kind: ErrInvalidAuthorizationType, Value: algo}
	}

	kvPairs := strings.Split(authParts[1], ",")
	if len(kvPairs) != 3 {
		return a, &ParseError{Kind: ErrMissingComponents, Input: authorization}
	}

	var access, region, service, signedHeaders, signature, date string
	for i, kv := range kvPairs {
		keyValue := strings.Split(kv, "=")
		if len(keyValue) != 2 {
			return a, &ParseError{Kind: ErrMalformedComponent, Value: kv}
		}
		key, value := keyValue[0], keyValue[1]
		switch i {
		case 0:
			if key != "Credential" {
				return a, &ParseError{Kind: ErrMissingCredential}
			}
		case 1:
			if key != "SignedHeaders" {
				return a, &ParseError{Kind: ErrMissingSignedHeaders}
			}
		case 2:
			if key != "Signature" {
				return a, &ParseError{Kind: ErrMissingSignature}
			}
		}

		switch key {
		case "Credential":
			creds, err := ParseCredentials(value, expectedService)
			if err != nil {
				return a, err
			}
			access = creds.Access
			date = creds.Date
			region = creds.Region
			service = creds.Service
		case "SignedHeaders":
			signedHeaders = value
		case "Signature":
			signature = value
		}
	}

	return AuthData{
		Algorithm:     algo,
		Access:        access,
		Region:        region,
		Service:       service,
		SignedHeaders: signedHeaders,
		Signature:     signature,
		Date:          date,
	}, nil
}

func ParseCredentials(input, expectedService string) (*CredentialsScope, error) {
	creds := strings.Split(input, "/")
	if len(creds) != 5 {
		return nil, &ParseError{Kind: ErrMalformedCredential, Input: input}
	}
	if creds[3] != expectedService {
		return nil, &ParseError{
			Kind:     ErrIncorrectService,
			Input:    input,
			Expected: expectedService,
			Actual:   creds[3],
		}
	}
	if creds[4] != Terminal {
		return nil, &ParseError{
			Kind:     ErrIncorrectTerminal,
			Input:    input,
			Expected: Terminal,
			Actual:   creds[4],
		}
	}
	if _, err := time.Parse(YYYYMMDD, creds[1]); err != nil {
		return nil, &ParseError{Kind: ErrInvalidDateFormat, Input: input, Value: creds[1]}
	}

	return &CredentialsScope{
		Access:  creds[0],
		Date:    creds[1],
		Region:  creds[2],
		Service: creds[3],
	}, nil
}

func removeSpace(str string) string {
	var b strings.Builder
	b.Grow(len(str))
	for _, ch := range str {
		if !unicode.IsSpace(ch) {
			b.WriteRune(ch)
		}
	}
	return b.String()
}
