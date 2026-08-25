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
	"slices"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/debuglogger"
)

type CheckOptions struct {
	Service                string
	DisableURIPathEscaping bool
	// RequiredSignedHeaders overrides the default AWS signed-header policy.
	// A nil slice requires every applicable X-Amz-* header to be signed.
	RequiredSignedHeaders []string
}

type CheckResult struct {
	CanonicalString string
	StringToSign    string
}

type HeadersNotSignedError struct {
	Headers []string
}

func (e *HeadersNotSignedError) Error() string {
	return fmt.Sprintf("headers not signed: %s", strings.Join(e.Headers, ", "))
}

type SignatureMismatchError struct {
	AccessKeyID           string
	StringToSign          string
	SignatureProvided     string
	StringToSignBytes     string
	CanonicalRequest      string
	CanonicalRequestBytes string
}

func (e *SignatureMismatchError) Error() string {
	return "signature does not match"
}

// CheckSignature rebuilds the canonical request with the supplied service,
// region, payload hash, signing time, and signed headers. Then compares the
// generated signature to the signature presented by the client.
// derivedKey is the request's kSigning value — either computed
// locally via DeriveKey from a known secret, or obtained from a standalone
// IAM service that never reveals the secret itself.
func CheckSignature(ctx fiber.Ctx, auth AuthData, derivedKey []byte, payloadHash string, tdate time.Time, contentLen int64, opts CheckOptions) (*CheckResult, error) {
	service := opts.Service
	if service == "" {
		service = auth.Service
	}
	signedHdrs := strings.Split(auth.SignedHeaders, ";")

	in, err := signingInputFromCtx(ctx, signedHdrs, contentLen, opts.RequiredSignedHeaders, false)
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

	// This prints the canonical request and string-to-sign verbatim,
	// bypassing the redaction layer entirely — replayable signature
	// material, so only ever log it at LevelUnsafe, never at plain debug.
	if debuglogger.IsUnsafeEnabled() {
		debuglogger.Logf("Request Signature:\n"+
			"---[ CANONICAL STRING  ]-----------------------------\n%s\n"+
			"---[ STRING TO SIGN ]--------------------------------\n%s\n"+
			"-----------------------------------------------------",
			result.CanonicalString, result.StringToSign)
	}

	if !SecureCompare(auth.Signature, result.Signature) {
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

func validateRequiredSignedHeaders(signedHdrs, requiredSignedHdrs []string) error {
	if requiredSignedHdrs == nil {
		return nil
	}

	headersNotSigned := []string{}
	for _, header := range requiredSignedHdrs {
		if !includeHeader(header, signedHdrs) {
			headersNotSigned = append(headersNotSigned, strings.ToLower(header))
		}
	}
	if len(headersNotSigned) != 0 {
		return &HeadersNotSignedError{Headers: headersNotSigned}
	}

	return nil
}

func isRequiredSignedHeader(header string, requiredSignedHdrs []string) bool {
	if requiredSignedHdrs == nil {
		return IsRequiredSignedHeader(header)
	}

	return includeHeader(header, requiredSignedHdrs)
}

func includeHeader(hdr string, signedHdrs []string) bool {
	return slices.ContainsFunc(signedHdrs, func(shdr string) bool {
		return strings.EqualFold(hdr, shdr)
	})
}
