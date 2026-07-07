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
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/smithy-go/logging"
	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/aws/signer/v4"
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
// region, payload hash, signing time, and signed headers, then compares the
// generated signature to the signature presented by the client.
func CheckSignature(ctx fiber.Ctx, auth AuthData, secret, payloadHash string, tdate time.Time, contentLen int64, opts CheckOptions) (*CheckResult, error) {
	service := opts.Service
	if service == "" {
		service = auth.Service
	}
	signedHdrs := strings.Split(auth.SignedHeaders, ";")

	req, err := createHTTPRequestFromCtx(ctx, signedHdrs, contentLen, opts.RequiredSignedHeaders)
	if err != nil {
		return nil, err
	}

	signer := v4.NewSigner()

	signMeta, err := signer.SignHTTP(req.Context(),
		aws.Credentials{
			AccessKeyID:     auth.Access,
			SecretAccessKey: secret,
		},
		req, payloadHash, service, auth.Region, tdate, signedHdrs,
		func(options *v4.SignerOptions) {
			options.DisableURIPathEscaping = opts.DisableURIPathEscaping
			if debuglogger.IsDebugEnabled() {
				options.LogSigning = true
				options.Logger = logging.NewStandardLogger(os.Stderr)
			}
		})
	if err != nil {
		return nil, fmt.Errorf("sign generated http request: %w", err)
	}

	genAuth, err := ParseAuthorization(req.Header.Get("Authorization"), service)
	if err != nil {
		return nil, err
	}

	if auth.Signature != genAuth.Signature {
		return nil, &SignatureMismatchError{
			AccessKeyID:           auth.Access,
			StringToSign:          signMeta.StringToSign,
			SignatureProvided:     auth.Signature,
			StringToSignBytes:     HexBytes(signMeta.StringToSign),
			CanonicalRequest:      signMeta.CanonicalString,
			CanonicalRequestBytes: HexBytes(signMeta.CanonicalString),
		}
	}

	return &CheckResult{
		CanonicalString: signMeta.CanonicalString,
		StringToSign:    signMeta.StringToSign,
	}, nil
}

func CreateHTTPRequestFromCtx(ctx fiber.Ctx, signedHdrs []string, contentLength int64) (*http.Request, error) {
	return createHTTPRequestFromCtx(ctx, signedHdrs, contentLength, nil)
}

func createHTTPRequestFromCtx(ctx fiber.Ctx, signedHdrs []string, contentLength int64, requiredSignedHdrs []string) (*http.Request, error) {
	req := ctx.Request()
	if err := validateRequiredSignedHeaders(signedHdrs, requiredSignedHdrs); err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest(string(req.Header.Method()), ctx.OriginalURL(), nil)
	if err != nil {
		return nil, errors.New("error in creating an http request")
	}

	if err := addRequestHeadersFromCtx(ctx, httpReq, signedHdrs, requiredSignedHdrs); err != nil {
		return nil, err
	}

	for _, header := range signedHdrs {
		if httpReq.Header.Get(header) == "" {
			httpReq.Header.Set(header, "")
		}
	}

	if !includeHeader("Content-Length", signedHdrs) {
		httpReq.ContentLength = 0
	} else {
		httpReq.ContentLength = contentLength
	}

	httpReq.Host = string(req.Header.Host())

	return httpReq, nil
}

func AddRequestHeadersFromCtx(ctx fiber.Ctx, httpReq *http.Request, signedHdrs []string) error {
	return addRequestHeadersFromCtx(ctx, httpReq, signedHdrs, nil)
}

func addRequestHeadersFromCtx(ctx fiber.Ctx, httpReq *http.Request, signedHdrs, requiredSignedHdrs []string) error {
	headersNotSigned := []string{}
	for key, value := range ctx.Request().Header.All() {
		keyStr := string(key)
		if includeHeader(keyStr, signedHdrs) || v4.IsIgnoredHeader(keyStr) {
			httpReq.Header.Add(keyStr, string(value))
			continue
		}
		if isRequiredSignedHeader(keyStr, requiredSignedHdrs) {
			headersNotSigned = append(headersNotSigned, strings.ToLower(keyStr))
		}
	}

	if len(headersNotSigned) != 0 {
		debuglogger.Logf("headers present in request but not included in SignedHeaders: %q", strings.Join(headersNotSigned, ", "))
		return &HeadersNotSignedError{Headers: headersNotSigned}
	}

	return nil
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
		return v4.IsRequiredSignedHeader(header)
	}

	return includeHeader(header, requiredSignedHdrs)
}

func includeHeader(hdr string, signedHdrs []string) bool {
	return slices.ContainsFunc(signedHdrs, func(shdr string) bool {
		return strings.EqualFold(hdr, shdr)
	})
}
