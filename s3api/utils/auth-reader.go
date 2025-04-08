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
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/smithy-go/logging"
	"github.com/gofiber/fiber/v2"
	v4 "github.com/versity/versitygw/aws/signer/v4"
	"github.com/versity/versitygw/s3err"
)

const (
	iso8601Format = "20060102T150405Z"
	yyyymmdd      = "20060102"
)

// AuthReader is an io.Reader that validates the request authorization
// once the underlying reader returns io.EOF.  This is needed for streaming
// data requests where the data size and checksum are not known until
// the data is completely read.
type AuthReader struct {
	ctx    *fiber.Ctx
	auth   AuthData
	secret string
	size   int
	r      *HashReader
	debug  bool
}

// NewAuthReader initializes an io.Reader that will verify the request
// v4 auth when the underlying reader returns io.EOF. This postpones the
// authorization check until the reader is consumed. So it is important that
// the consumer of this reader checks for the auth errors while reading.
func NewAuthReader(ctx *fiber.Ctx, r io.Reader, auth AuthData, secret string, debug bool) *AuthReader {
	var hr *HashReader
	hashPayload := ctx.Get("X-Amz-Content-Sha256")
	if !IsSpecialPayload(hashPayload) {
		hr, _ = NewHashReader(r, "", HashTypeSha256Hex)
	} else {
		hr, _ = NewHashReader(r, "", HashTypeNone)
	}

	return &AuthReader{
		ctx:    ctx,
		r:      hr,
		auth:   auth,
		secret: secret,
		debug:  debug,
	}
}

// Read allows *AuthReader to be used as an io.Reader
func (ar *AuthReader) Read(p []byte) (int, error) {
	n, err := ar.r.Read(p)
	ar.size += n

	if errors.Is(err, io.EOF) {
		verr := ar.validateSignature()
		if verr != nil {
			return n, verr
		}
	}

	return n, err
}

func (ar *AuthReader) validateSignature() error {
	date := ar.ctx.Get("X-Amz-Date")
	if date == "" {
		return s3err.GetAPIError(s3err.ErrMissingDateHeader)
	}

	hashPayload := ar.ctx.Get("X-Amz-Content-Sha256")
	if !IsSpecialPayload(hashPayload) {
		hexPayload := ar.r.Sum()

		// Compare the calculated hash with the hash provided
		if hashPayload != hexPayload {
			return s3err.GetAPIError(s3err.ErrContentSHA256Mismatch)
		}
	}

	// Parse the date and check the date validity
	tdate, err := time.Parse(iso8601Format, date)
	if err != nil {
		return s3err.GetAPIError(s3err.ErrMalformedDate)
	}

	return CheckValidSignature(ar.ctx, ar.auth, ar.secret, hashPayload, tdate, int64(ar.size), ar.debug)
}

const (
	service = "s3"
)

// CheckValidSignature validates the ctx v4 auth signature
func CheckValidSignature(ctx *fiber.Ctx, auth AuthData, secret, checksum string, tdate time.Time, contentLen int64, debug bool) error {
	signedHdrs := strings.Split(auth.SignedHeaders, ";")

	// Create a new http request instance from fasthttp request
	req, err := createHttpRequestFromCtx(ctx, signedHdrs, contentLen)
	if err != nil {
		return fmt.Errorf("create http request from context: %w", err)
	}

	signer := v4.NewSigner()

	signErr := signer.SignHTTP(req.Context(),
		aws.Credentials{
			AccessKeyID:     auth.Access,
			SecretAccessKey: secret,
		},
		req, checksum, service, auth.Region, tdate, signedHdrs,
		func(options *v4.SignerOptions) {
			options.DisableURIPathEscaping = true
			if debug {
				options.LogSigning = true
				options.Logger = logging.NewStandardLogger(os.Stderr)
			}
		})
	if signErr != nil {
		return fmt.Errorf("sign generated http request: %w", err)
	}

	genAuth, err := ParseAuthorization(req.Header.Get("Authorization"))
	if err != nil {
		return err
	}

	if auth.Signature != genAuth.Signature {
		return s3err.GetAPIError(s3err.ErrSignatureDoesNotMatch)
	}

	return nil
}

// AuthData is the parsed authorization data from the header
type AuthData struct {
	Algorithm     string
	Access        string
	Region        string
	SignedHeaders string
	Signature     string
	Date          string
}

// ParseAuthorization returns the parsed fields for the aws v4 auth header
// example authorization string from aws docs:
// Authorization: AWS4-HMAC-SHA256
// Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,
// SignedHeaders=host;range;x-amz-date,
// Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024
func ParseAuthorization(authorization string) (AuthData, error) {
	a := AuthData{}

	// authorization must start with:
	// Authorization: <ALGORITHM>
	// followed by key=value pairs separated by ","
	authParts := strings.SplitN(authorization, " ", 2)
	for i, el := range authParts {
		if strings.Contains(el, " ") {
			authParts[i] = removeSpace(el)
		}
	}

	if len(authParts) < 2 {
		return a, s3err.GetAPIError(s3err.ErrMissingFields)
	}

	algo := authParts[0]

	if algo != "AWS4-HMAC-SHA256" {
		return a, s3err.GetAPIError(s3err.ErrSignatureVersionNotSupported)
	}

	kvData := authParts[1]
	kvPairs := strings.Split(kvData, ",")
	// we are expecting at least Credential, SignedHeaders, and Signature
	// key value pairs here
	if len(kvPairs) < 3 {
		return a, s3err.GetAPIError(s3err.ErrMissingFields)
	}

	var access, region, signedHeaders, signature, date string

	for _, kv := range kvPairs {
		keyValue := strings.Split(kv, "=")
		if len(keyValue) != 2 {
			switch {
			case strings.HasPrefix(kv, "Credential"):
				return a, s3err.GetAPIError(s3err.ErrCredMalformed)
			case strings.HasPrefix(kv, "SignedHeaders"):
				return a, s3err.GetAPIError(s3err.ErrInvalidQueryParams)
			}
			return a, s3err.GetAPIError(s3err.ErrMissingFields)
		}
		key := strings.TrimSpace(keyValue[0])
		value := strings.TrimSpace(keyValue[1])

		switch key {
		case "Credential":
			creds := strings.Split(value, "/")
			if len(creds) != 5 {
				return a, s3err.GetAPIError(s3err.ErrCredMalformed)
			}
			if creds[3] != "s3" {
				return a, s3err.GetAPIError(s3err.ErrSignatureIncorrService)
			}
			if creds[4] != "aws4_request" {
				return a, s3err.GetAPIError(s3err.ErrSignatureTerminationStr)
			}
			_, err := time.Parse(yyyymmdd, creds[1])
			if err != nil {
				return a, s3err.GetAPIError(s3err.ErrSignatureDateDoesNotMatch)
			}
			access = creds[0]
			date = creds[1]
			region = creds[2]
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
		SignedHeaders: signedHeaders,
		Signature:     signature,
		Date:          date,
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
