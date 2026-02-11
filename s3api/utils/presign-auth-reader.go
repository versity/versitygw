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
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/smithy-go/logging"
	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/s3err"
)

const (
	unsignedPayload string = "UNSIGNED-PAYLOAD"

	algoHMAC  string = "AWS4-HMAC-SHA256"
	algoECDSA string = "AWS4-ECDSA-P256-SHA256"
)

// PresignedAuthReader is an io.Reader that validates presigned request authorization
// once the underlying reader returns io.EOF.  This is needed for streaming
// data requests where the data size is not known until
// the data is completely read.
type PresignedAuthReader struct {
	ctx    fiber.Ctx
	auth   AuthData
	secret string
	r      io.Reader
}

func NewPresignedAuthReader(ctx fiber.Ctx, r io.Reader, auth AuthData, secret string) *PresignedAuthReader {
	return &PresignedAuthReader{
		ctx:    ctx,
		r:      r,
		auth:   auth,
		secret: secret,
	}
}

// Read allows *PresignedAuthReader to be used as an io.Reader
func (pr *PresignedAuthReader) Read(p []byte) (int, error) {
	n, err := pr.r.Read(p)

	if errors.Is(err, io.EOF) {
		cerr := CheckPresignedSignature(pr.ctx, pr.auth, pr.secret, true)
		if cerr != nil {
			return n, cerr
		}
	}

	return n, err
}

// CheckPresignedSignature validates presigned request signature
func CheckPresignedSignature(ctx fiber.Ctx, auth AuthData, secret string, streamBody bool) error {
	signedHdrs := strings.Split(auth.SignedHeaders, ";")

	var contentLength int64
	var err error
	contentLengthStr := ctx.Get("Content-Length")
	if contentLengthStr != "" {
		contentLength, err = strconv.ParseInt(contentLengthStr, 10, 64)
		if err != nil {
			return s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
	}

	// Create a new http request instance from fasthttp request
	req, err := createPresignedHttpRequestFromCtx(ctx, signedHdrs, contentLength, streamBody)
	if err != nil {
		return fmt.Errorf("create http request from context: %w", err)
	}

	date, _ := time.Parse(iso8601Format, auth.Date)

	signer := v4.NewSigner()
	uri, _, signErr := signer.PresignHTTP(ctx.RequestCtx(), aws.Credentials{
		AccessKeyID:     auth.Access,
		SecretAccessKey: secret,
	}, req, unsignedPayload, service, auth.Region, date, func(options *v4.SignerOptions) {
		options.DisableURIPathEscaping = true
		if debuglogger.IsDebugEnabled() {
			options.LogSigning = true
			options.Logger = logging.NewStandardLogger(os.Stderr)
		}
	})
	if signErr != nil {
		return fmt.Errorf("presign generated http request: %w", err)
	}

	urlParts, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("parse presigned url: %w", err)
	}

	signature := urlParts.Query().Get("X-Amz-Signature")
	if signature != auth.Signature {
		return s3err.GetAPIError(s3err.ErrSignatureDoesNotMatch)
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
func ParsePresignedURIParts(ctx fiber.Ctx) (AuthData, error) {
	a := AuthData{}

	// Get and verify algorithm query parameter
	algo := ctx.Query("X-Amz-Algorithm")
	err := validateAlgorithm(algo)
	if err != nil {
		return a, err
	}

	// Parse and validate credentials query parameter
	credsQuery := ctx.Query("X-Amz-Credential")
	if credsQuery == "" {
		return a, s3err.QueryAuthErrors.MissingRequiredParams()
	}

	creds := strings.Split(credsQuery, "/")
	if len(creds) != 5 {
		return a, s3err.QueryAuthErrors.MalformedCredential()
	}

	// validate the service
	if creds[3] != "s3" {
		return a, s3err.QueryAuthErrors.IncorrectService(creds[3])
	}

	// validate the terminal
	if creds[4] != "aws4_request" {
		return a, s3err.QueryAuthErrors.IncorrectTerminal(creds[4])
	}

	// validate the date
	_, err = time.Parse(yyyymmdd, creds[1])
	if err != nil {
		return a, s3err.QueryAuthErrors.InvalidDateFormat(creds[1])
	}

	region, ok := ContextKeyRegion.Get(ctx).(string)
	if !ok {
		region = ""
	}
	// validate the region
	if creds[2] != region {
		return a, s3err.QueryAuthErrors.IncorrectRegion(region, creds[2])
	}

	// Parse and validate Date query param
	date := ctx.Query("X-Amz-Date")
	if date == "" {
		return a, s3err.QueryAuthErrors.MissingRequiredParams()
	}

	tdate, err := time.Parse(iso8601Format, date)
	if err != nil {
		return a, s3err.QueryAuthErrors.InvalidXAmzDateFormat()
	}

	if date[:8] != creds[1] {
		return a, s3err.QueryAuthErrors.DateMismatch(creds[1], date[:8])
	}

	signature := ctx.Query("X-Amz-Signature")
	if signature == "" {
		return a, s3err.QueryAuthErrors.MissingRequiredParams()
	}

	signedHdrs := ctx.Query("X-Amz-SignedHeaders")
	if signedHdrs == "" {
		return a, s3err.QueryAuthErrors.MissingRequiredParams()
	}

	// Validate X-Amz-Expires query param and check if request is expired
	err = validateExpiration(ctx.Query("X-Amz-Expires"), tdate)
	if err != nil {
		return a, err
	}

	a.Signature = signature
	a.Access = creds[0]
	a.Algorithm = algo
	a.Region = creds[2]
	a.SignedHeaders = signedHdrs
	a.Date = date

	return a, nil
}

func validateExpiration(str string, date time.Time) error {
	if str == "" {
		return s3err.QueryAuthErrors.MissingRequiredParams()
	}

	exp, err := strconv.Atoi(str)
	if err != nil {
		return s3err.QueryAuthErrors.ExpiresNumber()
	}

	if exp < 0 {
		return s3err.QueryAuthErrors.ExpiresNegative()
	}

	if exp > 604800 {
		return s3err.QueryAuthErrors.ExpiresTooLarge()
	}

	now := time.Now()
	passed := int(now.Sub(date).Seconds())

	if passed > exp {
		return s3err.GetAPIError(s3err.ErrExpiredPresignRequest)
	}

	return nil
}

// validateAlgorithm validates the algorithm
// for AWS4-ECDSA-P256-SHA256 it returns a custom non AWS error
// currently only AWS4-HMAC-SHA256 algorithm is supported
func validateAlgorithm(algo string) error {
	switch algo {
	case "":
		return s3err.QueryAuthErrors.MissingRequiredParams()
	case algoHMAC:
		return nil
	case algoECDSA:
		return s3err.QueryAuthErrors.OnlyHMACSupported()
	default:
		// all other algorithms are considerd as invalid
		return s3err.QueryAuthErrors.UnsupportedAlgorithm()
	}
}

// IsPresignedURLAuth determines if the request is presigned:
// which is authorization with query params
func IsPresignedURLAuth(ctx fiber.Ctx) bool {
	algo := ctx.Query("X-Amz-Algorithm")
	creds := ctx.Query("X-Amz-Credential")
	signature := ctx.Query("X-Amz-Signature")
	signedHeaders := ctx.Query("X-Amz-SignedHeaders")
	expires := ctx.Query("X-Amz-Expires")

	return !isEmpty(algo, creds, signature, signedHeaders, expires)
}

// isEmpty checks if all the given strings are empty
func isEmpty(args ...string) bool {
	for _, a := range args {
		if a != "" {
			return false
		}
	}

	return true
}
