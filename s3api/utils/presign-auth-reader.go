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
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/smithy-go/logging"
	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/s3err"
)

const (
	unsignedPayload string = "UNSIGNED-PAYLOAD"
)

// PresignedAuthReader is an io.Reader that validates presigned request authorization
// once the underlying reader returns io.EOF.  This is needed for streaming
// data requests where the data size is not known until
// the data is completely read.
type PresignedAuthReader struct {
	ctx    *fiber.Ctx
	auth   AuthData
	secret string
	r      io.Reader
	debug  bool
}

func NewPresignedAuthReader(ctx *fiber.Ctx, r io.Reader, auth AuthData, secret string, debug bool) *PresignedAuthReader {
	return &PresignedAuthReader{
		ctx:    ctx,
		r:      r,
		auth:   auth,
		secret: secret,
		debug:  debug,
	}
}

// Read allows *PresignedAuthReader to be used as an io.Reader
func (pr *PresignedAuthReader) Read(p []byte) (int, error) {
	n, err := pr.r.Read(p)

	if errors.Is(err, io.EOF) {
		cerr := CheckPresignedSignature(pr.ctx, pr.auth, pr.secret, pr.debug)
		if cerr != nil {
			return n, cerr
		}
	}

	return n, err
}

// CheckPresignedSignature validates presigned request signature
func CheckPresignedSignature(ctx *fiber.Ctx, auth AuthData, secret string, debug bool) error {
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
	req, err := createPresignedHttpRequestFromCtx(ctx, signedHdrs, contentLength)
	if err != nil {
		return fmt.Errorf("create http request from context: %w", err)
	}

	date, _ := time.Parse(iso8601Format, auth.Date)

	signer := v4.NewSigner()
	uri, _, signErr := signer.PresignHTTP(ctx.Context(), aws.Credentials{
		AccessKeyID:     auth.Access,
		SecretAccessKey: secret,
	}, req, unsignedPayload, service, auth.Region, date, func(options *v4.SignerOptions) {
		options.DisableURIPathEscaping = true
		if debug {
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
func ParsePresignedURIParts(ctx *fiber.Ctx) (AuthData, error) {
	a := AuthData{}

	// Get and verify algorithm query parameter
	algo := ctx.Query("X-Amz-Algorithm")
	if algo == "" {
		return a, s3err.GetAPIError(s3err.ErrInvalidQueryParams)
	}
	if algo != "AWS4-HMAC-SHA256" {
		return a, s3err.GetAPIError(s3err.ErrInvalidQuerySignatureAlgo)
	}

	// Parse and validate credentials query parameter
	credsQuery := ctx.Query("X-Amz-Credential")
	if credsQuery == "" {
		return a, s3err.GetAPIError(s3err.ErrInvalidQueryParams)
	}

	creds := strings.Split(credsQuery, "/")
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

	// Parse and validate Date query param
	date := ctx.Query("X-Amz-Date")
	if date == "" {
		return a, s3err.GetAPIError(s3err.ErrInvalidQueryParams)
	}

	tdate, err := time.Parse(iso8601Format, date)
	if err != nil {
		return a, s3err.GetAPIError(s3err.ErrMalformedDate)
	}

	if date[:8] != creds[1] {
		return a, s3err.GetAPIError(s3err.ErrSignatureDateDoesNotMatch)
	}

	if ContextKeyRegion.Get(ctx) != creds[2] {
		return a, s3err.APIError{
			Code:           "SignatureDoesNotMatch",
			Description:    fmt.Sprintf("Credential should be scoped to a valid Region, not %v", creds[2]),
			HTTPStatusCode: http.StatusForbidden,
		}
	}

	signature := ctx.Query("X-Amz-Signature")
	if signature == "" {
		return a, s3err.GetAPIError(s3err.ErrInvalidQueryParams)
	}

	signedHdrs := ctx.Query("X-Amz-SignedHeaders")
	if signedHdrs == "" {
		return a, s3err.GetAPIError(s3err.ErrInvalidQueryParams)
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
		return s3err.GetAPIError(s3err.ErrInvalidQueryParams)
	}

	exp, err := strconv.Atoi(str)
	if err != nil {
		return s3err.GetAPIError(s3err.ErrMalformedExpires)
	}

	if exp < 0 {
		return s3err.GetAPIError(s3err.ErrNegativeExpires)
	}

	if exp > 604800 {
		return s3err.GetAPIError(s3err.ErrMaximumExpires)
	}

	now := time.Now()
	passed := int(now.Sub(date).Seconds())

	if passed > exp {
		return s3err.GetAPIError(s3err.ErrExpiredPresignRequest)
	}

	return nil
}
