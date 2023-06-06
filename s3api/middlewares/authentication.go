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

package middlewares

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/backend/auth"
	"github.com/versity/versitygw/s3api/controllers"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
)

const (
	iso8601Format = "20060102T150405Z"
)

type AdminConfig struct {
	AdminAccess string
	AdminSecret string
	Region      string
}

func VerifyV4Signature(config AdminConfig, iam auth.IAMService) fiber.Handler {
	acct := accounts{
		admin: config,
		iam:   iam,
	}

	return func(ctx *fiber.Ctx) error {
		authorization := ctx.Get("Authorization")
		if authorization == "" {
			return controllers.Responce[any](ctx, nil, s3err.GetAPIError(s3err.ErrAuthHeaderEmpty))
		}

		// Check the signature version
		authParts := strings.Split(authorization, " ")
		if len(authParts) < 4 {
			return controllers.Responce[any](ctx, nil, s3err.GetAPIError(s3err.ErrMissingFields))
		}
		if authParts[0] != "AWS4-HMAC-SHA256" {
			return controllers.Responce[any](ctx, nil, s3err.GetAPIError(s3err.ErrSignatureVersionNotSupported))
		}

		creds := strings.Split(strings.Split(authParts[1], "=")[1], "/")
		if len(creds) < 4 {
			return controllers.Responce[any](ctx, nil, s3err.GetAPIError(s3err.ErrCredMalformed))
		}

		secret, ok := acct.getAcctSecret(creds[0])
		if !ok {
			return controllers.Responce[any](ctx, nil, s3err.GetAPIError(s3err.ErrInvalidAccessKeyID))
		}

		// Check X-Amz-Date header
		date := ctx.Get("X-Amz-Date")
		if date == "" {
			return controllers.Responce[any](ctx, nil, s3err.GetAPIError(s3err.ErrMissingDateHeader))
		}

		// Parse the date and check the date validity
		tdate, err := time.Parse(iso8601Format, date)
		if err != nil {
			return controllers.Responce[any](ctx, nil, s3err.GetAPIError(s3err.ErrMalformedDate))
		}

		// Calculate the hash of the request payload
		hashedPayload := sha256.Sum256(ctx.Body())
		hexPayload := hex.EncodeToString(hashedPayload[:])

		hashPayloadHeader := ctx.Get("X-Amz-Content-Sha256")

		// Compare the calculated hash with the hash provided
		if hashPayloadHeader != hexPayload {
			return controllers.Responce[any](ctx, nil, s3err.GetAPIError(s3err.ErrContentSHA256Mismatch))
		}

		// Create a new http request instance from fasthttp request
		req, err := utils.CreateHttpRequestFromCtx(ctx)
		if err != nil {
			return controllers.Responce[any](ctx, nil, s3err.GetAPIError(s3err.ErrInternalError))
		}

		signer := v4.NewSigner()

		signErr := signer.SignHTTP(req.Context(), aws.Credentials{
			AccessKeyID:     creds[0],
			SecretAccessKey: secret,
		}, req, hexPayload, creds[3], config.Region, tdate)
		if signErr != nil {
			return controllers.Responce[any](ctx, nil, s3err.GetAPIError(s3err.ErrInternalError))
		}

		parts := strings.Split(req.Header.Get("Authorization"), " ")
		if len(parts) < 4 {
			return controllers.Responce[any](ctx, nil, s3err.GetAPIError(s3err.ErrMissingFields))
		}
		calculatedSign := strings.Split(parts[3], "=")[1]
		expectedSign := strings.Split(authParts[3], "=")[1]

		if expectedSign != calculatedSign {
			return controllers.Responce[any](ctx, nil, s3err.GetAPIError(s3err.ErrSignatureDoesNotMatch))
		}

		return ctx.Next()
	}
}

type accounts struct {
	admin AdminConfig
	iam   auth.IAMService
}

func (a accounts) getAcctSecret(access string) (string, bool) {
	if a.admin.AdminAccess == access {
		return a.admin.AdminSecret, true
	}

	conf, err := a.iam.GetIAMConfig()
	if err != nil {
		return "", false
	}

	secret, ok := conf.AccessAccounts[access]
	return secret, ok
}
