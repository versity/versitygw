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
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/smithy-go/logging"
	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/s3api/controllers"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3log"
)

const (
	iso8601Format = "20060102T150405Z"
)

type RootUserConfig struct {
	Access string
	Secret string
}

func VerifyV4Signature(root RootUserConfig, iam auth.IAMService, logger s3log.AuditLogger, region string, debug bool) fiber.Handler {
	acct := accounts{root: root, iam: iam}

	return func(ctx *fiber.Ctx) error {
		ctx.Locals("region", region)
		ctx.Locals("startTime", time.Now())
		authorization := ctx.Get("Authorization")
		if authorization == "" {
			return controllers.SendResponse(ctx, s3err.GetAPIError(s3err.ErrAuthHeaderEmpty), &controllers.MetaOpts{Logger: logger})
		}

		// Check the signature version
		authParts := strings.Split(authorization, ",")
		for i, el := range authParts {
			authParts[i] = strings.TrimSpace(el)
		}

		if len(authParts) != 3 {
			return controllers.SendResponse(ctx, s3err.GetAPIError(s3err.ErrMissingFields), &controllers.MetaOpts{Logger: logger})
		}

		startParts := strings.Split(authParts[0], " ")

		if startParts[0] != "AWS4-HMAC-SHA256" {
			return controllers.SendResponse(ctx, s3err.GetAPIError(s3err.ErrSignatureVersionNotSupported), &controllers.MetaOpts{Logger: logger})
		}

		credKv := strings.Split(startParts[1], "=")
		if len(credKv) != 2 {
			return controllers.SendResponse(ctx, s3err.GetAPIError(s3err.ErrCredMalformed), &controllers.MetaOpts{Logger: logger})
		}
		creds := strings.Split(credKv[1], "/")
		if len(creds) < 4 {
			return controllers.SendResponse(ctx, s3err.GetAPIError(s3err.ErrCredMalformed), &controllers.MetaOpts{Logger: logger})
		}

		ctx.Locals("access", creds[0])
		ctx.Locals("isRoot", creds[0] == root.Access)

		signHdrKv := strings.Split(authParts[1], "=")
		if len(signHdrKv) != 2 {
			return controllers.SendResponse(ctx, s3err.GetAPIError(s3err.ErrCredMalformed), &controllers.MetaOpts{Logger: logger})
		}
		signedHdrs := strings.Split(signHdrKv[1], ";")

		account, err := acct.getAccount(creds[0])
		if err == auth.ErrNoSuchUser {
			return controllers.SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidAccessKeyID), &controllers.MetaOpts{Logger: logger})
		}
		if err != nil {
			return controllers.SendResponse(ctx, err, &controllers.MetaOpts{Logger: logger})
		}
		ctx.Locals("role", account.Role)

		// Check X-Amz-Date header
		date := ctx.Get("X-Amz-Date")
		if date == "" {
			return controllers.SendResponse(ctx, s3err.GetAPIError(s3err.ErrMissingDateHeader), &controllers.MetaOpts{Logger: logger})
		}

		// Parse the date and check the date validity
		tdate, err := time.Parse(iso8601Format, date)
		if err != nil {
			return controllers.SendResponse(ctx, s3err.GetAPIError(s3err.ErrMalformedDate), &controllers.MetaOpts{Logger: logger})
		}

		hashPayloadHeader := ctx.Get("X-Amz-Content-Sha256")
		ok := isSpecialPayload(hashPayloadHeader)

		if !ok {
			// Calculate the hash of the request payload
			hashedPayload := sha256.Sum256(ctx.Body())
			hexPayload := hex.EncodeToString(hashedPayload[:])

			// Compare the calculated hash with the hash provided
			if hashPayloadHeader != hexPayload {
				return controllers.SendResponse(ctx, s3err.GetAPIError(s3err.ErrContentSHA256Mismatch), &controllers.MetaOpts{Logger: logger})
			}
		}

		// Create a new http request instance from fasthttp request
		req, err := utils.CreateHttpRequestFromCtx(ctx, signedHdrs)
		if err != nil {
			return controllers.SendResponse(ctx, s3err.GetAPIError(s3err.ErrInternalError), &controllers.MetaOpts{Logger: logger})
		}

		signer := v4.NewSigner()

		signErr := signer.SignHTTP(req.Context(), aws.Credentials{
			AccessKeyID:     creds[0],
			SecretAccessKey: account.Secret,
		}, req, hashPayloadHeader, creds[3], region, tdate, func(options *v4.SignerOptions) {
			if debug {
				options.LogSigning = true
				options.Logger = logging.NewStandardLogger(os.Stderr)
			}
		})
		if signErr != nil {
			return controllers.SendResponse(ctx, s3err.GetAPIError(s3err.ErrInternalError), &controllers.MetaOpts{Logger: logger})
		}

		parts := strings.Split(req.Header.Get("Authorization"), " ")
		if len(parts) < 4 {
			return controllers.SendResponse(ctx, s3err.GetAPIError(s3err.ErrMissingFields), &controllers.MetaOpts{Logger: logger})
		}
		calculatedSign := strings.Split(parts[3], "=")[1]
		expectedSign := strings.Split(authParts[2], "=")[1]

		if expectedSign != calculatedSign {
			return controllers.SendResponse(ctx, s3err.GetAPIError(s3err.ErrSignatureDoesNotMatch), &controllers.MetaOpts{Logger: logger})
		}

		return ctx.Next()
	}
}

type accounts struct {
	root RootUserConfig
	iam  auth.IAMService
}

func (a accounts) getAccount(access string) (auth.Account, error) {
	if access == a.root.Access {
		return auth.Account{
			Secret: a.root.Secret,
			Role:   "admin",
		}, nil
	}

	return a.iam.GetUserAccount(access)
}

func isSpecialPayload(str string) bool {
	specialValues := map[string]bool{
		"UNSIGNED-PAYLOAD":                                 true,
		"STREAMING-UNSIGNED-PAYLOAD-TRAILER":               true,
		"STREAMING-AWS4-HMAC-SHA256-PAYLOAD":               true,
		"STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER":       true,
		"STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD":         true,
		"STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER": true,
	}

	return specialValues[str]
}
