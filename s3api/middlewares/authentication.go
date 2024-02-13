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
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

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
		// If account is set in context locals, it means it was presigned url case
		_, ok := ctx.Locals("account").(auth.Account)
		if ok {
			return ctx.Next()
		}

		ctx.Locals("region", region)
		ctx.Locals("startTime", time.Now())
		authorization := ctx.Get("Authorization")
		if authorization == "" {
			return sendResponse(ctx, s3err.GetAPIError(s3err.ErrAuthHeaderEmpty), logger)
		}

		authData, err := utils.ParseAuthorization(authorization)
		if err != nil {
			return sendResponse(ctx, err, logger)
		}

		if authData.Algorithm != "AWS4-HMAC-SHA256" {
			return sendResponse(ctx, s3err.GetAPIError(s3err.ErrSignatureVersionNotSupported), logger)
		}

		if authData.Region != region {
			return sendResponse(ctx, s3err.APIError{
				Code:           "SignatureDoesNotMatch",
				Description:    fmt.Sprintf("Credential should be scoped to a valid Region, not %v", authData.Region),
				HTTPStatusCode: http.StatusForbidden,
			}, logger)
		}

		ctx.Locals("isRoot", authData.Access == root.Access)

		account, err := acct.getAccount(authData.Access)
		if err == auth.ErrNoSuchUser {
			return sendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidAccessKeyID), logger)
		}
		if err != nil {
			return sendResponse(ctx, err, logger)
		}
		ctx.Locals("account", account)

		// Check X-Amz-Date header
		date := ctx.Get("X-Amz-Date")
		if date == "" {
			return sendResponse(ctx, s3err.GetAPIError(s3err.ErrMissingDateHeader), logger)
		}

		// Parse the date and check the date validity
		tdate, err := time.Parse(iso8601Format, date)
		if err != nil {
			return sendResponse(ctx, s3err.GetAPIError(s3err.ErrMalformedDate), logger)
		}

		if date[:8] != authData.Date {
			return sendResponse(ctx, s3err.GetAPIError(s3err.ErrSignatureDateDoesNotMatch), logger)
		}

		// Validate the dates difference
		err = utils.ValidateDate(tdate)
		if err != nil {
			return sendResponse(ctx, err, logger)
		}

		if utils.IsBigDataAction(ctx) {
			// for streaming PUT actions, authorization is deferred
			// until end of stream due to need to get length and
			// checksum of the stream to validate authorization
			wrapBodyReader(ctx, func(r io.Reader) io.Reader {
				return utils.NewAuthReader(ctx, r, authData, account.Secret, debug)
			})
			return ctx.Next()
		}

		hashPayload := ctx.Get("X-Amz-Content-Sha256")
		if !utils.IsSpecialPayload(hashPayload) {
			// Calculate the hash of the request payload
			hashedPayload := sha256.Sum256(ctx.Body())
			hexPayload := hex.EncodeToString(hashedPayload[:])

			// Compare the calculated hash with the hash provided
			if hashPayload != hexPayload {
				return sendResponse(ctx, s3err.GetAPIError(s3err.ErrContentSHA256Mismatch), logger)
			}
		}

		var contentLength int64
		contentLengthStr := ctx.Get("Content-Length")
		if contentLengthStr != "" {
			contentLength, err = strconv.ParseInt(contentLengthStr, 10, 64)
			if err != nil {
				return sendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest), logger)
			}
		}

		err = utils.CheckValidSignature(ctx, authData, account.Secret, hashPayload, tdate, contentLength, debug)
		if err != nil {
			return sendResponse(ctx, err, logger)
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
			Access: a.root.Access,
			Secret: a.root.Secret,
			Role:   "admin",
		}, nil
	}

	return a.iam.GetUserAccount(access)
}

func sendResponse(ctx *fiber.Ctx, err error, logger s3log.AuditLogger) error {
	return controllers.SendResponse(ctx, err, &controllers.MetaOpts{Logger: logger})
}
