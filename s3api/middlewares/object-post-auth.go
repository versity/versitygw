// Copyright 2026 Versity Software
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
	"bytes"
	"mime"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
)

const (
	formFieldPolicy     = "policy"
	formFieldAlgorithm  = "x-amz-algorithm"
	formFieldCredential = "x-amz-credential"
	formFieldDate       = "x-amz-date"
	formFieldSignature  = "x-amz-signature"

	aws4HMACSHA256 = "AWS4-HMAC-SHA256"
)

type PostObjectResult struct {
	ContentLength int64
	// FileRdr streams the file payload. Length() reports the exact number of
	// file-content bytes read after the backend has consumed the body.
	FileRdr utils.MpFileReader
	Fields  map[string]string
}

func AuthorizePostObject(root RootUserConfig, iam auth.IAMService, region string) fiber.Handler {
	acct := accounts{root: root, iam: iam}

	return func(ctx *fiber.Ctx) error {
		contentLengthStr := ctx.Get("Content-Length")
		reqContentLength, err := strconv.ParseInt(contentLengthStr, 10, 64)
		if err != nil {
			debuglogger.Logf("invalid POST object Content-Length %q: %v", contentLengthStr, err)
			return s3err.GetAPIError(s3err.ErrInvalidRequest)
		}

		mediaType, params, err := mime.ParseMediaType(ctx.Get("Content-Type"))
		if err != nil || mediaType != fiber.MIMEMultipartForm {
			debuglogger.Logf("invalid POST object Content-Type %q: mediaType=%q err=%v", ctx.Get("Content-Type"), mediaType, err)
			return s3err.GetAPIError(s3err.ErrPreconditionFailed)
		}

		boundary := params["boundary"]
		if boundary == "" {
			debuglogger.Logf("missing multipart boundary in POST object request")
			return s3err.GetAPIError(s3err.ErrMalformedPOSTRequest)
		}

		bodyRdr := ctx.Request().BodyStream()
		if bodyRdr == nil {
			bodyRdr = bytes.NewReader(ctx.Body())
		}

		mpParser, err := utils.NewMultipartParser(bodyRdr, boundary, reqContentLength)
		if err != nil {
			return err
		}

		result, err := mpParser.Parse()
		if err != nil {
			return err
		}

		fields := result.Fields

		policyB64 := fields[formFieldPolicy]
		algorithm := fields[formFieldAlgorithm]
		credentialStr := fields[formFieldCredential]
		amzDate := fields[formFieldDate]
		signatureHex := fields[formFieldSignature]

		// Determine if the request carries form-based credentials.
		// A request is considered signed if ANY of the five auth fields is
		// present; in that case ALL of them are required.
		hasAnyAuthField := policyB64 != "" || algorithm != "" || credentialStr != "" || amzDate != "" || signatureHex != ""

		if hasAnyAuthField {
			// Signed POST Object — validate every required auth field.
			for _, field := range []struct {
				key   string
				value string
			}{
				{formFieldPolicy, policyB64},
				{formFieldAlgorithm, algorithm},
				{formFieldCredential, credentialStr},
				{formFieldDate, amzDate},
				{formFieldSignature, signatureHex},
			} {
				if field.value == "" {
					debuglogger.Logf("missing required POST object field: %s", field.key)
					return s3err.PostAuth.MissingField(field.key)
				}
			}

			if algorithm != aws4HMACSHA256 {
				debuglogger.Logf("unsupported POST object signing algorithm: %s", algorithm)
				return s3err.GetAPIError(s3err.ErrOnlyAws4HmacSha256)
			}

			// Parse the date and check the date validity
			tdate, err := time.Parse(iso8601Format, amzDate)
			if err != nil {
				debuglogger.Logf("invalid POST object x-amz-date %q: %v", amzDate, err)
				return s3err.GetAPIError(s3err.ErrInvalidDateHeader)
			}

			// Validate the dates difference
			// TODO: Seems s3 doesn't validate this
			err = utils.ValidateDate(tdate)
			if err != nil {
				return err
			}

			creds, err := utils.ParseCredentials(credentialStr, s3err.PostAuth)
			if err != nil {
				return err
			}

			if region != creds.Region {
				debuglogger.Logf("incorrect POST object credential region: got %q want %q", creds.Region, region)
				return s3err.MalformedAuth.IncorrectRegion(region, creds.Region)
			}

			account, err := acct.getAccount(creds.Access)
			if err == auth.ErrNoSuchUser {
				debuglogger.Logf("POST object access key not found: %s", creds.Access)
				return s3err.GetAPIError(s3err.ErrInvalidAccessKeyID)
			}
			if err != nil {
				debuglogger.Logf("failed to resolve POST object account %q: %v", creds.Access, err)
				return err
			}

			utils.ContextKeyAccount.Set(ctx, account)
			utils.ContextKeyIsRoot.Set(ctx, account.Access == root.Access)

			expectedSig, err := utils.SignPostPolicy(policyB64, creds.Date, region, account.Secret)
			if err != nil {
				return err
			}

			if expectedSig != signatureHex {
				debuglogger.Logf("POST object signature mismatch: expected %s got %s", expectedSig, signatureHex)
				return s3err.GetAPIError(s3err.ErrSignatureDoesNotMatch)
			}

			// Mark this request as authenticated so that
			// AuthorizePublicBucketAccess (running after this middleware)
			// skips its anonymous-access check.
			utils.ContextKeyAuthenticated.Set(ctx, true)
		}
		// else: anonymous POST Object — no credentials in form fields.
		// AuthorizePublicBucketAccess will verify public bucket access next.

		utils.ContextKeyObjectPostResult.Set(ctx,
			PostObjectResult{
				Fields:        fields,
				FileRdr:       result.FileRdr,
				ContentLength: result.ContentLength,
			},
		)

		return nil
	}
}
