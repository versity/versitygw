package middlewares

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/gofiber/fiber/v2"
	"github.com/versity/scoutgw/s3api/controllers"
	"github.com/versity/scoutgw/s3api/utils"
	"github.com/versity/scoutgw/s3err"
)

const (
	iso8601Format = "20060102T150405Z"
)

func VerifyV4Signature(user utils.RootUser) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		authorization := ctx.Get("Authorization")
		if authorization == "" {
			return controllers.Responce[any](ctx, nil, s3err.GetAPIError(s3err.ErrAuthHeaderEmpty))
		}

		// Check the signature version
		authParts := strings.Split(authorization, " ")
		if authParts[0] != "AWS4-HMAC-SHA256" {
			return controllers.Responce[any](ctx, nil, s3err.GetAPIError(s3err.ErrSignatureVersionNotSupported))
		}

		creds := strings.Split(strings.Split(authParts[1], "=")[1], "/")

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
			return controllers.Responce[any](ctx, nil, s3err.GetAPIError(s3err.ErrAccessDenied))
		}

		signer := v4.NewSigner()

		signErr := signer.SignHTTP(req.Context(), aws.Credentials{
			AccessKeyID:     user.Login,
			SecretAccessKey: user.Password,
		}, req, hexPayload, creds[3], creds[2], tdate)
		if signErr != nil {
			return controllers.Responce[any](ctx, nil, s3err.GetAPIError(s3err.ErrAccessDenied))
		}

		parts := strings.Split(req.Header.Get("Authorization"), " ")
		calculatedSign := strings.Split(parts[3], "=")[1]
		expectedSign := strings.Split(authParts[3], "=")[1]

		if expectedSign != calculatedSign {
			return controllers.Responce[any](ctx, nil, s3err.GetAPIError(s3err.ErrSignatureDoesNotMatch))
		}

		return ctx.Next()
	}
}
