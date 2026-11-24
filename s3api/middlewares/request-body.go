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
	"io"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/s3err"
)

// RequestBodyLimit is the largest request body an action takes, and the error
// a larger one is refused with.
type RequestBodyLimit struct {
	max int64
	err error
}

// The request body limits S3 sets the actions that take an XML or JSON
// document as their body. A body of exactly the limit is accepted, and one
// byte more is refused, with MaxMessageLengthExceeded unless noted otherwise.
var (
	CreateBucketBodyLimit               = maxMessageLength(35240)
	PutBucketTaggingBodyLimit           = maxMessageLength(163840)
	PutBucketOwnershipControlsBodyLimit = maxMessageLength(2048)
	PutBucketVersioningBodyLimit        = maxMessageLength(1024)
	PutObjectLockConfigurationBodyLimit = maxMessageLength(2097152)
	PutBucketCorsBodyLimit              = maxMessageLength(65536)
	PutBucketAclBodyLimit               = maxMessageLength(204800)
	PutBucketWebsiteBodyLimit           = maxMessageLength(131072)
	DeleteObjectsBodyLimit              = maxMessageLength(2048000)
	PutObjectTaggingBodyLimit           = maxMessageLength(204800)
	PutObjectRetentionBodyLimit         = maxMessageLength(1048576)
	PutObjectLegalHoldBodyLimit         = maxMessageLength(1048576)
	PutObjectAclBodyLimit               = maxMessageLength(204800)
	RestoreObjectBodyLimit              = maxMessageLength(307200)
	CompleteMultipartUploadBodyLimit    = maxMessageLength(2621440)

	// S3 sizes a policy by its normalized JSON, but does not read a body
	// past this to normalize it, and refuses that body as a too large policy
	PutBucketPolicyBodyLimit = RequestBodyLimit{max: 204800, err: auth.ErrPolicyTooLarge}
	// the limit is decimal, and S3 refuses past it with an error of its own
	SelectObjectContentBodyLimit = RequestBodyLimit{max: 1000000, err: s3err.GetAPIError(s3err.ErrRequestBodyTooLarge)}

	// NoRequestBody is for the actions that take no body at all, and
	// refuse a non-empty one: CopyObject, UploadPartCopy and
	// CreateMultipartUpload
	NoRequestBody = RequestBodyLimit{max: 0, err: s3err.GetAPIError(s3err.ErrNonEmptyRequestBody)}

	// AdminBodyLimit is for the admin API, which has no S3 counterpart. Its
	// documents describe a single account, well below this.
	AdminBodyLimit = maxMessageLength(1048576)
)

// ReadRequestBody reads the body of an action that takes it whole into
// memory, where the handlers down the chain get it with ctx.BodyRaw(). A body
// is refused one byte past limit, so the memory a request can make the gateway
// hold is bounded by its action, and none of a body its Content-Length
// declares over the limit is held at all.
//
// It must follow the authentication middlewares on the route. They verify
// the signature, which covers the headers alone, without reading the body, and
// stack the payload hash check on the body reader instead, so no byte of the
// body is read before the request is authenticated, and the hash is verified
// here, as the body is read.
//
// Only the actions that take a body read it. Any other route leaves the body
// unread and unverified, as S3 does, for DrainRequestBody to discard.
func ReadRequestBody(limit RequestBodyLimit) fiber.Handler {
	return func(ctx fiber.Ctx) error {
		// one byte past the limit is enough to tell a body that ends at the
		// limit from a larger one
		rdr := io.LimitReader(requestBodyReader(ctx), limit.max+1)

		if declared := ctx.Request().Header.ContentLength(); int64(declared) > limit.max {
			debuglogger.Logf("the declared request body size %v exceeds the %v byte limit", declared, limit.max)
			// Still read it as far as a body found too large while reading
			// it is. DrainRequestBody can then take the rest of a body just
			// over the limit, and its client reads the error instead of a
			// connection reset.
			_, _ = io.Copy(io.Discard, rdr)
			return limit.err
		}

		body, err := io.ReadAll(rdr)
		if int64(len(body)) > limit.max {
			debuglogger.Logf("the request body exceeds the %v byte limit", limit.max)
			return limit.err
		}
		// fasthttp ends a body whose client stopped sending it early as if
		// it were complete, and the payload hash would only call it a
		// mismatch
		if declared := ctx.Request().Header.ContentLength(); declared >= 0 && len(body) < declared {
			debuglogger.Logf("the request body ended after %v of its %v bytes", len(body), declared)
			return s3err.GetAPIError(s3err.ErrIncompleteBody)
		}
		if err != nil {
			if _, ok := err.(s3err.S3Error); ok {
				// the payload hash does not match
				return err
			}

			debuglogger.Logf("failed to read the request body: %v", err)
			return s3err.GetAPIError(s3err.ErrIncompleteBody)
		}

		// the body has been read to its end, and replacing the stream with it
		// is what hands it to ctx.BodyRaw()
		ctx.Request().SetBodyRaw(body)
		return nil
	}
}

func maxMessageLength(max int64) RequestBodyLimit {
	return RequestBodyLimit{max: max, err: s3err.GetMaxMessageLengthExceeded(max)}
}
