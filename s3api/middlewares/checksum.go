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
	"bytes"
	"encoding/base64"
	"io"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
)

// VerifyChecksums parses, validates, and calculates the
// Content-MD5 and x-amz-checksum-* headers.
// Additionally, it ensures that the request body is not empty
// for actions that require a non-empty body. For large data actions(PutObject, UploadPart),
// it wraps the body reader to handle Content-MD5:
// the x-amz-checksum-* headers are explicitly processed by the backend.
func VerifyChecksums(streamBody bool, requireBody bool, requireChecksum bool) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		md5sum := ctx.Get("Content-Md5")

		if streamBody {
			// for large data actions(PutObject, UploadPart)
			// only stack the md5 reader,as x-amz-checksum-*
			// calculation is explicitly handled in back-end
			if md5sum == "" {
				return nil
			}

			if !isValidMD5(md5sum) {
				return s3err.GetAPIError(s3err.ErrInvalidDigest)
			}

			var err error
			wrapBodyReader(ctx, func(r io.Reader) io.Reader {
				r, err = utils.NewHashReader(r, md5sum, utils.HashTypeMd5)
				return r
			})
			if err != nil {
				return err
			}
			return nil
		}

		body := ctx.Body()
		if requireBody && len(body) == 0 {
			return s3err.GetAPIError(s3err.ErrMissingRequestBody)
		}

		var rdr io.Reader
		var err error
		if md5sum != "" {
			if !isValidMD5(md5sum) {
				return s3err.GetAPIError(s3err.ErrInvalidDigest)
			}

			rdr, err = utils.NewHashReader(bytes.NewReader(body), md5sum, utils.HashTypeMd5)
			if err != nil {
				return err
			}
		}

		// parse and validate checksum headers
		algo, checksums, err := utils.ParseChecksumHeadersAndSdkAlgo(ctx)
		if err != nil {
			return err
		}

		if algo != "" {
			r, err := utils.NewHashReader(bytes.NewReader(body), checksums[algo], utils.HashType(strings.ToLower(string(algo))))
			if err != nil {
				return err
			}

			if rdr != nil {
				// combine both md5 and the checksum readers
				rdr = io.MultiReader(rdr, r)
			} else {
				rdr = r
			}
		}

		if rdr == nil && requireChecksum {
			return s3err.GetAPIError(s3err.ErrChecksumRequired)
		}

		if rdr != nil {
			_, err = io.Copy(io.Discard, rdr)
			if err != nil {
				return err
			}
		}

		return nil
	}
}

func isValidMD5(s string) bool {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return false
	}

	return len(decoded) == 16
}
