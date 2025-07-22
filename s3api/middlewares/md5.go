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
	"crypto/md5"
	"io"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
)

func VerifyMD5Body() fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		incomingSum := ctx.Get("Content-Md5")
		if incomingSum == "" {
			return nil
		}

		if utils.IsBigDataAction(ctx) {
			var err error
			wrapBodyReader(ctx, func(r io.Reader) io.Reader {
				r, err = utils.NewHashReader(r, incomingSum, utils.HashTypeMd5)
				return r
			})
			if err != nil {
				return err
			}
			return nil
		}

		sum := md5.Sum(ctx.Body())
		calculatedSum := utils.Base64SumString(sum[:])

		if incomingSum != calculatedSum {
			return s3err.GetAPIError(s3err.ErrInvalidDigest)
		}

		return nil
	}
}
