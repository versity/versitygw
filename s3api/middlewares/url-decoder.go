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
	"net/url"

	"github.com/gofiber/fiber/v3"
)

// DecodeURL url path unescapes the request url for the gateway
// to handle some special characters
func DecodeURL(ctx fiber.Ctx) error {
	unescp, err := url.PathUnescape(string(ctx.Request().URI().PathOriginal()))
	if err != nil {
		return err
	}
	ctx.Path(unescp)
	return nil
}
