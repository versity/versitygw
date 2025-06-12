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
	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/s3api/utils"
)

func MatchQueryArgs(args ...string) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		if utils.ContextKeySkip.IsSet(ctx) {
			return ctx.Next()
		}
		for _, query := range args {
			if !ctx.Request().URI().QueryArgs().Has(query) {
				utils.ContextKeySkip.Set(ctx, true)
				break
			}
		}
		return ctx.Next()
	}
}

func MatchQueryArgWithValue(key, val string) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		if utils.ContextKeySkip.IsSet(ctx) {
			return ctx.Next()
		}

		if ctx.Query(key) != val {
			utils.ContextKeySkip.Set(ctx, true)
		}

		return ctx.Next()
	}
}
