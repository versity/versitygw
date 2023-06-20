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
	"fmt"
	"log"

	"github.com/gofiber/fiber/v2"
)

func RequestLogger(isDebug bool) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		ctx.Locals("isDebug", isDebug)
		if isDebug {
			log.Println("Request headers: ")
			ctx.Request().Header.VisitAll(func(key, val []byte) {
				log.Printf("%s: %s", key, val)
			})

			if ctx.Request().URI().QueryArgs().Len() != 0 {
				fmt.Println()
				log.Println("Request query arguments: ")
				ctx.Request().URI().QueryArgs().VisitAll(func(key, val []byte) {
					log.Printf("%s: %s", key, val)
				})
			}
		}

		return ctx.Next()
	}
}
