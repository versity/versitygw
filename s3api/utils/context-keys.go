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

package utils

import (
	"github.com/gofiber/fiber/v2"
)

// Region, StartTime, IsRoot, Account, AccessKey context locals
// are set to defualut values in middlewares.SetDefaultValues
// to avoid the nil interface conversions
type ContextKey string

const (
	ContextKeyRegion         ContextKey = "region"
	ContextKeyStartTime      ContextKey = "start-time"
	ContextKeyIsRoot         ContextKey = "is-root"
	ContextKeyRootAccessKey  ContextKey = "root-access-key"
	ContextKeyAccount        ContextKey = "account"
	ContextKeyAuthenticated  ContextKey = "authenticated"
	ContextKeyPublicBucket   ContextKey = "public-bucket"
	ContextKeyParsedAcl      ContextKey = "parsed-acl"
	ContextKeySkipResBodyLog ContextKey = "skip-res-body-log"
	ContextKeyBodyReader     ContextKey = "body-reader"
)

func (ck ContextKey) Values() []ContextKey {
	return []ContextKey{
		ContextKeyRegion,
		ContextKeyStartTime,
		ContextKeyIsRoot,
		ContextKeyRootAccessKey,
		ContextKeyAccount,
		ContextKeyAuthenticated,
		ContextKeyPublicBucket,
		ContextKeyParsedAcl,
		ContextKeySkipResBodyLog,
		ContextKeyBodyReader,
	}
}

func (ck ContextKey) Set(ctx *fiber.Ctx, val any) {
	ctx.Locals(string(ck), val)
}

func (ck ContextKey) IsSet(ctx *fiber.Ctx) bool {
	val := ctx.Locals(string(ck))
	return val != nil
}

func (ck ContextKey) Get(ctx *fiber.Ctx) any {
	return ctx.Locals(string(ck))
}
