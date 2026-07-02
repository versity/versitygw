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

import "github.com/versity/versitygw/internal/httpctx"

// Region, StartTime, IsRoot, Account, AccessKey context locals
// are set to default values in middlewares.SetDefaultValues
// to avoid the nil interface conversions
type ContextKey = httpctx.ContextKey

const (
	ContextKeyRegion           = httpctx.ContextKeyRegion
	ContextKeyStartTime        = httpctx.ContextKeyStartTime
	ContextKeyIsRoot           = httpctx.ContextKeyIsRoot
	ContextKeyRootAccessKey    = httpctx.ContextKeyRootAccessKey
	ContextKeyAccount          = httpctx.ContextKeyAccount
	ContextKeyAuthenticated    = httpctx.ContextKeyAuthenticated
	ContextKeyPublicBucket     = httpctx.ContextKeyPublicBucket
	ContextKeyParsedAcl        = httpctx.ContextKeyParsedAcl
	ContextKeySkipResBodyLog   = httpctx.ContextKeySkipResBodyLog
	ContextKeyBodyReader       = httpctx.ContextKeyBodyReader
	ContextKeySkip             = httpctx.ContextKeySkip
	ContextKeyStack            = httpctx.ContextKeyStack
	ContextKeyBucketOwner      = httpctx.ContextKeyBucketOwner
	ContextKeyObjectPostResult = httpctx.ContextKeyObjectPostResult
	ContextKeyRequestID        = httpctx.ContextKeyRequestID
	ContextKeyHostID           = httpctx.ContextKeyHostID
	ContextKeyWebsiteConfig    = httpctx.ContextKeyWebsiteConfig
)
