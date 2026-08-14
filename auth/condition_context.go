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

package auth

import (
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"
)

// requestConditionContext builds the IAM policy-condition keys describing
// this request — aws:SourceIp, aws:SecureTransport, aws:CurrentTime and
// friends — for identity-policy and bucket-policy Condition blocks to
// evaluate against. The identity-derived keys (aws:PrincipalArn,
// aws:username, aws:PrincipalTag/*, …) are deliberately absent: the S3
// gateway has no way to know them, so the IAM service fills them in itself
// when it evaluates an identity policy.
func requestConditionContext(ctx fiber.Ctx) map[string][]string {
	now := time.Now().UTC()
	condCtx := map[string][]string{
		"aws:CurrentTime":     {now.Format(time.RFC3339)},
		"aws:EpochTime":       {strconv.FormatInt(now.Unix(), 10)},
		"aws:SecureTransport": {strconv.FormatBool(ctx.Secure())},
	}
	// ctx.IP() is the real peer address: the gateway's fiber app configures
	// neither ProxyHeader nor TrustProxy, so no client-supplied header can
	// influence it. Adding either for logging would make aws:SourceIp
	// client-controlled — revisit this if that ever changes.
	if ip := ctx.IP(); ip != "" {
		condCtx["aws:SourceIp"] = []string{ip}
	}
	if ua := ctx.Get("User-Agent"); ua != "" {
		condCtx["aws:UserAgent"] = []string{ua}
	}
	if ref := ctx.Get("Referer"); ref != "" {
		condCtx["aws:Referer"] = []string{ref}
	}
	if prefix := ctx.Query("prefix"); prefix != "" {
		condCtx["s3:prefix"] = []string{prefix}
	}
	if delim := ctx.Query("delimiter"); delim != "" {
		condCtx["s3:delimiter"] = []string{delim}
	}
	if maxKeys := ctx.Query("max-keys"); maxKeys != "" {
		condCtx["s3:max-keys"] = []string{maxKeys}
	}
	if acl := ctx.Get("X-Amz-Acl"); acl != "" {
		condCtx["s3:x-amz-acl"] = []string{acl}
	}
	if versionID := ctx.Query("versionId"); versionID != "" {
		condCtx["s3:VersionId"] = []string{versionID}
	}

	return condCtx
}
