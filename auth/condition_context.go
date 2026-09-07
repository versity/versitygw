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
	"slices"
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
//
// actions is the action set this request is being authorized under, used by
// the keys whose applicability AWS defines per action. Pass nil where no
// such key can apply.
func requestConditionContext(ctx fiber.Ctx, actions []Action) map[string][]string {
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
	addConditionalWriteKeys(ctx, actions, condCtx)

	return condCtx
}

// addConditionalWriteKeys populates s3:if-match and s3:if-none-match from
// the request's If-Match/If-None-Match headers, each only on a request
// whose action the key applies to. The applicability rules are the ones
// PutBucketPolicy validates a Condition against, so a key can never reach
// the request context on an action a policy isn't allowed to name it on.
// The value is the header with its surrounding ETag quotes removed, so a
// policy compares against the bare ETag whichever form the client sent.
func addConditionalWriteKeys(ctx fiber.Ctx, actions []Action, condCtx map[string][]string) {
	action := conditionalWriteAction(ctx, actions)
	if isConditionalWriteAction(action) {
		if ifMatch := trimETagQuotes(ctx.Get("If-Match")); ifMatch != "" {
			condCtx["s3:if-match"] = []string{ifMatch}
		}
	}
	if isConditionalCreateAction(action) {
		if ifNoneMatch := trimETagQuotes(ctx.Get("If-None-Match")); ifNoneMatch != "" {
			condCtx["s3:if-none-match"] = []string{ifNoneMatch}
		}
	}
}

// nonConditionalWriteSubresources names the query parameters that route an
// object PUT or DELETE to a handler other than PutObject/DeleteObject:
// tagging, retention, legal-hold and ACL writes, plus UploadPart and
// AbortMultipartUpload. UploadPart and UploadPartCopy are authorized as
// s3:PutObject just like PutObject itself, so only the route tells them
// apart.
var nonConditionalWriteSubresources = []string{"acl", "tagging", "retention", "legal-hold", "uploadId"}

// conditionalWriteAction reports the action ctx is authorized under, for
// the requests whose If-Match/If-None-Match the gateway enforces: PutObject
// and CompleteMultipartUpload, both authorized as s3:PutObject, and
// DeleteObject, which a versionId turns into s3:DeleteObjectVersion exactly
// as the handler does. It returns the empty action for everything else.
//
// Everything else ignores those headers, and a policy must never grant on a
// precondition that won't be checked — otherwise a form upload, a
// DeleteObjects batch, a copy or an upload part could satisfy a statement
// demanding a conditional write by sending a header that changes nothing.
// Reads are the same case: GET and HEAD take these headers as ordinary HTTP
// cache preconditions. Excluding a request leaves both keys absent, which
// denies it under such a policy rather than letting it through.
//
// The request shape alone doesn't identify an object write: a bucket
// sub-resource write is a PUT or DELETE carrying none of the object
// sub-resources, so it has to be recognized by what it is authorized as.
// actions is that set, and the shape's action must be in it — the two
// disagree exactly when the request routes somewhere else, as
// PutBucketVersioning, CreateBucket and DeleteBucket all do.
func conditionalWriteAction(ctx fiber.Ctx, actions []Action) Action {
	action := conditionalWriteRouteAction(ctx)
	if action == "" || !slices.Contains(actions, action) {
		return ""
	}
	return action
}

// conditionalWriteRouteAction is conditionalWriteAction's request-shape
// half: the action this method, query and copy-source header would route
// to, before checking what the request is actually authorized as.
func conditionalWriteRouteAction(ctx fiber.Ctx) Action {
	// A copy carries its preconditions in the X-Amz-Copy-Source-If-*
	// headers, which name the source object and populate neither key. Both
	// a copy and a plain upload are authorized as s3:PutObject, so only
	// this header tells them apart.
	if ctx.Get("X-Amz-Copy-Source") != "" {
		return ""
	}
	query := ctx.Request().URI().QueryArgs()
	switch string(ctx.Request().Header.Method()) {
	case fiber.MethodPut:
		if slices.ContainsFunc(nonConditionalWriteSubresources, query.Has) {
			return ""
		}
		return PutObjectAction
	case fiber.MethodDelete:
		if slices.ContainsFunc(nonConditionalWriteSubresources, query.Has) {
			return ""
		}
		// A delete naming a version removes that version rather than
		// overwriting the current one, so it is authorized as
		// s3:DeleteObjectVersion — an action neither key applies to. The
		// gateway still enforces the precondition against the named
		// version; a policy simply has no vocabulary to require it there,
		// and the key stays absent so such a statement denies instead.
		if query.Has("versionId") {
			return DeleteObjectVersionAction
		}
		return DeleteObjectAction
	case fiber.MethodPost:
		// CompleteMultipartUpload is the only POST that enforces them.
		if query.Has("uploadId") {
			return PutObjectAction
		}
		return ""
	default:
		return ""
	}
}

// trimETagQuotes strips one leading and one trailing double quote from an
// ETag-valued header, leaving any other value (notably If-None-Match's "*")
// untouched.
func trimETagQuotes(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}
