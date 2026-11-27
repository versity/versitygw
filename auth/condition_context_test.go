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
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
	"github.com/versity/versitygw/internal/httpctx"
)

func TestRequestConditionContextConditionalWriteKeys(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		ifMatch     string
		ifNoneMatch string
		copySource  string
		// uri defaults to an object path when empty.
		uri     string
		query   string
		actions []Action
		want    map[string][]string
	}{
		{
			name:    "no conditional headers",
			method:  fiber.MethodPut,
			actions: []Action{PutObjectAction},
			want:    map[string][]string{},
		},
		{
			name:    "If-Match quotes are stripped",
			method:  fiber.MethodPut,
			ifMatch: `"abc123"`,
			actions: []Action{PutObjectAction},
			want:    map[string][]string{"s3:if-match": {"abc123"}},
		},
		{
			// Both wire forms land on the same context value, so a policy
			// always compares against the bare ETag.
			name:    "unquoted If-Match is taken as-is",
			method:  fiber.MethodPut,
			ifMatch: "abc123",
			actions: []Action{PutObjectAction},
			want:    map[string][]string{"s3:if-match": {"abc123"}},
		},
		{
			// A multi-ETag If-Match is one value, not a list: the gateway
			// compares the whole header against the object's ETag, and the
			// key carries exactly what that comparison sees.
			name:    "a multi-ETag If-Match is one value",
			method:  fiber.MethodPut,
			ifMatch: `"abc123", "def456"`,
			actions: []Action{PutObjectAction},
			want:    map[string][]string{"s3:if-match": {`abc123", "def456`}},
		},
		{
			name:        "If-None-Match wildcard",
			method:      fiber.MethodPut,
			ifNoneMatch: "*",
			actions:     []Action{PutObjectAction},
			want:        map[string][]string{"s3:if-none-match": {"*"}},
		},
		{
			name:        "both headers on one request",
			method:      fiber.MethodPut,
			ifMatch:     `"abc123"`,
			ifNoneMatch: "*",
			actions:     []Action{PutObjectAction},
			want: map[string][]string{
				"s3:if-match":      {"abc123"},
				"s3:if-none-match": {"*"},
			},
		},
		{
			// An upload carrying tagging or lock headers is authorized
			// under those actions too; s3:PutObject is still among them.
			name:    "an upload authorized under several actions",
			method:  fiber.MethodPut,
			ifMatch: `"abc123"`,
			actions: []Action{PutObjectAction, PutObjectTaggingAction, PutObjectRetentionAction},
			want:    map[string][]string{"s3:if-match": {"abc123"}},
		},
		{
			name:    "CompleteMultipartUpload populates the keys",
			method:  fiber.MethodPost,
			query:   "uploadId=abc",
			ifMatch: `"abc123"`,
			actions: []Action{PutObjectAction},
			want:    map[string][]string{"s3:if-match": {"abc123"}},
		},
		{
			name:    "DeleteObject populates s3:if-match",
			method:  fiber.MethodDelete,
			ifMatch: `"abc123"`,
			actions: []Action{DeleteObjectAction},
			want:    map[string][]string{"s3:if-match": {"abc123"}},
		},
		{
			// A delete is authorized as s3:DeleteObject, which
			// s3:if-none-match doesn't apply to — DeleteObject reads no
			// If-None-Match, so the header changes nothing.
			name:        "a delete populates no s3:if-none-match",
			method:      fiber.MethodDelete,
			ifMatch:     `"abc123"`,
			ifNoneMatch: "*",
			actions:     []Action{DeleteObjectAction},
			want:        map[string][]string{"s3:if-match": {"abc123"}},
		},
		{
			// A versioned delete is authorized as s3:DeleteObjectVersion,
			// which neither key applies to, even though the gateway does
			// check the precondition against the named version.
			name:        "a versioned delete populates neither key",
			method:      fiber.MethodDelete,
			query:       "versionId=v1",
			ifMatch:     `"abc123"`,
			ifNoneMatch: "*",
			actions:     []Action{DeleteObjectVersionAction},
			want:        map[string][]string{},
		},
		{
			// A bucket sub-resource write is a bare PUT carrying none of
			// the object sub-resources, so only the action it authorizes
			// under separates it from an upload.
			name:    "PutBucketVersioning populates neither key",
			method:  fiber.MethodPut,
			uri:     "/bucket",
			query:   "versioning=",
			ifMatch: `"abc123"`,
			actions: []Action{PutBucketVersioningAction},
			want:    map[string][]string{},
		},
		{
			name:        "PutBucketPolicy populates neither key",
			method:      fiber.MethodPut,
			uri:         "/bucket",
			query:       "policy=",
			ifMatch:     `"abc123"`,
			ifNoneMatch: "*",
			actions:     []Action{PutBucketPolicyAction},
			want:        map[string][]string{},
		},
		{
			name:        "CreateBucket populates neither key",
			method:      fiber.MethodPut,
			uri:         "/bucket",
			ifMatch:     `"abc123"`,
			ifNoneMatch: "*",
			actions:     []Action{CreateBucketAction},
			want:        map[string][]string{},
		},
		{
			name:    "DeleteBucket populates neither key",
			method:  fiber.MethodDelete,
			uri:     "/bucket",
			ifMatch: `"abc123"`,
			actions: []Action{DeleteBucketAction},
			want:    map[string][]string{},
		},
		{
			// The object-lock paths authorize s3:BypassGovernanceRetention,
			// an action neither key applies to, on the very requests that
			// do carry a precondition.
			name:        "a governance bypass populates neither key",
			method:      fiber.MethodPut,
			ifMatch:     `"abc123"`,
			ifNoneMatch: "*",
			actions:     []Action{BypassGovernanceRetentionAction},
			want:        map[string][]string{},
		},
		{
			name:        "no actions populates neither key",
			method:      fiber.MethodPut,
			ifMatch:     `"abc123"`,
			ifNoneMatch: "*",
			want:        map[string][]string{},
		},
		{
			// A form upload and a DeleteObjects batch are POSTs that never
			// look at the headers.
			name:        "a form upload populates neither key",
			method:      fiber.MethodPost,
			ifMatch:     `"abc123"`,
			ifNoneMatch: "*",
			actions:     []Action{PutObjectAction},
			want:        map[string][]string{},
		},
		{
			name:    "a DeleteObjects batch populates neither key",
			method:  fiber.MethodPost,
			uri:     "/bucket",
			query:   "delete=",
			ifMatch: `"abc123"`,
			actions: []Action{DeleteObjectAction},
			want:    map[string][]string{},
		},
		{
			name:    "an upload part populates neither key",
			method:  fiber.MethodPut,
			query:   "partNumber=1&uploadId=abc",
			ifMatch: `"abc123"`,
			actions: []Action{PutObjectAction},
			want:    map[string][]string{},
		},
		{
			name:    "a tagging write populates neither key",
			method:  fiber.MethodPut,
			query:   "tagging=",
			ifMatch: `"abc123"`,
			actions: []Action{PutObjectTaggingAction},
			want:    map[string][]string{},
		},
		{
			name:    "an ACL write populates neither key",
			method:  fiber.MethodPut,
			query:   "acl=",
			ifMatch: `"abc123"`,
			actions: []Action{PutObjectAclAction},
			want:    map[string][]string{},
		},
		{
			// On a read the same headers are ordinary HTTP cache
			// preconditions, not conditional writes.
			name:        "GET populates neither key",
			method:      fiber.MethodGet,
			ifMatch:     `"abc123"`,
			ifNoneMatch: `"abc123"`,
			actions:     []Action{GetObjectAction},
			want:        map[string][]string{},
		},
		{
			name:        "HEAD populates neither key",
			method:      fiber.MethodHead,
			ifMatch:     `"abc123"`,
			ifNoneMatch: `"abc123"`,
			actions:     []Action{GetObjectAction},
			want:        map[string][]string{},
		},
		{
			// A copy's If-Match/If-None-Match are conditional writes on
			// its destination, like a plain upload's.
			name:        "a copy populates both keys",
			method:      fiber.MethodPut,
			ifMatch:     `"abc123"`,
			ifNoneMatch: "*",
			copySource:  "/src-bucket/src-key",
			actions:     []Action{PutObjectAction},
			want: map[string][]string{
				"s3:if-match":      {"abc123"},
				"s3:if-none-match": {"*"},
			},
		},
		{
			name:        "an upload part copy populates neither key",
			method:      fiber.MethodPut,
			query:       "partNumber=1&uploadId=abc",
			ifMatch:     `"abc123"`,
			ifNoneMatch: "*",
			copySource:  "/src-bucket/src-key",
			actions:     []Action{PutObjectAction},
			want:        map[string][]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := fiber.New()
			fctx := &fasthttp.RequestCtx{}
			fctx.Request.Header.SetMethod(tt.method)
			uri := tt.uri
			if uri == "" {
				uri = "/bucket/object"
			}
			if tt.query != "" {
				uri += "?" + tt.query
			}
			fctx.Request.SetRequestURI(uri)
			if tt.ifMatch != "" {
				fctx.Request.Header.Set("If-Match", tt.ifMatch)
			}
			if tt.ifNoneMatch != "" {
				fctx.Request.Header.Set("If-None-Match", tt.ifNoneMatch)
			}
			if tt.copySource != "" {
				fctx.Request.Header.Set("X-Amz-Copy-Source", tt.copySource)
			}

			ctx := app.AcquireCtx(fctx)
			defer app.ReleaseCtx(ctx)

			condCtx := requestConditionContext(ctx, tt.actions)
			for _, key := range []string{"s3:if-match", "s3:if-none-match"} {
				if want, ok := tt.want[key]; ok {
					assert.Equal(t, want, condCtx[key])
					continue
				}
				assert.NotContains(t, condCtx, key)
			}
		})
	}
}

func TestRequestConditionContextSignatureKeys(t *testing.T) {
	tests := []struct {
		name string
		// sig is the signature recorded for the request, nil for an
		// anonymous one.
		sig          *Signature
		wantAuthType string
		// wantAge is the expected s3:signatureAge in milliseconds, and
		// absent when wantNoAge is set. The request is evaluated right
		// after it is built, so the actual age may run slightly past it.
		wantAge   int64
		wantNoAge bool
	}{
		{
			name:      "an anonymous request has neither key",
			wantNoAge: true,
		},
		{
			// S3 never supplies a signature age for a header-signed
			// request, however old its X-Amz-Date is.
			name:         "a header-signed request has no signature age",
			sig:          &Signature{AuthType: AuthTypeHeader, SigningTime: time.Now().Add(-5 * time.Minute)},
			wantAuthType: "REST-HEADER",
			wantNoAge:    true,
		},
		{
			name:         "a presigned URL is aged from its signing time",
			sig:          &Signature{AuthType: AuthTypeQueryString, SigningTime: time.Now().Add(-90 * time.Second)},
			wantAuthType: "REST-QUERY-STRING",
			wantAge:      90000,
		},
		{
			name:         "a POST upload is aged from its signing time",
			sig:          &Signature{AuthType: AuthTypePost, SigningTime: time.Now().Add(-10 * time.Second)},
			wantAuthType: "POST",
			wantAge:      10000,
		},
		{
			name:         "a signature dated in the future has a negative age",
			sig:          &Signature{AuthType: AuthTypeQueryString, SigningTime: time.Now().Add(time.Minute)},
			wantAuthType: "REST-QUERY-STRING",
			wantAge:      -60000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := fiber.New()
			fctx := &fasthttp.RequestCtx{}
			fctx.Request.Header.SetMethod(fiber.MethodGet)
			fctx.Request.SetRequestURI("/bucket/object")
			ctx := app.AcquireCtx(fctx)
			defer app.ReleaseCtx(ctx)
			if tt.sig != nil {
				httpctx.ContextKeySignature.Set(ctx, *tt.sig)
			}

			condCtx := requestConditionContext(ctx, []Action{GetObjectAction})

			if tt.wantAuthType == "" {
				assert.NotContains(t, condCtx, "s3:authType")
			} else {
				assert.Equal(t, []string{tt.wantAuthType}, condCtx["s3:authType"])
			}

			if tt.wantNoAge {
				assert.NotContains(t, condCtx, "s3:signatureAge")
				return
			}
			if assert.Len(t, condCtx["s3:signatureAge"], 1) {
				age, err := strconv.ParseInt(condCtx["s3:signatureAge"][0], 10, 64)
				assert.NoError(t, err, "the age is a whole number of milliseconds")
				assert.GreaterOrEqual(t, age, tt.wantAge)
				assert.Less(t, age, tt.wantAge+5000)
			}
		})
	}
}
