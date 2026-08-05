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

package debuglogger

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"
)

func TestRedact(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
		want  string
	}{
		{name: "Authorization header", key: "Authorization", value: "AWS4-HMAC-SHA256 ...", want: redactedValue},
		{name: "header name matched case-insensitively", key: "AUTHORIZATION", value: "secret", want: redactedValue},
		{name: "security token", key: "X-Amz-Security-Token", value: "secret", want: redactedValue},
		{name: "presigned request signature", key: "X-Amz-Signature", value: "deadbeef", want: redactedValue},
		{name: "presigned request signature matched case-insensitively", key: "x-amz-signature", value: "deadbeef", want: redactedValue},
		{name: "presigned request credential", key: "X-Amz-Credential", value: "AKIAEXAMPLE/20260101/us-east-1/s3/aws4_request", want: redactedValue},
		{name: "web identity token form/query field", key: "WebIdentityToken", value: "secret", want: redactedValue},
		{name: "SSE-C customer key header", key: "X-Amz-Server-Side-Encryption-Customer-Key", value: "base64key==", want: redactedValue},
		{name: "SSE-C copy-source customer key header", key: "X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key", value: "base64key==", want: redactedValue},
		{name: "SSE-C customer key MD5 untouched (checksum, not a secret)", key: "X-Amz-Server-Side-Encryption-Customer-Key-MD5", value: "deadbeef==", want: "deadbeef=="},
		{name: "unrelated header untouched", key: "Content-Type", value: "application/xml", want: "application/xml"},
		{name: "unrelated query param untouched", key: "Action", value: "AssumeRoleWithWebIdentity", want: "AssumeRoleWithWebIdentity"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := redact(tt.key, tt.value); got != tt.want {
				t.Errorf("redact(%q, %q) = %q, want %q", tt.key, tt.value, got, tt.want)
			}
		})
	}
}

func TestDebugRedactHonorsUnsafeLevel(t *testing.T) {
	defer SetLevel(LevelSilent)

	SetLevel(LevelDebug)
	if got := debugRedact("Authorization", "secret-sig"); got != redactedValue {
		t.Errorf("debugRedact at LevelDebug = %q, want %q", got, redactedValue)
	}

	SetLevel(LevelUnsafe)
	if got := debugRedact("Authorization", "secret-sig"); got != "secret-sig" {
		t.Errorf("debugRedact at LevelUnsafe = %q, want unmasked value", got)
	}
}

func TestRedactedQueryString(t *testing.T) {
	args := &fasthttp.Args{}
	args.Parse("Action=AssumeRoleWithWebIdentity&WebIdentityToken=super-secret-jwt")

	got := RedactedQueryString(args)

	if strings.Contains(got, "super-secret-jwt") {
		t.Fatalf("RedactedQueryString leaked the token: %q", got)
	}
	if !strings.Contains(got, "Action=AssumeRoleWithWebIdentity") {
		t.Errorf("RedactedQueryString dropped a non-sensitive param: %q", got)
	}
	if !strings.Contains(got, url.QueryEscape(redactedValue)) {
		t.Errorf("RedactedQueryString missing redaction marker: %q", got)
	}
}

func TestRedactedQueryStringEmpty(t *testing.T) {
	if got := RedactedQueryString(&fasthttp.Args{}); got != "" {
		t.Errorf("RedactedQueryString(empty) = %q, want empty string", got)
	}
}

// TestRedactedQueryStringMasksPresignedCredentials asserts that a presigned
// request's X-Amz-Signature (and X-Amz-Credential) never reach the default
// access log, since together with the rest of the (non-secret) presigned URL
// they're everything needed to replay the exact signed request until it
// expires.
func TestRedactedQueryStringMasksPresignedCredentials(t *testing.T) {
	args := &fasthttp.Args{}
	args.Parse("X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAEXAMPLE%2F20260101%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature=deadbeefcafe")

	got := RedactedQueryString(args)

	for _, secret := range []string{"deadbeefcafe", "AKIAEXAMPLE"} {
		if strings.Contains(got, secret) {
			t.Fatalf("RedactedQueryString leaked presigned credential material %q: %q", secret, got)
		}
	}
	if !strings.Contains(got, "X-Amz-Algorithm=AWS4-HMAC-SHA256") {
		t.Errorf("RedactedQueryString dropped a non-sensitive param: %q", got)
	}
}

// TestLogFiberRequestAndResponseDetailsRedactSensitiveFields sends dummy
// secrets through the request header, query, and form-body paths (plus the
// response header path) and asserts that none of them appear in the debug
// logger's captured output, only the redaction marker in their place. This
// covers a GET AssumeRoleWithWebIdentity's WebIdentityToken query parameter,
// and, in debug mode, the Authorization and X-Amz-Security-Token headers.
func TestLogFiberRequestAndResponseDetailsRedactSensitiveFields(t *testing.T) {
	const (
		dummyToken    = "dummy-web-identity-jwt"
		dummyAuth     = "AWS4-HMAC-SHA256 Credential=AKIADUMMYEXAMPLE/..."
		dummySecurity = "dummy-security-token"
	)

	app := fiber.New()
	app.Post("/", func(ctx fiber.Ctx) error {
		LogFiberRequestDetails(ctx)
		ctx.Response().Header.Set("X-Amz-Security-Token", dummySecurity)
		LogFiberResponseDetails(ctx)
		return ctx.SendString("ok")
	})

	body := "Action=AssumeRoleWithWebIdentity&WebIdentityToken=" + dummyToken
	req := httptest.NewRequest(http.MethodPost, "/?WebIdentityToken="+dummyToken, strings.NewReader(body))
	req.Header.Set("Content-Type", fiber.MIMEApplicationForm)
	req.Header.Set("Authorization", dummyAuth)
	req.Header.Set("X-Amz-Security-Token", dummySecurity)

	output := captureLogOutput(t, func() {
		if _, err := app.Test(req); err != nil {
			t.Fatalf("app.Test: %v", err)
		}
	})

	for _, secret := range []string{dummyToken, dummyAuth, dummySecurity} {
		if strings.Contains(output, secret) {
			t.Errorf("captured debug output leaked secret %q:\n%s", secret, output)
		}
	}
	if !strings.Contains(output, redactedValue) {
		t.Errorf("expected redaction marker %q in captured output:\n%s", redactedValue, output)
	}
}

// captureLogOutput redirects both fmt.Printf (via os.Stdout, used by the
// box-drawing helpers) and the standard "log" package (used for the
// per-query-arg lines) into a buffer for the duration of fn.
func captureLogOutput(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}

	origStdout := os.Stdout
	origLogOutput := log.Writer()
	os.Stdout = w
	log.SetOutput(w)
	defer func() {
		os.Stdout = origStdout
		log.SetOutput(origLogOutput)
	}()

	fn()

	w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("io.Copy: %v", err)
	}
	return buf.String()
}
