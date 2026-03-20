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

package middlewares

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
)

// chainHandlers mimics controllers.ProcessHandlers: it calls each handler in
// sequence and stops on the first error. AuthorizePostObject (like all
// versitygw middlewares) returns nil without calling c.Next(), so they must
// be chained explicitly rather than relying on fiber's c.Next() mechanism.
func chainHandlers(handlers ...fiber.Handler) fiber.Handler {
	return func(c *fiber.Ctx) error {
		for _, h := range handlers {
			if err := h(c); err != nil {
				return err
			}
		}
		return nil
	}
}

// postObjectTestApp creates a fiber app that chains AuthorizePostObject with
// the provided follow-up handler on POST /:bucket.
func postObjectTestApp(root RootUserConfig, region string, next fiber.Handler) *fiber.App {
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if apiErr, ok := err.(s3err.APIError); ok {
				return c.Status(apiErr.HTTPStatusCode).SendString(apiErr.Code)
			}
			return c.Status(500).SendString(err.Error())
		},
	})
	app.Post("/:bucket", chainHandlers(AuthorizePostObject(root, nil, region), next))
	return app
}

// buildMultipartBody returns a multipart/form-data body and its boundary.
// The given fields are written as form fields; fileContent is written as the
// "file" part.
func buildMultipartBody(t *testing.T, fields map[string]string, fileContent string) ([]byte, string) {
	t.Helper()

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	for key, value := range fields {
		assert.NoError(t, w.WriteField(key, value))
	}

	fw, err := w.CreateFormFile("file", "upload.bin")
	assert.NoError(t, err)
	_, err = io.WriteString(fw, fileContent)
	assert.NoError(t, err)

	assert.NoError(t, w.Close())
	return buf.Bytes(), w.Boundary()
}

// encodePOSTPolicy encodes a minimal valid policy expiring 15 minutes in the
// future with the supplied conditions.
func encodePOSTPolicy(t *testing.T, conditions []any) string {
	t.Helper()

	policy := map[string]any{
		"expiration": time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339),
		"conditions": conditions,
	}
	b, err := json.Marshal(policy)
	assert.NoError(t, err)
	return base64.StdEncoding.EncodeToString(b)
}

func makePostRequest(t *testing.T, body []byte, boundary string) *http.Request {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, "/mybucket", bytes.NewReader(body))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", fmt.Sprintf("multipart/form-data; boundary=%s", boundary))
	// Set both the header and the int64 field: app.Test() serialises the
	// request via req.Write() which uses req.ContentLength; fasthttp then
	// re-reads it as the Content-Length header.
	req.ContentLength = int64(len(body))
	return req
}

// TestAuthorizePostObject_AnonymousRequest verifies that a POST with no auth
// fields succeeds: PostObjectResult is populated and ContextKeyAuthenticated
// is NOT set.
func TestAuthorizePostObject_AnonymousRequest(t *testing.T) {
	var (
		gotResult        PostObjectResult
		gotAuthenticated bool
	)

	app := postObjectTestApp(
		RootUserConfig{Access: "root", Secret: "rootsecret"},
		"us-east-1",
		func(c *fiber.Ctx) error {
			gotResult = utils.ContextKeyObjectPostResult.Get(c).(PostObjectResult)
			gotAuthenticated = utils.ContextKeyAuthenticated.IsSet(c)
			return c.SendStatus(http.StatusOK)
		},
	)

	body, boundary := buildMultipartBody(t, map[string]string{
		"key": "uploads/photo.jpg",
	}, "file-content")

	resp, err := app.Test(makePostRequest(t, body, boundary))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "uploads/photo.jpg", gotResult.Fields["key"])
	assert.False(t, gotAuthenticated, "anonymous request must not set ContextKeyAuthenticated")
}

// TestAuthorizePostObject_AnonymousRequest_SetsPostObjectResult verifies that
// ContentType and FileRdr are populated for an anonymous upload.
func TestAuthorizePostObject_AnonymousRequest_SetsPostObjectResult(t *testing.T) {
	var gotResult PostObjectResult

	app := postObjectTestApp(
		RootUserConfig{Access: "root", Secret: "rootsecret"},
		"us-east-1",
		func(c *fiber.Ctx) error {
			gotResult = utils.ContextKeyObjectPostResult.Get(c).(PostObjectResult)
			return c.SendStatus(http.StatusOK)
		},
	)

	body, boundary := buildMultipartBody(t, map[string]string{
		"key":          "uploads/hello.txt",
		"Content-Type": "text/plain",
	}, "hello world")

	resp, err := app.Test(makePostRequest(t, body, boundary))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "uploads/hello.txt", gotResult.Fields["key"])
	assert.NotNil(t, gotResult.FileRdr)
}

// TestAuthorizePostObject_SignedRequest verifies that a correctly signed POST
// succeeds and sets ContextKeyAuthenticated.
func TestAuthorizePostObject_SignedRequest(t *testing.T) {
	const (
		region    = "us-east-1"
		accessKey = "testaccess"
		secretKey = "testsecret"
	)

	now := time.Now().UTC()
	dateShort := now.Format("20060102")
	dateLong := now.Format("20060102T150405Z")

	credential := fmt.Sprintf("%s/%s/%s/s3/aws4_request", accessKey, dateShort, region)
	policyB64 := encodePOSTPolicy(t, []any{
		map[string]string{"bucket": "mybucket"},
		[]any{"starts-with", "$key", "uploads/"},
	})
	sig, err := utils.SignPostPolicy(policyB64, dateShort, region, secretKey)
	assert.NoError(t, err)

	var gotAuthenticated bool

	app := postObjectTestApp(
		RootUserConfig{Access: accessKey, Secret: secretKey},
		region,
		func(c *fiber.Ctx) error {
			gotAuthenticated = utils.ContextKeyAuthenticated.IsSet(c)
			return c.SendStatus(http.StatusOK)
		},
	)

	body, boundary := buildMultipartBody(t, map[string]string{
		"key":              "uploads/photo.jpg",
		"policy":           policyB64,
		"x-amz-algorithm":  "AWS4-HMAC-SHA256",
		"x-amz-credential": credential,
		"x-amz-date":       dateLong,
		"x-amz-signature":  sig,
	}, "file-content")

	resp, err := app.Test(makePostRequest(t, body, boundary))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, gotAuthenticated, "signed request must set ContextKeyAuthenticated")
}

// TestAuthorizePostObject_SignedRequest_WrongSignature verifies that a signed
// POST with a bad signature is rejected.
func TestAuthorizePostObject_SignedRequest_WrongSignature(t *testing.T) {
	const (
		region    = "us-east-1"
		accessKey = "testaccess"
		secretKey = "testsecret"
	)

	now := time.Now().UTC()
	dateShort := now.Format("20060102")
	dateLong := now.Format("20060102T150405Z")

	credential := fmt.Sprintf("%s/%s/%s/s3/aws4_request", accessKey, dateShort, region)
	policyB64 := encodePOSTPolicy(t, []any{
		map[string]string{"bucket": "mybucket"},
	})

	app := postObjectTestApp(
		RootUserConfig{Access: accessKey, Secret: secretKey},
		region,
		func(c *fiber.Ctx) error { return c.SendStatus(http.StatusOK) },
	)

	body, boundary := buildMultipartBody(t, map[string]string{
		"key":              "uploads/photo.jpg",
		"policy":           policyB64,
		"x-amz-algorithm":  "AWS4-HMAC-SHA256",
		"x-amz-credential": credential,
		"x-amz-date":       dateLong,
		"x-amz-signature":  "baadsignature00000000000",
	}, "file-content")

	resp, err := app.Test(makePostRequest(t, body, boundary))
	assert.NoError(t, err)
	assert.Equal(t, s3err.GetAPIError(s3err.ErrSignatureDoesNotMatch).HTTPStatusCode, resp.StatusCode)
}

// TestAuthorizePostObject_PartialAuthFields_ReturnsError verifies that
// providing only some auth fields (e.g. x-amz-algorithm only) is rejected.
func TestAuthorizePostObject_PartialAuthFields_ReturnsError(t *testing.T) {
	app := postObjectTestApp(
		RootUserConfig{Access: "root", Secret: "rootsecret"},
		"us-east-1",
		func(c *fiber.Ctx) error { return c.SendStatus(http.StatusOK) },
	)

	// Only algorithm is provided — credential, date, policy, signature absent.
	body, boundary := buildMultipartBody(t, map[string]string{
		"key":             "uploads/photo.jpg",
		"x-amz-algorithm": "AWS4-HMAC-SHA256",
	}, "file-content")

	resp, err := app.Test(makePostRequest(t, body, boundary))
	assert.NoError(t, err)
	assert.NotEqual(t, http.StatusOK, resp.StatusCode)
}

// TestAuthorizePostObject_InvalidContentType_ReturnsError verifies that a
// non-multipart Content-Type is rejected.
func TestAuthorizePostObject_InvalidContentType_ReturnsError(t *testing.T) {
	app := postObjectTestApp(
		RootUserConfig{Access: "root", Secret: "rootsecret"},
		"us-east-1",
		func(c *fiber.Ctx) error { return c.SendStatus(http.StatusOK) },
	)

	req, err := http.NewRequest(http.MethodPost, "/mybucket", strings.NewReader("body"))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", "4")

	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, s3err.GetAPIError(s3err.ErrPreconditionFailed).HTTPStatusCode, resp.StatusCode)
}
