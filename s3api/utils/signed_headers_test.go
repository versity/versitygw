// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
	v4 "github.com/versity/versitygw/aws/signer/v4"
	"github.com/versity/versitygw/s3err"
)

const signedHeadersTestRegion = "us-east-1"

var signedHeadersTestCreds = aws.Credentials{
	AccessKeyID:     "AKID",
	SecretAccessKey: "SECRET",
}

func TestCheckPresignedSignatureRejectsUnsignedAmzHeader(t *testing.T) {
	signedURL := buildPresignedURL(t, nil)
	ctx := fiberCtxFromURL(t, http.MethodPut, signedURL, http.Header{
		"X-Amz-Copy-Source": []string{"source/key"},
	})
	authData, err := ParsePresignedURIParts(ctx, signedHeadersTestRegion)
	require.NoError(t, err)

	err = CheckPresignedSignature(ctx, authData, signedHeadersTestCreds.SecretAccessKey)
	requireHeadersNotSigned(t, err, "x-amz-copy-source")
}

func TestCheckPresignedSignatureAllowsSignedAmzHeader(t *testing.T) {
	headers := http.Header{
		"X-Amz-Copy-Source": []string{"source/key"},
	}
	signedURL := buildPresignedURL(t, headers)
	ctx := fiberCtxFromURL(t, http.MethodPut, signedURL, headers)
	authData, err := ParsePresignedURIParts(ctx, signedHeadersTestRegion)
	require.NoError(t, err)

	err = CheckPresignedSignature(ctx, authData, signedHeadersTestCreds.SecretAccessKey)
	require.NoError(t, err)
}

func TestCheckPresignedSignatureAllowsUnsignedNonAmzHeader(t *testing.T) {
	signedURL := buildPresignedURL(t, nil)
	ctx := fiberCtxFromURL(t, http.MethodPut, signedURL, http.Header{
		"Content-Type":    []string{"text/plain"},
		"X-Custom-Header": []string{"value"},
	})
	authData, err := ParsePresignedURIParts(ctx, signedHeadersTestRegion)
	require.NoError(t, err)

	err = CheckPresignedSignature(ctx, authData, signedHeadersTestCreds.SecretAccessKey)
	require.NoError(t, err)
}

func TestCheckValidSignatureRejectsUnsignedAmzHeader(t *testing.T) {
	ctx, authData, signingTime := signedHeaderAuthCtx(t, nil, http.Header{
		"X-Amz-Tagging": []string{"a=b"},
	})

	_, err := CheckValidSignature(ctx, authData, signedHeadersTestCreds.SecretAccessKey, unsignedPayload, signingTime, 0)
	requireHeadersNotSigned(t, err, "x-amz-tagging")
}

func TestCheckValidSignatureAllowsSignedAmzHeader(t *testing.T) {
	ctx, authData, signingTime := signedHeaderAuthCtx(t, http.Header{
		"X-Amz-Tagging": []string{"a=b"},
	}, nil)

	_, err := CheckValidSignature(ctx, authData, signedHeadersTestCreds.SecretAccessKey, unsignedPayload, signingTime, 0)
	require.NoError(t, err)
}

func TestCheckValidSignatureAllowsUnsignedNonAmzHeader(t *testing.T) {
	ctx, authData, signingTime := signedHeaderAuthCtx(t, nil, http.Header{
		"Content-Type":    []string{"text/plain"},
		"X-Custom-Header": []string{"value"},
	})

	_, err := CheckValidSignature(ctx, authData, signedHeadersTestCreds.SecretAccessKey, unsignedPayload, signingTime, 0)
	require.NoError(t, err)
}

func TestCheckPresignedSignatureRejectsUnsignedAmzHeaderPattern(t *testing.T) {
	signedURL := buildPresignedURL(t, nil)
	ctx := fiberCtxFromURL(t, http.MethodPut, signedURL, http.Header{
		"X-Amz-Some-Other-Header": []string{"value"},
	})
	authData, err := ParsePresignedURIParts(ctx, signedHeadersTestRegion)
	require.NoError(t, err)

	err = CheckPresignedSignature(ctx, authData, signedHeadersTestCreds.SecretAccessKey)
	requireHeadersNotSigned(t, err, "x-amz-some-other-header")
}

func TestCheckValidSignatureRejectsUnsignedAmzHeaderPattern(t *testing.T) {
	ctx, authData, signingTime := signedHeaderAuthCtx(t, nil, http.Header{
		"X-Amz-Some-Other-Header": []string{"value"},
	})

	_, err := CheckValidSignature(ctx, authData, signedHeadersTestCreds.SecretAccessKey, unsignedPayload, signingTime, 0)
	requireHeadersNotSigned(t, err, "x-amz-some-other-header")
}

func buildPresignedURL(t *testing.T, headers http.Header) string {
	t.Helper()

	req, err := http.NewRequest(http.MethodPut, "http://example.com/bucket/key?X-Amz-Expires=600", nil)
	require.NoError(t, err)
	req.Header = headers.Clone()
	if req.Header == nil {
		req.Header = make(http.Header)
	}

	signer := v4.NewSigner()
	signedURL, _, _, err := signer.PresignHTTP(
		context.Background(),
		signedHeadersTestCreds,
		req,
		unsignedPayload,
		service,
		signedHeadersTestRegion,
		time.Now().UTC(),
		nil,
		func(options *v4.SignerOptions) {
			options.DisableURIPathEscaping = true
		},
	)
	require.NoError(t, err)

	return signedURL
}

func signedHeaderAuthCtx(t *testing.T, signedHeaders, extraHeaders http.Header) (*fiber.Ctx, AuthData, time.Time) {
	t.Helper()

	signingTime := time.Now().UTC()
	req, err := http.NewRequest(http.MethodPut, "http://example.com/bucket/key", nil)
	require.NoError(t, err)
	req.Header = signedHeaders.Clone()
	if req.Header == nil {
		req.Header = make(http.Header)
	}

	signer := v4.NewSigner()
	_, err = signer.SignHTTP(
		context.Background(),
		signedHeadersTestCreds,
		req,
		unsignedPayload,
		service,
		signedHeadersTestRegion,
		signingTime,
		nil,
		func(options *v4.SignerOptions) {
			options.DisableURIPathEscaping = true
		},
	)
	require.NoError(t, err)

	headers := req.Header.Clone()
	for key, values := range extraHeaders {
		for _, value := range values {
			headers.Add(key, value)
		}
	}

	ctx := fiberCtxFromURL(t, http.MethodPut, req.URL.String(), headers)
	authData, err := ParseAuthorization(ctx.Get("Authorization"))
	require.NoError(t, err)

	return ctx, authData, signingTime
}

func fiberCtxFromURL(t *testing.T, method, rawURL string, headers http.Header) *fiber.Ctx {
	t.Helper()

	parsedURL, err := url.Parse(rawURL)
	require.NoError(t, err)

	app := fiber.New()
	ctx := app.AcquireCtx(&fasthttp.RequestCtx{})
	t.Cleanup(func() {
		app.ReleaseCtx(ctx)
	})

	ctx.Request().Header.SetMethod(method)
	ctx.Request().SetRequestURI(parsedURL.RequestURI())
	ctx.Request().Header.SetHost(parsedURL.Host)
	for key, values := range headers {
		for _, value := range values {
			ctx.Request().Header.Add(key, value)
		}
	}

	return ctx
}

func requireHeadersNotSigned(t *testing.T, err error, expected string) {
	t.Helper()

	require.Error(t, err)
	serr, ok := err.(s3err.HeadersNotSignedError)
	require.Truef(t, ok, "expected HeadersNotSignedError, got %T", err)
	require.Equal(t, "AccessDenied", serr.Code)
	require.Equal(t, expected, serr.HeadersNotSigned)
}
