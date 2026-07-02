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

package iamapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/gofiber/fiber/v3"
	vgwv4 "github.com/versity/versitygw/aws/signer/v4"
	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/iamapi/internal/iammiddleware"
	"github.com/versity/versitygw/internal/sigv4auth"
)

var testRoot = RootCredentials{
	Access: "AKID",
	Secret: "SECRET",
}

func TestVerifyIAMAuthAcceptsSignedGet(t *testing.T) {
	app := newIAMAuthTestApp(t)
	req := signedIAMRequest(t, http.MethodGet, "http://example.com/?Action=ListUsers&Version=2010-05-08", nil, testRoot.Secret)

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", resp.StatusCode, http.StatusOK, readBody(t, resp))
	}
}

func TestVerifyIAMAuthAcceptsSignedPost(t *testing.T) {
	app := newIAMAuthTestApp(t)
	body := []byte("Action=CreateUser&UserName=test-user&Version=2010-05-08")
	req := signedIAMRequest(t, http.MethodPost, "http://example.com/", body, testRoot.Secret)
	req.Header.Set("Content-Type", fiber.MIMEApplicationForm)

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", resp.StatusCode, http.StatusOK, readBody(t, resp))
	}
}

func TestVerifyIAMAuthAcceptsUnsignedNonHostHeaders(t *testing.T) {
	app := newIAMAuthTestApp(t)
	req := signedIAMRequest(t, http.MethodGet, "http://example.com/?Action=ListUsers&Version=2010-05-08", nil, testRoot.Secret)
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("X-Amz-Copy-Source", "source-bucket/source-key")
	req.Header.Set("X-Amz-Content-Sha256", "invalid_sha256")
	req.Header.Set("X-Amz-Tagging", "key=value")
	req.Header.Set("X-Custom-Header", "value")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", resp.StatusCode, http.StatusOK, readBody(t, resp))
	}
}

func TestVerifyIAMAuthRejectsUnsignedHost(t *testing.T) {
	app := newIAMAuthTestApp(t)
	req := signedIAMRequest(t, http.MethodGet, "http://example.com/?Action=ListUsers&Version=2010-05-08", nil, testRoot.Secret)
	authorization := req.Header.Get("Authorization")
	withoutHost := strings.Replace(authorization, "SignedHeaders=host;", "SignedHeaders=", 1)
	if withoutHost == authorization {
		t.Fatalf("Authorization does not contain a signed host header: %q", authorization)
	}
	req.Header.Set("Authorization", withoutHost)

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	want := iamerr.GetAPIError(iamerr.ErrMissingHostSignedHeader)
	requireIAMError(t, resp, want.HTTPStatusCode, string(want.Type), want.Code, want.Message)
}

func TestVerifyIAMAuthAcceptsQuerySignedGet(t *testing.T) {
	app := newIAMAuthTestApp(t)
	req := querySignedIAMRequest(t, http.MethodGet, "http://example.com/?Action=ListUsers&Version=2010-05-08", nil, testRoot.Secret, iammiddleware.SigningRegion, time.Now().UTC())

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", resp.StatusCode, http.StatusOK, readBody(t, resp))
	}
}

func TestVerifyIAMAuthRejectsMissingQueryParameters(t *testing.T) {
	testCases := []struct {
		name      string
		parameter string
		want      iamerr.Error
	}{
		{
			name:      "algorithm",
			parameter: sigv4auth.QueryAlgorithm,
			want:      iamerr.GetAPIError(iamerr.ErrMissingAuthenticationToken),
		},
		{
			name:      "credential",
			parameter: sigv4auth.QueryCredential,
			want:      iamerr.IncompleteSignatureMissingQueryParameter(sigv4auth.QueryCredential),
		},
		{
			name:      "date",
			parameter: sigv4auth.QueryDate,
			want:      iamerr.IncompleteSignatureMissingQueryParameter(sigv4auth.QueryDate),
		},
		{
			name:      "signed headers",
			parameter: sigv4auth.QuerySignedHeaders,
			want:      iamerr.IncompleteSignatureMissingQueryParameter(sigv4auth.QuerySignedHeaders),
		},
		{
			name:      "signature",
			parameter: sigv4auth.QuerySignature,
			want:      iamerr.IncompleteSignatureMissingQueryParameter(sigv4auth.QuerySignature),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			app := newIAMAuthTestApp(t)
			req := querySignedIAMRequest(t, http.MethodGet, "http://example.com/?Action=ListUsers&Version=2010-05-08", nil, testRoot.Secret, iammiddleware.SigningRegion, time.Now().UTC())
			query := req.URL.Query()
			query.Del(testCase.parameter)
			req.URL.RawQuery = query.Encode()

			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("app.Test: %v", err)
			}

			want := testCase.want
			requireIAMError(t, resp, want.HTTPStatusCode, string(want.Type), want.Code, want.Message)
		})
	}
}

func TestVerifyIAMAuthRejectsUnsupportedQueryAlgorithm(t *testing.T) {
	for _, algorithm := range []string{"AWS4-SHA256", sigv4auth.AlgorithmECDSAP256SHA256} {
		t.Run(algorithm, func(t *testing.T) {
			app := newIAMAuthTestApp(t)
			req := querySignedIAMRequest(t, http.MethodGet, "http://example.com/?Action=ListUsers&Version=2010-05-08", nil, testRoot.Secret, iammiddleware.SigningRegion, time.Now().UTC())
			query := req.URL.Query()
			query.Set(sigv4auth.QueryAlgorithm, algorithm)
			req.URL.RawQuery = query.Encode()

			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("app.Test: %v", err)
			}

			want := iamerr.GetAPIError(iamerr.ErrUnsupportedQueryAlgorithm)
			requireIAMError(t, resp, want.HTTPStatusCode, string(want.Type), want.Code, want.Message)
		})
	}
}

func TestVerifyIAMAuthRejectsInvalidQueryDate(t *testing.T) {
	app := newIAMAuthTestApp(t)
	req := querySignedIAMRequest(t, http.MethodGet, "http://example.com/?Action=ListUsers&Version=2010-05-08", nil, testRoot.Secret, iammiddleware.SigningRegion, time.Now().UTC())
	const invalidDate = "03032006"
	query := req.URL.Query()
	query.Set(sigv4auth.QueryDate, invalidDate)
	req.URL.RawQuery = query.Encode()

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	want := iamerr.IncompleteSignatureInvalidXAmzDate(invalidDate)
	requireIAMError(t, resp, want.HTTPStatusCode, string(want.Type), want.Code, want.Message)
}

func TestVerifyIAMAuthRejectsQueryCredentialDateMismatch(t *testing.T) {
	app := newIAMAuthTestApp(t)
	req := querySignedIAMRequest(t, http.MethodGet, "http://example.com/?Action=ListUsers&Version=2010-05-08", nil, testRoot.Secret, iammiddleware.SigningRegion, time.Now().UTC())
	query := req.URL.Query()
	credential := strings.Split(query.Get(sigv4auth.QueryCredential), "/")
	credential[1] = "20000101"
	query.Set(sigv4auth.QueryCredential, strings.Join(credential, "/"))
	req.URL.RawQuery = query.Encode()

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	want := iamerr.GetAPIError(iamerr.ErrInvalidCredentialDate)
	requireIAMError(t, resp, want.HTTPStatusCode, string(want.Type), want.Code, want.Message)
}

func TestVerifyIAMAuthQueryCredentialParsingMatchesHeaderAuth(t *testing.T) {
	testCases := []struct {
		name       string
		credential string
		want       iamerr.Error
	}{
		{
			name:       "malformed",
			credential: "access/hello/world",
			want:       iamerr.IncompleteSignatureMalformedCredential("access/hello/world"),
		},
		{
			name:       "invalid terminal",
			credential: "access/20260627/us-east-1/iam/aws_request",
			want:       iamerr.GetAPIError(iamerr.ErrInvalidTerminal),
		},
		{
			name:       "incorrect service",
			credential: "access/20260627/us-east-1/ec2/aws4_request",
			want:       iamerr.GetAPIError(iamerr.ErrIncorrectService),
		},
		{
			name:       "invalid credential date",
			credential: "access/3223423234/us-east-1/iam/aws4_request",
			want:       iamerr.GetAPIError(iamerr.ErrInvalidCredentialDate),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			app := newIAMAuthTestApp(t)
			req := querySignedIAMRequest(t, http.MethodGet, "http://example.com/?Action=ListUsers&Version=2010-05-08", nil, testRoot.Secret, iammiddleware.SigningRegion, time.Now().UTC())
			query := req.URL.Query()
			query.Set(sigv4auth.QueryCredential, testCase.credential)
			req.URL.RawQuery = query.Encode()

			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("app.Test: %v", err)
			}

			want := testCase.want
			requireIAMError(t, resp, want.HTTPStatusCode, string(want.Type), want.Code, want.Message)
		})
	}
}

func TestVerifyIAMAuthRejectsQuerySignatureMismatch(t *testing.T) {
	app := newIAMAuthTestApp(t)
	req := querySignedIAMRequest(t, http.MethodGet, "http://example.com/?Action=ListUsers&Version=2010-05-08", nil, testRoot.Secret+"-wrong", iammiddleware.SigningRegion, time.Now().UTC())

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	requireIAMError(t, resp, http.StatusForbidden, "Sender", "SignatureDoesNotMatch", "The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details.")
}

func TestVerifyIAMAuthRejectsUnsignedQueryParameter(t *testing.T) {
	app := newIAMAuthTestApp(t)
	req := querySignedIAMRequest(t, http.MethodGet, "http://example.com/?Action=ListUsers&Version=2010-05-08", nil, testRoot.Secret, iammiddleware.SigningRegion, time.Now().UTC())
	query := req.URL.Query()
	query.Set("ExtraParam", "value")
	req.URL.RawQuery = query.Encode()

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	want := iamerr.GetAPIError(iamerr.ErrSignatureDoesNotMatch)
	requireIAMError(t, resp, want.HTTPStatusCode, string(want.Type), want.Code, want.Message)
}

func TestVerifyIAMAuthRejectsQueryWrongCredentialRegion(t *testing.T) {
	app := newIAMAuthTestApp(t)
	req := querySignedIAMRequest(t, http.MethodGet, "http://example.com/?Action=ListUsers&Version=2010-05-08", nil, testRoot.Secret, "us-west-2", time.Now().UTC())

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	requireIAMError(t, resp, http.StatusForbidden, "Sender", "SignatureDoesNotMatch", "Credential should be scoped to a valid region. ")
}

func TestVerifyIAMAuthRejectsMissingAuthorization(t *testing.T) {
	app := newIAMAuthTestApp(t)

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/?Action=ListUsers&Version=2010-05-08", nil))
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	requireIAMError(t, resp, http.StatusForbidden, "Sender", "MissingAuthenticationToken", "Request is missing Authentication Token")
}

func TestVerifyIAMAuthRejectsUnrecognizedAuthorizationHeaders(t *testing.T) {
	testCases := []struct {
		name          string
		authorization string
	}{
		{
			name:          "invalid header",
			authorization: "invalid_header",
		},
		{
			name:          "unsupported signature version",
			authorization: "AWS2-HMAC-SHA1 Credential=AKID/20260701/us-east-1/iam/aws4_request,SignedHeaders=host;x-amz-date,Signature=signature",
		},
		{
			name:          "ECDSA algorithm",
			authorization: sigv4auth.AlgorithmECDSAP256SHA256 + " Credential=AKID/20260701/us-east-1/iam/aws4_request,SignedHeaders=host;x-amz-date,Signature=signature",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			app := newIAMAuthTestApp(t)
			req := signedIAMRequest(t, http.MethodGet, "http://example.com/?Action=ListUsers&Version=2010-05-08", nil, testRoot.Secret)
			req.Header.Set("Authorization", testCase.authorization)

			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("app.Test: %v", err)
			}

			want := iamerr.GetAPIError(iamerr.ErrMissingAuthenticationToken)
			requireIAMError(t, resp, want.HTTPStatusCode, string(want.Type), want.Code, want.Message)
		})
	}
}

func TestVerifyIAMAuthRejectsMalformedAuthorizationComponent(t *testing.T) {
	app := newIAMAuthTestApp(t)
	req := signedIAMRequest(t, http.MethodGet, "http://example.com/?Action=ListUsers&Version=2010-05-08", nil, testRoot.Secret)
	const component = "SignedHeaders-Content-Length"
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKID/20260701/us-east-1/iam/aws4_request,"+component+",Signature=signature")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	want := iamerr.IncompleteSignatureMalformedComponent(component)
	requireIAMError(t, resp, want.HTTPStatusCode, string(want.Type), want.Code, want.Message)
}

func TestVerifyIAMAuthRejectsMissingDate(t *testing.T) {
	app := newIAMAuthTestApp(t)
	req := signedIAMRequest(t, http.MethodGet, "http://example.com/?Action=ListUsers&Version=2010-05-08", nil, testRoot.Secret)
	authorization := req.Header.Get("Authorization")
	req.Header.Del("X-Amz-Date")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	want := iamerr.IncompleteSignatureMissingDate(authorization)
	requireIAMError(t, resp, want.HTTPStatusCode, string(want.Type), want.Code, want.Message)
}

func TestVerifyIAMAuthRejectsInvalidDate(t *testing.T) {
	app := newIAMAuthTestApp(t)
	req := signedIAMRequest(t, http.MethodGet, "http://example.com/?Action=ListUsers&Version=2010-05-08", nil, testRoot.Secret)
	const invalidDate = "03032006"
	req.Header.Set("X-Amz-Date", invalidDate)

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	want := iamerr.IncompleteSignatureInvalidXAmzDate(invalidDate)
	requireIAMError(t, resp, want.HTTPStatusCode, string(want.Type), want.Code, want.Message)
}

func TestVerifyIAMAuthRejectsSignatureMismatch(t *testing.T) {
	app := newIAMAuthTestApp(t)
	req := signedIAMRequest(t, http.MethodGet, "http://example.com/?Action=ListUsers&Version=2010-05-08", nil, testRoot.Secret+"-wrong")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	requireIAMError(t, resp, http.StatusForbidden, "Sender", "SignatureDoesNotMatch", "The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details.")
}

func TestVerifyIAMAuthRejectsWrongCredentialRegion(t *testing.T) {
	app := newIAMAuthTestApp(t)
	req := signedIAMRequestWithRegion(t, http.MethodGet, "http://example.com/?Action=ListUsers&Version=2010-05-08", nil, testRoot.Secret, "us-west-2")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	requireIAMError(t, resp, http.StatusForbidden, "Sender", "SignatureDoesNotMatch", "Credential should be scoped to a valid region. ")
}

func TestVerifyIAMAuthRejectsCredentialDateMismatch(t *testing.T) {
	app := newIAMAuthTestApp(t)
	req := signedIAMRequest(t, http.MethodGet, "http://example.com/?Action=ListUsers&Version=2010-05-08", nil, testRoot.Secret)
	authorization := req.Header.Get("Authorization")
	regExp := regexp.MustCompile("Credential=[^,]+,")
	req.Header.Set("Authorization", regExp.ReplaceAllString(authorization, "Credential=access/20000101/us-east-1/iam/aws4_request,"))

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	want := iamerr.GetAPIError(iamerr.ErrInvalidCredentialDate)
	requireIAMError(t, resp, want.HTTPStatusCode, string(want.Type), want.Code, want.Message)
}

func TestVerifyIAMAuthRejectsMalformedCredential(t *testing.T) {
	app := newIAMAuthTestApp(t)
	req := signedIAMRequest(t, http.MethodGet, "http://example.com/?Action=ListUsers&Version=2010-05-08", nil, testRoot.Secret)
	const credential = "access/32234/us-east-1/iam/extra/things"
	authHdr := req.Header.Get("Authorization")
	regExp := regexp.MustCompile("Credential=[^,]+,")
	req.Header.Set("Authorization", regExp.ReplaceAllString(authHdr, "Credential="+credential+","))

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	requireIAMError(t, resp, http.StatusBadRequest, "Sender", "IncompleteSignature", "Credential must have exactly 5 slash-delimited elements, e.g. keyid/date/region/service/term, got '"+credential+"'")
}

func TestVerifyIAMAuthRejectsInvalidCredentialTerminal(t *testing.T) {
	app := newIAMAuthTestApp(t)
	req := signedIAMRequest(t, http.MethodGet, "http://example.com/?Action=ListUsers&Version=2010-05-08", nil, testRoot.Secret)
	authHdr := req.Header.Get("Authorization")
	regExp := regexp.MustCompile("Credential=[^,]+,")
	req.Header.Set("Authorization", regExp.ReplaceAllString(authHdr, "Credential=access/32234/us-east-1/iam/aws_request,"))

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	want := iamerr.GetAPIError(iamerr.ErrInvalidTerminal)
	requireIAMError(t, resp, want.HTTPStatusCode, string(want.Type), want.Code, want.Message)
}

func TestValidateDateAtRejectsFutureDate(t *testing.T) {
	serverTime := time.Date(2026, time.June, 27, 20, 18, 14, 0, time.UTC)
	requestTime := time.Date(2026, time.July, 2, 20, 18, 13, 0, time.UTC)

	err := iammiddleware.ValidateDateAt(requestTime, serverTime)
	want := iamerr.SignatureDoesNotMatchNotYetCurrent(requestTime, serverTime, 15*time.Minute)
	if err != want {
		t.Fatalf("ValidateDateAt() error = %#v, want %#v", err, want)
	}
}

func TestValidateDateAtRejectsPastDate(t *testing.T) {
	serverTime := time.Date(2026, time.June, 27, 20, 19, 55, 0, time.UTC)
	requestTime := time.Date(2026, time.June, 22, 20, 19, 54, 0, time.UTC)

	err := iammiddleware.ValidateDateAt(requestTime, serverTime)
	want := iamerr.SignatureDoesNotMatchExpired(requestTime, serverTime, 15*time.Minute)
	if err != want {
		t.Fatalf("ValidateDateAt() error = %#v, want %#v", err, want)
	}
}

func newIAMAuthTestApp(t *testing.T) *fiber.App {
	t.Helper()

	app := fiber.New(fiber.Config{ErrorHandler: iammiddleware.GlobalErrorHandler})
	app.All("/", ProcessHandlers(
		func(ctx fiber.Ctx) (*Response, error) {
			return &Response{Status: http.StatusOK}, nil
		},
		iammiddleware.VerifyIAMAuth(&testRoot),
	))
	return app
}

func signedIAMRequest(t *testing.T, method, target string, body []byte, secret string) *http.Request {
	t.Helper()

	return signedIAMRequestWithRegion(t, method, target, body, secret, iammiddleware.SigningRegion)
}

func signedIAMRequestWithRegion(t *testing.T, method, target string, body []byte, secret, region string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	hash := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(hash[:])

	signer := awsv4.NewSigner()
	if err := signer.SignHTTP(
		context.Background(),
		aws.Credentials{AccessKeyID: testRoot.Access, SecretAccessKey: secret},
		req,
		payloadHash,
		"iam",
		region,
		time.Now().UTC(),
	); err != nil {
		t.Fatalf("sign request: %v", err)
	}

	return req
}

func querySignedIAMRequest(t *testing.T, method, target string, body []byte, secret, region string, signingTime time.Time) *http.Request {
	t.Helper()

	req := httptest.NewRequest(method, target, bytes.NewReader(body))

	hash := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(hash[:])

	signer := vgwv4.NewSigner()
	signedURL, signedHeaders, _, err := signer.PresignHTTP(
		context.Background(),
		aws.Credentials{AccessKeyID: testRoot.Access, SecretAccessKey: secret},
		req,
		payloadHash,
		"iam",
		region,
		signingTime,
		nil,
	)
	if err != nil {
		t.Fatalf("presign request: %v", err)
	}

	signedReq := httptest.NewRequest(method, signedURL, bytes.NewReader(body))
	for key, values := range signedHeaders {
		for _, value := range values {
			signedReq.Header.Add(key, value)
		}
	}

	return signedReq
}

func requireIAMError(t *testing.T, resp *http.Response, status int, errType, code, message string) {
	t.Helper()

	body := readBody(t, resp)
	if resp.StatusCode != status {
		t.Fatalf("status = %d, want %d; body=%s", resp.StatusCode, status, body)
	}

	var errResp struct {
		XMLName xml.Name `xml:"ErrorResponse"`
		Error   struct {
			Type    string
			Code    string
			Message string
		}
		RequestID string `xml:"RequestId"`
	}
	if err := xml.Unmarshal([]byte(body), &errResp); err != nil {
		t.Fatalf("unmarshal IAM error: %v\n%s", err, body)
	}

	wantNamespace := iamerr.Namespace
	if code == "InvalidAction" {
		wantNamespace = iamerr.AWSFaultNamespace
	}
	if errResp.XMLName.Space != wantNamespace {
		t.Fatalf("namespace = %q, want %q", errResp.XMLName.Space, wantNamespace)
	}
	if errResp.Error.Type != errType || errResp.Error.Code != code || errResp.Error.Message != message {
		t.Fatalf("error = %#v, want type=%q code=%q message=%q", errResp.Error, errType, code, message)
	}
	if errResp.RequestID == "" {
		t.Fatal("missing RequestId")
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(body)
}
