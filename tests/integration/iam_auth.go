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

package integration

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/versity/versitygw/iamapi/iamerr"
)

const (
	iamAuthPath   = "?Action=ListUsers&Version=2010-05-08"
	iamAuthRegion = "us-east-1"
)

func IAMAuth_invalid_auth_header(s *S3Conf) error {
	testName := "IAMAuth_invalid_auth_header"
	return authHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		req.Header.Set("Authorization", "invalid_header")

		return checkIAMAuthRequest(s, req, iamerr.GetAPIError(iamerr.ErrMissingAuthenticationToken))
	})
}

func IAMAuth_unsupported_signature_version(s *S3Conf) error {
	testName := "IAMAuth_unsupported_signature_version"
	return authHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		authHdr := req.Header.Get("Authorization")
		authHdr = strings.Replace(authHdr, "AWS4-HMAC-SHA256", "AWS2-HMAC-SHA1", 1)
		req.Header.Set("Authorization", authHdr)

		return checkIAMAuthRequest(s, req, iamerr.GetAPIError(iamerr.ErrMissingAuthenticationToken))
	})
}

func IAMAuth_malformed_component(s *S3Conf) error {
	testName := "IAMAuth_malformed_component"
	return authHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=access/20250912/us-east-1/iam/aws4_request,SignedHeaders-Content-Length,Signature=signature")

		return checkIAMAuthRequest(s, req, iamerr.IncompleteSignatureMalformedComponent("SignedHeaders-Content-Length"))
	})
}

func IAMAuth_missing_authorization_component(s *S3Conf) error {
	testName := "IAMAuth_missing_authorization_component"
	return authHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		testCases := []struct {
			name          string
			component     string
			authorization string
		}{
			{
				name:          "missing_credentials",
				component:     "Credential",
				authorization: "AWS4-HMAC-SHA256 missing_creds=access/20250912/us-east-1/iam/aws4_request,SignedHeaders=content-length;x-amz-date,Signature=5fb279ae552098ea7c5c807df54cdb159e74939e19449b29831552639ec34b29",
			},
			{
				name:          "missing_signedheaders",
				component:     "SignedHeaders",
				authorization: "AWS4-HMAC-SHA256 Credential=access/20250912/us-east-1/iam/aws4_request,missing=content-length;x-amz-date,Signature=5fb279ae552098ea7c5c807df54cdb159e74939e19449b29831552639ec34b29",
			},
			{
				name:          "missing_signature",
				component:     "Signature",
				authorization: "AWS4-HMAC-SHA256 Credential=access/20250912/us-east-1/iam/aws4_request,SignedHeaders=content-length;x-amz-date,missing=5fb279ae552098ea7c5c807df54cdb159e74939e19449b29831552639ec34b29",
			},
		}

		for _, testCase := range testCases {
			testReq := req.Clone(req.Context())
			testReq.Header.Set("Authorization", testCase.authorization)
			err := checkIAMAuthRequest(s, testReq, iamerr.IncompleteSignatureMissingAuthorizationComponent(testCase.component, testCase.authorization))
			if err != nil {
				return fmt.Errorf("%s: %w", testCase.name, err)
			}
		}

		return nil
	})
}

func IAMAuth_malformed_credential(s *S3Conf) error {
	testName := "IAMAuth_malformed_credential"
	return authHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		authHdr := req.Header.Get("Authorization")
		regExp := regexp.MustCompile("Credential=[^,]+,")
		hdr := regExp.ReplaceAllString(authHdr, "Credential=access/20260627/us-east-1/iam/extra/things,")
		req.Header.Set("Authorization", hdr)

		return checkIAMAuthRequest(s, req, iamerr.IncompleteSignatureMalformedCredential("access/20260627/us-east-1/iam/extra/things"))
	})
}

func IAMAuth_credentials_invalid_terminal(s *S3Conf) error {
	testName := "IAMAuth_credentials_invalid_terminal"
	return authHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		authHdr := req.Header.Get("Authorization")
		regExp := regexp.MustCompile("Credential=[^,]+,")
		hdr := regExp.ReplaceAllString(authHdr, "Credential=access/20260627/us-east-1/iam/aws_request,")
		req.Header.Set("Authorization", hdr)

		return checkIAMAuthRequest(s, req, iamerr.GetAPIError(iamerr.ErrInvalidTerminal))
	})
}

func IAMAuth_credentials_incorrect_service(s *S3Conf) error {
	testName := "IAMAuth_credentials_incorrect_service"
	return authHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		authHdr := req.Header.Get("Authorization")
		regExp := regexp.MustCompile("Credential=[^,]+,")
		hdr := regExp.ReplaceAllString(authHdr, "Credential=access/20260627/us-east-1/ec2/aws4_request,")
		req.Header.Set("Authorization", hdr)

		return checkIAMAuthRequest(s, req, iamerr.GetAPIError(iamerr.ErrIncorrectService))
	})
}

func IAMAuth_credentials_incorrect_region(s *S3Conf) error {
	testName := "IAMAuth_credentials_incorrect_region"
	cfg := iamAuthConfig(testName)
	cfg.region = "us-west-1"
	return authHandler(s, cfg, func(req *http.Request) error {
		return checkIAMAuthRequest(s, req, iamerr.GetAPIError(iamerr.ErrInvalidRegion))
	})
}

func IAMAuth_credentials_invalid_date(s *S3Conf) error {
	testName := "IAMAuth_credentials_invalid_date"
	return authHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		authHdr := req.Header.Get("Authorization")
		regExp := regexp.MustCompile("Credential=[^,]+,")
		hdr := regExp.ReplaceAllString(authHdr, "Credential=access/3223423234/us-east-1/iam/aws4_request,")
		req.Header.Set("Authorization", hdr)

		return checkIAMAuthRequest(s, req, iamerr.GetAPIError(iamerr.ErrInvalidCredentialDate))
	})
}

func IAMAuth_credentials_future_date(s *S3Conf) error {
	testName := "IAMAuth_credentials_future_date"
	cfg := iamAuthConfig(testName)
	cfg.date = time.Now().UTC().Add(5 * 24 * time.Hour)
	return authHandler(s, cfg, func(req *http.Request) error {
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		var received IAMErrorResponse
		if err := xml.Unmarshal(body, &received); err != nil {
			return err
		}
		if resp.StatusCode != http.StatusForbidden {
			return fmt.Errorf("expected response status code to be %v, instead got %v", http.StatusForbidden, resp.StatusCode)
		}
		if received.Error.Type != string(iamerr.TypeSender) {
			return fmt.Errorf("expected IAM error type to be %q, instead got %q", iamerr.TypeSender, received.Error.Type)
		}
		if received.Error.Code != "SignatureDoesNotMatch" {
			return fmt.Errorf("expected IAM error code to be %q, instead got %q", "SignatureDoesNotMatch", received.Error.Code)
		}

		messagePattern := `^Signature not yet current: [0-9]{8}T[0-9]{6}Z is still later than [0-9]{8}T[0-9]{6}Z \([0-9]{8}T[0-9]{6}Z \+ 15 min\.\)$`
		if !regexp.MustCompile(messagePattern).MatchString(received.Error.Message) {
			return fmt.Errorf("IAM error message %q does not match %q", received.Error.Message, messagePattern)
		}

		return nil
	})
}

func IAMAuth_credentials_past_date(s *S3Conf) error {
	testName := "IAMAuth_credentials_past_date"
	cfg := iamAuthConfig(testName)
	cfg.date = time.Now().UTC().Add(-5 * 24 * time.Hour)
	return authHandler(s, cfg, func(req *http.Request) error {
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		var received IAMErrorResponse
		if err := xml.Unmarshal(body, &received); err != nil {
			return err
		}
		if resp.StatusCode != http.StatusForbidden {
			return fmt.Errorf("expected response status code to be %v, instead got %v", http.StatusForbidden, resp.StatusCode)
		}
		if received.Error.Type != string(iamerr.TypeSender) {
			return fmt.Errorf("expected IAM error type to be %q, instead got %q", iamerr.TypeSender, received.Error.Type)
		}
		if received.Error.Code != "SignatureDoesNotMatch" {
			return fmt.Errorf("expected IAM error code to be %q, instead got %q", "SignatureDoesNotMatch", received.Error.Code)
		}

		messagePattern := `^Signature expired: [0-9]{8}T[0-9]{6}Z is now earlier than [0-9]{8}T[0-9]{6}Z \([0-9]{8}T[0-9]{6}Z - 15 min\.\)$`
		if !regexp.MustCompile(messagePattern).MatchString(received.Error.Message) {
			return fmt.Errorf("IAM error message %q does not match %q", received.Error.Message, messagePattern)
		}

		return nil
	})
}

func IAMAuth_credentials_non_existing_access_key(s *S3Conf) error {
	testName := "IAMAuth_credentials_non_existing_access_key"
	return authHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		accessKeyID := "a_rarely_existing_access_key_id_a7s86df78as6df89790a8sd7f"
		authHdr := req.Header.Get("Authorization")
		regExp := regexp.MustCompile("Credential=([^/]+)")
		hdr := regExp.ReplaceAllString(authHdr, "Credential="+accessKeyID)
		req.Header.Set("Authorization", hdr)

		return checkIAMAuthRequest(s, req, iamerr.GetAPIError(iamerr.ErrInvalidClientTokenID))
	})
}

func IAMAuth_missing_date_header(s *S3Conf) error {
	testName := "IAMAuth_missing_date_header"
	return authHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		req.Header.Set("X-Amz-Date", "")

		return checkIAMAuthRequest(s, req, iamerr.IncompleteSignatureMissingDate(req.Header.Get("Authorization")))
	})
}

func IAMAuth_invalid_date_header(s *S3Conf) error {
	testName := "IAMAuth_invalid_date_header"
	return authHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		const invalidDate = "03032006"
		req.Header.Set("X-Amz-Date", invalidDate)

		return checkIAMAuthRequest(s, req, iamerr.IncompleteSignatureInvalidXAmzDate(invalidDate))
	})
}

func IAMAuth_date_mismatch(s *S3Conf) error {
	testName := "IAMAuth_date_mismatch"
	return authHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		authHdr := req.Header.Get("Authorization")
		regExp := regexp.MustCompile("Credential=[^,]+,")
		hdr := regExp.ReplaceAllString(authHdr, fmt.Sprintf("Credential=%s/20000101/us-east-1/iam/aws4_request,", s.awsID))
		req.Header.Set("Authorization", hdr)

		return checkIAMAuthRequest(s, req, iamerr.GetAPIError(iamerr.ErrInvalidCredentialDate))
	})
}

func IAMAuth_invalid_sha256_payload_hash_ignored(s *S3Conf) error {
	testName := "IAMAuth_invalid_sha256_payload_hash_ignored"
	return authHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		req.Header.Set("X-Amz-Content-Sha256", "invalid_sha256")
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkIAMSuccess(resp)
	})
}

func IAMAuth_unsigned_required_header(s *S3Conf) error {
	testName := "IAMAuth_unsigned_required_header"
	return authHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		authorization := req.Header.Get("Authorization")
		authorization = strings.Replace(authorization, "SignedHeaders=host;", "SignedHeaders=", 1)
		req.Header.Set("Authorization", authorization)

		return checkIAMAuthRequest(s, req, iamerr.GetAPIError(iamerr.ErrMissingHostSignedHeader))
	})
}

func IAMAuth_unsigned_non_required_header(s *S3Conf) error {
	testName := "IAMAuth_unsigned_non_required_header"
	return authHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		req.Header.Set("Content-Type", "text/plain")
		req.Header.Set("X-Amz-Copy-Source", "source-bucket/source-key")
		req.Header.Set("X-Amz-Tagging", "key=value")
		req.Header.Set("X-Custom-Header", "value")
		req.Header.Set("X-Another-Custom-Header", "value")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkIAMSuccess(resp)
	})
}

func IAMAuth_signature_error_incorrect_secret_key(s *S3Conf) error {
	testName := "IAMAuth_signature_error_incorrect_secret_key"
	cfg := iamAuthConfig(testName)
	cfg.secret = s.awsSecret + "a"
	return authHandler(s, cfg, func(req *http.Request) error {
		return checkIAMAuthRequest(s, req, iamerr.GetAPIError(iamerr.ErrSignatureDoesNotMatch))
	})
}

func IAMAuth_sigv2_not_supported(s *S3Conf) error {
	testName := "IAMAuth_sigv2_not_supported"
	return authHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		req.Header.Set("Authorization", "AWS seed_signature")

		return checkIAMAuthRequest(s, req, iamerr.GetAPIError(iamerr.ErrUnsupportedSignatureVersion))
	})
}

func IAMAuth_with_expect_header(s *S3Conf) error {
	testName := "IAMAuth_with_expect_header"
	cfg := iamAuthConfig(testName)
	cfg.headers = map[string]string{
		"Expect": "100-continue",
	}
	return authHandler(s, cfg, func(req *http.Request) error {
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkIAMSuccess(resp)
	})
}

func iamAuthConfig(testName string) *authConfig {
	return &authConfig{
		testName: testName,
		method:   http.MethodGet,
		path:     iamAuthPath,
		service:  "iam",
		region:   iamAuthRegion,
		date:     time.Now().UTC(),
	}
}
