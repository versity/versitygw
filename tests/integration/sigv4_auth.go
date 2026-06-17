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

package integration

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/s3err"
)

func Authentication_invalid_auth_header(s *S3Conf) error {
	testName := "Authentication_invalid_auth_header"
	return authHandler(s, &authConfig{
		testName: testName,
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		req.Header.Set("Authorization", "invalid_header")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetInvalidArgumentErr(s3err.InvalidArgAuthHeader, "invalid_header"))
	})
}

func Authentication_unsupported_signature_version(s *S3Conf) error {
	testName := "Authentication_unsupported_signature_version"
	return authHandler(s, &authConfig{
		testName: testName,
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		authHdr := req.Header.Get("Authorization")
		authHdr = strings.Replace(authHdr, "AWS4-HMAC-SHA256", "AWS2-HMAC-SHA1", 1)
		req.Header.Set("Authorization", authHdr)

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetInvalidArgumentErr(s3err.InvalidArgAuthorizationType, "AWS2-HMAC-SHA1"))
	})
}

func Authentication_missing_components(s *S3Conf) error {
	testName := "Authentication_missing_components"
	return authHandler(s, &authConfig{
		testName: testName,
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		// missing SignedHeaders component
		req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=access/20250912/us-east-1/s3/aws4_request,Signature=5fb279ae552098ea7c5c807df54cdb159e74939e19449b29831552639ec34b29")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.MalformedAuth.MissingComponents())
	})
}

func Authentication_malformed_component(s *S3Conf) error {
	testName := "Authentication_malformed_component"
	return authHandler(s, &authConfig{
		testName: testName,
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		// malformed SignedHeaders
		req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=access/20250912/us-east-1/s3/aws4_request,SignedHeaders-Content-Length,Signature=signature")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.MalformedAuth.MalformedComponent("SignedHeaders-Content-Length"))
	})
}

func Authentication_missing_credentials(s *S3Conf) error {
	testName := "Authentication_missing_credentials"
	return authHandler(s, &authConfig{
		testName: testName,
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		// missing Credentials
		req.Header.Set("Authorization", "AWS4-HMAC-SHA256 missing_creds=access/20250912/us-east-1/s3/aws4_request,SignedHeaders=content-length;x-amz-date,Signature=5fb279ae552098ea7c5c807df54cdb159e74939e19449b29831552639ec34b29")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.MalformedAuth.MissingCredential())
	})
}

func Authentication_missing_signedheaders(s *S3Conf) error {
	testName := "Authentication_missing_signedheaders"
	return authHandler(s, &authConfig{
		testName: testName,
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		// missing SignedHeaders
		req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=access/20250912/us-east-1/s3/aws4_request,missing=content-length;x-amz-date,Signature=5fb279ae552098ea7c5c807df54cdb159e74939e19449b29831552639ec34b29")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.MalformedAuth.MissingSignedHeaders())
	})
}

func Authentication_missing_signature(s *S3Conf) error {
	testName := "Authentication_missing_signature"
	return authHandler(s, &authConfig{
		testName: testName,
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		// missing Signature
		req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=access/20250912/us-east-1/s3/aws4_request,SignedHeaders=content-length;x-amz-date,missing=5fb279ae552098ea7c5c807df54cdb159e74939e19449b29831552639ec34b29")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.MalformedAuth.MissingSignature())
	})
}

func Authentication_malformed_credential(s *S3Conf) error {
	testName := "Authentication_malformed_credential"
	return authHandler(s, &authConfig{
		testName: testName,
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		authHdr := req.Header.Get("Authorization")
		regExp := regexp.MustCompile("Credential=[^,]+,")
		hdr := regExp.ReplaceAllString(authHdr, "Credential=access/32234/us-east-1/s3/extra/things,")
		req.Header.Set("Authorization", hdr)

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.MalformedAuth.MalformedCredential(""))
	})
}

func Authentication_credentials_invalid_terminal(s *S3Conf) error {
	testName := "Authentication_credentials_invalid_terminal"
	return authHandler(s, &authConfig{
		testName: testName,
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		authHdr := req.Header.Get("Authorization")
		regExp := regexp.MustCompile("Credential=[^,]+,")
		hdr := regExp.ReplaceAllString(authHdr, "Credential=access/32234/us-east-1/s3/aws_request,")
		req.Header.Set("Authorization", hdr)

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.MalformedAuth.IncorrectTerminal("", "aws_request"))
	})
}

func Authentication_credentials_incorrect_service(s *S3Conf) error {
	testName := "Authentication_credentials_incorrect_service"
	return authHandler(s, &authConfig{
		testName: testName,
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		authHdr := req.Header.Get("Authorization")
		regExp := regexp.MustCompile("Credential=[^,]+,")
		hdr := regExp.ReplaceAllString(authHdr, "Credential=access/32234/us-east-1/ec2/aws4_request,")
		req.Header.Set("Authorization", hdr)

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.MalformedAuth.IncorrectService("", "ec2"))
	})
}

func Authentication_credentials_incorrect_region(s *S3Conf) error {
	testName := "Authentication_credentials_incorrect_region"
	cfg := *s
	if cfg.awsRegion == "us-east-1" {
		cfg.awsRegion = "us-west-1"
	} else {
		cfg.awsRegion = "us-east-1"
	}
	return authHandler(&cfg, &authConfig{
		testName: testName,
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.MalformedAuth.IncorrectRegion(s.awsRegion, cfg.awsRegion))
	})
}

func Authentication_credentials_invalid_date(s *S3Conf) error {
	testName := "Authentication_credentials_invalid_date"
	return authHandler(s, &authConfig{
		testName: testName,
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		authHdr := req.Header.Get("Authorization")
		regExp := regexp.MustCompile("Credential=[^,]+,")
		hdr := regExp.ReplaceAllString(authHdr, "Credential=access/3223423234/us-east-1/s3/aws4_request,")
		req.Header.Set("Authorization", hdr)

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.MalformedAuth.InvalidDateFormat("", "3223423234"))
	})
}

func Authentication_credentials_future_date(s *S3Conf) error {
	testName := "Authentication_credentials_future_date"
	return authHandler(s, &authConfig{
		testName: testName,
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now().Add(time.Duration(5) * 24 * time.Hour),
	}, func(req *http.Request) error {

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		var errResp APIErrorResponse
		err = xml.Unmarshal(body, &errResp)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusForbidden {
			return fmt.Errorf("expected response status code to be %v, instead got %v", http.StatusForbidden, resp.StatusCode)
		}
		if errResp.Code != "RequestTimeTooSkewed" {
			return fmt.Errorf("expected error code to be %v, instead got %v", "RequestTimeTooSkewed", errResp.Code)
		}

		return nil
	})
}

func Authentication_credentials_past_date(s *S3Conf) error {
	testName := "Authentication_credentials_past_date"
	return authHandler(s, &authConfig{
		testName: testName,
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now().Add(time.Duration(-5) * 24 * time.Hour),
	}, func(req *http.Request) error {

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		var errResp APIErrorResponse
		err = xml.Unmarshal(body, &errResp)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusForbidden {
			return fmt.Errorf("expected response status code to be %v, instead got %v", http.StatusForbidden, resp.StatusCode)
		}
		if errResp.Code != "RequestTimeTooSkewed" {
			return fmt.Errorf("expected error code to be %v, instead got %v", "RequestTimeTooSkewed", errResp.Code)
		}

		return nil
	})
}

func Authentication_credentials_non_existing_access_key(s *S3Conf) error {
	testName := "Authentication_credentials_non_existing_access_key"
	return authHandler(s, &authConfig{
		testName: testName,
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		accessKeyID := "a_rarely_existing_access_key_id_a7s86df78as6df89790a8sd7f"
		authHdr := req.Header.Get("Authorization")
		regExp := regexp.MustCompile("Credential=([^/]+)")
		hdr := regExp.ReplaceAllString(authHdr, "Credential="+accessKeyID)
		req.Header.Set("Authorization", hdr)

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetInvalidAccessKeyIdErr(accessKeyID))
	})
}

func Authentication_missing_date_header(s *S3Conf) error {
	testName := "Authentication_missing_date_header"
	return authHandler(s, &authConfig{
		testName: testName,
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		req.Header.Set("X-Amz-Date", "")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrMissingDateHeader))
	})
}

func Authentication_invalid_date_header(s *S3Conf) error {
	testName := "Authentication_invalid_date_header"
	return authHandler(s, &authConfig{
		testName: testName,
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		req.Header.Set("X-Amz-Date", "03032006")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrMissingDateHeader))
	})
}

func Authentication_date_mismatch(s *S3Conf) error {
	testName := "Authentication_date_mismatch"
	return authHandler(s, &authConfig{
		testName: testName,
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		testuser := getUser("user")
		err := createUsers(s, []user{testuser})
		if err != nil {
			return err
		}

		authHdr := req.Header.Get("Authorization")
		regExp := regexp.MustCompile("Credential=[^,]+,")
		hdr := regExp.ReplaceAllString(authHdr, fmt.Sprintf("Credential=%s/20250912/us-east-1/s3/aws4_request,", testuser.access))
		req.Header.Set("Authorization", hdr)

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.MalformedAuth.DateMismatch())
	})
}

func Authentication_invalid_sha256_payload_hash(s *S3Conf) error {
	testName := "Authentication_invalid_sha256_payload_hash"
	return authHandler(s, &authConfig{
		testName: testName,
		method:   http.MethodPut,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
		path:     "bucket/object",
	}, func(req *http.Request) error {
		req.Header.Set("X-Amz-Content-Sha256", "invalid_sha256")
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetInvalidArgumentErr(s3err.InvalidArgSHA256Payload, "invalid_sha256"))
	})
}

func Authentication_incorrect_payload_hash(s *S3Conf) error {
	testName := "Authentication_incorrect_payload_hash"
	const incorrectPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b854"
	return authHandler(s, &authConfig{
		testName:       testName,
		method:         http.MethodPut,
		body:           nil,
		service:        "s3",
		date:           time.Now(),
		path:           "bucket/object?tagging",
		overrideSha256: incorrectPayloadHash,
	}, func(req *http.Request) error {
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetContentSHA256MismatchErr(incorrectPayloadHash, emptySHA256Hash))
	})
}

func Authentication_unsigned_required_header(s *S3Conf) error {
	testName := "Authentication_unsigned_required_header"
	return actionHandler(s, testName, func(_ *s3.Client, bucket string) error {
		req, err := createSignedReq(http.MethodPut, s.endpoint, fmt.Sprintf("%s/obj", bucket), s.awsID, s.awsSecret, "s3", s.awsRegion, "", nil, time.Now(), nil)
		if err != nil {
			return err
		}

		req.Header.Set("X-Amz-Copy-Source", "source-bucket/source-key")
		req.Header.Set("X-Amz-Tagging", "a=b")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetHeadersNotSignedErr([]string{"x-amz-copy-source", "x-amz-tagging"}))
	})
}

func Authentication_unsigned_non_required_header(s *S3Conf) error {
	testName := "Authentication_unsigned_non_required_header"
	return actionHandler(s, testName, func(_ *s3.Client, bucket string) error {
		req, err := createSignedReq(http.MethodPut, s.endpoint, fmt.Sprintf("%s/obj", bucket), s.awsID, s.awsSecret, "s3", s.awsRegion, "", nil, time.Now(), nil)
		if err != nil {
			return err
		}

		req.Header.Set("Content-Type", "text/plain")
		req.Header.Set("X-Custom-Header", "value")
		req.Header.Set("X-Another-Custom-Header", "value")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("expected response status code to be %v, instead got %v", http.StatusOK, resp.StatusCode)
		}

		return nil
	})
}

func Authentication_signature_error_incorrect_secret_key(s *S3Conf) error {
	testName := "Authentication_signature_error_incorrect_secret_key"
	cfg := *s
	cfg.awsSecret = s.awsSecret + "a"
	return authHandler(&cfg, &authConfig{
		testName: testName,
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrSignatureDoesNotMatch))
	})
}

func Authentication_sigv2_not_supported(s *S3Conf) error {
	testName := "Authentication_sigv2_not_supported"
	bucket := getBucketName()
	return authHandler(s, &authConfig{
		testName: testName,
		method:   http.MethodPut,
		service:  "s3",
		date:     time.Now(),
		path:     fmt.Sprintf("%s/object", bucket),
	}, func(req *http.Request) error {
		err := setup(s, bucket)
		if err != nil {
			return err
		}

		req.Header.Del("Authorization")
		req.Header.Set("Authorization", "AWS seed_signature")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		if err := checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrUnsupportedAuthorizationMechanism)); err != nil {
			return err
		}

		return teardown(s, bucket)
	})
}

func Authentication_with_expect_header(s *S3Conf) error {
	testName := "Authentication_with_expect_header"
	bucket, object := getBucketName(), "object"
	return authHandler(s, &authConfig{
		testName: testName,
		method:   http.MethodPut,
		body:     []byte("dummy data"),
		service:  "s3",
		date:     time.Now(),
		path:     fmt.Sprintf("%s/%s", bucket, object),
		headers: map[string]string{
			"Expect": "100-continue",
		},
	}, func(req *http.Request) error {
		err := setup(s, bucket)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != 200 {
			return fmt.Errorf("expected the response status to be 200, instead got %v", resp.StatusCode)
		}

		err = teardown(s, bucket)
		return err
	})
}
