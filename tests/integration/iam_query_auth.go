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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	vgwv4 "github.com/versity/versitygw/aws/signer/v4"
	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/internal/sigv4auth"
)

func IAMQueryAuth_success(s *S3Conf) error {
	testName := "IAMQueryAuth_success"
	return iamQueryAuthHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		return checkIAMQueryAuthRequest(s, req, nil)
	})
}

func IAMQueryAuth_security_token_not_supported(s *S3Conf) error {
	testName := "IAMQueryAuth_security_token_not_supported"
	return iamQueryAuthHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		setIAMQueryParameter(req, sigv4auth.QuerySecurityToken, "my_token")

		return checkIAMQueryAuthRequest(s, req, iamerr.GetAPIError(iamerr.ErrInvalidClientTokenID))
	})
}

func IAMQueryAuth_unsupported_algorithm(s *S3Conf) error {
	testName := "IAMQueryAuth_unsupported_algorithm"
	return iamQueryAuthHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		const algorithm = "AWS4-SHA256"
		setIAMQueryParameter(req, sigv4auth.QueryAlgorithm, algorithm)

		return checkIAMQueryAuthRequest(s, req, iamerr.GetAPIError(iamerr.ErrUnsupportedQueryAlgorithm))
	})
}

func IAMQueryAuth_ECDSA_not_supported(s *S3Conf) error {
	testName := "IAMQueryAuth_ECDSA_not_supported"
	return iamQueryAuthHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		setIAMQueryParameter(req, sigv4auth.QueryAlgorithm, sigv4auth.AlgorithmECDSAP256SHA256)

		return checkIAMQueryAuthRequest(s, req, iamerr.GetAPIError(iamerr.ErrUnsupportedQueryAlgorithm))
	})
}

func IAMQueryAuth_missing_query_parameters(s *S3Conf) error {
	testName := "IAMQueryAuth_missing_query_parameters"
	return iamQueryAuthHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		testCases := []struct {
			name      string
			parameter string
			expected  iamerr.APIError
		}{
			{
				name:      "missing_algorithm",
				parameter: sigv4auth.QueryAlgorithm,
				expected:  iamerr.GetAPIError(iamerr.ErrMissingAuthenticationToken),
			},
			{
				name:      "missing_credential",
				parameter: sigv4auth.QueryCredential,
				expected:  iamerr.IncompleteSignatureMissingQueryParameter(sigv4auth.QueryCredential),
			},
			{
				name:      "missing_date",
				parameter: sigv4auth.QueryDate,
				expected:  iamerr.IncompleteSignatureMissingQueryParameter(sigv4auth.QueryDate),
			},
			{
				name:      "missing_signed_headers",
				parameter: sigv4auth.QuerySignedHeaders,
				expected:  iamerr.IncompleteSignatureMissingQueryParameter(sigv4auth.QuerySignedHeaders),
			},
			{
				name:      "missing_signature",
				parameter: sigv4auth.QuerySignature,
				expected:  iamerr.IncompleteSignatureMissingQueryParameter(sigv4auth.QuerySignature),
			},
		}

		for _, testCase := range testCases {
			testReq := req.Clone(req.Context())
			deleteIAMQueryParameter(testReq, testCase.parameter)
			if err := checkIAMQueryAuthRequest(s, testReq, testCase.expected); err != nil {
				return fmt.Errorf("%s: %w", testCase.name, err)
			}
		}

		return nil
	})
}

func IAMQueryAuth_malformed_credential(s *S3Conf) error {
	testName := "IAMQueryAuth_malformed_credential"
	return iamQueryAuthHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		const credential = "access/hello/world"
		setIAMQueryParameter(req, sigv4auth.QueryCredential, credential)

		return checkIAMQueryAuthRequest(s, req, iamerr.IncompleteSignatureMalformedCredential(credential))
	})
}

func IAMQueryAuth_credentials_invalid_terminal(s *S3Conf) error {
	testName := "IAMQueryAuth_credentials_invalid_terminal"
	return iamQueryAuthHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		if err := changeIAMQueryCredential(req, "aws_request", credTerminator); err != nil {
			return err
		}

		return checkIAMQueryAuthRequest(s, req, iamerr.GetAPIError(iamerr.ErrInvalidTerminal))
	})
}

func IAMQueryAuth_credentials_incorrect_service(s *S3Conf) error {
	testName := "IAMQueryAuth_credentials_incorrect_service"
	return iamQueryAuthHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		if err := changeIAMQueryCredential(req, "ec2", credService); err != nil {
			return err
		}

		return checkIAMQueryAuthRequest(s, req, iamerr.GetAPIError(iamerr.ErrIncorrectService))
	})
}

func IAMQueryAuth_credentials_incorrect_region(s *S3Conf) error {
	testName := "IAMQueryAuth_credentials_incorrect_region"
	cfg := iamAuthConfig(testName)
	cfg.region = "us-west-1"
	return iamQueryAuthHandler(s, cfg, func(req *http.Request) error {
		return checkIAMQueryAuthRequest(s, req, iamerr.GetAPIError(iamerr.ErrInvalidRegion))
	})
}

func IAMQueryAuth_credentials_invalid_date(s *S3Conf) error {
	testName := "IAMQueryAuth_credentials_invalid_date"
	return iamQueryAuthHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		if err := changeIAMQueryCredential(req, "3223423234", credDate); err != nil {
			return err
		}

		return checkIAMQueryAuthRequest(s, req, iamerr.GetAPIError(iamerr.ErrInvalidCredentialDate))
	})
}

func IAMQueryAuth_non_existing_access_key(s *S3Conf) error {
	testName := "IAMQueryAuth_non_existing_access_key"
	cfg := iamAuthConfig(testName)
	cfg.access = "a_rarely_existing_access_key_id_a7s86df78as6df89790a8sd7f"
	return iamQueryAuthHandler(s, cfg, func(req *http.Request) error {
		return checkIAMQueryAuthRequest(s, req, iamerr.GetAPIError(iamerr.ErrInvalidClientTokenID))
	})
}

func IAMQueryAuth_invalid_date(s *S3Conf) error {
	testName := "IAMQueryAuth_invalid_date"
	return iamQueryAuthHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		const invalidDate = "03032006"
		setIAMQueryParameter(req, sigv4auth.QueryDate, invalidDate)

		return checkIAMQueryAuthRequest(s, req, iamerr.IncompleteSignatureInvalidXAmzDate(invalidDate))
	})
}

func IAMQueryAuth_date_mismatch(s *S3Conf) error {
	testName := "IAMQueryAuth_date_mismatch"
	return iamQueryAuthHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		if err := changeIAMQueryCredential(req, "20000101", credDate); err != nil {
			return err
		}

		return checkIAMQueryAuthRequest(s, req, iamerr.GetAPIError(iamerr.ErrInvalidCredentialDate))
	})
}

func IAMQueryAuth_unsigned_query_parameter(s *S3Conf) error {
	testName := "IAMQueryAuth_unsigned_query_parameter"
	return iamQueryAuthHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		setIAMQueryParameter(req, "ExtraParam", "value")

		return checkIAMQueryAuthRequest(s, req, iamerr.GetAPIError(iamerr.ErrSignatureDoesNotMatch))
	})
}

func IAMQueryAuth_incorrect_secret_key(s *S3Conf) error {
	testName := "IAMQueryAuth_incorrect_secret_key"
	cfg := iamAuthConfig(testName)
	cfg.secret = s.awsSecret + "a"
	return iamQueryAuthHandler(s, cfg, func(req *http.Request) error {
		return checkIAMQueryAuthRequest(s, req, iamerr.GetAPIError(iamerr.ErrSignatureDoesNotMatch))
	})
}

func IAMQueryAuth_invalid_sha256_payload_hash_ignored(s *S3Conf) error {
	testName := "IAMQueryAuth_invalid_sha256_payload_hash_ignored"
	return iamQueryAuthHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		req.Header.Set("X-Amz-Content-Sha256", "invalid_sha256")

		return checkIAMQueryAuthRequest(s, req, nil)
	})
}

func IAMQueryAuth_with_expect_header(s *S3Conf) error {
	testName := "IAMQueryAuth_with_expect_header"
	return iamQueryAuthHandler(s, iamAuthConfig(testName), func(req *http.Request) error {
		req.Header.Set("Expect", "100-continue")

		return checkIAMQueryAuthRequest(s, req, nil)
	})
}

func iamQueryAuthHandler(s *S3Conf, cfg *authConfig, handler func(req *http.Request) error) error {
	runF(cfg.testName)

	access, secret, region := s.awsID, s.awsSecret, s.awsRegion
	if cfg.access != "" {
		access = cfg.access
	}
	if cfg.secret != "" {
		secret = cfg.secret
	}
	if cfg.region != "" {
		region = cfg.region
	}

	req, err := createIAMQuerySignedRequest(s.endpoint, cfg, access, secret, region)
	if err == nil {
		err = handler(req)
	}
	if err != nil {
		failF("%v: %v", cfg.testName, err)
		return fmt.Errorf("%v: %w", cfg.testName, err)
	}

	passF(cfg.testName)
	return nil
}

func createIAMQuerySignedRequest(endpoint string, cfg *authConfig, access, secret, region string) (*http.Request, error) {
	target := strings.TrimRight(endpoint, "/") + "/" + strings.TrimLeft(cfg.path, "/")
	req, err := http.NewRequest(cfg.method, target, bytes.NewReader(cfg.body))
	if err != nil {
		return nil, fmt.Errorf("create IAM query auth request: %w", err)
	}

	for key, value := range cfg.headers {
		req.Header.Set(key, value)
	}

	payloadHash := cfg.overrideSha256
	if payloadHash == "" {
		hash := sha256.Sum256(cfg.body)
		payloadHash = hex.EncodeToString(hash[:])
	}

	signer := vgwv4.NewSigner()
	signedURL, signedHeaders, _, err := signer.PresignHTTP(
		context.Background(),
		aws.Credentials{AccessKeyID: access, SecretAccessKey: secret},
		req,
		payloadHash,
		cfg.service,
		region,
		cfg.date,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("sign IAM query auth request: %w", err)
	}

	signedReq, err := http.NewRequest(cfg.method, signedURL, bytes.NewReader(cfg.body))
	if err != nil {
		return nil, fmt.Errorf("create signed IAM query auth request: %w", err)
	}
	for key, value := range cfg.headers {
		signedReq.Header.Set(key, value)
	}
	for key, values := range signedHeaders {
		signedReq.Header[key] = append([]string(nil), values...)
	}

	return signedReq, nil
}

func checkIAMQueryAuthRequest(s *S3Conf, req *http.Request, expected iamerr.APIError) error {
	if expected != nil {
		return checkIAMAuthRequest(s, req, expected)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	return checkIAMSuccess(resp)
}

func setIAMQueryParameter(req *http.Request, parameter, value string) {
	query := req.URL.Query()
	query.Set(parameter, value)
	req.URL.RawQuery = query.Encode()
}

func deleteIAMQueryParameter(req *http.Request, parameter string) {
	query := req.URL.Query()
	query.Del(parameter)
	req.URL.RawQuery = query.Encode()
}

func changeIAMQueryCredential(req *http.Request, value string, index int) error {
	query := req.URL.Query()
	credential := query.Get(sigv4auth.QueryCredential)
	parts := strings.Split(credential, "/")
	if len(parts) != 5 {
		return fmt.Errorf("unexpected generated IAM query credential %q", credential)
	}
	parts[index] = value
	query.Set(sigv4auth.QueryCredential, strings.Join(parts, "/"))
	req.URL.RawQuery = query.Encode()
	return nil
}
