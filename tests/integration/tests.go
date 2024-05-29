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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

var (
	shortTimeout  = 10 * time.Second
	iso8601Format = "20060102T150405Z"
)

func Authentication_empty_auth_header(s *S3Conf) error {
	testName := "Authentication_empty_auth_header"
	return authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		req.Header.Set("Authorization", "")
		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrAuthHeaderEmpty)); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_invalid_auth_header(s *S3Conf) error {
	testName := "Authentication_invalid_auth_header"
	return authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		req.Header.Set("Authorization", "invalid header")
		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrMissingFields)); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_unsupported_signature_version(s *S3Conf) error {
	testName := "Authentication_unsupported_signature_version"
	return authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		authHdr := req.Header.Get("Authorization")
		authHdr = strings.Replace(authHdr, "AWS4-HMAC-SHA256", "AWS2-HMAC-SHA1", 1)
		req.Header.Set("Authorization", authHdr)

		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrSignatureVersionNotSupported)); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_malformed_credentials(s *S3Conf) error {
	testName := "Authentication_malformed_credentials"
	return authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		authHdr := req.Header.Get("Authorization")
		regExp := regexp.MustCompile("Credential=[^,]+,")
		hdr := regExp.ReplaceAllString(authHdr, "Credential-access/32234/us-east-1/s3/aws4_request,")
		req.Header.Set("Authorization", hdr)

		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrCredMalformed)); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_malformed_credentials_invalid_parts(s *S3Conf) error {
	testName := "Authentication_malformed_credentials_invalid_parts"
	return authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		authHdr := req.Header.Get("Authorization")
		regExp := regexp.MustCompile("Credential=[^,]+,")
		hdr := regExp.ReplaceAllString(authHdr, "Credential=access/32234/us-east-1/s3,")
		req.Header.Set("Authorization", hdr)

		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrCredMalformed)); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_credentials_terminated_string(s *S3Conf) error {
	testName := "Authentication_credentials_terminated_string"
	return authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		authHdr := req.Header.Get("Authorization")
		regExp := regexp.MustCompile("Credential=[^,]+,")
		hdr := regExp.ReplaceAllString(authHdr, "Credential=access/32234/us-east-1/s3/aws_request,")
		req.Header.Set("Authorization", hdr)

		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrSignatureTerminationStr)); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_credentials_incorrect_service(s *S3Conf) error {
	testName := "Authentication_credentials_incorrect_service"
	return authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "ec2",
		date:     time.Now(),
	}, func(req *http.Request) error {
		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrSignatureIncorrService)); err != nil {
			return err
		}

		return nil
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
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		client := http.Client{
			Timeout: shortTimeout,
		}
		apiErr := s3err.APIError{
			Code:           "SignatureDoesNotMatch",
			Description:    fmt.Sprintf("Credential should be scoped to a valid Region, not %v", cfg.awsRegion),
			HTTPStatusCode: http.StatusForbidden,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, apiErr); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_credentials_invalid_date(s *S3Conf) error {
	testName := "Authentication_credentials_invalid_date"
	return authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		authHdr := req.Header.Get("Authorization")
		regExp := regexp.MustCompile("Credential=[^,]+,")
		hdr := regExp.ReplaceAllString(authHdr, "Credential=access/3223423234/us-east-1/s3/aws4_request,")
		req.Header.Set("Authorization", hdr)

		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrSignatureDateDoesNotMatch)); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_credentials_future_date(s *S3Conf) error {
	testName := "Authentication_credentials_future_date"
	return authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now().Add(time.Duration(5) * 24 * time.Hour),
	}, func(req *http.Request) error {
		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		var errResp s3err.APIErrorResponse
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
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now().Add(time.Duration(-5) * 24 * time.Hour),
	}, func(req *http.Request) error {
		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		var errResp s3err.APIErrorResponse
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
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		authHdr := req.Header.Get("Authorization")
		regExp := regexp.MustCompile("Credential=([^/]+)")
		hdr := regExp.ReplaceAllString(authHdr, "Credential=a_rarely_existing_access_key_id_a7s86df78as6df89790a8sd7f")
		req.Header.Set("Authorization", hdr)

		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrInvalidAccessKeyID)); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_invalid_signed_headers(s *S3Conf) error {
	testName := "Authentication_invalid_signed_headers"
	return authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		authHdr := req.Header.Get("Authorization")
		regExp := regexp.MustCompile("SignedHeaders=[^,]+,")
		hdr := regExp.ReplaceAllString(authHdr, "SignedHeaders-host;x-amz-content-sha256;x-amz-date,")
		req.Header.Set("Authorization", hdr)

		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrInvalidQueryParams)); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_missing_date_header(s *S3Conf) error {
	testName := "Authentication_missing_date_header"
	return authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		client := http.Client{
			Timeout: shortTimeout,
		}
		req.Header.Set("X-Amz-Date", "")

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrMissingDateHeader)); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_invalid_date_header(s *S3Conf) error {
	testName := "Authentication_invalid_date_header"
	return authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		client := http.Client{
			Timeout: shortTimeout,
		}
		req.Header.Set("X-Amz-Date", "03032006")

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrMalformedDate)); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_date_mismatch(s *S3Conf) error {
	testName := "Authentication_date_mismatch"
	return authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		client := http.Client{
			Timeout: shortTimeout,
		}
		req.Header.Set("X-Amz-Date", "20220830T095525Z")

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrSignatureDateDoesNotMatch)); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_incorrect_payload_hash(s *S3Conf) error {
	testName := "Authentication_incorrect_payload_hash"
	return authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		client := http.Client{
			Timeout: shortTimeout,
		}
		req.Header.Set("X-Amz-Content-Sha256", "7sa6df576dsa5f675sad67f")

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrContentSHA256Mismatch)); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_incorrect_md5(s *S3Conf) error {
	testName := "Authentication_incorrect_md5"
	return authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		client := http.Client{
			Timeout: shortTimeout,
		}

		req.Header.Set("Content-Md5", "sadfasdf87sad6f87==")

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrInvalidDigest)); err != nil {
			return err
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
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrSignatureDoesNotMatch)); err != nil {
			return err
		}

		return nil
	})
}

func PresignedAuth_missing_algo_query_param(s *S3Conf) error {
	testName := "PresignedAuth_missing_algo_query_param"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: getPtr("my-bucket")})
		cancel()
		if err != nil {
			return err
		}

		httpClient := http.Client{
			Timeout: shortTimeout,
		}

		urlParsed, err := url.Parse(v4req.URL)
		if err != nil {
			return err
		}

		queries := urlParsed.Query()
		queries.Del("X-Amz-Algorithm")
		urlParsed.RawQuery = queries.Encode()

		req, err := http.NewRequest(v4req.Method, urlParsed.String(), nil)
		if err != nil {
			return err
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return err
		}

		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrInvalidQueryParams)); err != nil {
			return err
		}

		return nil
	})
}

func PresignedAuth_unsupported_algorithm(s *S3Conf) error {
	testName := "PresignedAuth_unsupported_algorithm"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: getPtr("my-bucket")})
		cancel()
		if err != nil {
			return err
		}

		httpClient := http.Client{
			Timeout: shortTimeout,
		}

		uri := strings.Replace(v4req.URL, "AWS4-HMAC-SHA256", "AWS4-SHA256", 1)

		req, err := http.NewRequest(v4req.Method, uri, nil)
		if err != nil {
			return err
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return err
		}

		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrInvalidQuerySignatureAlgo)); err != nil {
			return err
		}

		return nil
	})
}

func PresignedAuth_missing_credentials_query_param(s *S3Conf) error {
	testName := "PresignedAuth_missing_credentials_query_param"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: getPtr("my-bucket")})
		cancel()
		if err != nil {
			return err
		}

		httpClient := http.Client{
			Timeout: shortTimeout,
		}

		urlParsed, err := url.Parse(v4req.URL)
		if err != nil {
			return err
		}

		queries := urlParsed.Query()
		queries.Del("X-Amz-Credential")
		urlParsed.RawQuery = queries.Encode()

		req, err := http.NewRequest(v4req.Method, urlParsed.String(), nil)
		if err != nil {
			return err
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return err
		}

		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrInvalidQueryParams)); err != nil {
			return err
		}

		return nil
	})
}

func PresignedAuth_malformed_creds_invalid_parts(s *S3Conf) error {
	testName := "PresignedAuth_malformed_creds_invalid_parts"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: getPtr("my-bucket")})
		cancel()
		if err != nil {
			return err
		}

		httpClient := http.Client{
			Timeout: shortTimeout,
		}

		urlParsed, err := url.Parse(v4req.URL)
		if err != nil {
			return err
		}

		queries := urlParsed.Query()
		queries.Set("X-Amz-Credential", "access/hello/world")
		urlParsed.RawQuery = queries.Encode()

		req, err := http.NewRequest(v4req.Method, urlParsed.String(), nil)
		if err != nil {
			return err
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return err
		}

		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrCredMalformed)); err != nil {
			return err
		}

		return nil
	})
}

func PresignedAuth_creds_invalid_terminator(s *S3Conf) error {
	testName := "PresignedAuth_creds_invalid_terminator"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: getPtr("my-bucket")})
		cancel()
		if err != nil {
			return err
		}

		httpClient := http.Client{
			Timeout: shortTimeout,
		}

		uri, err := changeAuthCred(v4req.URL, "aws5_request", credTerminator)
		if err != nil {
			return err
		}

		req, err := http.NewRequest(v4req.Method, uri, nil)
		if err != nil {
			return err
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return err
		}

		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrSignatureTerminationStr)); err != nil {
			return err
		}

		return nil
	})
}

func PresignedAuth_creds_incorrect_service(s *S3Conf) error {
	testName := "PresignedAuth_creds_incorrect_service"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: getPtr("my-bucket")})
		cancel()
		if err != nil {
			return err
		}

		httpClient := http.Client{
			Timeout: shortTimeout,
		}

		uri, err := changeAuthCred(v4req.URL, "sns", credService)
		if err != nil {
			return err
		}

		req, err := http.NewRequest(v4req.Method, uri, nil)
		if err != nil {
			return err
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return err
		}

		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrSignatureIncorrService)); err != nil {
			return err
		}

		return nil
	})
}

func PresignedAuth_creds_incorrect_region(s *S3Conf) error {
	testName := "PresignedAuth_creds_incorrect_region"
	cfg := *s

	if cfg.awsRegion == "us-east-1" {
		cfg.awsRegion = "us-west-1"
	} else {
		cfg.awsRegion = "us-east-1"
	}

	return presignedAuthHandler(&cfg, testName, func(client *s3.PresignClient) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: getPtr("my-bucket")})
		cancel()
		if err != nil {
			return err
		}

		httpClient := http.Client{
			Timeout: shortTimeout,
		}

		req, err := http.NewRequest(v4req.Method, v4req.URL, nil)
		if err != nil {
			return err
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return err
		}

		if err := checkAuthErr(resp, s3err.APIError{
			Code:           "SignatureDoesNotMatch",
			Description:    fmt.Sprintf("Credential should be scoped to a valid Region, not %v", cfg.awsRegion),
			HTTPStatusCode: http.StatusForbidden,
		}); err != nil {
			return err
		}

		return nil
	})
}

func PresignedAuth_creds_invalid_date(s *S3Conf) error {
	testName := "PresignedAuth_creds_invalid_date"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: getPtr("my-bucket")})
		cancel()
		if err != nil {
			return err
		}

		httpClient := http.Client{
			Timeout: shortTimeout,
		}

		uri, err := changeAuthCred(v4req.URL, "32234Z34", credDate)
		if err != nil {
			return err
		}

		req, err := http.NewRequest(v4req.Method, uri, nil)
		if err != nil {
			return err
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return err
		}

		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrSignatureDateDoesNotMatch)); err != nil {
			return err
		}

		return nil
	})
}

func PresignedAuth_non_existing_access_key_id(s *S3Conf) error {
	testName := "PresignedAuth_non_existing_access_key_id"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: getPtr("my-bucket")})
		cancel()
		if err != nil {
			return err
		}

		httpClient := http.Client{
			Timeout: shortTimeout,
		}

		uri, err := changeAuthCred(v4req.URL, "a_rarely_existing_access_key_id890asd6f807as6ydf870say", credAccess)
		if err != nil {
			return err
		}

		req, err := http.NewRequest(v4req.Method, uri, nil)
		if err != nil {
			return err
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return err
		}

		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrInvalidAccessKeyID)); err != nil {
			return err
		}

		return nil
	})
}

func PresignedAuth_missing_date_query(s *S3Conf) error {
	testName := "PresignedAuth_missing_date_query"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: getPtr("my-bucket")})
		cancel()
		if err != nil {
			return err
		}

		httpClient := http.Client{
			Timeout: shortTimeout,
		}

		urlParsed, err := url.Parse(v4req.URL)
		if err != nil {
			return err
		}

		queries := urlParsed.Query()
		queries.Del("X-Amz-Date")
		urlParsed.RawQuery = queries.Encode()

		req, err := http.NewRequest(v4req.Method, urlParsed.String(), nil)
		if err != nil {
			return err
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return err
		}

		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrInvalidQueryParams)); err != nil {
			return err
		}

		return nil
	})
}

func PresignedAuth_dates_mismatch(s *S3Conf) error {
	testName := "PresignedAuth_dates_mismatch"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: getPtr("my-bucket")})
		cancel()
		if err != nil {
			return err
		}

		httpClient := http.Client{
			Timeout: shortTimeout,
		}

		uri, err := changeAuthCred(v4req.URL, "20060102", credDate)
		if err != nil {
			return err
		}

		req, err := http.NewRequest(v4req.Method, uri, nil)
		if err != nil {
			return err
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return err
		}

		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrSignatureDateDoesNotMatch)); err != nil {
			return err
		}

		return nil
	})
}

func PresignedAuth_missing_signed_headers_query_param(s *S3Conf) error {
	testName := "PresignedAuth_missing_signed_headers_query_param"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: getPtr("my-bucket")})
		cancel()
		if err != nil {
			return err
		}

		httpClient := http.Client{
			Timeout: shortTimeout,
		}

		urlParsed, err := url.Parse(v4req.URL)
		if err != nil {
			return err
		}

		queries := urlParsed.Query()
		queries.Del("X-Amz-SignedHeaders")
		urlParsed.RawQuery = queries.Encode()

		req, err := http.NewRequest(v4req.Method, urlParsed.String(), nil)
		if err != nil {
			return err
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return err
		}

		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrInvalidQueryParams)); err != nil {
			return err
		}

		return nil
	})
}

func PresignedAuth_missing_expiration_query_param(s *S3Conf) error {
	testName := "PresignedAuth_missing_expiration_query_param"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: getPtr("my-bucket")})
		cancel()
		if err != nil {
			return err
		}

		httpClient := http.Client{
			Timeout: shortTimeout,
		}

		urlParsed, err := url.Parse(v4req.URL)
		if err != nil {
			return err
		}

		queries := urlParsed.Query()
		queries.Del("X-Amz-Expires")
		urlParsed.RawQuery = queries.Encode()

		req, err := http.NewRequest(v4req.Method, urlParsed.String(), nil)
		if err != nil {
			return err
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return err
		}

		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrInvalidQueryParams)); err != nil {
			return err
		}

		return nil
	})
}

func PresignedAuth_invalid_expiration_query_param(s *S3Conf) error {
	testName := "PresignedAuth_invalid_expiration_query_param"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: getPtr("my-bucket")})
		cancel()
		if err != nil {
			return err
		}

		httpClient := http.Client{
			Timeout: shortTimeout,
		}

		urlParsed, err := url.Parse(v4req.URL)
		if err != nil {
			return err
		}

		queries := urlParsed.Query()
		queries.Set("X-Amz-Expires", "invalid_value")
		urlParsed.RawQuery = queries.Encode()

		req, err := http.NewRequest(v4req.Method, urlParsed.String(), nil)
		if err != nil {
			return err
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return err
		}

		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrMalformedExpires)); err != nil {
			return err
		}

		return nil
	})
}

func PresignedAuth_negative_expiration_query_param(s *S3Conf) error {
	testName := "PresignedAuth_negative_expiration_query_param"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: getPtr("my-bucket")})
		cancel()
		if err != nil {
			return err
		}

		httpClient := http.Client{
			Timeout: shortTimeout,
		}

		urlParsed, err := url.Parse(v4req.URL)
		if err != nil {
			return err
		}

		queries := urlParsed.Query()
		queries.Set("X-Amz-Expires", "-3")
		urlParsed.RawQuery = queries.Encode()

		req, err := http.NewRequest(v4req.Method, urlParsed.String(), nil)
		if err != nil {
			return err
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return err
		}

		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrNegativeExpires)); err != nil {
			return err
		}

		return nil
	})
}

func PresignedAuth_exceeding_expiration_query_param(s *S3Conf) error {
	testName := "PresignedAuth_exceeding_expiration_query_param"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: getPtr("my-bucket")})
		cancel()
		if err != nil {
			return err
		}

		httpClient := http.Client{
			Timeout: shortTimeout,
		}

		urlParsed, err := url.Parse(v4req.URL)
		if err != nil {
			return err
		}

		queries := urlParsed.Query()
		queries.Set("X-Amz-Expires", "60580000")
		urlParsed.RawQuery = queries.Encode()

		req, err := http.NewRequest(v4req.Method, urlParsed.String(), nil)
		if err != nil {
			return err
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return err
		}

		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrMaximumExpires)); err != nil {
			return err
		}

		return nil
	})
}

func PresignedAuth_expired_request(s *S3Conf) error {
	testName := "PresignedAuth_expired_request"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: getPtr("my-bucket")})
		cancel()
		if err != nil {
			return err
		}

		httpClient := http.Client{
			Timeout: shortTimeout,
		}

		urlParsed, err := url.Parse(v4req.URL)
		if err != nil {
			return err
		}

		expDate := time.Now().AddDate(0, -1, 0).Format(iso8601Format)

		queries := urlParsed.Query()
		queries.Set("X-Amz-Date", expDate)
		urlParsed.RawQuery = queries.Encode()

		uri, err := changeAuthCred(urlParsed.String(), expDate[:8], credDate)
		if err != nil {
			return err
		}

		req, err := http.NewRequest(v4req.Method, uri, nil)
		if err != nil {
			return err
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return err
		}

		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrExpiredPresignRequest)); err != nil {
			return err
		}

		return nil
	})
}

func PresignedAuth_incorrect_secret_key(s *S3Conf) error {
	testName := "PresignedAuth_incorrect_secret_key"
	cfg := *s
	cfg.awsSecret += "x"
	return presignedAuthHandler(&cfg, testName, func(client *s3.PresignClient) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: getPtr("my-bucket")})
		cancel()
		if err != nil {
			return err
		}

		httpClient := http.Client{
			Timeout: shortTimeout,
		}

		req, err := http.NewRequest(v4req.Method, v4req.URL, nil)
		if err != nil {
			return err
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return err
		}

		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrSignatureDoesNotMatch)); err != nil {
			return err
		}

		return nil
	})
}

func PresignedAuth_PutObject_success(s *S3Conf) error {
	testName := "PresignedAuth_PutObject_success"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient) error {
		bucket := getBucketName()
		err := setup(s, bucket)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignPutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("my-obj")})
		cancel()
		if err != nil {
			return err
		}

		httpClient := http.Client{
			Timeout: shortTimeout,
		}

		req, err := http.NewRequest(http.MethodPut, v4req.URL, nil)
		if err != nil {
			return err
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("expected my-obj to be successfully uploaded and get 200 response status, instead got %v", resp.StatusCode)
		}

		err = teardown(s, bucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func PresignedAuth_Put_GetObject_with_data(s *S3Conf) error {
	testName := "PresignedAuth_Put_GetObject_with_data"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient) error {
		bucket, obj := getBucketName(), "my-obj"
		err := setup(s, bucket)
		if err != nil {
			return err
		}

		data := "Hello world"
		body := strings.NewReader(data)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignPutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &obj, Body: body})
		cancel()
		if err != nil {
			return err
		}

		httpClient := http.Client{
			Timeout: shortTimeout,
		}

		req, err := http.NewRequest(v4req.Method, v4req.URL, body)
		if err != nil {
			return err
		}

		req.Header = v4req.SignedHeader

		resp, err := httpClient.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("expected my-obj to be successfully uploaded and get %v response status, instead got %v", http.StatusOK, resp.StatusCode)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		v4GetReq, err := client.PresignGetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &obj})
		cancel()
		if err != nil {
			return err
		}

		req, err = http.NewRequest(v4GetReq.Method, v4GetReq.URL, nil)
		if err != nil {
			return err
		}

		resp, err = httpClient.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("expected get object response status to be %v, instead got %v", http.StatusOK, resp.StatusCode)
		}

		defer resp.Body.Close()
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("read get object response body %w", err)
		}

		if string(respBody) != data {
			return fmt.Errorf("expected get object response body to be %v, instead got %s", data, respBody)
		}

		err = teardown(s, bucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func PresignedAuth_Put_GetObject_with_UTF8_chars(s *S3Conf) error {
	testName := "PresignedAuth_Put_GetObject_with_data"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient) error {
		bucket, obj := getBucketName(), "my-$%^&*;"
		err := setup(s, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignPutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &obj})
		cancel()
		if err != nil {
			return err
		}

		httpClient := http.Client{
			Timeout: shortTimeout,
		}

		req, err := http.NewRequest(v4req.Method, v4req.URL, nil)
		if err != nil {
			return err
		}

		req.Header = v4req.SignedHeader

		resp, err := httpClient.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("expected my-obj to be successfully uploaded and get %v response status, instead got %v", http.StatusOK, resp.StatusCode)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		v4GetReq, err := client.PresignGetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &obj})
		cancel()
		if err != nil {
			return err
		}

		req, err = http.NewRequest(v4GetReq.Method, v4GetReq.URL, nil)
		if err != nil {
			return err
		}

		resp, err = httpClient.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("expected get object response status to be %v, instead got %v", http.StatusOK, resp.StatusCode)
		}

		err = teardown(s, bucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func PresignedAuth_UploadPart(s *S3Conf) error {
	testName := "PresignedAuth_UploadPart"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient) error {
		bucket, key, partNumber := getBucketName(), "my-mp", int32(1)

		err := setup(s, bucket)
		if err != nil {
			return err
		}

		clt := s3.NewFromConfig(s.Config())
		mp, err := createMp(clt, bucket, key)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignUploadPart(ctx, &s3.UploadPartInput{Bucket: &bucket, Key: &key, UploadId: mp.UploadId, PartNumber: &partNumber})
		cancel()
		if err != nil {
			return err
		}

		httpClient := http.Client{
			Timeout: shortTimeout,
		}

		req, err := http.NewRequest(v4req.Method, v4req.URL, nil)
		if err != nil {
			return err
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("expected response status code to be %v, instead got %v", http.StatusOK, resp.StatusCode)
		}

		etag := resp.Header.Get("Etag")

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := clt.ListParts(ctx, &s3.ListPartsInput{Bucket: &bucket, Key: &key, UploadId: mp.UploadId})
		cancel()
		if err != nil {
			return err
		}

		if len(out.Parts) != 1 {
			return fmt.Errorf("expected mp upload parts length to be 1, instead got %v", len(out.Parts))
		}
		if *out.Parts[0].ETag != etag {
			return fmt.Errorf("expected uploaded part etag to be %v, instead got %v", etag, *out.Parts[0].ETag)
		}
		if *out.Parts[0].PartNumber != partNumber {
			return fmt.Errorf("expected uploaded part part-number to be %v, instead got %v", partNumber, *out.Parts[0].PartNumber)
		}

		err = teardown(s, bucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func CreateBucket_invalid_bucket_name(s *S3Conf) error {
	testName := "CreateBucket_invalid_bucket_name"
	runF(testName)
	err := setup(s, "aa")
	if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidBucketName)); err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	err = setup(s, ".gitignore")
	if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidBucketName)); err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	err = setup(s, "my-bucket.")
	if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidBucketName)); err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	err = setup(s, "bucket-%")
	if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidBucketName)); err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}
	passF(testName)
	return nil
}

func CreateBucket_as_user(s *S3Conf) error {
	testName := "CreateBucket_as_user"
	runF(testName)
	usr := user{
		access: "grt1",
		secret: "grt1secret",
		role:   "user",
	}
	cfg := *s
	cfg.awsID = usr.access
	cfg.awsSecret = usr.secret
	err := createUsers(s, []user{usr})
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	err = setup(&cfg, getBucketName())
	if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	passF(testName)
	return nil
}

func CreateBucket_existing_bucket(s *S3Conf) error {
	testName := "CreateBucket_existing_bucket"
	runF(testName)
	bucket := getBucketName()
	admin := user{
		access: "admin1",
		secret: "admin1secret",
		role:   "admin",
	}
	if err := createUsers(s, []user{admin}); err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	adminCfg := *s
	adminCfg.awsID = admin.access
	adminCfg.awsSecret = admin.secret

	err := setup(&adminCfg, bucket)
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}
	err = setup(s, bucket)
	var bne *types.BucketAlreadyExists
	if !errors.As(err, &bne) {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	err = teardown(s, bucket)
	if err != nil {
		failF("%v: %v", err)
		return fmt.Errorf("%v: %w", testName, err)
	}
	passF(testName)
	return nil
}

func CreateBucket_owned_by_you(s *S3Conf) error {
	testName := "CreateBucket_owned_by_you"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.CreateBucket(ctx, &s3.CreateBucketInput{
			Bucket: &bucket,
		})
		cancel()
		var bErr *types.BucketAlreadyOwnedByYou
		if !errors.As(err, &bErr) {
			return fmt.Errorf("expected error to be %w, instead got %w", s3err.GetAPIError(s3err.ErrBucketAlreadyOwnedByYou), err)
		}

		return nil
	})
}

func CreateBucket_default_acl(s *S3Conf) error {
	testName := "CreateBucket_default_acl"
	runF(testName)

	bucket := getBucketName()
	client := s3.NewFromConfig(s.Config())

	err := setup(s, bucket)
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	out, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: &bucket})
	cancel()
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	if *out.Owner.ID != s.awsID {
		failF("%v: expected bucket owner to be %v, instead got %v", testName, s.awsID, *out.Owner.ID)
		return fmt.Errorf("%v: expected bucket owner to be %v, instead got %v", testName, s.awsID, *out.Owner.ID)
	}

	if len(out.Grants) != 0 {
		failF("%v: expected grants to be empty instead got %v", testName, len(out.Grants))
		return fmt.Errorf("%v: expected grants to be empty instead got %v", testName, len(out.Grants))
	}

	err = teardown(s, bucket)
	if err != nil {
		failF("%v: %v", err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	passF(testName)
	return nil
}

func CreateBucket_non_default_acl(s *S3Conf) error {
	testName := "CreateBucket_non_default_acl"
	runF(testName)

	err := createUsers(s, []user{
		{"grt1", "grt1secret", "user"},
		{"grt2", "grt2secret", "user"},
		{"grt3", "grt3secret", "user"},
	})
	if err != nil {
		failF("%v: %v", err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	grants := []types.Grant{
		{
			Grantee: &types.Grantee{
				ID: getPtr("grt1"),
			},
			Permission: types.PermissionFullControl,
		},
		{
			Grantee: &types.Grantee{
				ID: getPtr("grt2"),
			},
			Permission: types.PermissionReadAcp,
		},
		{
			Grantee: &types.Grantee{
				ID: getPtr("grt3"),
			},
			Permission: types.PermissionWrite,
		},
	}

	bucket := getBucketName()
	client := s3.NewFromConfig(s.Config())

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	_, err = client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket, GrantFullControl: getPtr("grt1"), GrantReadACP: getPtr("grt2"), GrantWrite: getPtr("grt3")})
	cancel()
	if err != nil {
		failF("%v: %v", err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	out, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: &bucket})
	cancel()
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	if !compareGrants(out.Grants, grants) {
		failF("%v: expected bucket acl grants to be %v, instead got %v", testName, grants, out.Grants)
		return fmt.Errorf("%v: expected bucket acl grants to be %v, instead got %v", testName, grants, out.Grants)
	}

	err = teardown(s, bucket)
	if err != nil {
		failF("%v: %v", err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	passF(testName)
	return nil
}

func CreateBucket_default_object_lock(s *S3Conf) error {
	testName := "CreateBucket_default_object_lock"
	runF(testName)

	bucket := getBucketName()
	lockEnabled := true

	client := s3.NewFromConfig(s.Config())

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	_, err := client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket:                     &bucket,
		ObjectLockEnabledForBucket: &lockEnabled,
	})
	cancel()
	if err != nil {
		failF("%v: %v", err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	resp, err := client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
		Bucket: &bucket,
	})
	cancel()
	if err != nil {
		failF("%v: %v", err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	if resp.ObjectLockConfiguration.ObjectLockEnabled != types.ObjectLockEnabledEnabled {
		failF("%v: expected object lock to be enabled", testName)
		return fmt.Errorf("%v: expected object lock to be enabled", testName)
	}

	err = teardown(s, bucket)
	if err != nil {
		failF("%v: %v", err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	passF(testName)
	return nil
}

func HeadBucket_non_existing_bucket(s *S3Conf) error {
	testName := "HeadBucket_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		bcktName := getBucketName()

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.HeadBucket(ctx, &s3.HeadBucketInput{
			Bucket: &bcktName,
		})
		cancel()
		if err := checkSdkApiErr(err, "NotFound"); err != nil {
			return err
		}
		return nil
	})
}

func HeadBucket_success(s *S3Conf) error {
	testName := "HeadBucket_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.HeadBucket(ctx, &s3.HeadBucketInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if resp.AccessPointAlias != nil && *resp.AccessPointAlias {
			return fmt.Errorf("expected bucket access point alias to be false")
		}
		if *resp.BucketRegion != s.awsRegion {
			return fmt.Errorf("expected bucket region to be %v, instead got %v", s.awsRegion, *resp.BucketRegion)
		}

		return nil
	})
}

func ListBuckets_as_user(s *S3Conf) error {
	testName := "ListBuckets_as_user"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		buckets := []s3response.ListAllMyBucketsEntry{{Name: bucket}}
		for i := 0; i < 6; i++ {
			bckt := getBucketName()

			err := setup(s, bckt)
			if err != nil {
				return err
			}

			buckets = append(buckets, s3response.ListAllMyBucketsEntry{
				Name: bckt,
			})
		}
		usr := user{
			access: "grt1",
			secret: "grt1secret",
			role:   "user",
		}

		err := createUsers(s, []user{usr})
		if err != nil {
			return err
		}

		cfg := *s
		cfg.awsID = usr.access
		cfg.awsSecret = usr.secret

		bckts := []string{}
		for i := 0; i < 3; i++ {
			bckts = append(bckts, buckets[i].Name)
		}

		err = changeBucketsOwner(s, bckts, usr.access)
		if err != nil {
			return err
		}

		userClient := s3.NewFromConfig(cfg.Config())

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := userClient.ListBuckets(ctx, &s3.ListBucketsInput{})
		cancel()
		if err != nil {
			return err
		}

		if *out.Owner.ID != usr.access {
			return fmt.Errorf("expected buckets owner to be %v, instead got %v", usr.access, *out.Owner.ID)
		}
		if ok := compareBuckets(out.Buckets, buckets[:3]); !ok {
			return fmt.Errorf("expected list buckets result to be %v, instead got %v", buckets[:3], out.Buckets)
		}

		for _, elem := range buckets[1:] {
			err = teardown(s, elem.Name)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func ListBuckets_as_admin(s *S3Conf) error {
	testName := "ListBuckets_as_admin"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		buckets := []s3response.ListAllMyBucketsEntry{{Name: bucket}}
		for i := 0; i < 6; i++ {
			bckt := getBucketName()

			err := setup(s, bckt)
			if err != nil {
				return err
			}

			buckets = append(buckets, s3response.ListAllMyBucketsEntry{
				Name: bckt,
			})
		}
		usr := user{
			access: "grt1",
			secret: "grt1secret",
			role:   "user",
		}
		admin := user{
			access: "admin1",
			secret: "admin1secret",
			role:   "admin",
		}

		err := createUsers(s, []user{usr, admin})
		if err != nil {
			return err
		}

		cfg := *s
		cfg.awsID = admin.access
		cfg.awsSecret = admin.secret

		bckts := []string{}
		for i := 0; i < 3; i++ {
			bckts = append(bckts, buckets[i].Name)
		}

		err = changeBucketsOwner(s, bckts, usr.access)
		if err != nil {
			return err
		}

		adminClient := s3.NewFromConfig(cfg.Config())

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := adminClient.ListBuckets(ctx, &s3.ListBucketsInput{})
		cancel()
		if err != nil {
			return err
		}

		if *out.Owner.ID != admin.access {
			return fmt.Errorf("expected buckets owner to be %v, instead got %v", admin.access, *out.Owner.ID)
		}
		if ok := compareBuckets(out.Buckets, buckets); !ok {
			return fmt.Errorf("expected list buckets result to be %v, instead got %v", buckets, out.Buckets)
		}

		for _, elem := range buckets[1:] {
			err = teardown(s, elem.Name)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func ListBuckets_success(s *S3Conf) error {
	testName := "ListBuckets_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		buckets := []s3response.ListAllMyBucketsEntry{{Name: bucket}}
		for i := 0; i < 5; i++ {
			bckt := getBucketName()

			err := setup(s, bckt)
			if err != nil {
				return err
			}

			buckets = append(buckets, s3response.ListAllMyBucketsEntry{
				Name: bckt,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListBuckets(ctx, &s3.ListBucketsInput{})
		cancel()
		if err != nil {
			return err
		}

		if *out.Owner.ID != s.awsID {
			return fmt.Errorf("expected owner to be %v, instead got %v", s.awsID, *out.Owner.ID)
		}
		if ok := compareBuckets(out.Buckets, buckets); !ok {
			return fmt.Errorf("expected list buckets result to be %v, instead got %v", buckets, out.Buckets)
		}

		for _, elem := range buckets[1:] {
			err = teardown(s, elem.Name)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func CreateDeleteBucket_success(s *S3Conf) error {
	testName := "CreateBucket_success"
	runF(testName)
	bucket := getBucketName()

	err := setup(s, bucket)
	if err != nil {
		failF("%v: %v", err)
		return fmt.Errorf("%v: %w", testName, err)

	}

	err = teardown(s, bucket)
	if err != nil {
		failF("%v: %v", err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	passF(testName)
	return nil
}

func DeleteBucket_non_existing_bucket(s *S3Conf) error {
	testName := "DeleteBucket_non_existing_bucket"
	runF(testName)
	bucket := getBucketName()
	s3client := s3.NewFromConfig(s.Config())

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	_, err := s3client.DeleteBucket(ctx, &s3.DeleteBucketInput{
		Bucket: &bucket,
	})
	cancel()
	if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}
	passF(testName)
	return nil
}

func DeleteBucket_non_empty_bucket(s *S3Conf) error {
	testName := "DeleteBucket_non_empty_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putObjects(s3client, []string{"foo"}, bucket)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteBucket(ctx, &s3.DeleteBucketInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrBucketNotEmpty)); err != nil {
			return err
		}

		return nil
	})
}

func DeleteBucket_success_status_code(s *S3Conf) error {
	testName := "DeleteBucket_success_status_code"
	runF(testName)
	bucket := getBucketName()

	err := setup(s, bucket)
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	req, err := createSignedReq(http.MethodDelete, s.endpoint, bucket, s.awsID, s.awsSecret, "s3", s.awsRegion, nil, time.Now(), nil)
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	client := http.Client{
		Timeout: shortTimeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	if resp.StatusCode != http.StatusNoContent {
		failF("%v: expected response status to be %v, instead got %v", testName, http.StatusNoContent, resp.StatusCode)
		return fmt.Errorf("%v: expected response status to be %v, instead got %v", testName, http.StatusNoContent, resp.StatusCode)
	}

	passF(testName)
	return nil
}

func PutBucketTagging_non_existing_bucket(s *S3Conf) error {
	testName := "PutBucketTagging_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
			Bucket:  getPtr(getBucketName()),
			Tagging: &types.Tagging{TagSet: []types.Tag{}},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func PutBucketTagging_long_tags(s *S3Conf) error {
	testName := "PutBucketTagging_long_tags"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		tagging := types.Tagging{TagSet: []types.Tag{{Key: getPtr(genRandString(200)), Value: getPtr("val")}}}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
			Bucket:  &bucket,
			Tagging: &tagging})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidTag)); err != nil {
			return err
		}

		tagging = types.Tagging{TagSet: []types.Tag{{Key: getPtr("key"), Value: getPtr(genRandString(300))}}}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
			Bucket:  &bucket,
			Tagging: &tagging})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidTag)); err != nil {
			return err
		}

		return nil
	})
}

func PutBucketTagging_success(s *S3Conf) error {
	testName := "PutBucketTagging_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		tagging := types.Tagging{TagSet: []types.Tag{{Key: getPtr("key1"), Value: getPtr("val2")}, {Key: getPtr("key2"), Value: getPtr("val2")}}}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
			Bucket:  &bucket,
			Tagging: &tagging})
		cancel()
		if err != nil {
			return err
		}

		return nil
	})
}

func GetBucketTagging_non_existing_bucket(s *S3Conf) error {
	testName := "GetBucketTagging_non_existing_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
			Bucket: getPtr(getBucketName()),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}
		return nil
	})
}

func GetBucketTagging_unset_tags(s *S3Conf) error {
	testName := "GetBucketTagging_unset_tags"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrBucketTaggingNotFound)); err != nil {
			return err
		}
		return nil
	})
}

func GetBucketTagging_success(s *S3Conf) error {
	testName := "GetBucketTagging_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		tagging := types.Tagging{TagSet: []types.Tag{{Key: getPtr("key1"), Value: getPtr("val2")}, {Key: getPtr("key2"), Value: getPtr("val2")}}}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
			Bucket:  &bucket,
			Tagging: &tagging})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return nil
		}

		if !areTagsSame(out.TagSet, tagging.TagSet) {
			return fmt.Errorf("expected %v instead got %v", tagging.TagSet, out.TagSet)
		}

		return nil
	})
}

func DeleteBucketTagging_non_existing_object(s *S3Conf) error {
	testName := "DeleteBucketTagging_non_existing_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteBucketTagging(ctx, &s3.DeleteBucketTaggingInput{
			Bucket: getPtr(getBucketName()),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}
		return nil
	})
}

func DeleteBucketTagging_success_status(s *S3Conf) error {
	testName := "DeleteBucketTagging_success_status"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		tagging := types.Tagging{
			TagSet: []types.Tag{
				{
					Key:   getPtr("Hello"),
					Value: getPtr("World"),
				},
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
			Bucket:  &bucket,
			Tagging: &tagging,
		})
		cancel()
		if err != nil {
			return err
		}

		req, err := createSignedReq(http.MethodDelete, s.endpoint, fmt.Sprintf("%v?tagging", bucket), s.awsID, s.awsSecret, "s3", s.awsRegion, nil, time.Now(), nil)
		if err != nil {
			return err
		}

		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusNoContent {
			return fmt.Errorf("expected response status to be %v, instead got %v", http.StatusNoContent, resp.StatusCode)
		}

		return nil
	})
}

func DeleteBucketTagging_success(s *S3Conf) error {
	testName := "DeleteBucketTagging_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		tagging := types.Tagging{TagSet: []types.Tag{{Key: getPtr("key1"), Value: getPtr("val2")}, {Key: getPtr("key2"), Value: getPtr("val2")}}}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
			Bucket:  &bucket,
			Tagging: &tagging})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteBucketTagging(ctx, &s3.DeleteBucketTaggingInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return nil
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return nil
		}

		if len(out.TagSet) > 0 {
			return fmt.Errorf("expected empty tag set, instead got %v", out.TagSet)
		}

		return nil
	})
}

func PutObject_non_existing_bucket(s *S3Conf) error {
	testName := "PutObject_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putObjects(s3client, []string{"my-obj"}, "non-existing-bucket")
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}
		return nil
	})
}

func PutObject_special_chars(s *S3Conf) error {
	testName := "PutObject_special_chars"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putObjects(s3client, []string{"my%key", "my^key", "my*key", "my.key", "my-key", "my_key", "my!key", "my'key", "my(key", "my)key", "my\\key", "my{}key", "my[]key", "my`key", "my+key", "my%25key", "my@key"}, bucket)
		if err != nil {
			return err
		}
		return nil
	})
}

func PutObject_invalid_long_tags(s *S3Conf) error {
	testName := "PutObject_invalid_long_tags"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key := "my-obj"
		tagging := fmt.Sprintf("%v=val", genRandString(200))

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:  &bucket,
			Key:     &key,
			Tagging: &tagging,
		})
		cancel()

		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidTag)); err != nil {
			return err
		}

		tagging = fmt.Sprintf("key=%v", genRandString(300))

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:  &bucket,
			Key:     &key,
			Tagging: &tagging,
		})
		cancel()

		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidTag)); err != nil {
			return err
		}

		return nil
	})
}

func PutObject_missing_object_lock_retention_config(s *S3Conf) error {
	testName := "PutObject_missing_object_lock_retention_config"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key := "my-obj"

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:         &bucket,
			Key:            &key,
			ObjectLockMode: types.ObjectLockModeCompliance,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLockInvalidHeaders)); err != nil {
			return err
		}

		retainDate := time.Now().Add(time.Hour * 48)

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:                    &bucket,
			Key:                       &key,
			ObjectLockRetainUntilDate: &retainDate,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLockInvalidHeaders)); err != nil {
			return err
		}

		return nil
	})
}

func PutObject_with_object_lock(s *S3Conf) error {
	testName := "PutObject_with_object_lock"
	runF(testName)
	bucket, obj, lockStatus := getBucketName(), "my-obj", true

	client := s3.NewFromConfig(s.Config())
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	_, err := client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket:                     &bucket,
		ObjectLockEnabledForBucket: &lockStatus,
	})
	cancel()
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	retainDate := time.Now().Add(time.Hour * 48)

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:                    &bucket,
		Key:                       &obj,
		ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatusOn,
		ObjectLockMode:            types.ObjectLockModeCompliance,
		ObjectLockRetainUntilDate: &retainDate,
	})

	cancel()
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	out, err := client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: &bucket,
		Key:    &obj,
	})
	cancel()
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	if out.ObjectLockMode != types.ObjectLockModeCompliance {
		failF("%v: expected object lock mode to be %v, instead got %v", testName, types.ObjectLockModeCompliance, out.ObjectLockMode)
		return fmt.Errorf("%v: expected object lock mode to be %v, instead got %v", testName, types.ObjectLockModeCompliance, out.ObjectLockMode)
	}
	if out.ObjectLockLegalHoldStatus != types.ObjectLockLegalHoldStatusOn {
		failF("%v: expected object lock mode to be %v, instead got %v", testName, types.ObjectLockLegalHoldStatusOn, out.ObjectLockLegalHoldStatus)
		return fmt.Errorf("%v: expected object lock mode to be %v, instead got %v", testName, types.ObjectLockLegalHoldStatusOn, out.ObjectLockLegalHoldStatus)
	}

	if err := changeBucketObjectLockStatus(client, bucket, false); err != nil {
		failF("%v: %v", err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	err = teardown(s, bucket)
	if err != nil {
		failF("%v: %v", err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	passF(testName)
	return nil
}

func PutObject_success(s *S3Conf) error {
	testName := "PutObject_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putObjects(s3client, []string{"my-obj"}, bucket)
		if err != nil {
			return err
		}
		return nil
	})
}

func PutObject_invalid_credentials(s *S3Conf) error {
	testName := "PutObject_invalid_credentials"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		newconf := *s
		newconf.awsSecret = newconf.awsSecret + "badpassword"
		client := s3.NewFromConfig(newconf.Config())
		err := putObjects(client, []string{"my-obj"}, bucket)
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrSignatureDoesNotMatch))
	})
}

func HeadObject_non_existing_object(s *S3Conf) error {
	testName := "HeadObject_non_existing_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
		})
		cancel()
		if err := checkSdkApiErr(err, "NotFound"); err != nil {
			return err
		}
		return nil
	})
}

func HeadObject_invalid_part_number(s *S3Conf) error {
	testName := "HeadObject_invalid_part_number"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		partNumber := int32(-3)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:     &bucket,
			Key:        getPtr("my-obj"),
			PartNumber: &partNumber,
		})
		cancel()
		if err := checkSdkApiErr(err, "BadRequest"); err != nil {
			return err
		}
		return nil
	})
}

func HeadObject_non_existing_mp(s *S3Conf) error {
	testName := "HeadObject_non_existing_mp"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		partNumber := int32(4)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:     &bucket,
			Key:        getPtr("my-obj"),
			PartNumber: &partNumber,
		})
		cancel()
		if err := checkSdkApiErr(err, "NotFound"); err != nil {
			return err
		}
		return nil
	})
}

func HeadObject_mp_success(s *S3Conf) error {
	testName := "HeadObject_mp_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		partCount, partSize := 5, 1024
		partNumber := int32(3)

		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		parts, err := uploadParts(s3client, partCount*partSize, partCount, bucket, obj, *mp.UploadId)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:     &bucket,
			Key:        &obj,
			PartNumber: &partNumber,
		})
		cancel()
		if err != nil {
			return err
		}

		if *out.ContentLength != int64(partSize) {
			return fmt.Errorf("expected content length to be %v, instead got %v", partSize, *out.ContentLength)
		}
		if *out.ETag != *parts[partNumber-1].ETag {
			return fmt.Errorf("expected ETag to be %v, instead got %v", *parts[partNumber-1].ETag, *out.ETag)
		}
		if *out.PartsCount != int32(partCount) {
			return fmt.Errorf("expected part count to be %v, instead got %v", partCount, *out.PartsCount)
		}

		return nil
	})
}

func HeadObject_success(s *S3Conf) error {
	testName := "HeadObject_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, dataLen := "my-obj", int64(1234567)
		meta := map[string]string{
			"key1": "val1",
			"key2": "val2",
		}

		_, _, err := putObjectWithData(dataLen, &s3.PutObjectInput{
			Bucket:   &bucket,
			Key:      &obj,
			Metadata: meta,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		defer cancel()
		if err != nil {
			return err
		}

		if !areMapsSame(out.Metadata, meta) {
			return fmt.Errorf("incorrect object metadata")
		}
		contentLength := int64(0)
		if out.ContentLength != nil {
			contentLength = *out.ContentLength
		}
		if contentLength != dataLen {
			return fmt.Errorf("expected data length %v, instead got %v", dataLen, contentLength)
		}

		return nil
	})
}

func GetObjectAttributes_non_existing_bucket(s *S3Conf) error {
	testName := "GetObjectAttributes_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
			Bucket:           getPtr(getBucketName()),
			Key:              getPtr("my-obj"),
			ObjectAttributes: []types.ObjectAttributes{},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func GetObjectAttributes_non_existing_object(s *S3Conf) error {
	testName := "GetObjectAttributes_non_existing_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
			Bucket:           &bucket,
			Key:              getPtr("my-obj"),
			ObjectAttributes: []types.ObjectAttributes{},
		})
		cancel()
		if err := checkSdkApiErr(err, "NoSuchKey"); err != nil {
			return err
		}

		return nil
	})
}

func GetObjectAttributes_existing_object(s *S3Conf) error {
	testName := "GetObjectAttributes_existing_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, data_len := "my-obj", int64(45679)
		data := make([]byte, data_len)

		_, err := rand.Read(data)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
			Body:   bytes.NewReader(data),
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
			Bucket: &bucket,
			Key:    &obj,
			ObjectAttributes: []types.ObjectAttributes{
				types.ObjectAttributesEtag,
				types.ObjectAttributesObjectSize,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if resp.ETag == nil || out.ETag == nil {
			return fmt.Errorf("nil ETag output")
		}
		if *resp.ETag != *out.ETag {
			return fmt.Errorf("expected ETag to be %v, instead got %v", *resp.ETag, *out.ETag)
		}
		if out.ObjectSize == nil {
			return fmt.Errorf("nil object size output")
		}
		if *out.ObjectSize != data_len {
			return fmt.Errorf("expected object size to be %v, instead got %v", data_len, *out.ObjectSize)
		}
		if out.Checksum != nil {
			return fmt.Errorf("expected checksum do be nil, instead got %v", *out.Checksum)
		}

		return nil
	})
}

func GetObjectAttributes_multipart_upload(s *S3Conf) error {
	testName := "GetObjectAttributes_multipart_upload"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		parts, err := uploadParts(s3client, 5*1024*1024, 5, bucket, obj, *out.UploadId)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
			Bucket: &bucket,
			Key:    &obj,
			ObjectAttributes: []types.ObjectAttributes{
				types.ObjectAttributesObjectParts,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if resp.ObjectParts == nil {
			return fmt.Errorf("expected non nil object parts")
		}

		for i, p := range resp.ObjectParts.Parts {
			if *p.PartNumber != *parts[i].PartNumber {
				return fmt.Errorf("expected part number to be %v, instead got %v", *parts[i].PartNumber, *p.PartNumber)
			}
			if *p.Size != *parts[i].Size {
				return fmt.Errorf("expected part size to be %v, instead got %v", *parts[i].Size, *p.Size)
			}
		}

		return nil
	})
}

func GetObjectAttributes_multipart_upload_truncated(s *S3Conf) error {
	testName := "GetObjectAttributes_multipart_upload_truncated"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		parts, err := uploadParts(s3client, 5*1024*1024, 5, bucket, obj, *out.UploadId)
		if err != nil {
			return err
		}

		maxParts := int32(3)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
			Bucket: &bucket,
			Key:    &obj,
			ObjectAttributes: []types.ObjectAttributes{
				types.ObjectAttributesObjectParts,
			},
			MaxParts: &maxParts,
		})
		cancel()
		if err != nil {
			return err
		}

		if resp.ObjectParts == nil {
			return fmt.Errorf("expected non nil object parts")
		}
		if resp.ObjectParts.IsTruncated == nil {
			return fmt.Errorf("expected non nil isTruncated")
		}
		if !*resp.ObjectParts.IsTruncated {
			return fmt.Errorf("expected object parts to be truncated")
		}
		if resp.ObjectParts.MaxParts == nil {
			return fmt.Errorf("expected non nil max-parts")
		}
		if *resp.ObjectParts.MaxParts != maxParts {
			return fmt.Errorf("expected max-parts to be %v, instead got %v", maxParts, *resp.ObjectParts.MaxParts)
		}
		if resp.ObjectParts.NextPartNumberMarker == nil {
			return fmt.Errorf("expected non nil NextPartNumberMarker")
		}
		if *resp.ObjectParts.NextPartNumberMarker != fmt.Sprint(*parts[2].PartNumber) {
			return fmt.Errorf("expected NextPartNumberMarker to be %v, instead got %v", fmt.Sprint(*parts[2].PartNumber), *resp.ObjectParts.NextPartNumberMarker)
		}
		if len(resp.ObjectParts.Parts) != int(maxParts) {
			return fmt.Errorf("expected length of parts to be %v, instead got %v", maxParts, len(resp.ObjectParts.Parts))
		}

		for i, p := range resp.ObjectParts.Parts {
			if *p.PartNumber != *parts[i].PartNumber {
				return fmt.Errorf("expected part number to be %v, instead got %v", *parts[i].PartNumber, *p.PartNumber)
			}
			if *p.Size != *parts[i].Size {
				return fmt.Errorf("expected part size to be %v, instead got %v", *parts[i].Size, *p.Size)
			}
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		resp, err = s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
			Bucket: &bucket,
			Key:    &obj,
			ObjectAttributes: []types.ObjectAttributes{
				types.ObjectAttributesObjectParts,
			},
			PartNumberMarker: resp.ObjectParts.NextPartNumberMarker,
		})
		cancel()
		if err != nil {
			return err
		}

		if resp.ObjectParts == nil {
			return fmt.Errorf("expected non nil object parts")
		}
		if resp.ObjectParts.IsTruncated == nil {
			return fmt.Errorf("expected non nil isTruncated")
		}
		if *resp.ObjectParts.IsTruncated {
			return fmt.Errorf("expected object parts to not be truncated")
		}

		if len(resp.ObjectParts.Parts) != len(parts)-int(maxParts) {
			return fmt.Errorf("expected length of parts to be %v, instead got %v", len(parts)-int(maxParts), len(resp.ObjectParts.Parts))
		}

		for i, p := range resp.ObjectParts.Parts {
			if *p.PartNumber != *parts[i+int(maxParts)].PartNumber {
				return fmt.Errorf("expected part number to be %v, instead got %v", *parts[i+int(maxParts)].PartNumber, *p.PartNumber)
			}
			if *p.Size != *parts[i+int(maxParts)].Size {
				return fmt.Errorf("expected part size to be %v, instead got %v", *parts[i+int(maxParts)].Size, *p.Size)
			}
		}

		return nil
	})
}

func GetObject_non_existing_key(s *S3Conf) error {
	testName := "GetObject_non_existing_key"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    getPtr("non-existing-key"),
		})
		cancel()
		var bae *types.NoSuchKey
		if !errors.As(err, &bae) {
			return err
		}
		return nil
	})
}

func GetObject_invalid_ranges(s *S3Conf) error {
	testName := "GetObject_invalid_ranges"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dataLength, obj := int64(1234567), "my-obj"

		_, _, err := putObjectWithData(dataLength, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
			Range:  getPtr("bytes=invalid-range"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidRange)); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
			Range:  getPtr("bytes=33-10"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidRange)); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
			Range:  getPtr("bytes=1000000000-999999999999"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidRange)); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
			Range:  getPtr("bytes=0-0"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidRange)); err != nil {
			return err
		}
		return nil
	})
}

func GetObject_with_meta(s *S3Conf) error {
	testName := "GetObject_with_meta"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		meta := map[string]string{
			"key1": "val1",
			"key2": "val2",
		}

		_, _, err := putObjectWithData(0, &s3.PutObjectInput{Bucket: &bucket, Key: &obj, Metadata: meta}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		defer cancel()
		if err != nil {
			return err
		}

		if !areMapsSame(out.Metadata, meta) {
			return fmt.Errorf("incorrect object metadata")
		}

		return nil
	})
}

func GetObject_success(s *S3Conf) error {
	testName := "GetObject_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dataLength, obj := int64(1234567), "my-obj"

		csum, _, err := putObjectWithData(dataLength, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		defer cancel()
		if err != nil {
			return err
		}
		if *out.ContentLength != dataLength {
			return fmt.Errorf("expected content-length %v, instead got %v", dataLength, out.ContentLength)
		}

		bdy, err := io.ReadAll(out.Body)
		if err != nil {
			return err
		}
		defer out.Body.Close()
		outCsum := sha256.Sum256(bdy)
		if outCsum != csum {
			return fmt.Errorf("invalid object data")
		}
		return nil
	})
}

func GetObject_by_range_success(s *S3Conf) error {
	testName := "GetObject_by_range_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dataLength, obj := int64(1234567), "my-obj"

		_, data, err := putObjectWithData(dataLength, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		rangeString := "bytes=100-200"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
			Range:  &rangeString,
		})
		defer cancel()
		if err != nil {
			return err
		}
		defer out.Body.Close()

		if getString(out.ContentRange) != fmt.Sprintf("bytes 100-200/%v", dataLength) {
			return fmt.Errorf("expected content range: %v, instead got: %v", fmt.Sprintf("bytes 100-200/%v", dataLength), getString(out.ContentRange))
		}
		if getString(out.AcceptRanges) != rangeString {
			return fmt.Errorf("expected accept range: %v, instead got: %v", rangeString, getString(out.AcceptRanges))
		}
		b, err := io.ReadAll(out.Body)
		if err != nil {
			return err
		}

		// bytes range is inclusive, go range for second value is not
		if !isEqual(b, data[100:201]) {
			return fmt.Errorf("data mismatch of range")
		}

		rangeString = "bytes=100-"

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
			Range:  &rangeString,
		})
		defer cancel()
		if err != nil {
			return err
		}
		defer out.Body.Close()

		b, err = io.ReadAll(out.Body)
		if err != nil {
			return err
		}

		// bytes range is inclusive, go range for second value is not
		if !isEqual(b, data[100:]) {
			return fmt.Errorf("data mismatch of range")
		}
		return nil
	})
}

func GetObject_by_range_resp_status(s *S3Conf) error {
	testName := "GetObject_by_range_resp_status"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, dLen := "my-obj", int64(4000)
		_, _, err := putObjectWithData(dLen, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		req, err := createSignedReq(
			http.MethodGet,
			s.endpoint,
			fmt.Sprintf("%v/%v", bucket, obj),
			s.awsID,
			s.awsSecret,
			"s3",
			s.awsRegion,
			nil,
			time.Now(),
			map[string]string{
				"Range": "bytes=100-200",
			},
		)
		if err != nil {
			return err
		}

		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusPartialContent {
			return fmt.Errorf("expected response status to be %v, instead got %v", http.StatusPartialContent, resp.StatusCode)
		}

		return nil
	})
}

func ListObjects_non_existing_bucket(s *S3Conf) error {
	testName := "ListObjects_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		bckt := getBucketName()
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bckt,
		})
		cancel()
		if err := checkSdkApiErr(err, "NoSuchBucket"); err != nil {
			return err
		}
		return nil
	})
}

func ListObjects_with_prefix(s *S3Conf) error {
	testName := "ListObjects_with_prefix"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		prefix := "obj"
		objWithPrefix := []string{prefix + "/foo", prefix + "/bar", prefix + "/baz/bla"}
		err := putObjects(s3client, append(objWithPrefix, []string{"xzy/csf", "hell"}...), bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
			Prefix: &prefix,
		})
		cancel()
		if err != nil {
			return err
		}

		if *out.Prefix != prefix {
			return fmt.Errorf("expected prefix %v, instead got %v", prefix, *out.Prefix)
		}
		if !compareObjects(objWithPrefix, out.Contents) {
			return fmt.Errorf("unexpected output for list objects with prefix")
		}

		return nil
	})
}

func ListObject_truncated(s *S3Conf) error {
	testName := "ListObject_truncated"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		maxKeys := int32(2)
		err := putObjects(s3client, []string{"foo", "bar", "baz"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out1, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket:  &bucket,
			MaxKeys: &maxKeys,
		})
		cancel()
		if err != nil {
			return err
		}

		if out1.IsTruncated == nil || !*out1.IsTruncated {
			return fmt.Errorf("expected output to be truncated")
		}

		if *out1.MaxKeys != maxKeys {
			return fmt.Errorf("expected max-keys to be %v, instead got %v", maxKeys, out1.MaxKeys)
		}

		if *out1.NextMarker != "baz" {
			return fmt.Errorf("expected next-marker to be baz, instead got %v", *out1.NextMarker)
		}

		if !compareObjects([]string{"bar", "baz"}, out1.Contents) {
			return fmt.Errorf("unexpected output for list objects with max-keys")
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out2, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
			Marker: out1.NextMarker,
		})
		cancel()
		if err != nil {
			return err
		}

		if *out2.IsTruncated {
			return fmt.Errorf("expected output not to be truncated")
		}

		if *out2.Marker != *out1.NextMarker {
			return fmt.Errorf("expected marker to be %v, instead got %v", *out1.NextMarker, *out2.Marker)
		}

		if !compareObjects([]string{"foo"}, out2.Contents) {
			return fmt.Errorf("unexpected output for list objects with max-keys")
		}
		return nil
	})
}

func ListObjects_invalid_max_keys(s *S3Conf) error {
	testName := "ListObjects_invalid_max_keys"
	maxKeys := int32(-5)
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket:  &bucket,
			MaxKeys: &maxKeys,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidMaxKeys)); err != nil {
			return err
		}

		return nil
	})
}

func ListObjects_max_keys_0(s *S3Conf) error {
	testName := "ListObjects_max_keys_0"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objects := []string{"foo", "bar", "baz"}
		err := putObjects(s3client, objects, bucket)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		maxKeys := int32(0)
		out, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket:  &bucket,
			MaxKeys: &maxKeys,
		})
		cancel()
		if err != nil {
			return nil
		}

		if len(out.Contents) > 0 {
			return fmt.Errorf("unexpected output for list objects with max-keys 0")
		}

		return nil
	})
}

func ListObjects_delimiter(s *S3Conf) error {
	testName := "ListObjects_delimiter"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putObjects(s3client, []string{"foo/bar/baz", "foo/bar/xyzzy", "quux/thud", "asdf"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket:    &bucket,
			Delimiter: getPtr("/"),
		})
		cancel()
		if err != nil {
			return err
		}

		if out.Delimiter == nil || *out.Delimiter != "/" {
			if out.Delimiter == nil {
				return fmt.Errorf("expected delimiter to be /, instead got nil delim")
			}
			return fmt.Errorf("expected delimiter to be /, instead got %v", *out.Delimiter)
		}
		if len(out.Contents) != 1 || *out.Contents[0].Key != "asdf" {
			return fmt.Errorf("expected result [\"asdf\"], instead got %v", out.Contents)
		}

		if !comparePrefixes([]string{"foo/", "quux/"}, out.CommonPrefixes) {
			return fmt.Errorf("expected common prefixes to be %v, instead got %v", []string{"foo/", "quux/"}, out.CommonPrefixes)
		}

		return nil
	})
}

func ListObjects_max_keys_none(s *S3Conf) error {
	testName := "ListObjects_max_keys_none"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putObjects(s3client, []string{"foo", "bar", "baz"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if *out.MaxKeys != 1000 {
			return fmt.Errorf("expected max-keys to be 1000, instead got %v", out.MaxKeys)
		}

		return nil
	})
}

func ListObjects_marker_not_from_obj_list(s *S3Conf) error {
	testName := "ListObjects_marker_not_from_obj_list"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putObjects(s3client, []string{"foo", "bar", "baz", "qux", "hello", "xyz"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
			Marker: getPtr("ceil"),
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareObjects([]string{"foo", "qux", "hello", "xyz"}, out.Contents) {
			return fmt.Errorf("expected output to be %v, instead got %v", []string{"foo", "qux", "hello", "xyz"}, out.Contents)
		}

		return nil
	})
}

func ListObjectsV2_start_after(s *S3Conf) error {
	testName := "ListObjectsV2_start_after"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putObjects(s3client, []string{"foo", "bar", "baz"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:     &bucket,
			StartAfter: getPtr("bar"),
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareObjects([]string{"baz", "foo"}, out.Contents) {
			return fmt.Errorf("expected output to be %v, instead got %v", []string{"baz", "foo"}, out.Contents)
		}

		return nil
	})
}

func ListObjectsV2_both_start_after_and_continuation_token(s *S3Conf) error {
	testName := "ListObjectsV2_both_start_after_and_continuation_token"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putObjects(s3client, []string{"foo", "bar", "baz", "quxx"}, bucket)
		if err != nil {
			return err
		}
		var maxKeys int32 = 1

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:  &bucket,
			MaxKeys: &maxKeys,
		})
		cancel()
		if err != nil {
			return err
		}

		if out.IsTruncated == nil || !*out.IsTruncated {
			return fmt.Errorf("expected output to be truncated")
		}

		if *out.MaxKeys != maxKeys {
			return fmt.Errorf("expected max-keys to be %v, instead got %v", maxKeys, out.MaxKeys)
		}

		if *out.NextContinuationToken != "bar" {
			return fmt.Errorf("expected next-marker to be baz, instead got %v", *out.NextContinuationToken)
		}

		if !compareObjects([]string{"bar"}, out.Contents) {
			return fmt.Errorf("unexpected output for list objects with max-keys")
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            &bucket,
			ContinuationToken: out.NextContinuationToken,
			StartAfter:        getPtr("baz"),
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareObjects([]string{"foo", "quxx"}, resp.Contents) {
			return fmt.Errorf("unexpected output for list objects with max-keys")
		}

		return nil
	})
}

func ListObjectsV2_start_after_not_in_list(s *S3Conf) error {
	testName := "ListObjectsV2_start_after_not_in_list"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putObjects(s3client, []string{"foo", "bar", "baz", "quxx"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:     &bucket,
			StartAfter: getPtr("blah"),
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareObjects([]string{"foo", "quxx"}, out.Contents) {
			return fmt.Errorf("expected output to be %v, instead got %v", []string{"foo", "quxx"}, out.Contents)
		}

		return nil
	})
}

func ListObjectsV2_start_after_empty_result(s *S3Conf) error {
	testName := "ListObjectsV2_start_after_empty_result"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putObjects(s3client, []string{"foo", "bar", "baz", "quxx"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:     &bucket,
			StartAfter: getPtr("zzz"),
		})
		cancel()
		if err != nil {
			return err
		}

		if len(out.Contents) != 0 {
			return fmt.Errorf("expected empty output instead got %v", out.Contents)
		}

		return nil
	})
}

func DeleteObject_non_existing_object(s *S3Conf) error {
	testName := "DeleteObject_non_existing_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchKey)); err != nil {
			return err
		}
		return nil
	})
}

func DeleteObject_success(s *S3Conf) error {
	testName := "DeleteObject_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		defer cancel()
		if err := checkSdkApiErr(err, "NoSuchKey"); err != nil {
			return err
		}
		return nil
	})
}

func DeleteObject_success_status_code(s *S3Conf) error {
	testName := "DeleteObject_success_status_code"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		req, err := createSignedReq(http.MethodDelete, s.endpoint, fmt.Sprintf("%v/%v", bucket, obj), s.awsID, s.awsSecret, "s3", s.awsRegion, nil, time.Now(), nil)
		if err != nil {
			return err
		}

		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusNoContent {
			return fmt.Errorf("expected response status to be %v, instead got %v", http.StatusNoContent, resp.StatusCode)
		}

		return nil
	})
}

func DeleteObjects_empty_input(s *S3Conf) error {
	testName := "DeleteObjects_empty_input"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objects := []string{"foo", "bar", "baz"}
		err := putObjects(s3client, objects, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: &bucket,
			Delete: &types.Delete{
				Objects: []types.ObjectIdentifier{},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if len(out.Deleted) != 0 {
			return fmt.Errorf("expected deleted object count 0, instead got %v", len(out.Deleted))
		}
		if len(out.Errors) != 0 {
			return fmt.Errorf("expected 0 errors, instead got %v", len(out.Errors))
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareObjects(objects, res.Contents) {
			return fmt.Errorf("unexpected output for list objects with prefix")
		}

		return nil
	})
}

func DeleteObjects_non_existing_objects(s *S3Conf) error {
	testName := "DeleteObjects_empty_input"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		delObjects := []types.ObjectIdentifier{{Key: getPtr("obj1")}, {Key: getPtr("obj2")}}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: &bucket,
			Delete: &types.Delete{
				Objects: delObjects,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if len(out.Deleted) != 0 {
			return fmt.Errorf("expected deleted object count 0, instead got %v", len(out.Deleted))
		}
		if len(out.Errors) != 2 {
			return fmt.Errorf("expected 2 errors, instead got %v", len(out.Errors))
		}

		for _, delErr := range out.Errors {
			if *delErr.Code != "NoSuchKey" {
				return fmt.Errorf("expected NoSuchKey error, instead got %v", *delErr.Code)
			}
		}

		return nil
	})
}

func DeleteObjects_success(s *S3Conf) error {
	testName := "DeleteObjects_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objects, objToDel := []string{"obj1", "obj2", "obj3"}, []string{"foo", "bar", "baz"}
		err := putObjects(s3client, append(objToDel, objects...), bucket)
		if err != nil {
			return err
		}

		delObjects := []types.ObjectIdentifier{}
		for _, key := range objToDel {
			k := key
			delObjects = append(delObjects, types.ObjectIdentifier{Key: &k})
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: &bucket,
			Delete: &types.Delete{
				Objects: delObjects,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if len(out.Deleted) != 3 {
			return fmt.Errorf("expected deleted object count 3, instead got %v", len(out.Deleted))
		}
		if len(out.Errors) != 0 {
			return fmt.Errorf("expected 2 errors, instead got %v", len(out.Errors))
		}

		if !compareDelObjects(objToDel, out.Deleted) {
			return fmt.Errorf("unexpected deleted output")
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareObjects(objects, res.Contents) {
			return fmt.Errorf("unexpected output for list objects with prefix")
		}

		return nil
	})
}

func CopyObject_non_existing_dst_bucket(s *S3Conf) error {
	testName := "CopyObject_non_existing_dst_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        &obj,
			CopySource: getPtr("bucket/obj"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}
		return nil
	})
}

func CopyObject_not_owned_source_bucket(s *S3Conf) error {
	testName := "CopyObject_not_owned_source_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj := "my-obj"
		err := putObjects(s3client, []string{srcObj}, bucket)
		if err != nil {
			return err
		}

		usr := user{
			access: "grt1",
			secret: "grt1secret",
			role:   "user",
		}

		cfg := *s
		cfg.awsID = usr.access
		cfg.awsSecret = usr.secret

		userS3Client := s3.NewFromConfig(cfg.Config())

		err = createUsers(s, []user{usr})
		if err != nil {
			return err
		}

		dstBucket := getBucketName()
		err = setup(s, dstBucket)
		if err != nil {
			return err
		}

		err = changeBucketsOwner(s, []string{bucket}, usr.access)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = userS3Client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &dstBucket,
			Key:        getPtr("obj-1"),
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		err = teardown(s, dstBucket)
		if err != nil {
			return err
		}
		return nil
	})
}

func CopyObject_copy_to_itself(s *S3Conf) error {
	testName := "CopyObject_copy_to_itself"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        &obj,
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, obj)),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidCopyDest)); err != nil {
			return err
		}
		return nil
	})
}

func CopyObject_to_itself_with_new_metadata(s *S3Conf) error {
	testName := "CopyObject_to_itself_with_new_metadata"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        &obj,
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, obj)),
			Metadata: map[string]string{
				"Hello": "World",
			},
		})
		cancel()
		if err != nil {
			return err
		}

		return nil
	})
}

func CopyObject_success(s *S3Conf) error {
	testName := "CopyObject_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dataLength, obj := int64(1234567), "my-obj"
		dstBucket := getBucketName()
		err := setup(s, dstBucket)
		if err != nil {
			return err
		}

		csum, _, err := putObjectWithData(dataLength, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &dstBucket,
			Key:        &obj,
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, obj)),
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &dstBucket,
			Key:    &obj,
		})
		defer cancel()
		if err != nil {
			return err
		}
		if *out.ContentLength != dataLength {
			return fmt.Errorf("expected content-length %v, instead got %v", dataLength, out.ContentLength)
		}

		bdy, err := io.ReadAll(out.Body)
		if err != nil {
			return err
		}
		defer out.Body.Close()
		outCsum := sha256.Sum256(bdy)
		if outCsum != csum {
			return fmt.Errorf("invalid object data")
		}

		err = teardown(s, dstBucket)
		if err != nil {
			return nil
		}

		return nil
	})
}

func PutObjectTagging_non_existing_object(s *S3Conf) error {
	testName := "PutObjectTagging_non_existing_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
			Bucket:  &bucket,
			Key:     getPtr("my-obj"),
			Tagging: &types.Tagging{TagSet: []types.Tag{}}})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchKey)); err != nil {
			return err
		}
		return nil
	})
}

func PutObjectTagging_long_tags(s *S3Conf) error {
	testName := "PutObjectTagging_long_tags"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		tagging := types.Tagging{TagSet: []types.Tag{{Key: getPtr(genRandString(129)), Value: getPtr("val")}}}
		err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
			Bucket:  &bucket,
			Key:     &obj,
			Tagging: &tagging})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidTag)); err != nil {
			return err
		}

		tagging = types.Tagging{TagSet: []types.Tag{{Key: getPtr("key"), Value: getPtr(genRandString(257))}}}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
			Bucket:  &bucket,
			Key:     &obj,
			Tagging: &tagging})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidTag)); err != nil {
			return err
		}

		return nil
	})
}

func PutObjectTagging_success(s *S3Conf) error {
	testName := "PutObjectTagging_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		tagging := types.Tagging{TagSet: []types.Tag{{Key: getPtr("key1"), Value: getPtr("val2")}, {Key: getPtr("key2"), Value: getPtr("val2")}}}
		err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
			Bucket:  &bucket,
			Key:     &obj,
			Tagging: &tagging})
		cancel()
		if err != nil {
			return err
		}

		return nil
	})
}

func GetObjectTagging_non_existing_object(s *S3Conf) error {
	testName := "GetObjectTagging_non_existing_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchKey)); err != nil {
			return err
		}
		return nil
	})
}

func GetObjectTagging_unset_tags(s *S3Conf) error {
	testName := "GetObjectTagging_unset_tags"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		if err := putObjects(s3client, []string{obj}, bucket); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrBucketTaggingNotFound)); err != nil {
			return err
		}
		return nil
	})
}

func GetObjectTagging_success(s *S3Conf) error {
	testName := "PutObjectTagging_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		tagging := types.Tagging{TagSet: []types.Tag{{Key: getPtr("key1"), Value: getPtr("val2")}, {Key: getPtr("key2"), Value: getPtr("val2")}}}
		err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
			Bucket:  &bucket,
			Key:     &obj,
			Tagging: &tagging})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return nil
		}

		if !areTagsSame(out.TagSet, tagging.TagSet) {
			return fmt.Errorf("expected %v instead got %v", tagging.TagSet, out.TagSet)
		}

		return nil
	})
}

func DeleteObjectTagging_non_existing_object(s *S3Conf) error {
	testName := "DeleteObjectTagging_non_existing_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteObjectTagging(ctx, &s3.DeleteObjectTaggingInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchKey)); err != nil {
			return err
		}
		return nil
	})
}

func DeleteObjectTagging_success_status(s *S3Conf) error {
	testName := "DeleteObjectTagging_success_status"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		tagging := types.Tagging{
			TagSet: []types.Tag{
				{
					Key:   getPtr("Hello"),
					Value: getPtr("World"),
				},
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
			Bucket:  &bucket,
			Key:     &obj,
			Tagging: &tagging,
		})
		cancel()
		if err != nil {
			return err
		}

		req, err := createSignedReq(http.MethodDelete, s.endpoint, fmt.Sprintf("%v/%v?tagging", bucket, obj), s.awsID, s.awsSecret, "s3", s.awsRegion, nil, time.Now(), nil)
		if err != nil {
			return err
		}

		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusNoContent {
			return fmt.Errorf("expected response status to be %v, instead got %v", http.StatusNoContent, resp.StatusCode)
		}

		return nil
	})
}

func DeleteObjectTagging_success(s *S3Conf) error {
	testName := "DeleteObjectTagging_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		tagging := types.Tagging{TagSet: []types.Tag{{Key: getPtr("key1"), Value: getPtr("val2")}, {Key: getPtr("key2"), Value: getPtr("val2")}}}
		err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
			Bucket:  &bucket,
			Key:     &obj,
			Tagging: &tagging})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObjectTagging(ctx, &s3.DeleteObjectTaggingInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return nil
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return nil
		}

		if len(out.TagSet) > 0 {
			return fmt.Errorf("expected empty tag set, instead got %v", out.TagSet)
		}

		return nil
	})
}

func CreateMultipartUpload_non_existing_bucket(s *S3Conf) error {
	testName := "CreateMultipartUpload_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		bucketName := getBucketName()
		_, err := createMp(s3client, bucketName, "my-obj")
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func CreateMultipartUpload_with_metadata(s *S3Conf) error {
	testName := "CreateMultipartUpload_with_metadata"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		meta := map[string]string{
			"prop1": "val1",
			"prop2": "val2",
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			Metadata: meta,
		})
		cancel()
		if err != nil {
			return err
		}

		parts, err := uploadParts(s3client, 100, 1, bucket, obj, *out.UploadId)
		if err != nil {
			return err
		}

		compParts := []types.CompletedPart{}
		for _, el := range parts {
			compParts = append(compParts, types.CompletedPart{
				ETag:       el.ETag,
				PartNumber: el.PartNumber,
			})
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: compParts,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		if !areMapsSame(resp.Metadata, meta) {
			return fmt.Errorf("expected uploaded object metadata to be %v, instead got %v", meta, resp.Metadata)
		}

		return nil
	})
}

func CreateMultipartUpload_with_content_type(s *S3Conf) error {
	testName := "CreateMultipartUpload_with_content_type"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		cType := "application/octet-stream"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:      &bucket,
			Key:         &obj,
			ContentType: &cType,
		})
		cancel()
		if err != nil {
			return err
		}

		parts, err := uploadParts(s3client, 100, 1, bucket, obj, *out.UploadId)
		if err != nil {
			return err
		}

		compParts := []types.CompletedPart{}
		for _, el := range parts {
			compParts = append(compParts, types.CompletedPart{
				ETag:       el.ETag,
				PartNumber: el.PartNumber,
			})
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: compParts,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		if *resp.ContentType != cType {
			return fmt.Errorf("expected uploaded object content-type to be %v, instead got %v", cType, *resp.ContentType)
		}

		return nil
	})
}

func CreateMultipartUpload_with_object_lock(s *S3Conf) error {
	testName := "CreateMultipartUpload_with_object_lock"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		retainUntilDate := time.Now().Add(24 * time.Hour)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:                    &bucket,
			Key:                       &obj,
			ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatusOn,
			ObjectLockMode:            types.ObjectLockModeGovernance,
			ObjectLockRetainUntilDate: &retainUntilDate,
		})
		cancel()
		if err != nil {
			return err
		}

		parts, err := uploadParts(s3client, 100, 1, bucket, obj, *out.UploadId)
		if err != nil {
			return err
		}

		compParts := []types.CompletedPart{}
		for _, el := range parts {
			compParts = append(compParts, types.CompletedPart{
				ETag:       el.ETag,
				PartNumber: el.PartNumber,
			})
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: compParts,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		if resp.ObjectLockLegalHoldStatus != types.ObjectLockLegalHoldStatusOn {
			return fmt.Errorf("expected uploaded object legal hold status to be %v, instead got %v", types.ObjectLockLegalHoldStatusOn, resp.ObjectLockLegalHoldStatus)
		}
		if resp.ObjectLockMode != types.ObjectLockModeGovernance {
			return fmt.Errorf("expected uploaded object lock mode to be %v, instead got %v", types.ObjectLockModeGovernance, resp.ObjectLockMode)
		}

		if err := changeBucketObjectLockStatus(s3client, bucket, false); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func CreateMultipartUpload_with_object_lock_not_enabled(s *S3Conf) error {
	testName := "CreateMultipartUpload_with_object_lock_not_enabled"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:                    &bucket,
			Key:                       &obj,
			ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatusOn,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidBucketObjectLockConfiguration)); err != nil {
			return err
		}

		return nil
	})
}

func CreateMultipartUpload_with_object_lock_invalid_retention(s *S3Conf) error {
	testName := "CreateMultipartUpload_with_object_lock_invalid_retention"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		retentionDate := time.Now().Add(24 * time.Hour)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:         &bucket,
			Key:            &obj,
			ObjectLockMode: types.ObjectLockModeGovernance,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLockInvalidHeaders)); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:                    &bucket,
			Key:                       &obj,
			ObjectLockRetainUntilDate: &retentionDate,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLockInvalidHeaders)); err != nil {
			return err
		}

		return nil
	})
}

func CreateMultipartUpload_past_retain_until_date(s *S3Conf) error {
	testName := "CreateMultipartUpload_past_retain_until_date"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		rDate := time.Now().Add(-5 * time.Hour)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:                    &bucket,
			Key:                       &obj,
			ObjectLockMode:            types.ObjectLockModeGovernance,
			ObjectLockRetainUntilDate: &rDate,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrPastObjectLockRetainDate)); err != nil {
			return err
		}

		return nil
	})
}

func CreateMultipartUpload_with_invalid_tagging(s *S3Conf) error {
	testName := "CreateMultipartUpload_with_invalid_tagging"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:  &bucket,
			Key:     &obj,
			Tagging: getPtr("invalid_tag"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidTag)); err != nil {
			return err
		}

		return nil
	})
}

func CreateMultipartUpload_with_tagging(s *S3Conf) error {
	testName := "CreateMultipartUpload_with_tagging"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		tagging := "key1=val1&key2=val2"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:  &bucket,
			Key:     &obj,
			Tagging: &tagging,
		})
		cancel()
		if err != nil {
			return err
		}

		parts, err := uploadParts(s3client, 100, 1, bucket, obj, *out.UploadId)
		if err != nil {
			return err
		}

		compParts := []types.CompletedPart{}
		for _, el := range parts {
			compParts = append(compParts, types.CompletedPart{
				ETag:       el.ETag,
				PartNumber: el.PartNumber,
			})
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: compParts,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		expectedOutput := []types.Tag{
			{
				Key:   getPtr("key1"),
				Value: getPtr("val1"),
			},
			{
				Key:   getPtr("key2"),
				Value: getPtr("val2"),
			},
		}

		if !areTagsSame(resp.TagSet, expectedOutput) {
			return fmt.Errorf("expected object tagging to be %v, instead got %v", expectedOutput, resp.TagSet)
		}

		return nil
	})
}

func CreateMultipartUpload_success(s *S3Conf) error {
	testName := "CreateMultipartUpload_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		if *out.Bucket != bucket {
			return fmt.Errorf("expected bucket name %v, instead got %v", bucket, *out.Bucket)
		}
		if *out.Key != obj {
			return fmt.Errorf("expected object name %v, instead got %v", obj, *out.Key)
		}

		return nil
	})
}

func UploadPart_non_existing_bucket(s *S3Conf) error {
	testName := "UploadPart_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		bucketName := getBucketName()
		partNumber := int32(1)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     &bucketName,
			Key:        getPtr("my-obj"),
			UploadId:   getPtr("uploadId"),
			PartNumber: &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func UploadPart_invalid_part_number(s *S3Conf) error {
	testName := "UploadPart_invalid_part_number"
	partNumber := int32(-10)
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     &bucket,
			Key:        getPtr("my-obj"),
			UploadId:   getPtr("uploadId"),
			PartNumber: &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidPart)); err != nil {
			return err
		}
		return nil
	})
}

func UploadPart_non_existing_mp_upload(s *S3Conf) error {
	testName := "UploadPart_non_existing_mp_upload"
	partNumber := int32(1)
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     &bucket,
			Key:        getPtr("my-obj"),
			UploadId:   getPtr("uploadId"),
			PartNumber: &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchUpload)); err != nil {
			return err
		}
		return nil
	})
}

func UploadPart_non_existing_key(s *S3Conf) error {
	testName := "UploadPart_non_existing_key"
	partNumber := int32(1)
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     &bucket,
			Key:        getPtr("non-existing-object-key"),
			UploadId:   out.UploadId,
			PartNumber: &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchUpload)); err != nil {
			return err
		}
		return nil
	})
}

func UploadPart_success(s *S3Conf) error {
	testName := "UploadPart_success"
	partNumber := int32(1)
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     &bucket,
			Key:        &obj,
			UploadId:   out.UploadId,
			PartNumber: &partNumber,
		})
		cancel()
		if err != nil {
			return err
		}
		if *res.ETag == "" {
			return fmt.Errorf("expected a valid etag, instead got empty")
		}
		return nil
	})
}

func UploadPartCopy_non_existing_bucket(s *S3Conf) error {
	testName := "UploadPartCopy_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		bucketName := getBucketName()
		partNumber := int32(1)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucketName,
			CopySource: getPtr("Copy-Source"),
			UploadId:   getPtr("uploadId"),
			Key:        getPtr("my-obj"),
			PartNumber: &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}
		return nil
	})
}

func UploadPartCopy_incorrect_uploadId(s *S3Conf) error {
	testName := "UploadPartCopy_incorrect_uploadId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket, srcObj := "my-obj", getBucketName(), "src-obj"
		err := setup(s, srcBucket)
		if err != nil {
			return err
		}
		err = putObjects(s3client, []string{srcObj}, srcBucket)
		if err != nil {
			return err
		}

		_, err = createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(1)
		_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			CopySource: getPtr(srcBucket + "/" + srcObj),
			UploadId:   getPtr("incorrect-upload-id"),
			Key:        &obj,
			PartNumber: &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchUpload)); err != nil {
			return err
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_incorrect_object_key(s *S3Conf) error {
	testName := "UploadPartCopy_incorrect_object_key"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket, srcObj := "my-obj", getBucketName(), "src-obj"
		err := setup(s, srcBucket)
		if err != nil {
			return err
		}
		err = putObjects(s3client, []string{srcObj}, srcBucket)
		if err != nil {
			return err
		}

		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(1)
		_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			CopySource: getPtr(srcBucket + "/" + srcObj),
			UploadId:   out.UploadId,
			Key:        getPtr("non-existing-object-key"),
			PartNumber: &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchUpload)); err != nil {
			return err
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_invalid_part_number(s *S3Conf) error {
	testName := "UploadPartCopy_invalid_part_number"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(-10)
		_, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			CopySource: getPtr("Copy-Source"),
			UploadId:   getPtr("uploadId"),
			Key:        getPtr("non-existing-object-key"),
			PartNumber: &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidPartNumber)); err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_invalid_copy_source(s *S3Conf) error {
	testName := "UploadPartCopy_invalid_copy_source"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(1)
		_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			CopySource: getPtr("invalid-copy-source"),
			UploadId:   out.UploadId,
			Key:        &obj,
			PartNumber: &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidCopySource)); err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_non_existing_source_bucket(s *S3Conf) error {
	testName := "UploadPartCopy_non_existing_source_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(1)
		_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			CopySource: getPtr("src/bucket/src/obj"),
			UploadId:   out.UploadId,
			Key:        &obj,
			PartNumber: &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_non_existing_source_object_key(s *S3Conf) error {
	testName := "UploadPartCopy_non_existing_source_object_key"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket := "my-obj", getBucketName()

		err := setup(s, srcBucket)
		if err != nil {
			return nil
		}

		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(1)
		_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			CopySource: getPtr(srcBucket + "/non/existing/obj/key"),
			UploadId:   out.UploadId,
			Key:        &obj,
			PartNumber: &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchKey)); err != nil {
			return err
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_success(s *S3Conf) error {
	testName := "UploadPartCopy_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket, srcObj := "my-obj", getBucketName(), "src-obj"
		err := setup(s, srcBucket)
		if err != nil {
			return err
		}
		objSize := 5 * 1024 * 1024
		_, _, err = putObjectWithData(int64(objSize), &s3.PutObjectInput{
			Bucket: &srcBucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(1)
		copyOut, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			CopySource: getPtr(srcBucket + "/" + srcObj),
			UploadId:   out.UploadId,
			Key:        &obj,
			PartNumber: &partNumber,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
		})
		cancel()
		if err != nil {
			return err
		}

		if len(res.Parts) != 1 {
			return fmt.Errorf("expected parts to be 1, instead got %v", len(res.Parts))
		}
		if *res.Parts[0].PartNumber != 1 {
			return fmt.Errorf("expected part-number to be 1, instead got %v", res.Parts[0].PartNumber)
		}
		if *res.Parts[0].Size != int64(objSize) {
			return fmt.Errorf("expected part size to be %v, instead got %v", objSize, res.Parts[0].Size)
		}
		if *res.Parts[0].ETag != *copyOut.CopyPartResult.ETag {
			return fmt.Errorf("expected part etag to be %v, instead got %v", *copyOut.CopyPartResult.ETag, *res.Parts[0].ETag)
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_by_range_invalid_range(s *S3Conf) error {
	testName := "UploadPartCopy_by_range_invalid_range"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket, srcObj := "my-obj", getBucketName(), "src-obj"
		err := setup(s, srcBucket)
		if err != nil {
			return err
		}
		objSize := 5 * 1024 * 1024
		_, _, err = putObjectWithData(int64(objSize), &s3.PutObjectInput{
			Bucket: &srcBucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(1)
		_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:          &bucket,
			CopySource:      getPtr(srcBucket + "/" + srcObj),
			UploadId:        out.UploadId,
			Key:             &obj,
			PartNumber:      &partNumber,
			CopySourceRange: getPtr("invalid-range"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidRange)); err != nil {
			return err
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_greater_range_than_obj_size(s *S3Conf) error {
	testName := "UploadPartCopy_greater_range_than_obj_size"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket, srcObj := "my-obj", getBucketName(), "src-obj"
		err := setup(s, srcBucket)
		if err != nil {
			return err
		}
		srcObjSize := 5 * 1024 * 1024
		_, _, err = putObjectWithData(int64(srcObjSize), &s3.PutObjectInput{
			Bucket: &srcBucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(1)
		_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:          &bucket,
			CopySource:      getPtr(srcBucket + "/" + srcObj),
			UploadId:        out.UploadId,
			Key:             &obj,
			CopySourceRange: getPtr(fmt.Sprintf("bytes=0-%v", srcObjSize+50)), // The specified range is greater than the actual object size
			PartNumber:      &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidRange)); err != nil {
			return err
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_by_range_success(s *S3Conf) error {
	testName := "UploadPartCopy_by_range_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket, srcObj := "my-obj", getBucketName(), "src-obj"
		err := setup(s, srcBucket)
		if err != nil {
			return err
		}
		objSize := 5 * 1024 * 1024
		_, _, err = putObjectWithData(int64(objSize), &s3.PutObjectInput{
			Bucket: &srcBucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(1)
		copyOut, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:          &bucket,
			CopySource:      getPtr(srcBucket + "/" + srcObj),
			CopySourceRange: getPtr("bytes=100-200"),
			UploadId:        out.UploadId,
			Key:             &obj,
			PartNumber:      &partNumber,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
		})
		cancel()
		if err != nil {
			return err
		}

		if len(res.Parts) != 1 {
			return fmt.Errorf("expected parts to be 1, instead got %v", len(res.Parts))
		}
		if *res.Parts[0].PartNumber != 1 {
			return fmt.Errorf("expected part-number to be 1, instead got %v", res.Parts[0].PartNumber)
		}
		if *res.Parts[0].Size != 101 {
			return fmt.Errorf("expected part size to be %v, instead got %v", 101, res.Parts[0].Size)
		}
		if *res.Parts[0].ETag != *copyOut.CopyPartResult.ETag {
			return fmt.Errorf("expected part etag to be %v, instead got %v", *copyOut.CopyPartResult.ETag, *res.Parts[0].ETag)
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func ListParts_incorrect_uploadId(s *S3Conf) error {
	testName := "ListParts_incorrect_uploadId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			Key:      getPtr("my-obj"),
			UploadId: getPtr("invalid uploadId"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchUpload)); err != nil {
			return err
		}

		return nil
	})
}

func ListParts_incorrect_object_key(s *S3Conf) error {
	testName := "ListParts_incorrect_object_key"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			Key:      getPtr("incorrect-object-key"),
			UploadId: out.UploadId,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchUpload)); err != nil {
			return err
		}

		return nil
	})
}

func ListParts_success(s *S3Conf) error {
	testName := "ListParts_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		parts, err := uploadParts(s3client, 5*1024*1024, 5, bucket, obj, *out.UploadId)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
		})
		cancel()
		if err != nil {
			return err
		}

		if ok := compareParts(parts, res.Parts); !ok {
			return fmt.Errorf("expected parts %+v, instead got %+v", parts, res.Parts)
		}

		return nil
	})
}

func ListMultipartUploads_non_existing_bucket(s *S3Conf) error {
	testName := "ListMultipartUploads_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		bucketName := getBucketName()
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket: &bucketName,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func ListMultipartUploads_empty_result(s *S3Conf) error {
	testName := "ListMultipartUploads_empty_result"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}
		if len(out.Uploads) != 0 {
			return fmt.Errorf("expected empty uploads, instead got %+v", out.Uploads)
		}

		return nil
	})
}

func ListMultipartUploads_invalid_max_uploads(s *S3Conf) error {
	testName := "ListMultipartUploads_invalid_max_uploads"
	maxUploads := int32(-3)
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:     &bucket,
			MaxUploads: &maxUploads,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidMaxKeys)); err != nil {
			return err
		}

		return nil
	})
}

func ListMultipartUploads_max_uploads(s *S3Conf) error {
	testName := "ListMultipartUploads_max_uploads"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		uploads := []types.MultipartUpload{}
		for i := 1; i < 6; i++ {
			out, err := createMp(s3client, bucket, fmt.Sprintf("obj%v", i))
			if err != nil {
				return err
			}
			uploads = append(uploads, types.MultipartUpload{UploadId: out.UploadId, Key: out.Key})
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		maxUploads := int32(2)
		out, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:     &bucket,
			MaxUploads: &maxUploads,
		})
		cancel()
		if err != nil {
			return err
		}
		if !*out.IsTruncated {
			return fmt.Errorf("expected the output to be truncated")
		}
		if *out.MaxUploads != 2 {
			return fmt.Errorf("expected max-uploads to be 2, instead got %v", out.MaxUploads)
		}
		if ok := compareMultipartUploads(out.Uploads, uploads[:2]); !ok {
			return fmt.Errorf("expected multipart uploads to be %v, instead got %v", uploads[:2], out.Uploads)
		}
		if *out.NextKeyMarker != *uploads[1].Key {
			return fmt.Errorf("expected next-key-marker to be %v, instead got %v", *uploads[1].Key, *out.NextKeyMarker)
		}
		if *out.NextUploadIdMarker != *uploads[1].UploadId {
			return fmt.Errorf("expected next-upload-id-marker to be %v, instead got %v", *uploads[1].Key, *out.NextKeyMarker)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err = s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:    &bucket,
			KeyMarker: out.NextKeyMarker,
		})
		cancel()
		if err != nil {
			return err
		}
		if ok := compareMultipartUploads(out.Uploads, uploads[2:]); !ok {
			return fmt.Errorf("expected multipart uploads to be %v, instead got %v", uploads[2:], out.Uploads)
		}

		return nil
	})
}

func ListMultipartUploads_incorrect_next_key_marker(s *S3Conf) error {
	testName := "ListMultipartUploads_incorrect_next_key_marker"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for i := 1; i < 6; i++ {
			_, err := createMp(s3client, bucket, fmt.Sprintf("obj%v", i))
			if err != nil {
				return err
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:    &bucket,
			KeyMarker: getPtr("incorrect_object_key"),
		})
		cancel()
		if err != nil {
			return err
		}

		if len(out.Uploads) != 0 {
			return fmt.Errorf("expected empty list of multipart uploads, instead got %v", out.Uploads)
		}

		return nil
	})
}

func ListMultipartUploads_ignore_upload_id_marker(s *S3Conf) error {
	testName := "ListMultipartUploads_ignore_upload_id_marker"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		uploads := []types.MultipartUpload{}
		for i := 1; i < 6; i++ {
			out, err := createMp(s3client, bucket, fmt.Sprintf("obj%v", i))
			if err != nil {
				return err
			}
			uploads = append(uploads, types.MultipartUpload{UploadId: out.UploadId, Key: out.Key})
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:         &bucket,
			UploadIdMarker: uploads[2].UploadId,
		})
		cancel()
		if err != nil {
			return err
		}
		if ok := compareMultipartUploads(out.Uploads, uploads); !ok {
			return fmt.Errorf("expected multipart uploads to be %v, instead got %v", uploads, out.Uploads)
		}

		return nil
	})
}

func ListMultipartUploads_success(s *S3Conf) error {
	testName := "ListMultipartUploads_max_uploads"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj1, obj2 := "my-obj-1", "my-obj-2"
		out1, err := createMp(s3client, bucket, obj1)
		if err != nil {
			return err
		}

		out2, err := createMp(s3client, bucket, obj2)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		expected := []types.MultipartUpload{
			{
				Key:      &obj1,
				UploadId: out1.UploadId,
			},
			{
				Key:      &obj2,
				UploadId: out2.UploadId,
			},
		}

		if len(out.Uploads) != 2 {
			return fmt.Errorf("expected 2 upload, instead got %v", len(out.Uploads))
		}
		if ok := compareMultipartUploads(out.Uploads, expected); !ok {
			return fmt.Errorf("expected uploads %v, instead got %v", expected, out.Uploads)
		}

		return nil
	})
}

func AbortMultipartUpload_non_existing_bucket(s *S3Conf) error {
	testName := "AbortMultipartUpload_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   getPtr("incorrectBucket"),
			Key:      getPtr("my-obj"),
			UploadId: getPtr("uploadId"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func AbortMultipartUpload_incorrect_uploadId(s *S3Conf) error {
	testName := "AbortMultipartUpload_incorrect_uploadId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   &bucket,
			Key:      getPtr("my-obj"),
			UploadId: getPtr("invalid uploadId"),
		})
		cancel()
		if err := checkSdkApiErr(err, "NoSuchUpload"); err != nil {
			return err
		}

		return nil
	})
}

func AbortMultipartUpload_incorrect_object_key(s *S3Conf) error {
	testName := "AbortMultipartUpload_incorrect_object_key"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   &bucket,
			Key:      getPtr("incorrect-object-key"),
			UploadId: out.UploadId,
		})
		cancel()
		if err := checkSdkApiErr(err, "NoSuchUpload"); err != nil {
			return err
		}

		return nil
	})
}

func AbortMultipartUpload_success(s *S3Conf) error {
	testName := "AbortMultipartUpload_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if len(res.Uploads) != 0 {
			return fmt.Errorf("expected 0 upload, instead got %v", len(res.Uploads))
		}

		return nil
	})
}

func AbortMultipartUpload_success_status_code(s *S3Conf) error {
	testName := "AbortMultipartUpload_success_status_code"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		req, err := createSignedReq(http.MethodDelete, s.endpoint, fmt.Sprintf("%v/%v?uploadId=%v", bucket, obj, *out.UploadId), s.awsID, s.awsSecret, "s3", s.awsRegion, nil, time.Now(), nil)
		if err != nil {
			return err
		}

		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusNoContent {
			return fmt.Errorf("expected response status to be %v, instead got %v", http.StatusNoContent, resp.StatusCode)
		}

		return nil
	})
}

func CompletedMultipartUpload_non_existing_bucket(s *S3Conf) error {
	testName := "CompletedMultipartUpload_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   getPtr("non-existing-bucket"),
			Key:      getPtr("some/key"),
			UploadId: getPtr("uploadId"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_invalid_part_number(s *S3Conf) error {
	testName := "CompleteMultipartUpload_invalid_part_number"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(1)
		res, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     &bucket,
			Key:        &obj,
			UploadId:   out.UploadId,
			PartNumber: &partNumber,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		partNumber = int32(5)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: []types.CompletedPart{
					{
						ETag:       res.ETag,
						PartNumber: &partNumber,
					},
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidPart)); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_invalid_ETag(s *S3Conf) error {
	testName := "CompleteMultipartUpload_invalid_ETag"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(1)
		_, err = s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     &bucket,
			Key:        &obj,
			UploadId:   out.UploadId,
			PartNumber: &partNumber,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: []types.CompletedPart{
					{
						ETag:       getPtr("invalidETag"),
						PartNumber: &partNumber,
					},
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidPart)); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_success(s *S3Conf) error {
	testName := "CompleteMultipartUpload_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		objSize := 5 * 1024 * 1024
		parts, err := uploadParts(s3client, objSize, 5, bucket, obj, *out.UploadId)
		if err != nil {
			return err
		}

		compParts := []types.CompletedPart{}
		for _, el := range parts {
			compParts = append(compParts, types.CompletedPart{
				ETag:       el.ETag,
				PartNumber: el.PartNumber,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: compParts,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if *res.Key != obj {
			return fmt.Errorf("expected object key to be %v, instead got %v", obj, *res.Key)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		if *resp.ETag != *res.ETag {
			return fmt.Errorf("expected the uploaded object etag to be %v, instead got %v", *res.ETag, *resp.ETag)
		}
		if *resp.ContentLength != int64(objSize) {
			return fmt.Errorf("expected the uploaded object size to be %v, instead got %v", objSize, resp.ContentLength)
		}

		return nil
	})
}

func PutBucketAcl_non_existing_bucket(s *S3Conf) error {
	testName := "PutBucketAcl_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: getPtr(getBucketName()),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func PutBucketAcl_invalid_acl_canned_and_acp(s *S3Conf) error {
	testName := "PutBucketAcl_invalid_acl_canned_and_acp"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket:    &bucket,
			ACL:       types.BucketCannedACLPrivate,
			GrantRead: getPtr("user1"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidRequest)); err != nil {
			return err
		}

		return nil
	})
}

func PutBucketAcl_invalid_acl_canned_and_grants(s *S3Conf) error {
	testName := "PutBucketAcl_invalid_acl_canned_and_grants"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			ACL:    types.BucketCannedACLPrivate,
			AccessControlPolicy: &types.AccessControlPolicy{
				Grants: []types.Grant{
					{
						Grantee: &types.Grantee{
							ID:   getPtr("awsID"),
							Type: types.TypeCanonicalUser,
						},
					},
				},
				Owner: &types.Owner{
					ID: &s.awsID,
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidRequest)); err != nil {
			return err
		}

		return nil
	})
}

func PutBucketAcl_invalid_acl_acp_and_grants(s *S3Conf) error {
	testName := "PutBucketAcl_invalid_acl_acp_and_grants"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket:           &bucket,
			GrantFullControl: getPtr("userAccess"),
			AccessControlPolicy: &types.AccessControlPolicy{
				Grants: []types.Grant{
					{
						Grantee: &types.Grantee{
							ID:   getPtr("awsID"),
							Type: types.TypeCanonicalUser,
						},
					},
				},
				Owner: &types.Owner{
					ID: &s.awsID,
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidRequest)); err != nil {
			return err
		}

		return nil
	})
}

func PutBucketAcl_invalid_owner(s *S3Conf) error {
	testName := "PutBucketAcl_invalid_owner"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			AccessControlPolicy: &types.AccessControlPolicy{
				Grants: []types.Grant{
					{
						Grantee: &types.Grantee{
							ID:   getPtr("awsID"),
							Type: types.TypeCanonicalUser,
						},
					},
				},
				Owner: &types.Owner{
					ID: getPtr("invalidOwner"),
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		return nil
	})
}

func PutBucketAcl_invalid_owner_not_in_body(s *S3Conf) error {
	testName := "PutBucketAcl_invalid_owner_not_in_body"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		if err := createUsers(s, []user{{"grt1", "grt1secret", "user"}}); err != nil {
			return err
		}

		newConf := *s
		newConf.awsID = "grt1"
		newConf.awsSecret = "grt1secret"
		userClient := s3.NewFromConfig(newConf.Config())

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := userClient.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			ACL:    types.BucketCannedACLPublicRead,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		return nil
	})
}

func PutBucketAcl_success_access_denied(s *S3Conf) error {
	testName := "PutBucketAcl_success_access_denied"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := createUsers(s, []user{{"grt1", "grt1secret", "user"}})
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			AccessControlPolicy: &types.AccessControlPolicy{
				Grants: []types.Grant{
					{
						Grantee: &types.Grantee{
							ID:   getPtr("grt1"),
							Type: types.TypeCanonicalUser,
						},
						Permission: types.PermissionRead,
					},
				},
				Owner: &types.Owner{
					ID: &s.awsID,
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		newConf := *s
		newConf.awsID = "grt1"
		newConf.awsSecret = "grt1secret"
		userClient := s3.NewFromConfig(newConf.Config())

		err = putObjects(userClient, []string{"my-obj"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		return nil
	})
}

func PutBucketAcl_success_canned_acl(s *S3Conf) error {
	testName := "PutBucketAcl_success_canned_acl"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := createUsers(s, []user{{"grt1", "grt1secret", "user"}})
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			ACL:    types.BucketCannedACLPublicReadWrite,
		})
		cancel()
		if err != nil {
			return err
		}

		newConf := *s
		newConf.awsID = "grt1"
		newConf.awsSecret = "grt1secret"
		userClient := s3.NewFromConfig(newConf.Config())

		err = putObjects(userClient, []string{"my-obj"}, bucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func PutBucketAcl_success_acp(s *S3Conf) error {
	testName := "PutBucketAcl_success_acp"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := createUsers(s, []user{{"grt1", "grt1secret", "user"}})
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket:    &bucket,
			GrantRead: getPtr("grt1"),
		})
		cancel()
		if err != nil {
			return err
		}

		newConf := *s
		newConf.awsID = "grt1"
		newConf.awsSecret = "grt1secret"
		userClient := s3.NewFromConfig(newConf.Config())

		err = putObjects(userClient, []string{"my-obj"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.HeadBucket(ctx, &s3.HeadBucketInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		return nil
	})
}

func PutBucketAcl_success_grants(s *S3Conf) error {
	testName := "PutBucketAcl_success_grants"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := createUsers(s, []user{{"grt1", "grt1secret", "user"}})
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			AccessControlPolicy: &types.AccessControlPolicy{
				Grants: []types.Grant{
					{
						Grantee: &types.Grantee{
							ID:   getPtr("grt1"),
							Type: types.TypeCanonicalUser,
						},
						Permission: types.PermissionFullControl,
					},
				},
				Owner: &types.Owner{
					ID: &s.awsID,
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		newConf := *s
		newConf.awsID = "grt1"
		newConf.awsSecret = "grt1secret"
		userClient := s3.NewFromConfig(newConf.Config())

		err = putObjects(userClient, []string{"my-obj"}, bucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func GetBucketAcl_non_existing_bucket(s *S3Conf) error {
	testName := "GetBucketAcl_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
			Bucket: getPtr(getBucketName()),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func GetBucketAcl_access_denied(s *S3Conf) error {
	testName := "GetBucketAcl_access_denied"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := createUsers(s, []user{{"grt1", "grt1secret", "user"}})
		if err != nil {
			return err
		}

		newConf := *s
		newConf.awsID = "grt1"
		newConf.awsSecret = "grt1secret"
		userClient := s3.NewFromConfig(newConf.Config())

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.GetBucketAcl(ctx, &s3.GetBucketAclInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		return nil
	})
}

func GetBucketAcl_success(s *S3Conf) error {
	testName := "GetBucketAcl_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := createUsers(s, []user{
			{"grt1", "grt1secret", "user"},
			{"grt2", "grt2secret", "user"},
			{"grt3", "grt3secret", "user"},
		})
		if err != nil {
			return err
		}

		grants := []types.Grant{
			{
				Grantee: &types.Grantee{
					ID:   getPtr("grt1"),
					Type: types.TypeCanonicalUser,
				},
				Permission: types.PermissionFullControl,
			},
			{
				Grantee: &types.Grantee{
					ID:   getPtr("grt2"),
					Type: types.TypeCanonicalUser,
				},
				Permission: types.PermissionReadAcp,
			},
			{
				Grantee: &types.Grantee{
					ID:   getPtr("grt3"),
					Type: types.TypeCanonicalUser,
				},
				Permission: types.PermissionWrite,
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			AccessControlPolicy: &types.AccessControlPolicy{
				Grants: grants,
				Owner: &types.Owner{
					ID: &s.awsID,
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if ok := compareGrants(out.Grants, grants); !ok {
			return fmt.Errorf("expected grants to be %v, instead got %v", grants, out.Grants)
		}
		if *out.Owner.ID != s.awsID {
			return fmt.Errorf("expected bucket owner to be %v, instead got %v", s.awsID, *out.Owner.ID)
		}

		return nil
	})
}

func PutBucketPolicy_non_existing_bucket(s *S3Conf) error {
	testName := "PutBucketPolicy_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		doc := genPolicyDoc("Allow", `"*"`, `"s3:*"`, fmt.Sprintf(`"arn:aws:s3:::%v"`, bucket))
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: getPtr("non_existing_bucket"),
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_invalid_effect(s *S3Conf) error {
	testName := "PutBucketPolicy_invalid_effect"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		doc := genPolicyDoc("invalid_effect", `"*"`, `"s3:*"`, `"arn:aws:s3:::*"`)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError("invalid effect: invalid_effect")); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_empty_actions_string(s *S3Conf) error {
	testName := "PutBucketPolicy_empty_actions_string"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		doc := genPolicyDoc("Allow", `"*"`, `""`, `"arn:aws:s3:::*"`)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError("actions can't be empty")); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_empty_actions_array(s *S3Conf) error {
	testName := "PutBucketPolicy_empty_actions_array"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		doc := genPolicyDoc("Allow", `"*"`, `[]`, `"arn:aws:s3:::*"`)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError("actions can't be empty")); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_invalid_action(s *S3Conf) error {
	testName := "PutBucketPolicy_invalid_action"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		doc := genPolicyDoc("Allow", `"*"`, `"ListObjects"`, `"arn:aws:s3:::*"`)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError("invalid action: ListObjects")); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_unsupported_action(s *S3Conf) error {
	testName := "PutBucketPolicy_unsupported_action"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		doc := genPolicyDoc("Allow", `"*"`, `"s3:PutLifecycleConfiguration"`, `"arn:aws:s3:::*"`)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError("unsupported action: s3:PutLifecycleConfiguration")); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_incorrect_action_wildcard_usage(s *S3Conf) error {
	testName := "PutBucketPolicy_incorrect_action_wildcard_usage"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		doc := genPolicyDoc("Allow", `"*"`, `"s3:hello*"`, `"arn:aws:s3:::*"`)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError("invalid wildcard usage: s3:hello prefix is not in the supported actions list")); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_empty_principals_string(s *S3Conf) error {
	testName := "PutBucketPolicy_empty_principals_string"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		doc := genPolicyDoc("Allow", `""`, `"s3:*"`, `"arn:aws:s3:::*"`)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError("principals can't be empty")); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_empty_principals_array(s *S3Conf) error {
	testName := "PutBucketPolicy_empty_principals_array"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		doc := genPolicyDoc("Allow", `[]`, `"s3:*"`, `"arn:aws:s3:::*"`)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError("principals can't be empty")); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_principals_aws_struct_empty_string(s *S3Conf) error {
	testName := "PutBucketPolicy_principals_aws_struct_empty_string"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		doc := genPolicyDoc("Allow", `{"AWS": ""}`, `"s3:*"`, `"arn:aws:s3:::*"`)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError("principals can't be empty")); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_principals_aws_struct_empty_string_slice(s *S3Conf) error {
	testName := "PutBucketPolicy_principals_aws_struct_empty_string_slice"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		doc := genPolicyDoc("Allow", `{"AWS": []}`, `"s3:*"`, `"arn:aws:s3:::*"`)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError("principals can't be empty")); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_principals_incorrect_wildcard_usage(s *S3Conf) error {
	testName := "PutBucketPolicy_principals_incorrect_wildcard_usage"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		doc := genPolicyDoc("Allow", `["*", "grt1"]`, `"s3:*"`, `"arn:aws:s3:::*"`)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError("principals should either contain * or user access keys")); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_non_existing_principals(s *S3Conf) error {
	testName := "PutBucketPolicy_non_existing_principals"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		doc := genPolicyDoc("Allow", `["a_rarely_existing_user_account_1", "a_rarely_existing_user_account_2"]`, `"s3:*"`, `"arn:aws:s3:::*"`)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		apiErr1 := getMalformedPolicyError(fmt.Sprintf("user accounts don't exist: %v", []string{"a_rarely_existing_user_account_1", "a_rarely_existing_user_account_2"}))
		apiErr2 := getMalformedPolicyError(fmt.Sprintf("user accounts don't exist: %v", []string{"a_rarely_existing_user_account_2", "a_rarely_existing_user_account_1"}))

		err1 := checkApiErr(err, apiErr1)
		err2 := checkApiErr(err, apiErr2)

		if err1 != nil && err2 != nil {
			return err1
		}

		return nil
	})
}

func PutBucketPolicy_empty_resources_string(s *S3Conf) error {
	testName := "PutBucketPolicy_empty_resources_string"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		doc := genPolicyDoc("Allow", `["*"]`, `"s3:*"`, `""`)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError("resources can't be empty")); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_empty_resources_array(s *S3Conf) error {
	testName := "PutBucketPolicy_empty_resources_array"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		doc := genPolicyDoc("Allow", `["*"]`, `"s3:*"`, `[]`)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError("resources can't be empty")); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_invalid_resource_prefix(s *S3Conf) error {
	testName := "PutBucketPolicy_invalid_resource_prefix"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		resource := fmt.Sprintf(`"arn:aws:iam:::%v"`, bucket)
		doc := genPolicyDoc("Allow", `["*"]`, `"s3:*"`, resource)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError(fmt.Sprintf("invalid resource: %v", resource[1:len(resource)-1]))); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_invalid_resource_with_starting_slash(s *S3Conf) error {
	testName := "PutBucketPolicy_invalid_resource_with_starting_slash"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		resource := fmt.Sprintf(`"arn:aws:s3:::/%v"`, bucket)
		doc := genPolicyDoc("Allow", `["*"]`, `"s3:*"`, resource)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError(fmt.Sprintf("invalid resource: %v", resource[1:len(resource)-1]))); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_duplicate_resource(s *S3Conf) error {
	testName := "PutBucketPolicy_duplicate_resource"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		resource := fmt.Sprintf(`"arn:aws:s3:::%v"`, bucket)
		doc := genPolicyDoc("Allow", `["*"]`, `"s3:*"`, fmt.Sprintf("[%v, %v]", resource, resource))

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError(fmt.Sprintf("duplicate resource: %v", resource[1:len(resource)-1]))); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_incorrect_bucket_name(s *S3Conf) error {
	testName := "PutBucketPolicy_incorrect_bucket_name"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		resource := fmt.Sprintf(`"arn:aws:s3:::prefix-%v"`, bucket)
		doc := genPolicyDoc("Allow", `["*"]`, `"s3:*"`, resource)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError(fmt.Sprintf("incorrect bucket name in prefix-%v", bucket))); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_object_action_on_bucket_resource(s *S3Conf) error {
	testName := "PutBucketPolicy_object_action_on_bucket_resource"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		resource := fmt.Sprintf(`"arn:aws:s3:::%v"`, bucket)
		doc := genPolicyDoc("Allow", `["*"]`, `"s3:PutObjectTagging"`, resource)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError("unsupported object action 's3:PutObjectTagging' on the specified resources")); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_bucket_action_on_object_resource(s *S3Conf) error {
	testName := "PutBucketPolicy_object_action_on_bucket_resource"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		resource := fmt.Sprintf(`"arn:aws:s3:::%v/*"`, bucket)
		doc := genPolicyDoc("Allow", `["*"]`, `"s3:DeleteBucket"`, resource)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError("unsupported bucket action 's3:DeleteBucket' on the specified resources")); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_success(s *S3Conf) error {
	testName := "PutBucketPolicy_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := createUsers(s, []user{
			{"grt1", "grt1secret", "user"},
			{"grt2", "grt2secret", "user"},
		})
		if err != nil {
			return err
		}

		bucketResource := fmt.Sprintf(`"arn:aws:s3:::%v"`, bucket)
		objectResource := fmt.Sprintf(`"arn:aws:s3:::%v/*"`, bucket)

		for _, doc := range []string{
			genPolicyDoc("Allow", `["grt1", "grt2"]`, `["s3:DeleteBucket", "s3:GetBucketAcl"]`, bucketResource),
			genPolicyDoc("Allow", `{"AWS": ["grt1", "grt2"]}`, `["s3:DeleteBucket", "s3:GetBucketAcl"]`, bucketResource),
			genPolicyDoc("Deny", `"*"`, `"s3:DeleteBucket"`, fmt.Sprintf(`"arn:aws:s3:::%v"`, bucket)),
			genPolicyDoc("Deny", `{"AWS": "*"}`, `"s3:DeleteBucket"`, fmt.Sprintf(`"arn:aws:s3:::%v"`, bucket)),
			genPolicyDoc("Allow", `"grt1"`, `["s3:PutBucketVersioning", "s3:ListMultipartUploadParts", "s3:ListBucket"]`, fmt.Sprintf(`[%v, %v]`, bucketResource, objectResource)),
			genPolicyDoc("Allow", `"*"`, `"s3:*"`, fmt.Sprintf(`[%v, %v]`, bucketResource, objectResource)),
			genPolicyDoc("Allow", `"*"`, `"s3:Get*"`, objectResource),
			genPolicyDoc("Deny", `"*"`, `"s3:Create*"`, fmt.Sprintf(`[%v, %v]`, bucketResource, objectResource)),
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
				Bucket: &bucket,
				Policy: &doc,
			})
			cancel()
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func GetBucketPolicy_non_existing_bucket(s *S3Conf) error {
	testName := "GetBucketPolicy_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
			Bucket: getPtr("non_existing_bucket"),
		})
		cancel()

		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}
		return nil
	})
}

func GetBucketPolicy_not_set(s *S3Conf) error {
	testName := "GetBucketPolicy_not_set"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucketPolicy)); err != nil {
			return err
		}

		return nil
	})
}

func GetBucketPolicy_success(s *S3Conf) error {
	testName := "GetBucketPolicy_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		doc := genPolicyDoc("Allow", `"*"`, `["s3:DeleteBucket", "s3:GetBucketTagging"]`, fmt.Sprintf(`"arn:aws:s3:::%v"`, bucket))
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()
		if err != nil {
			return err
		}
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if out.Policy == nil {
			return fmt.Errorf("expected non nil policy result")
		}

		if *out.Policy != doc {
			return fmt.Errorf("expected the bucket policy to be %v, instead got %v", doc, *out.Policy)
		}

		return nil
	})
}

func DeleteBucketPolicy_non_existing_bucket(s *S3Conf) error {
	testName := "DeleteBucketPolicy_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteBucketPolicy(ctx, &s3.DeleteBucketPolicyInput{
			Bucket: getPtr("non_existing_bucket"),
		})
		cancel()

		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}
		return nil
	})
}

func DeleteBucketPolicy_remove_before_setting(s *S3Conf) error {
	testName := "DeleteBucketPolicy_remove_before_setting"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteBucketPolicy(ctx, &s3.DeleteBucketPolicyInput{
			Bucket: &bucket,
		})
		cancel()

		return err
	})
}

func DeleteBucketPolicy_success(s *S3Conf) error {
	testName := "DeleteBucketPolicy_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		doc := genPolicyDoc("Allow", `"*"`, `["s3:DeleteBucket", "s3:GetBucketTagging"]`, fmt.Sprintf(`"arn:aws:s3:::%v"`, bucket))
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteBucketPolicy(ctx, &s3.DeleteBucketPolicyInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucketPolicy)); err != nil {
			return err
		}

		return nil
	})
}

// Object lock tests
func PutObjectLockConfiguration_non_existing_bucket(s *S3Conf) error {
	testName := "PutObjectLockConfiguration_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: getPtr(getBucketName()),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func PutObjectLockConfiguration_empty_config(s *S3Conf) error {
	testName := "PutObjectLockConfiguration_empty_config"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMalformedXML)); err != nil {
			return err
		}
		return nil
	})
}

func PutObjectLockConfiguration_not_enabled_on_bucket_creation(s *S3Conf) error {
	testName := "PutObjectLockConfiguration_not_enabled_on_bucket_creation"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		var days int32 = 12
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
			ObjectLockConfiguration: &types.ObjectLockConfiguration{
				ObjectLockEnabled: types.ObjectLockEnabledEnabled,
				Rule: &types.ObjectLockRule{
					DefaultRetention: &types.DefaultRetention{
						Days: &days,
						Mode: types.ObjectLockRetentionModeCompliance,
					},
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotAllowed)); err != nil {
			return err
		}
		return nil
	})
}

func PutObjectLockConfiguration_invalid_status(s *S3Conf) error {
	testName := "PutObjectLockConfiguration_invalid_status"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		var days int32 = 12
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
			ObjectLockConfiguration: &types.ObjectLockConfiguration{
				ObjectLockEnabled: types.ObjectLockEnabled("invalid_status"),
				Rule: &types.ObjectLockRule{
					DefaultRetention: &types.DefaultRetention{
						Days: &days,
					},
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMalformedXML)); err != nil {
			return err
		}
		return nil
	})
}

func PutObjectLockConfiguration_invalid_mode(s *S3Conf) error {
	testName := "PutObjectLockConfiguration_invalid_status"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		var days int32 = 12
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
			ObjectLockConfiguration: &types.ObjectLockConfiguration{
				ObjectLockEnabled: types.ObjectLockEnabledEnabled,
				Rule: &types.ObjectLockRule{
					DefaultRetention: &types.DefaultRetention{
						Days: &days,
						Mode: types.ObjectLockRetentionMode("invalid_mode"),
					},
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMalformedXML)); err != nil {
			return err
		}
		return nil
	})
}

func PutObjectLockConfiguration_both_years_and_days(s *S3Conf) error {
	testName := "PutObjectLockConfiguration_both_years_and_days"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		var days, years int32 = 12, 24
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
			ObjectLockConfiguration: &types.ObjectLockConfiguration{
				ObjectLockEnabled: types.ObjectLockEnabledEnabled,
				Rule: &types.ObjectLockRule{
					DefaultRetention: &types.DefaultRetention{
						Days:  &days,
						Years: &years,
					},
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMalformedXML)); err != nil {
			return err
		}
		return nil
	})
}

func PutObjectLockConfiguration_invalid_years_days(s *S3Conf) error {
	testName := "PutObjectLockConfiguration_invalid_years"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		var days, years int32 = -3, -5
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
			ObjectLockConfiguration: &types.ObjectLockConfiguration{
				ObjectLockEnabled: types.ObjectLockEnabledEnabled,
				Rule: &types.ObjectLockRule{
					DefaultRetention: &types.DefaultRetention{
						Days: &days,
						Mode: types.ObjectLockRetentionModeCompliance,
					},
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLockInvalidRetentionPeriod)); err != nil {
			return err
		}
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
			ObjectLockConfiguration: &types.ObjectLockConfiguration{
				ObjectLockEnabled: types.ObjectLockEnabledEnabled,
				Rule: &types.ObjectLockRule{
					DefaultRetention: &types.DefaultRetention{
						Years: &years,
						Mode:  types.ObjectLockRetentionModeCompliance,
					},
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLockInvalidRetentionPeriod)); err != nil {
			return err
		}

		return nil
	})
}

func PutObjectLockConfiguration_success(s *S3Conf) error {
	testName := "PutObjectLockConfiguration_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
			ObjectLockConfiguration: &types.ObjectLockConfiguration{
				ObjectLockEnabled: types.ObjectLockEnabledEnabled,
			},
		})
		cancel()
		if err != nil {
			return err
		}
		return nil
	}, withLock())
}

func GetObjectLockConfiguration_non_existing_bucket(s *S3Conf) error {
	testName := "GetObjectLockConfiguration_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
			Bucket: getPtr(getBucketName()),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func GetObjectLockConfiguration_unset_config(s *S3Conf) error {
	testName := "GetObjectLockConfiguration_unset_config"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound)); err != nil {
			return err
		}

		return nil
	})
}

func GetObjectLockConfiguration_success(s *S3Conf) error {
	testName := "GetObjectLockConfiguration_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		var days int32 = 20
		config := types.ObjectLockConfiguration{
			ObjectLockEnabled: types.ObjectLockEnabledEnabled,
			Rule: &types.ObjectLockRule{
				DefaultRetention: &types.DefaultRetention{
					Mode: types.ObjectLockRetentionModeCompliance,
					Days: &days,
				},
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket:                  &bucket,
			ObjectLockConfiguration: &config,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if resp.ObjectLockConfiguration == nil {
			return fmt.Errorf("got nil object lock configuration")
		}

		respConfig := resp.ObjectLockConfiguration

		if respConfig.ObjectLockEnabled != config.ObjectLockEnabled {
			return fmt.Errorf("expected lock status to be %v, instead got %v", config.ObjectLockEnabled, respConfig.ObjectLockEnabled)
		}
		if *respConfig.Rule.DefaultRetention.Days != *config.Rule.DefaultRetention.Days {
			return fmt.Errorf("expected lock config days to be %v, instead got %v", *config.Rule.DefaultRetention.Days, *respConfig.Rule.DefaultRetention.Days)
		}
		if respConfig.Rule.DefaultRetention.Mode != config.Rule.DefaultRetention.Mode {
			return fmt.Errorf("expected lock config mode to be %v, instead got %v", config.Rule.DefaultRetention.Mode, respConfig.Rule.DefaultRetention.Mode)
		}

		return nil
	}, withLock())
}

func PutObjectRetention_non_existing_bucket(s *S3Conf) error {
	testName := "PutObjectRetention_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: getPtr(getBucketName()),
			Key:    getPtr("my-obj"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func PutObjectRetention_non_existing_object(s *S3Conf) error {
	testName := "PutObjectRetention_non_existing_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		if err := changeBucketObjectLockStatus(s3client, bucket, true); err != nil {
			return err
		}

		date := time.Now().Add(time.Hour * 3)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeCompliance,
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchKey)); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func PutObjectRetention_unset_bucket_object_lock_config(s *S3Conf) error {
	testName := "PutObjectRetention_unset_bucket_object_lock_config"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		date := time.Now().Add(time.Hour * 3)
		key := "my-obj"

		if err := putObjects(s3client, []string{key}, bucket); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &key,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeCompliance,
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidBucketObjectLockConfiguration)); err != nil {
			return err
		}

		return nil
	})
}

func PutObjectRetention_disabled_bucket_object_lock_config(s *S3Conf) error {
	testName := "PutObjectRetention_disabled_bucket_object_lock_config"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket:                  &bucket,
			ObjectLockConfiguration: &types.ObjectLockConfiguration{},
		})
		cancel()
		if err != nil {
			return err
		}

		date := time.Now().Add(time.Hour * 3)
		key := "my-obj"

		if err := putObjects(s3client, []string{key}, bucket); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &key,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeCompliance,
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidBucketObjectLockConfiguration)); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func PutObjectRetention_expired_retain_until_date(s *S3Conf) error {
	testName := "PutObjectRetention_expired_retain_until_date"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		if err := changeBucketObjectLockStatus(s3client, bucket, true); err != nil {
			return err
		}

		date := time.Now().Add(-time.Hour * 3)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeCompliance,
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrPastObjectLockRetainDate)); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func PutObjectRetention_invalid_mode(s *S3Conf) error {
	testName := "PutObjectRetention_invalid_mode"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		date := time.Now().Add(time.Hour * 3)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionMode("invalid_mode"),
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMalformedXML)); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func PutObjectRetention_overwrite_compliance_mode(s *S3Conf) error {
	testName := "PutObjectRetention_overwrite_compliance_mode"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		date := time.Now().Add(time.Hour * 3)
		obj := "my-obj"
		if err := putObjects(s3client, []string{obj}, bucket); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &obj,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeCompliance,
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &obj,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeGovernance,
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMethodNotAllowed)); err != nil {
			return err
		}

		if err := changeBucketObjectLockStatus(s3client, bucket, false); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func PutObjectRetention_overwrite_governance_without_bypass_specified(s *S3Conf) error {
	testName := "PutObjectRetention_overwrite_governance_without_bypass_specified"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		date := time.Now().Add(time.Hour * 3)
		obj := "my-obj"
		if err := putObjects(s3client, []string{obj}, bucket); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &obj,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeGovernance,
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &obj,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeCompliance,
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMethodNotAllowed)); err != nil {
			return err
		}

		if err := changeBucketObjectLockStatus(s3client, bucket, false); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func PutObjectRetention_overwrite_governance_with_permission(s *S3Conf) error {
	testName := "PutObjectRetention_overwrite_governance_with_permission"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		date := time.Now().Add(time.Hour * 3)
		obj := "my-obj"
		if err := putObjects(s3client, []string{obj}, bucket); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &obj,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeGovernance,
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		policy := genPolicyDoc("Allow", `"*"`, `["s3:BypassGovernanceRetention"]`, fmt.Sprintf(`"arn:aws:s3:::%v/*"`, bucket))
		bypass := true

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &policy,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &obj,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeCompliance,
				RetainUntilDate: &date,
			},
			BypassGovernanceRetention: &bypass,
		})
		cancel()
		if err != nil {
			return err
		}

		if err := changeBucketObjectLockStatus(s3client, bucket, false); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func PutObjectRetention_success(s *S3Conf) error {
	testName := "PutObjectRetention_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		if err := changeBucketObjectLockStatus(s3client, bucket, true); err != nil {
			return err
		}

		date := time.Now().Add(time.Hour * 3)
		key := "my-obj"

		if err := putObjects(s3client, []string{key}, bucket); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &key,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeCompliance,
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if err := changeBucketObjectLockStatus(s3client, bucket, false); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func GetObjectRetention_non_existing_bucket(s *S3Conf) error {
	testName := "GetObjectRetention_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
			Bucket: getPtr(getBucketName()),
			Key:    getPtr("my-obj"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func GetObjectRetention_non_existing_object(s *S3Conf) error {
	testName := "GetObjectRetention_non_existing_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchKey)); err != nil {
			return err
		}

		return nil
	})
}

func GetObjectRetention_unset_config(s *S3Conf) error {
	testName := "GetObjectRetention_unset_config"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key := "my-obj"
		if err := putObjects(s3client, []string{key}, bucket); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
			Bucket: &bucket,
			Key:    &key,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchObjectLockConfiguration)); err != nil {
			return err
		}

		return nil
	})
}

func GetObjectRetention_success(s *S3Conf) error {
	testName := "GetObjectRetention_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		if err := changeBucketObjectLockStatus(s3client, bucket, true); err != nil {
			return err
		}
		key := "my-obj"
		if err := putObjects(s3client, []string{key}, bucket); err != nil {
			return err
		}

		date := time.Now().Add(time.Hour * 3)
		retention := types.ObjectLockRetention{
			Mode:            types.ObjectLockRetentionModeCompliance,
			RetainUntilDate: &date,
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket:    &bucket,
			Key:       &key,
			Retention: &retention,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
			Bucket: &bucket,
			Key:    &key,
		})
		cancel()
		if err != nil {
			return err
		}

		if resp.Retention == nil {
			return fmt.Errorf("got nil object lock retention")
		}

		ret := resp.Retention

		if ret.Mode != retention.Mode {
			return fmt.Errorf("expected retention mode to be %v, instead got %v", retention.Mode, ret.Mode)
		}
		// FIXME: There's a problem with storing retainUnitDate, most probably SDK changes the date before sending
		// if ret.RetainUntilDate.Format(iso8601Format)[:8] != retention.RetainUntilDate.Format(iso8601Format)[:8] {
		// 	return fmt.Errorf("expected retain until date to be %v, instead got %v", retention.RetainUntilDate.Format(iso8601Format), ret.RetainUntilDate.Format(iso8601Format))
		// }

		if err := changeBucketObjectLockStatus(s3client, bucket, false); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func PutObjectLegalHold_non_existing_bucket(s *S3Conf) error {
	testName := "PutObjectLegalHold_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
			Bucket: getPtr(getBucketName()),
			Key:    getPtr("my-obj"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func PutObjectLegalHold_non_existing_object(s *S3Conf) error {
	testName := "PutObjectLegalHold_non_existing_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		if err := changeBucketObjectLockStatus(s3client, bucket, true); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
			LegalHold: &types.ObjectLockLegalHold{
				Status: types.ObjectLockLegalHoldStatusOn,
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchKey)); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func PutObjectLegalHold_invalid_body(s *S3Conf) error {
	testName := "PutObjectLegalHold_invalid_body"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidRequest)); err != nil {
			return err
		}

		return nil
	})
}

func PutObjectLegalHold_invalid_status(s *S3Conf) error {
	testName := "PutObjectLegalHold_invalid_status"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
			LegalHold: &types.ObjectLockLegalHold{
				Status: types.ObjectLockLegalHoldStatus("invalid_status"),
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMalformedXML)); err != nil {
			return err
		}

		return nil
	})
}

func PutObjectLegalHold_unset_bucket_object_lock_config(s *S3Conf) error {
	testName := "PutObjectLegalHold_unset_bucket_object_lock_config"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key := "my-obj"

		if err := putObjects(s3client, []string{key}, bucket); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
			Bucket: &bucket,
			Key:    &key,
			LegalHold: &types.ObjectLockLegalHold{
				Status: types.ObjectLockLegalHoldStatusOn,
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidBucketObjectLockConfiguration)); err != nil {
			return err
		}

		return nil
	})
}

func PutObjectLegalHold_disabled_bucket_object_lock_config(s *S3Conf) error {
	testName := "PutObjectLegalHold_disabled_bucket_object_lock_config"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket:                  &bucket,
			ObjectLockConfiguration: &types.ObjectLockConfiguration{},
		})
		cancel()
		if err != nil {
			return err
		}

		key := "my-obj"

		if err := putObjects(s3client, []string{key}, bucket); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
			Bucket: &bucket,
			Key:    &key,
			LegalHold: &types.ObjectLockLegalHold{
				Status: types.ObjectLockLegalHoldStatusOn,
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidBucketObjectLockConfiguration)); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func PutObjectLegalHold_success(s *S3Conf) error {
	testName := "PutObjectLegalHold_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		if err := changeBucketObjectLockStatus(s3client, bucket, true); err != nil {
			return err
		}

		key := "my-obj"

		if err := putObjects(s3client, []string{key}, bucket); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
			Bucket: &bucket,
			Key:    &key,
			LegalHold: &types.ObjectLockLegalHold{
				Status: types.ObjectLockLegalHoldStatusOn,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if err := changeBucketObjectLockStatus(s3client, bucket, false); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func GetObjectLegalHold_non_existing_bucket(s *S3Conf) error {
	testName := "GetObjectLegalHold_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
			Bucket: getPtr(getBucketName()),
			Key:    getPtr("my-obj"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func GetObjectLegalHold_non_existing_object(s *S3Conf) error {
	testName := "GetObjectLegalHold_non_existing_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchKey)); err != nil {
			return err
		}

		return nil
	})
}

func GetObjectLegalHold_unset_config(s *S3Conf) error {
	testName := "GetObjectLegalHold_unset_config"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key := "my-obj"
		if err := putObjects(s3client, []string{key}, bucket); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
			Bucket: &bucket,
			Key:    &key,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchObjectLockConfiguration)); err != nil {
			return err
		}

		return nil
	})
}

func GetObjectLegalHold_success(s *S3Conf) error {
	testName := "GetObjectLegalHold_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		if err := changeBucketObjectLockStatus(s3client, bucket, true); err != nil {
			return err
		}
		key := "my-obj"
		if err := putObjects(s3client, []string{key}, bucket); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
			Bucket: &bucket,
			Key:    &key,
			LegalHold: &types.ObjectLockLegalHold{
				Status: types.ObjectLockLegalHoldStatusOn,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
			Bucket: &bucket,
			Key:    &key,
		})
		cancel()
		if err != nil {
			return err
		}

		if resp.LegalHold.Status != types.ObjectLockLegalHoldStatusOn {
			return fmt.Errorf("expected legal hold status to be On, instead got %v", resp.LegalHold.Status)
		}

		if err := changeBucketObjectLockStatus(s3client, bucket, false); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func WORMProtection_bucket_object_lock_configuration_compliance_mode(s *S3Conf) error {
	testName := "WORMProtection_bucket_object_lock_configuration_compliance_mode"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		var days int32 = 10
		object := "my-obj"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
			ObjectLockConfiguration: &types.ObjectLockConfiguration{
				ObjectLockEnabled: types.ObjectLockEnabledEnabled,
				Rule: &types.ObjectLockRule{
					DefaultRetention: &types.DefaultRetention{
						Mode: types.ObjectLockRetentionModeCompliance,
						Days: &days,
					},
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if err := putObjects(s3client, []string{object}, bucket); err != nil {
			return err
		}

		if err := checkWORMProtection(s3client, bucket, object); err != nil {
			return err
		}
		if err := changeBucketObjectLockStatus(s3client, bucket, false); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func WORMProtection_bucket_object_lock_configuration_governance_mode(s *S3Conf) error {
	testName := "WORMProtection_bucket_object_lock_configuration_governance_mode"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		var days int32 = 10
		object := "my-obj"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
			ObjectLockConfiguration: &types.ObjectLockConfiguration{
				ObjectLockEnabled: types.ObjectLockEnabledEnabled,
				Rule: &types.ObjectLockRule{
					DefaultRetention: &types.DefaultRetention{
						Mode: types.ObjectLockRetentionModeGovernance,
						Days: &days,
					},
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if err := putObjects(s3client, []string{object}, bucket); err != nil {
			return err
		}

		if err := checkWORMProtection(s3client, bucket, object); err != nil {
			return err
		}
		if err := changeBucketObjectLockStatus(s3client, bucket, false); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func WORMProtection_bucket_object_lock_governance_bypass_delete(s *S3Conf) error {
	testName := "WORMProtection_bucket_object_lock_governance_bypass_delete"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		var days int32 = 10
		object := "my-obj"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
			ObjectLockConfiguration: &types.ObjectLockConfiguration{
				ObjectLockEnabled: types.ObjectLockEnabledEnabled,
				Rule: &types.ObjectLockRule{
					DefaultRetention: &types.DefaultRetention{
						Mode: types.ObjectLockRetentionModeGovernance,
						Days: &days,
					},
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if err := putObjects(s3client, []string{object}, bucket); err != nil {
			return err
		}

		policy := genPolicyDoc("Allow", `"*"`, `["s3:BypassGovernanceRetention"]`, fmt.Sprintf(`"arn:aws:s3:::%v/*"`, bucket))
		bypass := true

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &policy,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:                    &bucket,
			Key:                       &object,
			BypassGovernanceRetention: &bypass,
		})
		cancel()
		if err != nil {
			return err
		}

		if err := changeBucketObjectLockStatus(s3client, bucket, false); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func WORMProtection_bucket_object_lock_governance_bypass_delete_multiple(s *S3Conf) error {
	testName := "WORMProtection_bucket_object_lock_governance_bypass_delete_multiple"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		var days int32 = 10
		obj1, obj2, obj3 := "my-obj-1", "my-obj-2", "my-obj-3"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
			ObjectLockConfiguration: &types.ObjectLockConfiguration{
				ObjectLockEnabled: types.ObjectLockEnabledEnabled,
				Rule: &types.ObjectLockRule{
					DefaultRetention: &types.DefaultRetention{
						Mode: types.ObjectLockRetentionModeGovernance,
						Days: &days,
					},
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if err := putObjects(s3client, []string{obj1, obj2, obj3}, bucket); err != nil {
			return err
		}

		policy := genPolicyDoc("Allow", `"*"`, `["s3:BypassGovernanceRetention"]`, fmt.Sprintf(`"arn:aws:s3:::%v/*"`, bucket))
		bypass := true

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &policy,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket:                    &bucket,
			BypassGovernanceRetention: &bypass,
			Delete: &types.Delete{
				Objects: []types.ObjectIdentifier{
					{
						Key: &obj1,
					},
					{
						Key: &obj2,
					},
					{
						Key: &obj3,
					},
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if err := changeBucketObjectLockStatus(s3client, bucket, false); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func WORMProtection_object_lock_retention_compliance_locked(s *S3Conf) error {
	testName := "WORMProtection_object_lock_retention_compliance_locked"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-obj"

		if err := putObjects(s3client, []string{object}, bucket); err != nil {
			return err
		}

		date := time.Now().Add(time.Hour * 3)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &object,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeCompliance,
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if err := checkWORMProtection(s3client, bucket, object); err != nil {
			return err
		}
		if err := changeBucketObjectLockStatus(s3client, bucket, false); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func WORMProtection_object_lock_retention_governance_locked(s *S3Conf) error {
	testName := "WORMProtection_object_lock_retention_governance_locked"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-obj"

		if err := putObjects(s3client, []string{object}, bucket); err != nil {
			return err
		}

		date := time.Now().Add(time.Hour * 3)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &object,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeGovernance,
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if err := checkWORMProtection(s3client, bucket, object); err != nil {
			return err
		}
		if err := changeBucketObjectLockStatus(s3client, bucket, false); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func WORMProtection_object_lock_retention_governance_bypass_overwrite(s *S3Conf) error {
	testName := "WORMProtection_object_lock_retention_governance_bypass_overwrite"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-obj"

		if err := putObjects(s3client, []string{object}, bucket); err != nil {
			return err
		}

		date := time.Now().Add(time.Hour * 3)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &object,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeGovernance,
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		policy := genPolicyDoc("Allow", `"*"`, `["s3:BypassGovernanceRetention"]`, fmt.Sprintf(`"arn:aws:s3:::%v/*"`, bucket))

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &policy,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &object,
		})
		cancel()
		if err != nil {
			return err
		}

		if err := changeBucketObjectLockStatus(s3client, bucket, false); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func WORMProtection_object_lock_retention_governance_bypass_delete(s *S3Conf) error {
	testName := "WORMProtection_object_lock_retention_governance_bypass_delete"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-obj"

		if err := putObjects(s3client, []string{object}, bucket); err != nil {
			return err
		}

		date := time.Now().Add(time.Hour * 3)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &object,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeGovernance,
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		policy := genPolicyDoc("Allow", `"*"`, `["s3:BypassGovernanceRetention"]`, fmt.Sprintf(`"arn:aws:s3:::%v/*"`, bucket))
		bypass := true

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &policy,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:                    &bucket,
			Key:                       &object,
			BypassGovernanceRetention: &bypass,
		})
		cancel()
		if err != nil {
			return err
		}

		if err := changeBucketObjectLockStatus(s3client, bucket, false); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func WORMProtection_object_lock_retention_governance_bypass_delete_mul(s *S3Conf) error {
	testName := "WORMProtection_object_lock_retention_governance_bypass_delete_mul"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objs := []string{"my-obj-1", "my-obj2", "my-obj-3"}

		if err := putObjects(s3client, objs, bucket); err != nil {
			return err
		}

		for _, obj := range objs {
			o := obj
			date := time.Now().Add(time.Hour * 3)
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
				Bucket: &bucket,
				Key:    &o,
				Retention: &types.ObjectLockRetention{
					Mode:            types.ObjectLockRetentionModeGovernance,
					RetainUntilDate: &date,
				},
			})
			cancel()
			if err != nil {
				return err
			}
		}

		policy := genPolicyDoc("Allow", `"*"`, `["s3:BypassGovernanceRetention"]`, fmt.Sprintf(`"arn:aws:s3:::%v/*"`, bucket))
		bypass := true

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &policy,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket:                    &bucket,
			BypassGovernanceRetention: &bypass,
			Delete: &types.Delete{
				Objects: []types.ObjectIdentifier{
					{
						Key: &objs[0],
					},
					{
						Key: &objs[1],
					},
					{
						Key: &objs[2],
					},
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if err := changeBucketObjectLockStatus(s3client, bucket, false); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func WORMProtection_object_lock_legal_hold_locked(s *S3Conf) error {
	testName := "WORMProtection_object_lock_legal_hold_locked"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		if err := changeBucketObjectLockStatus(s3client, bucket, true); err != nil {
			return err
		}

		object := "my-obj"

		if err := putObjects(s3client, []string{object}, bucket); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
			Bucket: &bucket,
			Key:    &object,
			LegalHold: &types.ObjectLockLegalHold{
				Status: types.ObjectLockLegalHoldStatusOn,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		err = putObjects(s3client, []string{object}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
			return err
		}

		if err := changeBucketObjectLockStatus(s3client, bucket, false); err != nil {
			return err
		}

		return nil
	}, withLock())
}

// Access control tests (with bucket ACLs and Policies)
func AccessControl_default_ACL_user_access_denied(s *S3Conf) error {
	testName := "AccessControl_default_ACL_user_access_denied"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		usr := user{
			access: "grt1",
			secret: "grt1secret",
			role:   "user",
		}
		err := createUsers(s, []user{usr})
		if err != nil {
			return err
		}

		cfg := *s
		cfg.awsID = usr.access
		cfg.awsSecret = usr.secret

		err = putObjects(s3.NewFromConfig(cfg.Config()), []string{"my-obj"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		return nil
	})
}

func AccessControl_default_ACL_userplus_access_denied(s *S3Conf) error {
	testName := "AccessControl_default_ACL_userplus_access_denied"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		usr := user{
			access: "userplus1",
			secret: "userplus1secret",
			role:   "userplus",
		}
		err := createUsers(s, []user{usr})
		if err != nil {
			return err
		}

		cfg := *s
		cfg.awsID = usr.access
		cfg.awsSecret = usr.secret

		err = putObjects(s3.NewFromConfig(cfg.Config()), []string{"my-obj"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		return nil
	})
}

func AccessControl_default_ACL_admin_successful_access(s *S3Conf) error {
	testName := "AccessControl_default_ACL_admin_successful_access"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		admin := user{
			access: "admin1",
			secret: "admin1secret",
			role:   "admin",
		}
		err := createUsers(s, []user{admin})
		if err != nil {
			return err
		}

		cfg := *s
		cfg.awsID = admin.access
		cfg.awsSecret = admin.secret

		err = putObjects(s3.NewFromConfig(cfg.Config()), []string{"my-obj"}, bucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func AccessControl_bucket_resource_single_action(s *S3Conf) error {
	testName := "AccessControl_bucket_resource_single_action"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		usr1 := user{
			access: "grt1",
			secret: "grt1secret",
			role:   "user",
		}
		usr2 := user{
			access: "grt2",
			secret: "grt2secret",
			role:   "user",
		}
		err := createUsers(s, []user{usr1, usr2})
		if err != nil {
			return err
		}

		doc := genPolicyDoc("Allow", `["grt1"]`, `"s3:PutBucketTagging"`, fmt.Sprintf(`"arn:aws:s3:::%v"`, bucket))
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()
		if err != nil {
			return err
		}

		user1Client := getUserS3Client(usr1, s)

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = user1Client.DeleteBucketTagging(ctx, &s3.DeleteBucketTaggingInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = user1Client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		user2Client := getUserS3Client(usr2, s)

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = user2Client.DeleteBucketTagging(ctx, &s3.DeleteBucketTaggingInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		return nil
	})
}

func AccessControl_bucket_resource_all_action(s *S3Conf) error {
	testName := "AccessControl_bucket_resource_all_action"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		usr1 := user{
			access: "grt1",
			secret: "grt1secret",
			role:   "user",
		}
		usr2 := user{
			access: "grt2",
			secret: "grt2secret",
			role:   "user",
		}
		err := createUsers(s, []user{usr1, usr2})
		if err != nil {
			return err
		}

		bucketResource := fmt.Sprintf(`"arn:aws:s3:::%v"`, bucket)
		objectResource := fmt.Sprintf(`"arn:aws:s3:::%v/*"`, bucket)
		doc := genPolicyDoc("Allow", `["grt1"]`, `"s3:*"`, fmt.Sprintf(`[%v, %v]`, bucketResource, objectResource))

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()
		if err != nil {
			return err
		}

		user1Client := getUserS3Client(usr1, s)
		err = putObjects(user1Client, []string{"my-obj"}, bucket)
		if err != nil {
			return err
		}

		user2Client := getUserS3Client(usr2, s)

		err = putObjects(user2Client, []string{"my-obj"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		return nil
	})
}

func AccessControl_single_object_resource_actions(s *S3Conf) error {
	testName := "AccessControl_single_object_resource_actions"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj/nested-obj"
		err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		usr1 := user{
			access: "grt1",
			secret: "grt1secret",
			role:   "user",
		}
		err = createUsers(s, []user{usr1})
		if err != nil {
			return err
		}

		doc := genPolicyDoc("Allow", `["grt1"]`, `"s3:*"`, fmt.Sprintf(`"arn:aws:s3:::%v/%v"`, bucket, obj))

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()
		if err != nil {
			return err
		}

		user1Client := getUserS3Client(usr1, s)

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = user1Client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = user1Client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		return nil
	})
}

func AccessControl_multi_statement_policy(s *S3Conf) error {
	testName := "AccessControl_multi_statement_policy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		policy := fmt.Sprintf(`
		{
			"Statement": [
				{
					"Effect": "Deny",
					"Principal": ["grt1"],
					"Action":  "s3:DeleteBucket",
					"Resource":  "arn:aws:s3:::%s"
				},
				{
					"Effect": "Allow",
					"Principal": "grt1",
					"Action": "s3:*",
					"Resource": ["arn:aws:s3:::%s", "arn:aws:s3:::%s/*"]
				}
			]
		}	
		`, bucket, bucket, bucket)

		usr := user{
			access: "grt1",
			secret: "grt1secret",
			role:   "user",
		}
		err := createUsers(s, []user{usr})
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &policy,
		})
		cancel()
		if err != nil {
			return err
		}

		userClient := getUserS3Client(usr, s)

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.DeleteBucket(ctx, &s3.DeleteBucketInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		return nil
	})
}

// IAM related tests
// multi-user iam tests
func IAM_user_access_denied(s *S3Conf) error {
	testName := "IAM_user_access_denied"
	runF(testName)

	usr := user{
		access: "grt1",
		secret: "grt1secret",
		role:   "user",
	}

	err := createUsers(s, []user{usr})
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	out, err := execCommand("admin", "-a", usr.access, "-s", usr.secret, "-er", s.endpoint, "delete-user", "-a", "random_access")
	if err == nil {
		failF("%v: expected cmd error", testName)
		return fmt.Errorf("%v: expected cmd error", testName)
	}
	if !strings.Contains(string(out), adminAccessDeniedMsg) {
		failF("%v: expected response error message to be %v, instead got %s", testName, adminAccessDeniedMsg, out)
		return fmt.Errorf("%v: expected response error message to be %v, instead got %s", testName, adminAccessDeniedMsg, out)
	}

	passF(testName)

	return nil
}

func IAM_userplus_access_denied(s *S3Conf) error {
	testName := "IAM_userplus_access_denied"
	runF(testName)

	usr := user{
		access: "grt1",
		secret: "grt1secret",
		role:   "userplus",
	}

	err := createUsers(s, []user{usr})
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	out, err := execCommand("admin", "-a", usr.access, "-s", usr.secret, "-er", s.endpoint, "delete-user", "-a", "random_access")
	if err == nil {
		failF("%v: expected cmd error", testName)
		return fmt.Errorf("%v: expected cmd error", testName)
	}
	if !strings.Contains(string(out), adminAccessDeniedMsg) {
		failF("%v: expected response error message to be %v, instead got %s", testName, adminAccessDeniedMsg, out)
		return fmt.Errorf("%v: expected response error message to be %v, instead got %s", testName, adminAccessDeniedMsg, out)
	}

	passF(testName)

	return nil
}

func IAM_userplus_CreateBucket(s *S3Conf) error {
	testName := "IAM_userplus_CreateBucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		usr := user{
			access: "grt1",
			secret: "grt1secret",
			role:   "userplus",
		}

		err := createUsers(s, []user{usr})
		if err != nil {
			return err
		}

		cfg := *s
		cfg.awsID = usr.access
		cfg.awsSecret = usr.secret

		bckt := getBucketName()
		err = setup(&cfg, bckt)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &bckt})
		cancel()
		if err != nil {
			return err
		}

		err = teardown(&cfg, bckt)
		if err != nil {
			return err
		}

		return nil
	})
}

func IAM_admin_ChangeBucketOwner(s *S3Conf) error {
	testName := "IAM_admin_ChangeBucketOwner"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		admin := user{
			access: "admin1",
			secret: "admin1secret",
			role:   "admin",
		}
		usr := user{
			access: "grt1",
			secret: "grt1secret",
			role:   "user",
		}
		err := createUsers(s, []user{admin, usr})
		if err != nil {
			return err
		}

		err = changeBucketsOwner(s, []string{bucket}, usr.access)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: &bucket})
		cancel()
		if err != nil {
			return err
		}

		if *resp.Owner.ID != usr.access {
			return fmt.Errorf("expected the bucket owner to be %v, instead got %v", usr.access, *resp.Owner.ID)
		}

		return nil
	})
}

// Posix related tests
func PutObject_overwrite_dir_obj(s *S3Conf) error {
	testName := "PutObject_overwrite_dir_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putObjects(s3client, []string{"foo/", "foo"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrExistingObjectIsDirectory)); err != nil {
			return err
		}
		return nil
	})
}

func PutObject_overwrite_file_obj(s *S3Conf) error {
	testName := "PutObject_overwrite_file_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putObjects(s3client, []string{"foo", "foo/"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectParentIsFile)); err != nil {
			return err
		}
		return nil
	})
}

func PutObject_dir_obj_with_data(s *S3Conf) error {
	testName := "PutObject_dir_obj_with_data"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, _, err := putObjectWithData(int64(20), &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    getPtr("obj/"),
		}, s3client)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrDirectoryObjectContainsData)); err != nil {
			return err
		}
		return nil
	})
}

func CreateMultipartUpload_dir_obj(s *S3Conf) error {
	testName := "CreateMultipartUpload_dir_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := createMp(s3client, bucket, "obj/")
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrDirectoryObjectContainsData)); err != nil {
			return err
		}
		return nil
	})
}
