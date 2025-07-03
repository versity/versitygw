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
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/versity/versitygw/s3err"
	"golang.org/x/sync/errgroup"
)

var (
	shortTimeout  = 30 * time.Second
	longTimeout   = 60 * time.Second
	iso8601Format = "20060102T150405Z"
	timefmt       = "Mon, 02 Jan 2006 15:04:05 GMT"
	nullVersionId = "null"
)

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
		req.Header.Set("Authorization", "invalid_header")

		resp, err := s.httpClient.Do(req)
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

		resp, err := s.httpClient.Do(req)
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

		resp, err := s.httpClient.Do(req)
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

		resp, err := s.httpClient.Do(req)
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

		resp, err := s.httpClient.Do(req)
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

		resp, err := s.httpClient.Do(req)
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
		apiErr := s3err.APIError{
			Code:           "SignatureDoesNotMatch",
			Description:    fmt.Sprintf("Credential should be scoped to a valid Region, not %v", cfg.awsRegion),
			HTTPStatusCode: http.StatusForbidden,
		}

		resp, err := s.httpClient.Do(req)
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

		resp, err := s.httpClient.Do(req)
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

		resp, err := s.httpClient.Do(req)
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

		resp, err := s.httpClient.Do(req)
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

		resp, err := s.httpClient.Do(req)
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

		resp, err := s.httpClient.Do(req)
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
		req.Header.Set("X-Amz-Date", "")

		resp, err := s.httpClient.Do(req)
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
		req.Header.Set("X-Amz-Date", "03032006")

		resp, err := s.httpClient.Do(req)
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
		req.Header.Set("X-Amz-Date", "20220830T095525Z")

		resp, err := s.httpClient.Do(req)
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
		req.Header.Set("X-Amz-Content-Sha256", "7sa6df576dsa5f675sad67f")

		resp, err := s.httpClient.Do(req)
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

		req.Header.Set("Content-Md5", "sadfasdf87sad6f87==")

		resp, err := s.httpClient.Do(req)
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

		resp, err := s.httpClient.Do(req)
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

func PresignedAuth_unsupported_algorithm(s *S3Conf) error {
	testName := "PresignedAuth_unsupported_algorithm"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: getPtr("my-bucket")})
		cancel()
		if err != nil {
			return err
		}

		uri := strings.Replace(v4req.URL, "AWS4-HMAC-SHA256", "AWS4-SHA256", 1)

		req, err := http.NewRequest(v4req.Method, uri, nil)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
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

		resp, err := s.httpClient.Do(req)
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

		resp, err := s.httpClient.Do(req)
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

		uri, err := changeAuthCred(v4req.URL, "aws5_request", credTerminator)
		if err != nil {
			return err
		}

		req, err := http.NewRequest(v4req.Method, uri, nil)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
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

		uri, err := changeAuthCred(v4req.URL, "sns", credService)
		if err != nil {
			return err
		}

		req, err := http.NewRequest(v4req.Method, uri, nil)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
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

		req, err := http.NewRequest(v4req.Method, v4req.URL, nil)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
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

		uri, err := changeAuthCred(v4req.URL, "32234Z34", credDate)
		if err != nil {
			return err
		}

		req, err := http.NewRequest(v4req.Method, uri, nil)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
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

		uri, err := changeAuthCred(v4req.URL, "a_rarely_existing_access_key_id890asd6f807as6ydf870say", credAccess)
		if err != nil {
			return err
		}

		req, err := http.NewRequest(v4req.Method, uri, nil)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
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

		resp, err := s.httpClient.Do(req)
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

		uri, err := changeAuthCred(v4req.URL, "20060102", credDate)
		if err != nil {
			return err
		}

		req, err := http.NewRequest(v4req.Method, uri, nil)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
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

		resp, err := s.httpClient.Do(req)
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

		resp, err := s.httpClient.Do(req)
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

		resp, err := s.httpClient.Do(req)
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

		resp, err := s.httpClient.Do(req)
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

		resp, err := s.httpClient.Do(req)
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

		resp, err := s.httpClient.Do(req)
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

		req, err := http.NewRequest(v4req.Method, v4req.URL, nil)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
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

		req, err := http.NewRequest(http.MethodPut, v4req.URL, nil)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
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

		req, err := http.NewRequest(v4req.Method, v4req.URL, body)
		if err != nil {
			return err
		}

		req.Header = v4req.SignedHeader

		resp, err := s.httpClient.Do(req)
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

		resp, err = s.httpClient.Do(req)
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
	testName := "PresignedAuth_Put_GetObject_with_UTF8_chars"
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

		req, err := http.NewRequest(v4req.Method, v4req.URL, nil)
		if err != nil {
			return err
		}

		req.Header = v4req.SignedHeader

		resp, err := s.httpClient.Do(req)
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

		resp, err = s.httpClient.Do(req)
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

		clt := s.GetClient()
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

		req, err := http.NewRequest(v4req.Method, v4req.URL, nil)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
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
		if getString(out.Parts[0].ETag) != etag {
			return fmt.Errorf("expected uploaded part etag to be %v, instead got %v", etag, getString(out.Parts[0].ETag))
		}
		if out.Parts[0].PartNumber == nil {
			return fmt.Errorf("expected uploaded part part-number to be not nil")
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

func CreateBucket_invalid_ownership(s *S3Conf) error {
	testName := "CreateBucket_invalid_ownership"
	runF(testName)

	invalidOwnership := types.ObjectOwnership("invalid_ownership")
	err := setup(s, getBucketName(), withOwnership(invalidOwnership))
	if err := checkApiErr(err, s3err.APIError{
		Code:           "InvalidArgument",
		Description:    fmt.Sprintf("Invalid x-amz-object-ownership header: %v", invalidOwnership),
		HTTPStatusCode: http.StatusBadRequest,
	}); err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	passF(testName)
	return nil
}

func CreateBucket_ownership_with_acl(s *S3Conf) error {
	testName := "CreateBucket_ownership_with_acl"

	runF(testName)
	client := s.GetClient()

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	_, err := client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket:          getPtr(getBucketName()),
		ObjectOwnership: types.ObjectOwnershipBucketOwnerEnforced,
		ACL:             types.BucketCannedACLPublicRead,
	})
	cancel()
	if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidBucketAclWithObjectOwnership)); err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	passF(testName)
	return nil
}

func CreateBucket_default_acl(s *S3Conf) error {
	testName := "CreateBucket_default_acl"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: &bucket})
		cancel()
		if err != nil {
			return err
		}

		if getString(out.Owner.ID) != s.awsID {
			return fmt.Errorf("expected bucket owner to be %v, instead got %v",
				s.awsID, getString(out.Owner.ID))
		}
		if len(out.Grants) != 1 {
			return fmt.Errorf("expected grants length to be 1, instead got %v",
				len(out.Grants))
		}
		grt := out.Grants[0]
		if grt.Permission != types.PermissionFullControl {
			return fmt.Errorf("expected the grantee to have full-control permission, instead got %v",
				grt.Permission)
		}
		if getString(grt.Grantee.ID) != s.awsID {
			return fmt.Errorf("expected the grantee id to be %v, instead got %v",
				s.awsID, getString(grt.Grantee.ID))
		}

		return nil
	})
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
				ID:   &s.awsID,
				Type: types.TypeCanonicalUser,
			},
			Permission: types.PermissionFullControl,
		},
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

	bucket := getBucketName()
	client := s.GetClient()

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	_, err = client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket:           &bucket,
		GrantFullControl: getPtr("grt1"),
		GrantReadACP:     getPtr("grt2"),
		GrantWrite:       getPtr("grt3"),
		ObjectOwnership:  types.ObjectOwnershipBucketOwnerPreferred,
	})
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

	client := s.GetClient()

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
		if getString(resp.BucketRegion) != s.awsRegion {
			return fmt.Errorf("expected bucket region to be %v, instead got %v",
				s.awsRegion, getString(resp.BucketRegion))
		}

		return nil
	})
}

func ListBuckets_as_user(s *S3Conf) error {
	testName := "ListBuckets_as_user"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		buckets := []types.Bucket{{Name: &bucket}}
		for range 6 {
			bckt := getBucketName()

			err := setup(s, bckt)
			if err != nil {
				return err
			}

			buckets = append(buckets, types.Bucket{
				Name: &bckt,
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
		for i := range 3 {
			bckts = append(bckts, *buckets[i].Name)
		}

		err = changeBucketsOwner(s, bckts, usr.access)
		if err != nil {
			return err
		}

		userClient := cfg.GetClient()

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := userClient.ListBuckets(ctx, &s3.ListBucketsInput{})
		cancel()
		if err != nil {
			return err
		}

		if getString(out.Owner.ID) != usr.access {
			return fmt.Errorf("expected buckets owner to be %v, instead got %v",
				usr.access, getString(out.Owner.ID))
		}
		if !compareBuckets(out.Buckets, buckets[:3]) {
			return fmt.Errorf("expected list buckets result to be %v, instead got %v",
				buckets[:3], out.Buckets)
		}

		for _, elem := range buckets[1:] {
			err = teardown(s, *elem.Name)
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
		buckets := []types.Bucket{{Name: &bucket}}
		for range 6 {
			bckt := getBucketName()

			err := setup(s, bckt)
			if err != nil {
				return err
			}

			buckets = append(buckets, types.Bucket{
				Name: &bckt,
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
		for i := range 3 {
			bckts = append(bckts, *buckets[i].Name)
		}

		err = changeBucketsOwner(s, bckts, usr.access)
		if err != nil {
			return err
		}

		adminClient := cfg.GetClient()

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := adminClient.ListBuckets(ctx, &s3.ListBucketsInput{})
		cancel()
		if err != nil {
			return err
		}

		if getString(out.Owner.ID) != admin.access {
			return fmt.Errorf("expected buckets owner to be %v, instead got %v",
				admin.access, getString(out.Owner.ID))
		}
		if !compareBuckets(out.Buckets, buckets) {
			return fmt.Errorf("expected list buckets result to be %v, instead got %v",
				buckets, out.Buckets)
		}

		for _, elem := range buckets[1:] {
			err = teardown(s, *elem.Name)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func ListBuckets_with_prefix(s *S3Conf) error {
	testName := "ListBuckets_with_prefix"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		prefix := "my-prefix-"
		allBuckets, prefixedBuckets := []types.Bucket{{Name: &bucket}}, []types.Bucket{}
		for i := range 5 {
			bckt := getBucketName()
			if i%2 == 0 {
				bckt = prefix + bckt
			}

			err := setup(s, bckt)
			if err != nil {
				return err
			}

			allBuckets = append(allBuckets, types.Bucket{
				Name: &bckt,
			})

			if i%2 == 0 {
				prefixedBuckets = append(prefixedBuckets, types.Bucket{
					Name: &bckt,
				})
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListBuckets(ctx, &s3.ListBucketsInput{
			Prefix: &prefix,
		})
		cancel()
		if err != nil {
			return err
		}

		if getString(out.Owner.ID) != s.awsID {
			return fmt.Errorf("expected owner to be %v, instead got %v",
				s.awsID, getString(out.Owner.ID))
		}
		if getString(out.Prefix) != prefix {
			return fmt.Errorf("expected prefix to be %v, instead got %v",
				prefix, getString(out.Prefix))
		}
		if !compareBuckets(out.Buckets, prefixedBuckets) {
			return fmt.Errorf("expected list buckets result to be %v, instead got %v",
				prefixedBuckets, out.Buckets)
		}

		for _, elem := range allBuckets[1:] {
			err = teardown(s, *elem.Name)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func ListBuckets_invalid_max_buckets(s *S3Conf) error {
	testName := "ListBuckets_invalid_max_buckets"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		listBuckets := func(maxBuckets int32) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.ListBuckets(ctx, &s3.ListBucketsInput{
				MaxBuckets: &maxBuckets,
			})
			cancel()
			return err
		}

		invMaxBuckets := int32(-3)
		err := listBuckets(invMaxBuckets)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidMaxBuckets)); err != nil {
			return err
		}

		invMaxBuckets = 2000000
		err = listBuckets(invMaxBuckets)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidMaxBuckets)); err != nil {
			return err
		}

		return nil
	})
}

func ListBuckets_truncated(s *S3Conf) error {
	testName := "ListBuckets_truncated"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		buckets := []types.Bucket{{Name: &bucket}}
		for range 5 {
			bckt := getBucketName()

			err := setup(s, bckt)
			if err != nil {
				return err
			}

			buckets = append(buckets, types.Bucket{
				Name: &bckt,
			})
		}

		maxBuckets := int32(3)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListBuckets(ctx, &s3.ListBucketsInput{
			MaxBuckets: &maxBuckets,
		})
		cancel()
		if err != nil {
			return err
		}

		if getString(out.Owner.ID) != s.awsID {
			return fmt.Errorf("expected owner to be %v, instead got %v",
				s.awsID, getString(out.Owner.ID))
		}
		if !compareBuckets(out.Buckets, buckets[:maxBuckets]) {
			return fmt.Errorf("expected list buckets result to be %v, instead got %v",
				buckets[:maxBuckets], out.Buckets)
		}
		if getString(out.ContinuationToken) != getString(buckets[maxBuckets-1].Name) {
			return fmt.Errorf("expected ContinuationToken to be %v, instead got %v",
				getString(buckets[maxBuckets-1].Name), getString(out.ContinuationToken))
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err = s3client.ListBuckets(ctx, &s3.ListBucketsInput{
			ContinuationToken: out.ContinuationToken,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareBuckets(out.Buckets, buckets[maxBuckets:]) {
			return fmt.Errorf("expected list buckets result to be %v, instead got %v",
				buckets[maxBuckets:], out.Buckets)
		}
		if out.ContinuationToken != nil {
			return fmt.Errorf("expected nil continuation token, instead got %v",
				*out.ContinuationToken)
		}
		if out.Prefix != nil {
			return fmt.Errorf("expected nil prefix, instead got %v", *out.Prefix)
		}

		for _, elem := range buckets[1:] {
			err = teardown(s, *elem.Name)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func ListBuckets_empty_success(s *S3Conf) error {
	testName := "ListBuckets_empty_success"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListBuckets(ctx, &s3.ListBucketsInput{})
		cancel()
		if err != nil {
			return err
		}

		if len(out.Buckets) > 0 {
			return fmt.Errorf("expected list buckets result to be %v, instead got %v",
				[]types.Bucket{}, out.Buckets)
		}

		return nil
	})
}

func ListBuckets_success(s *S3Conf) error {
	testName := "ListBuckets_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		buckets := []types.Bucket{{Name: &bucket}}
		for range 5 {
			bckt := getBucketName()

			err := setup(s, bckt)
			if err != nil {
				return err
			}

			buckets = append(buckets, types.Bucket{
				Name: &bckt,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListBuckets(ctx, &s3.ListBucketsInput{})
		cancel()
		if err != nil {
			return err
		}

		if getString(out.Owner.ID) != s.awsID {
			return fmt.Errorf("expected owner to be %v, instead got %v",
				s.awsID, getString(out.Owner.ID))
		}
		if !compareBuckets(out.Buckets, buckets) {
			return fmt.Errorf("expected list buckets result to be %v, instead got %v",
				buckets, out.Buckets)
		}

		for _, elem := range buckets[1:] {
			err = teardown(s, *elem.Name)
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
	s3client := s.GetClient()

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
		_, err := putObjects(s3client, []string{"foo"}, bucket)
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

	resp, err := s.httpClient.Do(req)
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

func PutBucketOwnershipControls_non_existing_bucket(s *S3Conf) error {
	testName := "PutBucketOwnershipControls_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketOwnershipControls(ctx, &s3.PutBucketOwnershipControlsInput{
			Bucket: getPtr(getBucketName()),
			OwnershipControls: &types.OwnershipControls{
				Rules: []types.OwnershipControlsRule{
					{
						ObjectOwnership: types.ObjectOwnershipBucketOwnerPreferred,
					},
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func PutBucketOwnershipControls_multiple_rules(s *S3Conf) error {
	testName := "PutBucketOwnershipControls_multiple_rules"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketOwnershipControls(ctx, &s3.PutBucketOwnershipControlsInput{
			Bucket: &bucket,
			OwnershipControls: &types.OwnershipControls{
				Rules: []types.OwnershipControlsRule{
					{
						ObjectOwnership: types.ObjectOwnershipBucketOwnerPreferred,
					},
					{
						ObjectOwnership: types.ObjectOwnershipObjectWriter,
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

func PutBucketOwnershipControls_invalid_ownership(s *S3Conf) error {
	testName := "PutBucketOwnershipControls_invalid_ownership"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketOwnershipControls(ctx, &s3.PutBucketOwnershipControlsInput{
			Bucket: &bucket,
			OwnershipControls: &types.OwnershipControls{
				Rules: []types.OwnershipControlsRule{
					{
						ObjectOwnership: types.ObjectOwnership("invalid_ownership"),
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

func PutBucketOwnershipControls_success(s *S3Conf) error {
	testName := "PutBucketOwnershipControls_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketOwnershipControls(ctx, &s3.PutBucketOwnershipControlsInput{
			Bucket: &bucket,
			OwnershipControls: &types.OwnershipControls{
				Rules: []types.OwnershipControlsRule{
					{
						ObjectOwnership: types.ObjectOwnershipObjectWriter,
					},
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		return nil
	})
}

func GetBucketOwnershipControls_non_existing_bucket(s *S3Conf) error {
	testName := "GetBucketOwnershipControls_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetBucketOwnershipControls(ctx, &s3.GetBucketOwnershipControlsInput{
			Bucket: getPtr(getBucketName()),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func GetBucketOwnershipControls_default_ownership(s *S3Conf) error {
	testName := "GetBucketOwnershipControls_default_ownership"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.GetBucketOwnershipControls(ctx, &s3.GetBucketOwnershipControlsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if len(resp.OwnershipControls.Rules) != 1 {
			return fmt.Errorf("expected ownership control rules length to be 1, instead got %v", len(resp.OwnershipControls.Rules))
		}
		if resp.OwnershipControls.Rules[0].ObjectOwnership != types.ObjectOwnershipBucketOwnerEnforced {
			return fmt.Errorf("expected the bucket ownership to be %v, instead got %v", types.ObjectOwnershipBucketOwnerEnforced, resp.OwnershipControls.Rules[0].ObjectOwnership)
		}

		return nil
	})
}

func GetBucketOwnershipControls_success(s *S3Conf) error {
	testName := "GetBucketOwnershipControls_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketOwnershipControls(ctx, &s3.PutBucketOwnershipControlsInput{
			Bucket: &bucket,
			OwnershipControls: &types.OwnershipControls{
				Rules: []types.OwnershipControlsRule{
					{
						ObjectOwnership: types.ObjectOwnershipObjectWriter,
					},
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.GetBucketOwnershipControls(ctx, &s3.GetBucketOwnershipControlsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if len(resp.OwnershipControls.Rules) != 1 {
			return fmt.Errorf("expected ownership control rules length to be 1, instead got %v", len(resp.OwnershipControls.Rules))
		}
		if resp.OwnershipControls.Rules[0].ObjectOwnership != types.ObjectOwnershipObjectWriter {
			return fmt.Errorf("expected the bucket ownership to be %v, instead got %v", types.ObjectOwnershipObjectWriter, resp.OwnershipControls.Rules[0].ObjectOwnership)
		}

		return nil
	})
}

func DeleteBucketOwnershipControls_non_existing_bucket(s *S3Conf) error {
	testName := "DeleteBucketOwnershipControls_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteBucketOwnershipControls(ctx, &s3.DeleteBucketOwnershipControlsInput{
			Bucket: getPtr(getBucketName()),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func DeleteBucketOwnershipControls_success(s *S3Conf) error {
	testName := "DeleteBucketOwnershipControls_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteBucketOwnershipControls(ctx, &s3.DeleteBucketOwnershipControlsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetBucketOwnershipControls(ctx, &s3.GetBucketOwnershipControlsInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrOwnershipControlsNotFound)); err != nil {
			return err
		}

		return nil
	})
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
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidTagKey)); err != nil {
			return err
		}

		tagging = types.Tagging{TagSet: []types.Tag{{Key: getPtr("key"), Value: getPtr(genRandString(300))}}}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
			Bucket:  &bucket,
			Tagging: &tagging})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidTagValue)); err != nil {
			return err
		}

		return nil
	})
}

func PutBucketTagging_duplicate_keys(s *S3Conf) error {
	testName := "PutBucketTagging_duplicate_keys"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		tagging := types.Tagging{
			TagSet: []types.Tag{
				{Key: getPtr("key"), Value: getPtr("value")},
				{Key: getPtr("key"), Value: getPtr("value-1")},
				{Key: getPtr("key-1"), Value: getPtr("value-2")},
				{Key: getPtr("key-2"), Value: getPtr("value-3")},
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
			Bucket:  &bucket,
			Tagging: &tagging,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrDuplicateTagKey)); err != nil {
			return err
		}

		return nil
	})
}

func PutBucketTagging_tag_count_limit(s *S3Conf) error {
	testName := "PutBucketTagging_tag_count_limit"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		tagSet := []types.Tag{}

		for i := range 51 {
			tagSet = append(tagSet, types.Tag{
				Key:   getPtr(fmt.Sprintf("key-%v", i)),
				Value: getPtr(genRandString(10)),
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
			Bucket: &bucket,
			Tagging: &types.Tagging{
				TagSet: tagSet,
			},
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrBucketTaggingLimited))
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

func PutBucketTagging_success_status(s *S3Conf) error {
	testName := "PutBucketTagging_success_status"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		tagging := types.Tagging{
			TagSet: []types.Tag{
				{
					Key:   getPtr("key"),
					Value: getPtr("val"),
				},
			},
		}

		taggingParsed, err := xml.Marshal(tagging)
		if err != nil {
			return fmt.Errorf("err parsing tagging: %w", err)
		}

		req, err := createSignedReq(http.MethodPut, s.endpoint, fmt.Sprintf("%v?tagging=", bucket), s.awsID, s.awsSecret, "s3", s.awsRegion, taggingParsed, time.Now(), nil)
		if err != nil {
			return fmt.Errorf("err signing the request: %w", err)
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("err sending request: %w", err)
		}

		if resp.StatusCode != http.StatusNoContent {
			return fmt.Errorf("expected the response status code to be %v, instad got %v", http.StatusNoContent, resp.StatusCode)
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

		resp, err := s.httpClient.Do(req)
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
		_, err := putObjects(s3client, []string{"my-obj"}, "non-existing-bucket")
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}
		return nil
	})
}

func PutObject_special_chars(s *S3Conf) error {
	testName := "PutObject_special_chars"

	objnames := []string{
		"my!key", "my-key", "my_key", "my.key", "my'key", "my(key", "my)key",
		"my&key", "my@key", "my=key", "my;key", "my:key", "my key", "my,key",
		"my?key", "my^key", "my{}key", "my%key", "my`key",
		"my[]key", "my~key", "my<>key", "my|key", "my#key",
	}
	if !s.azureTests {
		// azure currently can't handle backslashes in object names
		objnames = append(objnames, "my\\key")
	}

	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objs, err := putObjects(s3client, objnames, bucket)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareObjects(objs, res.Contents) {
			return fmt.Errorf("expected the objects to be %vß, instead got %v",
				objStrings(objs), objStrings(res.Contents))
		}

		return nil
	})
}

func PutObject_tagging(s *S3Conf) error {
	testName := "PutObject_tagging"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		testTagging := func(taggging string, result map[string]string, expectedErr error) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)

			_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
				Bucket:  &bucket,
				Key:     &obj,
				Tagging: &taggging,
			})
			cancel()
			if err == nil && expectedErr != nil {
				return fmt.Errorf("expected err %w, instead got nil", expectedErr)
			}
			if err != nil {
				if expectedErr == nil {
					return err
				}
				switch eErr := expectedErr.(type) {
				case s3err.APIError:
					return checkApiErr(err, eErr)
				default:
					return fmt.Errorf("invalid err provided: %w", expectedErr)
				}
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			if len(res.TagSet) != len(result) {
				return fmt.Errorf("tag lengths are not equal: (expected): %v, (got): %v", len(result), len(res.TagSet))
			}

			for _, tag := range res.TagSet {
				val, ok := result[getString(tag.Key)]
				if !ok {
					return fmt.Errorf("tag key not found: %v", getString(tag.Key))
				}

				if val != getString(tag.Value) {
					return fmt.Errorf("expected the %v tag value to be %v, instead got %v", getString(tag.Key), val, getString(tag.Value))
				}
			}

			return nil
		}

		for _, el := range []struct {
			tagging     string
			result      map[string]string
			expectedErr error
		}{
			// success cases
			{"&", map[string]string{}, nil},
			{"&&&", map[string]string{}, nil},
			{"key", map[string]string{"key": ""}, nil},
			{"key&", map[string]string{"key": ""}, nil},
			{"key=&", map[string]string{"key": ""}, nil},
			{"key=val&", map[string]string{"key": "val"}, nil},
			{"key1&key2", map[string]string{"key1": "", "key2": ""}, nil},
			{"key1=val1&key2=val2", map[string]string{"key1": "val1", "key2": "val2"}, nil},
			// invalid url-encoded
			{"=", nil, s3err.GetAPIError(s3err.ErrInvalidURLEncodedTagging)},
			{"key%", nil, s3err.GetAPIError(s3err.ErrInvalidURLEncodedTagging)},
			// duplicate keys
			{"key=val&key=val", nil, s3err.GetAPIError(s3err.ErrInvalidURLEncodedTagging)},
			// invalid tag keys
			{"key?=val", nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			{"key(=val", nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			{"key*=val", nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			{"key$=val", nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			{"key#=val", nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			{"key@=val", nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			{"key!=val", nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			// invalid tag values
			{"key=val?", nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{"key=val(", nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{"key=val*", nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{"key=val$", nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{"key=val#", nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{"key=val@", nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{"key=val!", nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			// success special chars
			{"key-key_key.key/key=value-value_value.value/value", map[string]string{"key-key_key.key/key": "value-value_value.value/value"}, nil},
			// should handle supported encoded characters
			{"key%2E=value%2F", map[string]string{"key.": "value/"}, nil},
			{"key%2D=value%2B", map[string]string{"key-": "value+"}, nil},
			{"key++key=value++value", map[string]string{"key  key": "value  value"}, nil},
			{"key%20key=value%20value", map[string]string{"key key": "value value"}, nil},
			{"key%5Fkey=value%5Fvalue", map[string]string{"key_key": "value_value"}, nil},
		} {
			err := testTagging(el.tagging, el.result, el.expectedErr)
			if err != nil {
				return err
			}
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
		if err := checkSdkApiErr(err, "InvalidRequest"); err != nil {
			return err
		}
		// client sdk regression issue prevents getting full error message,
		// change back to below once this is fixed:
		// https://github.com/aws/aws-sdk-go-v2/issues/2921
		// if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLockInvalidHeaders)); err != nil {
		// 	return err
		// }

		retainDate := time.Now().Add(time.Hour * 48)

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:                    &bucket,
			Key:                       &key,
			ObjectLockRetainUntilDate: &retainDate,
		})
		cancel()
		if err := checkSdkApiErr(err, "InvalidRequest"); err != nil {
			return err
		}
		// client sdk regression issue prevents getting full error message,
		// change back to below once this is fixed:
		// https://github.com/aws/aws-sdk-go-v2/issues/2921
		// if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLockInvalidHeaders)); err != nil {
		// 	return err
		// }

		return nil
	})
}

func PutObject_with_object_lock(s *S3Conf) error {
	testName := "PutObject_with_object_lock"
	runF(testName)
	bucket, obj, lockStatus := getBucketName(), "my-obj", true

	client := s.GetClient()
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

func PutObject_invalid_legal_hold(s *S3Conf) error {
	testName := "PutObject_invalid_legal_hold"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket:                    &bucket,
			Key:                       getPtr("foo"),
			ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatus("invalid_status"),
		}, s3client)
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidLegalHoldStatus))
	}, withLock())
}
func PutObject_invalid_object_lock_mode(s *S3Conf) error {
	testName := "PutObject_invalid_object_lock_mode"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		rDate := time.Now().Add(time.Hour * 10)
		_, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket:                    &bucket,
			Key:                       getPtr("foo"),
			ObjectLockRetainUntilDate: &rDate,
			ObjectLockMode:            types.ObjectLockMode("invalid_mode"),
		}, s3client)
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidObjectLockMode))
	}, withLock())
}

func PutObject_checksum_algorithm_and_header_mismatch(s *S3Conf) error {
	testName := "PutObject_checksum_algorithm_and_header_mismatch"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:            &bucket,
			Key:               &obj,
			ChecksumAlgorithm: types.ChecksumAlgorithmCrc32,
			ChecksumCRC32C:    getPtr("m0cB1Q=="),
		})
		cancel()
		// FIXME: The error message for PutObject is not properly serialized by the sdk
		// References to aws sdk issue https://github.com/aws/aws-sdk-go-v2/issues/2921

		// if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMultipleChecksumHeaders)); err != nil {
		// 	return err
		// }
		if err := checkSdkApiErr(err, "InvalidRequest"); err != nil {
			return err
		}

		return nil
	})
}

func PutObject_multiple_checksum_headers(s *S3Conf) error {
	testName := "PutObject_multiple_checksum_headers"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		_, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket:         &bucket,
			Key:            &obj,
			ChecksumSHA1:   getPtr("Kq5sNclPz7QV2+lfQIuc6R7oRu0="),
			ChecksumCRC32C: getPtr("m0cB1Q=="),
		}, s3client)
		// FIXME: The error message for PutObject is not properly serialized by the sdk
		// References to aws sdk issue https://github.com/aws/aws-sdk-go-v2/issues/2921

		// if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMultipleChecksumHeaders)); err != nil {
		// 	return err
		// }
		if err := checkSdkApiErr(err, "InvalidRequest"); err != nil {
			return err
		}

		// Empty checksums case
		_, err = putObjectWithData(10, &s3.PutObjectInput{
			Bucket:         &bucket,
			Key:            &obj,
			ChecksumSHA1:   getPtr(""),
			ChecksumCRC32C: getPtr(""),
		}, s3client)
		// FIXME: The error message for PutObject is not properly serialized by the sdk
		// References to aws sdk issue https://github.com/aws/aws-sdk-go-v2/issues/2921

		// if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMultipleChecksumHeaders)); err != nil {
		// 	return err
		// }
		if err := checkSdkApiErr(err, "InvalidRequest"); err != nil {
			return err
		}

		return nil
	})
}

func PutObject_invalid_checksum_header(s *S3Conf) error {
	testName := "PutObject_invalid_checksum_header"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		for i, el := range []struct {
			algo      string
			crc32     *string
			crc32c    *string
			sha1      *string
			sha256    *string
			crc64nvme *string
		}{
			// CRC32 tests
			{
				algo:  "crc32",
				crc32: getPtr(""),
			},
			{
				algo:  "crc32",
				crc32: getPtr("invalid_base64!"), // invalid base64
			},
			{
				algo:  "crc32",
				crc32: getPtr("YXNrZGpoZ2tqYXNo"), // valid base64 but not crc32
			},
			// CRC32C tests
			{
				algo:   "crc32c",
				crc32c: getPtr(""),
			},
			{
				algo:   "crc32c",
				crc32c: getPtr("invalid_base64!"), // invalid base64
			},
			{
				algo:   "crc32c",
				crc32c: getPtr("c2RhZnNhZGZzZGFm"), // valid base64 but not crc32c
			},
			// SHA1 tests
			{
				algo: "sha1",
				sha1: getPtr(""),
			},
			{
				algo: "sha1",
				sha1: getPtr("invalid_base64!"), // invalid base64
			},
			{
				algo: "sha1",
				sha1: getPtr("c2RhZmRhc2Zkc2Fmc2RhZnNhZGZzYWRm"), // valid base64 but not sha1
			},
			// SHA256 tests
			{
				algo:   "sha256",
				sha256: getPtr(""),
			},
			{
				algo:   "sha256",
				sha256: getPtr("invalid_base64!"), // invalid base64
			},
			{
				algo:   "sha256",
				sha256: getPtr("ZGZnbmRmZ2hoZmRoZmdkaA=="), // valid base64 but not sha56
			},
			// CRC64Nvme tests
			{
				algo:   "crc64nvme",
				sha256: getPtr(""),
			},
			{
				algo:   "crc64nvme",
				sha256: getPtr("invalid_base64!"), // invalid base64
			},
			{
				algo:   "crc64nvme",
				sha256: getPtr("ZHNhZmRzYWZzZGFmZHNhZg=="), // valid base64 but not crc64nvme
			},
		} {
			_, err := putObjectWithData(int64(i*100), &s3.PutObjectInput{
				Bucket:            &bucket,
				Key:               &obj,
				ChecksumCRC32:     el.crc32,
				ChecksumCRC32C:    el.crc32c,
				ChecksumSHA1:      el.sha1,
				ChecksumSHA256:    el.sha256,
				ChecksumCRC64NVME: el.crc64nvme,
			}, s3client)

			// FIXME: The error message for PutObject is not properly serialized by the sdk
			// References to aws sdk issue https://github.com/aws/aws-sdk-go-v2/issues/2921

			// if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMultipleChecksumHeaders)); err != nil {
			// 	return err
			// }
			if err := checkSdkApiErr(err, "InvalidRequest"); err != nil {
				return err
			}
		}

		return nil
	})
}

func PutObject_incorrect_checksums(s *S3Conf) error {
	testName := "PutObject_incorrect_checksums"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		for i, el := range []struct {
			algo      types.ChecksumAlgorithm
			crc32     *string
			crc32c    *string
			sha1      *string
			sha256    *string
			crc64nvme *string
		}{
			{
				algo:  types.ChecksumAlgorithmCrc32,
				crc32: getPtr("DUoRhQ=="),
			},
			{
				algo:   types.ChecksumAlgorithmCrc32c,
				crc32c: getPtr("yZRlqg=="),
			},
			{
				algo: types.ChecksumAlgorithmSha1,
				sha1: getPtr("Kq5sNclPz7QV2+lfQIuc6R7oRu0="),
			},
			{
				algo:   types.ChecksumAlgorithmSha256,
				sha256: getPtr("uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek="),
			},
			{
				algo:      types.ChecksumAlgorithmCrc64nvme,
				crc64nvme: getPtr("sV264W+gYBI="),
			},
		} {
			_, err := putObjectWithData(int64(i*100), &s3.PutObjectInput{
				Bucket:            &bucket,
				Key:               &obj,
				ChecksumCRC32:     el.crc32,
				ChecksumCRC32C:    el.crc32c,
				ChecksumSHA1:      el.sha1,
				ChecksumSHA256:    el.sha256,
				ChecksumCRC64NVME: el.crc64nvme,
			}, s3client)
			if err := checkApiErr(err, s3err.GetChecksumBadDigestErr(el.algo)); err != nil {
				return err
			}
		}

		return nil
	})
}

func PutObject_default_checksum(s *S3Conf) error {
	testName := "PutObject_default_checksum"
	return actionHandler(s, testName, func(_ *s3.Client, bucket string) error {
		customClient := s3.NewFromConfig(s.Config(), func(o *s3.Options) {
			o.RequestChecksumCalculation = aws.RequestChecksumCalculationUnset
		})

		obj := "my-obj"

		out, err := putObjectWithData(100, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, customClient)
		if err != nil {
			return err
		}

		if out.res.ChecksumCRC64NVME == nil {
			return fmt.Errorf("expected non nil default crc64nvme checksum")
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := customClient.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:       &bucket,
			Key:          &obj,
			ChecksumMode: types.ChecksumModeEnabled,
		})
		cancel()
		if err != nil {
			return err
		}

		if getString(res.ChecksumCRC64NVME) != getString(out.res.ChecksumCRC64NVME) {
			return fmt.Errorf("expected the object crc64nvme checksum to be %v, instead got %v", getString(res.ChecksumCRC64NVME), getString(out.res.ChecksumCRC64NVME))
		}

		return nil
	})
}

func PutObject_checksums_success(s *S3Conf) error {
	testName := "PutObject_checksums_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		for i, algo := range types.ChecksumAlgorithmCrc32.Values() {
			res, err := putObjectWithData(int64(i*200), &s3.PutObjectInput{
				Bucket:            &bucket,
				Key:               &obj,
				ChecksumAlgorithm: algo,
			}, s3client)
			if err != nil {
				return err
			}

			if res.res.ChecksumType != types.ChecksumTypeFullObject {
				return fmt.Errorf("expected the object checksum type to be %v, instead got %v", types.ChecksumTypeFullObject, res.res.ChecksumType)
			}

			switch algo {
			case types.ChecksumAlgorithmCrc32:
				if res.res.ChecksumCRC32 == nil {
					return fmt.Errorf("expected non empty crc32 checksum in the response")
				}
			case types.ChecksumAlgorithmCrc32c:
				if res.res.ChecksumCRC32C == nil {
					return fmt.Errorf("expected non empty crc32c checksum in the response")
				}
			case types.ChecksumAlgorithmSha1:
				if res.res.ChecksumSHA1 == nil {
					return fmt.Errorf("expected non empty sha1 checksum in the response")
				}
			case types.ChecksumAlgorithmSha256:
				if res.res.ChecksumSHA256 == nil {
					return fmt.Errorf("expected non empty sha256 checksum in the response")
				}
			case types.ChecksumAlgorithmCrc64nvme:
				if res.res.ChecksumCRC64NVME == nil {
					return fmt.Errorf("expected non empty crc64nvme checksum in the response")
				}
			}
		}

		return nil
	})
}

func PutObject_racey_success(s *S3Conf) error {
	testName := "PutObject_racey_success"
	runF(testName)
	bucket, obj, lockStatus := getBucketName(), "my-obj", true

	client := s.GetClient()
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

	eg := errgroup.Group{}
	for range 10 {
		eg.Go(func() error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := client.PutObject(ctx, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			return err
		})
	}
	err = eg.Wait()

	if err != nil {
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

func PutObject_success(s *S3Conf) error {
	testName := "PutObject_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"my-obj"}, bucket)
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
		client := newconf.GetClient()
		_, err := putObjects(client, []string{"my-obj"}, bucket)
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrSignatureDoesNotMatch))
	})
}

func PutObject_invalid_object_names(s *S3Conf) error {
	testName := "PutObject_invalid_object_names"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for _, obj := range []string{
			".",
			"..",
			"./",
			"/.",
			"//",
			"../",
			"/..",
			"/..",
			"../.",
			"../../../.",
			"../../../etc/passwd",
			"../../../../tmp/foo",
			"for/../../bar/",
			"a/a/a/../../../../../etc/passwd",
			"/a/../../b/../../c/../../../etc/passwd",
		} {
			_, err := putObjects(s3client, []string{obj}, bucket)
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrBadRequest)); err != nil {
				return err
			}
		}

		return nil
	})
}

func PutObject_false_negative_object_names(s *S3Conf) error {
	testName := "PutObject_false_negative_object_names"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objs := []string{
			"%252e%252e%252fetc/passwd",            // double encoding
			"%2e%2e/%2e%2e/%2e%2e/.ssh/id_rsa",     // double URL-encoded
			"%u002e%u002e/%u002e%u002e/etc/passwd", // unicode escape
			"..%2f..%2f..%2fsecret/file.txt",       // URL-encoded
			"..%c0%af..%c0%afetc/passwd",           // UTF-8 overlong trick
			".../.../.../target.txt",
			"..\\u2215..\\u2215etc/passwd",             // Unicode division slash
			"dir/%20../file.txt",                       // encoded space
			"dir/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", // overlong UTF-8 encoding
			"logs/latest -> /etc/passwd",               // symlink attacks
			//TODO: add this test case in advanced routing
			// "/etc/passwd" // absolute path injection
		}
		_, err := putObjects(s3client, objs, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if len(res.Contents) != len(objs) {
			return fmt.Errorf("expected %v objects, instead got %v", len(objs), len(res.Contents))
		}

		for i, obj := range res.Contents {
			if *obj.Key != objs[i] {
				return fmt.Errorf("expected the %vth object name to be %s, instead got %s", i+1, objs[i], *obj.Key)
			}
		}

		return nil
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
		partCount, partSize := int64(5), int64(1024)
		partNumber := int32(3)

		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, partCount*partSize, partCount, bucket, obj, *mp.UploadId)
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

		if out.ContentLength == nil {
			return fmt.Errorf("expected non nil content length")
		}
		if *out.ContentLength != int64(partSize) {
			return fmt.Errorf("expected content length to be %v, instead got %v",
				partSize, *out.ContentLength)
		}
		if getString(out.ETag) != getString(parts[partNumber-1].ETag) {
			return fmt.Errorf("expected ETag to be %v, instead got %v",
				getString(parts[partNumber-1].ETag), getString(out.ETag))
		}
		if out.PartsCount == nil {
			return fmt.Errorf("expected non nil parts count")
		}
		if *out.PartsCount != int32(partCount) {
			return fmt.Errorf("expected part count to be %v, instead got %v",
				partCount, *out.PartsCount)
		}
		if out.StorageClass != types.StorageClassStandard {
			return fmt.Errorf("expected the storage class to be %v, instead got %v",
				types.StorageClassStandard, out.StorageClass)
		}

		return nil
	})
}

func HeadObject_non_existing_dir_object(s *S3Conf) error {
	testName := "HeadObject_non_existing_dir_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, dataLen := "my-obj", int64(1234567)
		meta := map[string]string{
			"key1": "val1",
			"key2": "val2",
		}

		_, err := putObjectWithData(dataLen, &s3.PutObjectInput{
			Bucket:   &bucket,
			Key:      &obj,
			Metadata: meta,
		}, s3client)
		if err != nil {
			return err
		}

		obj = "my-obj/"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		defer cancel()
		if err := checkSdkApiErr(err, "NotFound"); err != nil {
			return err
		}

		return nil
	})
}

func HeadObject_directory_object_noslash(s *S3Conf) error {
	testName := "HeadObject_directory_object_noslash"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj/"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		obj = "my-obj"
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err := checkSdkApiErr(err, "NotFound"); err != nil {
			return err
		}

		return nil
	})
}

const defaultContentType = "binary/octet-stream"

func HeadObject_not_enabled_checksum_mode(s *S3Conf) error {
	testName := "HeadObject_not_enabled_checksum_mode"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		_, err := putObjectWithData(500, &s3.PutObjectInput{
			Bucket:            &bucket,
			Key:               &obj,
			ChecksumAlgorithm: types.ChecksumAlgorithmSha1,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.ChecksumCRC32 != nil {
			return fmt.Errorf("expected nil crc32 checksum, instead got %v", *res.ChecksumCRC32)
		}
		if res.ChecksumCRC32C != nil {
			return fmt.Errorf("expected nil crc32c checksum, instead got %v", *res.ChecksumCRC32C)
		}
		if res.ChecksumSHA1 != nil {
			return fmt.Errorf("expected nil sha1 checksum, instead got %v", *res.ChecksumSHA1)
		}
		if res.ChecksumSHA256 != nil {
			return fmt.Errorf("expected nil sha256 checksum, instead got %v", *res.ChecksumSHA256)
		}

		return nil
	})
}

func HeadObject_checksums(s *S3Conf) error {
	testName := "HeadObject_checksums"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objs := []struct {
			key          string
			checksumAlgo types.ChecksumAlgorithm
		}{
			{
				key:          "obj-1",
				checksumAlgo: types.ChecksumAlgorithmCrc32,
			},
			{
				key:          "obj-2",
				checksumAlgo: types.ChecksumAlgorithmCrc32c,
			},
			{
				key:          "obj-3",
				checksumAlgo: types.ChecksumAlgorithmSha1,
			},
			{
				key:          "obj-4",
				checksumAlgo: types.ChecksumAlgorithmSha256,
			},
			{
				key:          "obj-5",
				checksumAlgo: types.ChecksumAlgorithmCrc64nvme,
			},
		}

		for i, el := range objs {
			out, err := putObjectWithData(int64(i*200), &s3.PutObjectInput{
				Bucket:            &bucket,
				Key:               &el.key,
				ChecksumAlgorithm: el.checksumAlgo,
			}, s3client)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket:       &bucket,
				Key:          &el.key,
				ChecksumMode: types.ChecksumModeEnabled,
			})
			cancel()
			if err != nil {
				return err
			}

			if res.ChecksumType != types.ChecksumTypeFullObject {
				return fmt.Errorf("expected the %v object checksum type to be %v, instaed got %v", el.key, types.ChecksumTypeFullObject, res.ChecksumType)
			}
			if getString(res.ChecksumCRC32) != getString(out.res.ChecksumCRC32) {
				return fmt.Errorf("expected crc32 checksum to be %v, instead got %v", getString(out.res.ChecksumCRC32), getString(res.ChecksumCRC32))
			}
			if getString(res.ChecksumCRC32C) != getString(out.res.ChecksumCRC32C) {
				return fmt.Errorf("expected crc32c checksum to be %v, instead got %v", getString(out.res.ChecksumCRC32C), getString(res.ChecksumCRC32C))
			}
			if getString(res.ChecksumSHA1) != getString(out.res.ChecksumSHA1) {
				return fmt.Errorf("expected sha1 checksum to be %v, instead got %v", getString(out.res.ChecksumSHA1), getString(res.ChecksumSHA1))
			}
			if getString(res.ChecksumSHA256) != getString(out.res.ChecksumSHA256) {
				return fmt.Errorf("expected sha256 checksum to be %v, instead got %v", getString(out.res.ChecksumSHA256), getString(res.ChecksumSHA256))
			}
			if getString(res.ChecksumCRC64NVME) != getString(out.res.ChecksumCRC64NVME) {
				return fmt.Errorf("expected crc64nvme checksum to be %v, instead got %v", getString(out.res.ChecksumCRC64NVME), getString(res.ChecksumCRC64NVME))
			}
		}

		return nil
	})
}

func HeadObject_invalid_parent_dir(s *S3Conf) error {
	testName := "HeadObject_invalid_parent_dir"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, dataLen := "not-a-dir", int64(1)

		_, err := putObjectWithData(dataLen, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		obj = "not-a-dir/bad-obj"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		defer cancel()
		if err := checkSdkApiErr(err, "NotFound"); err != nil {
			return err
		}

		return nil
	})
}

func HeadObject_with_range(s *S3Conf) error {
	testName := "HeadObject_with_range"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, objLength := "my-obj", int64(2300)
		_, err := putObjectWithData(objLength, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		testRange := func(rg, contentRange string, cLength int64, expectErr bool) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: &bucket,
				Key:    &obj,
				Range:  &rg,
			})
			cancel()
			if err == nil && expectErr {
				return fmt.Errorf("expected err 'RequestedRangeNotSatisfiable' error, instead got nil")
			}
			if err != nil {
				if !expectErr {
					return err
				}

				var ae smithy.APIError
				if errors.As(err, &ae) {
					if ae.ErrorCode() != "RequestedRangeNotSatisfiable" {
						return fmt.Errorf("expected RequestedRangeNotSatisfiable, instead got %v", ae.ErrorCode())
					}
					if ae.ErrorMessage() != "Requested Range Not Satisfiable" {
						return fmt.Errorf("expected the error message to be 'Requested Range Not Satisfiable', instead got %v", ae.ErrorMessage())
					}
					return nil
				}

				return fmt.Errorf("invalid error got %w", err)
			}

			if getString(res.AcceptRanges) != "bytes" {
				return fmt.Errorf("expected accept ranges to be 'bytes', instead got %v", getString(res.AcceptRanges))
			}
			if res.ContentLength == nil {
				return fmt.Errorf("expected non nil content-length")
			}
			if *res.ContentLength != cLength {
				return fmt.Errorf("expected content-length to be %v, instead got %v", cLength, *res.ContentLength)
			}
			if getString(res.ContentRange) != contentRange {
				return fmt.Errorf("expected content-range to be %v, instead got %v", contentRange, getString(res.ContentRange))
			}

			return nil
		}

		for _, el := range []struct {
			objRange      string
			contentRange  string
			contentLength int64
			expectedErr   bool
		}{
			// invalid ranges: no error
			{"100", "", objLength, false},
			{"100-", "", objLength, false},
			{"invalid_range", "", objLength, false},
			{"bytes=120", "", objLength, false},
			{"bytes=20-10", "", objLength, false},
			{"bytes=abc", "", objLength, false},
			{"bytes=abc-xyz", "", objLength, false},
			{"bytes=100-x", "", objLength, false},
			{fmt.Sprintf("bytes=%v-%v", objLength+2, objLength-100), "", objLength, false},
			// valid ranges
			{"bytes=-1000000", fmt.Sprintf("bytes 0-%v/%v", objLength-1, objLength), objLength, false},
			{"bytes=100-", fmt.Sprintf("bytes 100-%v/%v", objLength-1, objLength), objLength - 100, false},
			{"bytes=-100", fmt.Sprintf("bytes %v-%v/%v", objLength-100, objLength-1, objLength), 100, false},
			{"bytes=0-", fmt.Sprintf("bytes 0-%v/%v", objLength-1, objLength), objLength, false},
			{"bytes=100-200", fmt.Sprintf("bytes 100-200/%v", objLength), 101, false},
			{fmt.Sprintf("bytes=100-%v", objLength), fmt.Sprintf("bytes 100-%v/%v", objLength-1, objLength), objLength - 100, false},
			{fmt.Sprintf("bytes=0-%v", objLength), fmt.Sprintf("bytes 0-%v/%v", objLength-1, objLength), objLength, false},
			{fmt.Sprintf("bytes=0-%v", objLength-1), fmt.Sprintf("bytes 0-%v/%v", objLength-1, objLength), objLength, false},
			{fmt.Sprintf("bytes=-%v", objLength), fmt.Sprintf("bytes 0-%v/%v", objLength-1, objLength), objLength, false},

			// not satisfiable ranges: return error
			{fmt.Sprintf("bytes=%v-", objLength), "", 0, true},
			{fmt.Sprintf("bytes=%v-", objLength+2), "", 0, true},
			{fmt.Sprintf("bytes=%v-%v", objLength+2, objLength+100), "", 0, true},
		} {
			err := testRange(el.objRange, el.contentRange, el.contentLength, el.expectedErr)
			if err != nil {
				return err
			}
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
		ctype, cDisp, cEnc, cLang := defaultContentType, "cont-desp", "json", "eng"
		cacheControl, expires := "cache-ctrl", time.Now().Add(time.Hour*2)

		_, err := putObjectWithData(dataLen, &s3.PutObjectInput{
			Bucket:             &bucket,
			Key:                &obj,
			Metadata:           meta,
			ContentType:        &ctype,
			ContentDisposition: &cDisp,
			ContentEncoding:    &cEnc,
			ContentLanguage:    &cLang,
			CacheControl:       &cacheControl,
			Expires:            &expires,
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
			return fmt.Errorf("expected data length %v, instead got %v",
				dataLen, contentLength)
		}
		if getString(out.ContentType) != defaultContentType {
			return fmt.Errorf("expected Content-Type %v, instead got %v",
				defaultContentType, getString(out.ContentType))
		}
		if getString(out.ContentDisposition) != cDisp {
			return fmt.Errorf("expected Content-Disposition %v, instead got %v",
				cDisp, getString(out.ContentDisposition))
		}
		if getString(out.ContentEncoding) != cEnc {
			return fmt.Errorf("expected Content-Encoding %v, instead got %v",
				cEnc, getString(out.ContentEncoding))
		}
		if getString(out.ContentLanguage) != cLang {
			return fmt.Errorf("expected Content-Language %v, instead got %v",
				cLang, getString(out.ContentLanguage))
		}
		if getString(out.ExpiresString) != expires.UTC().Format(timefmt) {
			return fmt.Errorf("expected Expiress %v, instead got %v",
				expires.UTC().Format(timefmt), getString(out.ExpiresString))
		}
		if getString(out.CacheControl) != cacheControl {
			return fmt.Errorf("expected Cache-Control %v, instead got %v",
				cacheControl, getString(out.CacheControl))
		}
		if out.StorageClass != types.StorageClassStandard {
			return fmt.Errorf("expected the storage class to be %v, instead got %v",
				types.StorageClassStandard, out.StorageClass)
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
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
			ObjectAttributes: []types.ObjectAttributes{
				types.ObjectAttributesEtag,
			},
		})
		cancel()
		if err := checkSdkApiErr(err, "NoSuchKey"); err != nil {
			return err
		}

		return nil
	})
}

func GetObjectAttributes_invalid_attrs(s *S3Conf) error {
	testName := "GetObjectAttributes_invalid_attrs"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
			Bucket: &bucket,
			Key:    &obj,
			ObjectAttributes: []types.ObjectAttributes{
				types.ObjectAttributesEtag,
				types.ObjectAttributes("Invalid_argument"),
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidObjectAttributes)); err != nil {
			return err
		}

		return nil
	})
}

func GetObjectAttributes_invalid_parent(s *S3Conf) error {
	testName := "GetObjectAttributes_invalid_parent"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "not-a-dir"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		obj = "not-a-dir/bad-obj"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
			Bucket: &bucket,
			Key:    &obj,
			ObjectAttributes: []types.ObjectAttributes{
				types.ObjectAttributesEtag,
			},
		})
		cancel()
		var bae *types.NoSuchKey
		if !errors.As(err, &bae) {
			return err
		}

		return nil
	})
}

func GetObjectAttributes_invalid_single_attribute(s *S3Conf) error {
	testName := "GetObjectAttributes_invalid_single_attribute"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
			Bucket: &bucket,
			Key:    &obj,
			ObjectAttributes: []types.ObjectAttributes{
				types.ObjectAttributes("invalid_attr"),
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidObjectAttributes)); err != nil {
			return err
		}

		return nil
	})
}

func GetObjectAttributes_empty_attrs(s *S3Conf) error {
	testName := "GetObjectAttributes_empty_attrs"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
			Bucket:           &bucket,
			Key:              &obj,
			ObjectAttributes: []types.ObjectAttributes{},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectAttributesInvalidHeader)); err != nil {
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
				types.ObjectAttributesStorageClass,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if resp.ETag == nil || out.ETag == nil {
			return fmt.Errorf("nil ETag output")
		}
		if strings.Trim(*resp.ETag, "\"") != *out.ETag {
			return fmt.Errorf("expected ETag to be %v, instead got %v",
				strings.Trim(*resp.ETag, "\""), *out.ETag)
		}
		if out.ObjectSize == nil {
			return fmt.Errorf("nil object size output")
		}
		if *out.ObjectSize != data_len {
			return fmt.Errorf("expected object size to be %v, instead got %v",
				data_len, *out.ObjectSize)
		}
		if out.Checksum != nil {
			return fmt.Errorf("expected checksum to be nil, instead got %v",
				*out.Checksum)
		}
		if out.StorageClass != types.StorageClassStandard {
			return fmt.Errorf("expected the storage class to be %v, instead got %v",
				types.StorageClassStandard, out.StorageClass)
		}
		if out.LastModified == nil {
			return fmt.Errorf("expected non nil LastModified")
		}

		return nil
	})
}

func GetObjectAttributes_checksums(s *S3Conf) error {
	testName := "GetObjectAttributes_checksums"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objs := []struct {
			key          string
			checksumAlgo types.ChecksumAlgorithm
		}{
			{
				key:          "obj-1",
				checksumAlgo: types.ChecksumAlgorithmCrc32,
			},
			{
				key:          "obj-2",
				checksumAlgo: types.ChecksumAlgorithmCrc32c,
			},
			{
				key:          "obj-3",
				checksumAlgo: types.ChecksumAlgorithmSha1,
			},
			{
				key:          "obj-4",
				checksumAlgo: types.ChecksumAlgorithmSha256,
			},
			{
				key:          "obj-5",
				checksumAlgo: types.ChecksumAlgorithmCrc64nvme,
			},
		}

		for i, el := range objs {
			out, err := putObjectWithData(int64(i*120), &s3.PutObjectInput{
				Bucket:            &bucket,
				Key:               &el.key,
				ChecksumAlgorithm: el.checksumAlgo,
			}, s3client)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
				Bucket: &bucket,
				Key:    &el.key,
				ObjectAttributes: []types.ObjectAttributes{
					types.ObjectAttributesChecksum,
				},
			})
			cancel()
			if err != nil {
				return err
			}

			if res.Checksum == nil {
				return fmt.Errorf("expected non-nil checksum in the response")
			}
			if res.Checksum.ChecksumType != types.ChecksumTypeFullObject {
				return fmt.Errorf("expected the %v object checksum type to be %v, instaed got %v",
					el.key, types.ChecksumTypeFullObject, res.Checksum.ChecksumType)
			}
			if getString(res.Checksum.ChecksumCRC32) != getString(out.res.ChecksumCRC32) {
				return fmt.Errorf("expected crc32 checksum to be %v, instead got %v",
					getString(out.res.ChecksumCRC32), getString(res.Checksum.ChecksumCRC32))
			}
			if getString(res.Checksum.ChecksumCRC32C) != getString(out.res.ChecksumCRC32C) {
				return fmt.Errorf("expected crc32c checksum to be %v, instead got %v",
					getString(out.res.ChecksumCRC32C), getString(res.Checksum.ChecksumCRC32C))
			}
			if getString(res.Checksum.ChecksumSHA1) != getString(out.res.ChecksumSHA1) {
				return fmt.Errorf("expected sha1 checksum to be %v, instead got %v",
					getString(out.res.ChecksumSHA1), getString(res.Checksum.ChecksumSHA1))
			}
			if getString(res.Checksum.ChecksumSHA256) != getString(out.res.ChecksumSHA256) {
				return fmt.Errorf("expected sha256 checksum to be %v, instead got %v",
					getString(out.res.ChecksumSHA256), getString(res.Checksum.ChecksumSHA256))
			}
			if getString(res.Checksum.ChecksumCRC64NVME) != getString(out.res.ChecksumCRC64NVME) {
				return fmt.Errorf("expected crc64nvme checksum to be %v, instead got %v",
					getString(out.res.ChecksumCRC64NVME), getString(res.Checksum.ChecksumCRC64NVME))
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

func GetObject_directory_object_noslash(s *S3Conf) error {
	testName := "GetObject_directory_object_noslash"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj/"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		obj = "my-obj"
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		var bae *types.NoSuchKey
		if !errors.As(err, &bae) {
			return err
		}
		return nil
	})
}

func GetObject_with_range(s *S3Conf) error {
	testName := "GetObject_with_range"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, objLength := "my-obj", int64(800)
		res, err := putObjectWithData(objLength, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		testGetObjectRange := func(rng, contentRange string, cLength int64, expData []byte, expErr error) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			defer cancel()
			out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
				Bucket: &bucket,
				Key:    &obj,
				Range:  &rng,
			})
			if err == nil && expErr != nil {
				return fmt.Errorf("expected err %w, instead got nil", expErr)
			}
			if err != nil {
				if expErr == nil {
					return err
				}

				parsedErr, ok := expErr.(s3err.APIError)
				if !ok {
					return fmt.Errorf("invalid error type provided, expected s3err.APIError")
				}

				return checkApiErr(err, parsedErr)
			}

			if out.ContentLength == nil {
				return fmt.Errorf("expected non nil content-length")
			}
			if *out.ContentLength != cLength {
				return fmt.Errorf("expected content-length to be %v, instead got %v", cLength, *out.ContentLength)
			}
			if getString(out.AcceptRanges) != "bytes" {
				return fmt.Errorf("expected accept-ranges to be 'bytes', instead got %v", getString(out.AcceptRanges))
			}
			if getString(out.ContentRange) != contentRange {
				return fmt.Errorf("expected content-range to be %v, instead got %v", contentRange, getString(out.ContentRange))
			}

			outData, err := io.ReadAll(out.Body)
			if err != nil {
				return fmt.Errorf("read object data: %w", err)
			}
			out.Body.Close()

			if !isSameData(outData, expData) {
				return fmt.Errorf("incorrect data retrieved")
			}

			return nil
		}

		for _, el := range []struct {
			rng          string
			contentRange string
			cLength      int64
			expData      []byte
			expErr       error
		}{
			// invalid ranges: no error
			{"100", "", objLength, res.data, nil},
			{"100-", "", objLength, res.data, nil},
			{"invalid_range", "", objLength, res.data, nil},
			{"bytes=120", "", objLength, res.data, nil},
			{"bytes=20-10", "", objLength, res.data, nil},
			{"bytes=abc", "", objLength, res.data, nil},
			{"bytes=abc-xyz", "", objLength, res.data, nil},
			{"bytes=100-x", "", objLength, res.data, nil},
			{fmt.Sprintf("bytes=%v-%v", objLength+2, objLength-100), "", objLength, res.data, nil},
			// valid ranges
			{"bytes=-1000000", fmt.Sprintf("bytes 0-%v/%v", objLength-1, objLength), objLength, res.data, nil},
			{"bytes=100-", fmt.Sprintf("bytes 100-%v/%v", objLength-1, objLength), objLength - 100, res.data[100:], nil},
			{"bytes=-100", fmt.Sprintf("bytes %v-%v/%v", objLength-100, objLength-1, objLength), 100, res.data[objLength-100:], nil},
			{"bytes=0-", fmt.Sprintf("bytes 0-%v/%v", objLength-1, objLength), objLength, res.data, nil},
			{"bytes=100-200", fmt.Sprintf("bytes 100-200/%v", objLength), 101, res.data[100:201], nil},
			{fmt.Sprintf("bytes=100-%v", objLength), fmt.Sprintf("bytes 100-%v/%v", objLength-1, objLength), objLength - 100, res.data[100:], nil},
			{fmt.Sprintf("bytes=0-%v", objLength), fmt.Sprintf("bytes 0-%v/%v", objLength-1, objLength), objLength, res.data, nil},
			{fmt.Sprintf("bytes=0-%v", objLength-1), fmt.Sprintf("bytes 0-%v/%v", objLength-1, objLength), objLength, res.data, nil},
			{fmt.Sprintf("bytes=-%v", objLength), fmt.Sprintf("bytes 0-%v/%v", objLength-1, objLength), objLength, res.data, nil},

			// not satisfiable ranges: return error
			{fmt.Sprintf("bytes=%v-", objLength), "", 0, nil, s3err.GetAPIError(s3err.ErrInvalidRange)},
			{fmt.Sprintf("bytes=%v-", objLength+2), "", 0, nil, s3err.GetAPIError(s3err.ErrInvalidRange)},
			{fmt.Sprintf("bytes=%v-%v", objLength+2, objLength+100), "", 0, nil, s3err.GetAPIError(s3err.ErrInvalidRange)},
		} {
			err := testGetObjectRange(el.rng, el.contentRange, el.cLength, el.expData, el.expErr)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func GetObject_invalid_parent(s *S3Conf) error {
	testName := "GetObject_invalid_parent"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dataLength, obj := int64(1234567), "not-a-dir"

		_, err := putObjectWithData(dataLength, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    getPtr("not-a-dir/bad-obj"),
		})
		cancel()
		var bae *types.NoSuchKey
		if !errors.As(err, &bae) {
			return err
		}
		return nil
	})
}

func GetObject_checksums(s *S3Conf) error {
	testName := "GetObject_checksums"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objs := []struct {
			key          string
			checksumAlgo types.ChecksumAlgorithm
		}{
			{
				key:          "obj-1",
				checksumAlgo: types.ChecksumAlgorithmCrc32,
			},
			{
				key:          "obj-2",
				checksumAlgo: types.ChecksumAlgorithmCrc32c,
			},
			{
				key:          "obj-3",
				checksumAlgo: types.ChecksumAlgorithmSha1,
			},
			{
				key:          "obj-4",
				checksumAlgo: types.ChecksumAlgorithmSha256,
			},
			{
				key:          "obj-5",
				checksumAlgo: types.ChecksumAlgorithmCrc64nvme,
			},
		}

		for i, el := range objs {
			out, err := putObjectWithData(int64(i*120), &s3.PutObjectInput{
				Bucket:            &bucket,
				Key:               &el.key,
				ChecksumAlgorithm: el.checksumAlgo,
			}, s3client)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.GetObject(ctx, &s3.GetObjectInput{
				Bucket:       &bucket,
				Key:          &el.key,
				ChecksumMode: types.ChecksumModeEnabled,
			})
			cancel()
			if err != nil {
				return err
			}

			if res.ChecksumType != types.ChecksumTypeFullObject {
				return fmt.Errorf("expected the %v object checksum type to be %v, instaed got %v",
					el.key, types.ChecksumTypeFullObject, res.ChecksumType)
			}
			if getString(res.ChecksumCRC32) != getString(out.res.ChecksumCRC32) {
				return fmt.Errorf("expected crc32 checksum to be %v, instead got %v",
					getString(out.res.ChecksumCRC32), getString(res.ChecksumCRC32))
			}
			if getString(res.ChecksumCRC32C) != getString(out.res.ChecksumCRC32C) {
				return fmt.Errorf("expected crc32c checksum to be %v, instead got %v",
					getString(out.res.ChecksumCRC32C), getString(res.ChecksumCRC32C))
			}
			if getString(res.ChecksumSHA1) != getString(out.res.ChecksumSHA1) {
				return fmt.Errorf("expected sha1 checksum to be %v, instead got %v",
					getString(out.res.ChecksumSHA1), getString(res.ChecksumSHA1))
			}
			if getString(res.ChecksumSHA256) != getString(out.res.ChecksumSHA256) {
				return fmt.Errorf("expected sha256 checksum to be %v, instead got %v",
					getString(out.res.ChecksumSHA256), getString(res.ChecksumSHA256))
			}
			if getString(res.ChecksumCRC64NVME) != getString(out.res.ChecksumCRC64NVME) {
				return fmt.Errorf("expected crc64nvme checksum to be %v, instead got %v",
					getString(out.res.ChecksumCRC64NVME), getString(res.ChecksumCRC64NVME))
			}
		}

		return nil
	})
}

func GetObject_large_object(s *S3Conf) error {
	testName := "GetObject_large_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		//FIXME: make the object size larger after
		// resolving the context deadline exceeding issue
		// in the github actions
		dataLength, obj := int64(100*1024*1024), "my-obj"
		ctype := defaultContentType

		r, err := putObjectWithData(dataLength, &s3.PutObjectInput{
			Bucket:      &bucket,
			Key:         &obj,
			ContentType: &ctype,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), longTimeout)
		out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		defer cancel()
		if err != nil {
			return err
		}
		if out.ContentLength == nil {
			return fmt.Errorf("expected non nil content length")
		}
		if *out.ContentLength != dataLength {
			return fmt.Errorf("expected content-length %v, instead got %v",
				dataLength, out.ContentLength)
		}

		bdy, err := io.ReadAll(out.Body)
		if err != nil {
			return err
		}
		defer out.Body.Close()
		outCsum := sha256.Sum256(bdy)
		if outCsum != r.csum {
			return fmt.Errorf("expected the output data checksum to be %v, instead got %v",
				r.csum, outCsum)
		}
		return nil
	})
}

func GetObject_success(s *S3Conf) error {
	testName := "GetObject_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dataLength, obj := int64(1234567), "my-obj"
		ctype, cDisp, cEnc, cLang := defaultContentType, "cont-desp", "json", "eng"
		cacheControl, expires := "cache-ctrl", time.Now().Add(time.Hour*2)
		meta := map[string]string{
			"foo": "bar",
			"baz": "quxx",
		}

		r, err := putObjectWithData(dataLength, &s3.PutObjectInput{
			Bucket:             &bucket,
			Key:                &obj,
			ContentType:        &ctype,
			ContentDisposition: &cDisp,
			ContentEncoding:    &cEnc,
			ContentLanguage:    &cLang,
			Expires:            &expires,
			CacheControl:       &cacheControl,
			Metadata:           meta,
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
			return fmt.Errorf("expected content-length %v, instead got %v",
				dataLength, out.ContentLength)
		}
		if getString(out.ContentType) != defaultContentType {
			return fmt.Errorf("expected Content-Type %v, instead got %v",
				defaultContentType, getString(out.ContentType))
		}
		if getString(out.ContentDisposition) != cDisp {
			return fmt.Errorf("expected Content-Disposition %v, instead got %v",
				cDisp, getString(out.ContentDisposition))
		}
		if getString(out.ContentEncoding) != cEnc {
			return fmt.Errorf("expected Content-Encoding %v, instead got %v",
				cEnc, getString(out.ContentEncoding))
		}
		if getString(out.ContentLanguage) != cLang {
			return fmt.Errorf("expected Content-Language %v, instead got %v",
				cLang, getString(out.ContentLanguage))
		}
		if getString(out.ExpiresString) != expires.UTC().Format(timefmt) {
			return fmt.Errorf("expected Expiress %v, instead got %v",
				expires.UTC().Format(timefmt), getString(out.ExpiresString))
		}
		if getString(out.CacheControl) != cacheControl {
			return fmt.Errorf("expected Cache-Control %v, instead got %v",
				cacheControl, getString(out.CacheControl))
		}
		if out.StorageClass != types.StorageClassStandard {
			return fmt.Errorf("expected the storage class to be %v, instead got %v",
				types.StorageClassStandard, out.StorageClass)
		}
		if !areMapsSame(out.Metadata, meta) {
			return fmt.Errorf("expected the object metadata to be %v, instead got %v",
				meta, out.Metadata)
		}

		bdy, err := io.ReadAll(out.Body)
		if err != nil {
			return err
		}
		defer out.Body.Close()
		outCsum := sha256.Sum256(bdy)
		if outCsum != r.csum {
			return fmt.Errorf("invalid object data")
		}
		return nil
	})
}

const directoryContentType = "application/x-directory"

func GetObject_directory_success(s *S3Conf) error {
	testName := "GetObject_directory_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dataLength, obj := int64(0), "my-dir/"

		_, err := putObjectWithData(dataLength, &s3.PutObjectInput{
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

		if out.ContentLength == nil {
			return fmt.Errorf("expected non nil content length")
		}
		if *out.ContentLength != dataLength {
			return fmt.Errorf("expected content-length %v, instead got %v",
				dataLength, out.ContentLength)
		}
		if getString(out.ContentType) != directoryContentType {
			return fmt.Errorf("expected content type %v, instead got %v",
				directoryContentType, getString(out.ContentType))
		}
		if out.StorageClass != types.StorageClassStandard {
			return fmt.Errorf("expected the storage class to be %v, instead got %v",
				types.StorageClassStandard, out.StorageClass)
		}

		out.Body.Close()
		return nil
	})
}

func GetObject_by_range_resp_status(s *S3Conf) error {
	testName := "GetObject_by_range_resp_status"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, dLen := "my-obj", int64(4000)
		_, err := putObjectWithData(dLen, &s3.PutObjectInput{
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

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusPartialContent {
			return fmt.Errorf("expected response status to be %v, instead got %v",
				http.StatusPartialContent, resp.StatusCode)
		}

		return nil
	})
}

func GetObject_non_existing_dir_object(s *S3Conf) error {
	testName := "GetObject_non_existing_dir_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dataLength, obj := int64(1234567), "my-obj"

		_, err := putObjectWithData(dataLength, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		obj = "my-obj/"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
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
		objWithPrefix := []string{prefix + "/bar", prefix + "/baz/bla", prefix + "/foo"}
		contents, err := putObjects(s3client, append(objWithPrefix, []string{"azy/csf", "hell"}...), bucket)
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

		if getString(out.Prefix) != prefix {
			return fmt.Errorf("expected prefix %v, instead got %v",
				prefix, getString(out.Prefix))
		}
		if !compareObjects(contents[2:], out.Contents) {
			return fmt.Errorf("expected the output to be %v, instead got %v",
				contents[2:], out.Contents)
		}

		return nil
	})
}

func ListObjects_paginated(s *S3Conf) error {
	testName := "ListObjects_paginated"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"dir1/subdir/file.txt", "dir1/subdir.ext", "dir1/subdir1.ext", "dir1/subdir2.ext"}, bucket)
		if err != nil {
			return err
		}

		objs, prefixes, err := listObjects(s3client, bucket, "dir1/", "/", 2)
		if err != nil {
			return err
		}

		expected := []string{"dir1/subdir.ext", "dir1/subdir1.ext", "dir1/subdir2.ext"}
		if !hasObjNames(objs, expected) {
			return fmt.Errorf("expected objects %v, instead got %v",
				expected, objStrings(objs))
		}

		expectedPrefix := []string{"dir1/subdir/"}
		if !hasPrefixName(prefixes, expectedPrefix) {
			return fmt.Errorf("expected prefixes %v, instead got %v",
				expectedPrefix, pfxStrings(prefixes))
		}

		return nil
	})
}

func ListObjects_truncated(s *S3Conf) error {
	testName := "ListObjects_truncated"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		maxKeys := int32(2)
		contents, err := putObjects(s3client, []string{"foo", "bar", "baz"}, bucket)
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

		if out1.MaxKeys == nil {
			return fmt.Errorf("expected non nil max-keys")
		}
		if *out1.MaxKeys != maxKeys {
			return fmt.Errorf("expected max-keys to be %v, instead got %v",
				maxKeys, out1.MaxKeys)
		}

		if out1.NextMarker == nil {
			return fmt.Errorf("expected non nil next marker")
		}
		if *out1.NextMarker != "baz" {
			return fmt.Errorf("expected next-marker to be baz, instead got %v",
				*out1.NextMarker)
		}

		if !compareObjects(contents[:2], out1.Contents) {
			return fmt.Errorf("expected the output to be %v, instead got %v",
				contents[:2], out1.Contents)
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

		if out2.IsTruncated == nil {
			return fmt.Errorf("expected non nil is-truncated")
		}
		if *out2.IsTruncated {
			return fmt.Errorf("expected output not to be truncated")
		}

		if getString(out2.Marker) != getString(out1.NextMarker) {
			return fmt.Errorf("expected marker to be %v, instead got %v",
				getString(out1.NextMarker), getString(out2.Marker))
		}

		if !compareObjects(contents[2:], out2.Contents) {
			return fmt.Errorf("expected the output to be %v, instead got %v",
				contents[2:], out2.Contents)
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
		_, err := putObjects(s3client, objects, bucket)
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

func ListObjects_exceeding_max_keys(s *S3Conf) error {
	testName := "ListObjects_exceeding_max_keys"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		maxKeys := int32(233333333)
		out, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket:  &bucket,
			MaxKeys: &maxKeys,
		})
		cancel()
		if err != nil {
			return nil
		}

		if out.MaxKeys == nil {
			return fmt.Errorf("unexpected nil max-keys")
		}
		if *out.MaxKeys != 1000 {
			return fmt.Errorf("expected the max-keys to be %v, instaed got %v",
				1000, *out.MaxKeys)
		}

		return nil
	})
}

func ListObjects_delimiter(s *S3Conf) error {
	testName := "ListObjects_delimiter"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"foo/bar/baz", "foo/bar/xyzzy", "quux/thud", "asdf"}, bucket)
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

		if getString(out.Delimiter) != "/" {
			return fmt.Errorf("expected delimiter to be /, instead got %v",
				getString(out.Delimiter))
		}
		if len(out.Contents) != 1 || getString(out.Contents[0].Key) != "asdf" {
			return fmt.Errorf("expected result [\"asdf\"], instead got %v",
				out.Contents)
		}

		if !comparePrefixes([]string{"foo/", "quux/"}, out.CommonPrefixes) {
			return fmt.Errorf("expected common prefixes to be %v, instead got %v",
				[]string{"foo/", "quux/"}, out.CommonPrefixes)
		}

		return nil
	})
}

func ListObjects_max_keys_none(s *S3Conf) error {
	testName := "ListObjects_max_keys_none"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"foo", "bar", "baz"}, bucket)
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

		if out.MaxKeys == nil {
			return fmt.Errorf("expected non nil max-keys")
		}
		if *out.MaxKeys != 1000 {
			return fmt.Errorf("expected max-keys to be 1000, instead got %v",
				out.MaxKeys)
		}

		return nil
	})
}

func ListObjects_marker_not_from_obj_list(s *S3Conf) error {
	testName := "ListObjects_marker_not_from_obj_list"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		contents, err := putObjects(s3client, []string{"foo", "bar", "baz", "qux", "hello", "xyz"}, bucket)
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

		if !compareObjects(contents[2:], out.Contents) {
			return fmt.Errorf("expected output to be %v, instead got %v",
				contents, out.Contents)
		}

		return nil
	})
}

func ListObjects_with_checksum(s *S3Conf) error {
	testName := "ListObjects_with_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		contents := []types.Object{}
		for i, el := range types.ChecksumAlgorithmCrc32.Values() {
			key := fmt.Sprintf("obj-%v", i)
			size := int64(i * 30)
			out, err := putObjectWithData(size, &s3.PutObjectInput{
				Bucket:            &bucket,
				Key:               &key,
				ChecksumAlgorithm: el,
			}, s3client)
			if err != nil {
				return err
			}

			contents = append(contents, types.Object{
				Key:          &key,
				ETag:         out.res.ETag,
				Size:         &size,
				StorageClass: types.ObjectStorageClassStandard,
				ChecksumAlgorithm: []types.ChecksumAlgorithm{
					el,
				},
				ChecksumType: out.res.ChecksumType,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareObjects(contents, res.Contents) {
			return fmt.Errorf("expected the objects list to be %v, instead got %v",
				contents, res.Contents)
		}

		return nil
	})
}

func ListObjects_list_all_objs(s *S3Conf) error {
	testName := "ListObjects_list_all_objs"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		contents, err := putObjects(s3client, []string{"foo", "bar", "baz", "quxx/ceil", "ceil", "hello/world"}, bucket)
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

		if out.Marker != nil {
			return fmt.Errorf("expected the Marker to be nil, instead got %v",
				*out.Marker)
		}
		if out.NextMarker != nil {
			return fmt.Errorf("expected the NextMarker to be nil, instead got %v",
				*out.NextMarker)
		}
		if out.Delimiter != nil {
			return fmt.Errorf("expected the Delimiter to be nil, instead got %v",
				*out.Delimiter)
		}
		if out.Prefix != nil {
			return fmt.Errorf("expected the Prefix to be nil, instead got %v",
				*out.Prefix)
		}

		if !compareObjects(contents, out.Contents) {
			return fmt.Errorf("expected the contents to be %v, instead got %v",
				contents, out.Contents)
		}

		return nil
	})
}

func ListObjects_nested_dir_file_objs(s *S3Conf) error {
	testName := "ListObjects_nested_dir_file_objs"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		contents, err := putObjects(s3client, []string{"foo/bar/", "foo/bar/baz", "foo/bar/quxx"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareObjects(contents, res.Contents) {
			return fmt.Errorf("expected the objects list to be %+v, instead got %+v", contents, res.Contents)
		}

		// Clean up the nested objects to avoid `ErrDirectoryNotEmpty` error on teardown
		for _, obj := range []string{"foo/bar/baz", "foo/bar/quxx"} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func ListObjects_check_owner(s *S3Conf) error {
	testName := "ListObjects_check_owner"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objs, err := putObjects(s3client, []string{"foo", "bar/baz", "quxx/xyz/eee", "abc/", "bcc"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		for i := range res.Contents {
			res.Contents[i].Owner = &types.Owner{
				ID: &s.awsID,
			}
		}

		if !compareObjects(objs, res.Contents) {
			return fmt.Errorf("expected the contents to be %v, instead got %v",
				objs, res.Contents)
		}

		return nil

	})
}

func ListObjects_non_truncated_common_prefixes(s *S3Conf) error {
	testName := "ListObjects_non_truncated_common_prefixes"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"asdf", "boo/bar", "boo/baz/xyzzy", "cquux/thud", "cquux/bla"}, bucket)
		if err != nil {
			return err
		}

		delim, marker, maxKeys := "/", "boo/", int32(1)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket:    &bucket,
			Marker:    &marker,
			Delimiter: &delim,
			MaxKeys:   &maxKeys,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.IsTruncated == nil {
			return fmt.Errorf("expected non-nil istruncated")
		}
		if *res.IsTruncated {
			return fmt.Errorf("expected non-truncated result")
		}
		if res.MaxKeys == nil {
			return fmt.Errorf("expected non nil max-keys")
		}
		if *res.MaxKeys != maxKeys {
			return fmt.Errorf("expected max-keys to be %v, instead got %v",
				maxKeys, *res.MaxKeys)
		}
		if getString(res.Delimiter) != delim {
			return fmt.Errorf("expected delimiter to be %v, instead got %v",
				delim, getString(res.Delimiter))
		}
		if getString(res.Marker) != marker {
			return fmt.Errorf("expected marker to be %v, instead got %v",
				getString(res.Marker), marker)
		}
		if len(res.Contents) != 0 {
			return fmt.Errorf("expected empty contents, instead got %+v",
				res.Contents)
		}
		cPrefs := []string{"cquux/"}
		if !comparePrefixes(cPrefs, res.CommonPrefixes) {
			return fmt.Errorf("expected common prefixes to be %v, instead got %+v",
				cPrefs, res.CommonPrefixes)
		}

		return nil
	})
}

func ListObjectsV2_start_after(s *S3Conf) error {
	testName := "ListObjectsV2_start_after"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		contents, err := putObjects(s3client, []string{"foo", "bar", "baz"}, bucket)
		if err != nil {
			return err
		}

		startAfter := "bar"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:     &bucket,
			StartAfter: &startAfter,
		})
		cancel()
		if err != nil {
			return err
		}

		if getString(out.StartAfter) != startAfter {
			return fmt.Errorf("expected StartAfter to be %v, insted got %v",
				startAfter, getString(out.StartAfter))
		}
		if !compareObjects(contents[1:], out.Contents) {
			return fmt.Errorf("expected the output to be %v, instead got %v",
				contents, out.Contents)
		}

		return nil
	})
}

func ListObjectsV2_both_start_after_and_continuation_token(s *S3Conf) error {
	testName := "ListObjectsV2_both_start_after_and_continuation_token"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		contents, err := putObjects(s3client, []string{"foo", "bar", "baz", "quxx"}, bucket)
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

		if out.MaxKeys == nil {
			return fmt.Errorf("expected non nil max-keys")
		}

		if *out.MaxKeys != maxKeys {
			return fmt.Errorf("expected max-keys to be %v, instead got %v",
				maxKeys, out.MaxKeys)
		}

		if getString(out.NextContinuationToken) != "bar" {
			return fmt.Errorf("expected next-marker to be baz, instead got %v",
				getString(out.NextContinuationToken))
		}

		if !compareObjects(contents[:1], out.Contents) {
			return fmt.Errorf("expected the output to be %v, instead got %v",
				contents[:1], out.Contents)
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

		if !compareObjects(contents[2:], resp.Contents) {
			return fmt.Errorf("expected the output to be %v, instead got %v",
				contents[2:], resp.Contents)
		}

		return nil
	})
}

func ListObjectsV2_start_after_not_in_list(s *S3Conf) error {
	testName := "ListObjectsV2_start_after_not_in_list"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		contents, err := putObjects(s3client, []string{"foo", "bar", "baz", "quxx"}, bucket)
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

		if !compareObjects(contents[2:], out.Contents) {
			return fmt.Errorf("expected the output to be %v, instead got %v",
				contents[2:], out.Contents)
		}

		return nil
	})
}

func ListObjectsV2_start_after_empty_result(s *S3Conf) error {
	testName := "ListObjectsV2_start_after_empty_result"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"foo", "bar", "baz", "quxx"}, bucket)
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

func ListObjectsV2_both_delimiter_and_prefix(s *S3Conf) error {
	testName := "ListObjectsV2_both_delimiter_and_prefix"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{
			"sample.jpg",
			"photos/2006/January/sample.jpg",
			"photos/2006/February/sample2.jpg",
			"photos/2006/February/sample3.jpg",
			"photos/2006/February/sample4.jpg",
		}, bucket)
		if err != nil {
			return err
		}
		delim, prefix := "/", "photos/2006/"

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:    &bucket,
			Delimiter: &delim,
			Prefix:    &prefix,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.Delimiter == nil || *res.Delimiter != delim {
			return fmt.Errorf("expected the delimiter to be %v", delim)
		}
		if res.Prefix == nil || *res.Prefix != prefix {
			return fmt.Errorf("expected the prefix to be %v", prefix)
		}
		if !comparePrefixes([]string{"photos/2006/February/", "photos/2006/January/"},
			res.CommonPrefixes) {
			return fmt.Errorf("expected the common prefixes to be %v, instead got %v",
				[]string{"photos/2006/February/", "photos/2006/January/"}, res.CommonPrefixes)
		}
		if len(res.Contents) != 0 {
			return fmt.Errorf("expected empty objects list, instead got %v", res.Contents)
		}

		return nil
	})
}

func ListObjectsV2_single_dir_object_with_delim_and_prefix(s *S3Conf) error {
	testName := "ListObjectsV2_single_dir_object_with_delim_and_prefix"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		contents, err := putObjects(s3client, []string{"a/"}, bucket)
		if err != nil {
			return err
		}

		delim, prefix := "/", "a"

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:    &bucket,
			Delimiter: &delim,
			Prefix:    &prefix,
		})
		cancel()
		if err != nil {
			return err
		}

		if !comparePrefixes([]string{"a/"}, res.CommonPrefixes) {
			return fmt.Errorf("expected the common prefixes to be %v, instead got %v",
				[]string{"a/"}, res.CommonPrefixes)
		}
		if len(res.Contents) != 0 {
			return fmt.Errorf("expected empty objects list, instead got %v",
				res.Contents)
		}

		prefix = "a/"

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err = s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:    &bucket,
			Delimiter: &delim,
			Prefix:    &prefix,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareObjects(contents, res.Contents) {
			return fmt.Errorf("expected the object list to be %v, instead got %v",
				[]string{"a/"}, res.Contents)
		}
		if len(res.CommonPrefixes) != 0 {
			return fmt.Errorf("expected empty common prefixes, instead got %v",
				res.CommonPrefixes)
		}

		return nil
	})
}

func ListObjectsV2_truncated_common_prefixes(s *S3Conf) error {
	testName := "ListObjectsV2_truncated_common_prefixes"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"d1/f1", "d2/f2", "d3/f3", "d4/f4"}, bucket)
		if err != nil {
			return err
		}

		delim, maxKeys := "/", int32(3)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:    &bucket,
			Delimiter: &delim,
			MaxKeys:   &maxKeys,
		})
		cancel()
		if err != nil {
			return err
		}

		if !comparePrefixes([]string{"d1/", "d2/", "d3/"}, out.CommonPrefixes) {
			return fmt.Errorf("expected the common prefixes to be %v, instead got %v", []string{"d1/", "d2/", "d3/"}, out.CommonPrefixes)
		}

		if out.MaxKeys == nil {
			return fmt.Errorf("expected non nil max-keys")
		}
		if *out.MaxKeys != maxKeys {
			return fmt.Errorf("expected the max-keys to be %v, instead got %v",
				maxKeys, *out.MaxKeys)
		}
		if getString(out.NextContinuationToken) != "d3/" {
			return fmt.Errorf("expected the NextContinuationToken to be d3/, instead got %v",
				getString(out.NextContinuationToken))
		}
		if getString(out.Delimiter) != delim {
			return fmt.Errorf("expected the delimiter to be %v, instead got %v",
				delim, getString(out.Delimiter))
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err = s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            &bucket,
			Delimiter:         &delim,
			ContinuationToken: out.NextContinuationToken,
		})
		cancel()
		if err != nil {
			return err
		}

		if !comparePrefixes([]string{"d4/"}, out.CommonPrefixes) {
			return fmt.Errorf("expected the common prefixes to be %v, instead got %v",
				[]string{"d4/"}, out.CommonPrefixes)
		}
		if getString(out.Delimiter) != delim {
			return fmt.Errorf("expected the delimiter to be %v, instead got %v",
				delim, getString(out.Delimiter))
		}

		return nil
	})
}

func ListObjectsV2_all_objs_max_keys(s *S3Conf) error {
	testName := "ListObjectsV2_all_objs_max_keys"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		contents, err := putObjects(s3client, []string{"bar", "baz", "foo"}, bucket)
		if err != nil {
			return err
		}

		maxKeys := int32(3)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:  &bucket,
			MaxKeys: &maxKeys,
		})
		cancel()
		if err != nil {
			return err
		}

		if out.IsTruncated == nil || *out.IsTruncated {
			return fmt.Errorf("expected the output not to be truncated")
		}
		if getString(out.NextContinuationToken) != "" {
			return fmt.Errorf("expected empty NextContinuationToken, instead got %v",
				getString(out.NextContinuationToken))
		}
		if out.MaxKeys == nil {
			return fmt.Errorf("expected non nil max-keys")
		}
		if *out.MaxKeys != maxKeys {
			return fmt.Errorf("expected the max-keys to be %v, instead got %v",
				maxKeys, *out.MaxKeys)
		}

		if !compareObjects(contents, out.Contents) {
			return fmt.Errorf("expected the objects list to be %v, instead got %v",
				contents, out.Contents)
		}

		return nil
	})
}

func ListObjectsV2_exceeding_max_keys(s *S3Conf) error {
	testName := "ListObjectsV2_exceeding_max_keys"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		maxKeys := int32(233453333)
		out, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:  &bucket,
			MaxKeys: &maxKeys,
		})
		cancel()
		if err != nil {
			return nil
		}

		if out.MaxKeys == nil {
			return fmt.Errorf("unexpected nil max-keys")
		}
		if *out.MaxKeys != 1000 {
			return fmt.Errorf("expected the max-keys to be %v, instaed got %v",
				1000, *out.MaxKeys)
		}

		return nil
	})
}

func ListObjectsV2_list_all_objs(s *S3Conf) error {
	testName := "ListObjectsV2_list_all_objs"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		contents, err := putObjects(s3client, []string{"bar", "baz", "foo", "obj1", "hell/", "xyzz/quxx"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if out.StartAfter != nil {
			return fmt.Errorf("expected the StartAfter to be nil, instead got %v",
				*out.StartAfter)
		}
		if out.ContinuationToken != nil {
			return fmt.Errorf("expected the ContinuationToken to be nil, instead got %v",
				*out.ContinuationToken)
		}
		if out.NextContinuationToken != nil {
			return fmt.Errorf("expected the NextContinuationToken to be nil, instead got %v",
				*out.NextContinuationToken)
		}
		if out.Delimiter != nil {
			return fmt.Errorf("expected the Delimiter to be nil, instead got %v",
				*out.Delimiter)
		}
		if out.Prefix != nil {
			return fmt.Errorf("expected the Prefix to be nil, instead got %v",
				*out.Prefix)
		}

		if !compareObjects(contents, out.Contents) {
			return fmt.Errorf("expected the contents to be %v, instead got %v",
				contents, out.Contents)
		}

		return nil
	})
}

func ListObjectsV2_with_owner(s *S3Conf) error {
	testName := "ListObjectsV2_with_owner"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objs, err := putObjects(s3client, []string{"foo", "bar/baz", "quxx/xyz/eee", "abc/", "bcc"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:     &bucket,
			FetchOwner: getBoolPtr(true),
		})
		cancel()
		if err != nil {
			return err
		}

		for i := range res.Contents {
			res.Contents[i].Owner = &types.Owner{
				ID: &s.awsID,
			}
		}

		if !compareObjects(objs, res.Contents) {
			return fmt.Errorf("expected the contents to be %v, instead got %v",
				objs, res.Contents)
		}

		return nil
	})
}

func ListObjectsV2_with_checksum(s *S3Conf) error {
	testName := "ListObjectsV2_with_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		contents := []types.Object{}

		for i, el := range types.ChecksumAlgorithmCrc32.Values() {
			key := fmt.Sprintf("obj-%v", i)
			size := int64(i * 100)
			out, err := putObjectWithData(size, &s3.PutObjectInput{
				Bucket:            &bucket,
				Key:               &key,
				ChecksumAlgorithm: el,
			}, s3client)
			if err != nil {
				return err
			}

			contents = append(contents, types.Object{
				Key:          &key,
				ETag:         out.res.ETag,
				Size:         &size,
				StorageClass: types.ObjectStorageClassStandard,
				ChecksumAlgorithm: []types.ChecksumAlgorithm{
					el,
				},
				ChecksumType: out.res.ChecksumType,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareObjects(res.Contents, contents) {
			return fmt.Errorf("expected the objects list to be %v, instead got %v",
				contents, res.Contents)
		}

		return nil
	})
}

func ListObjectsV2_invalid_parent_prefix(s *S3Conf) error {
	testName := "ListObjectsV2_invalid_parent_prefix"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"file"}, bucket)
		if err != nil {
			return err
		}

		delim, maxKeys := "/", int32(100)
		prefix := "file/file/file"

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:    &bucket,
			Delimiter: &delim,
			MaxKeys:   &maxKeys,
			Prefix:    &prefix,
		})
		cancel()
		if err != nil {
			return err
		}

		if len(out.CommonPrefixes) > 0 {
			return fmt.Errorf("expected the common prefixes to be %v, instead got %v",
				[]string{""}, out.CommonPrefixes)
		}
		if out.MaxKeys == nil {
			return fmt.Errorf("expected non nil max-keys")
		}
		if *out.MaxKeys != maxKeys {
			return fmt.Errorf("expected the max-keys to be %v, instead got %v",
				maxKeys, *out.MaxKeys)
		}
		if getString(out.Delimiter) != delim {
			return fmt.Errorf("expected the delimiter to be %v, instead got %v",
				delim, getString(out.Delimiter))
		}
		if len(out.Contents) > 0 {
			return fmt.Errorf("expected the objects to be %v, instead got %v",
				[]types.Object{}, out.Contents)
		}
		return nil
	})
}

func ListObjectVersions_VD_success(s *S3Conf) error {
	testName := "ListObjectVersions_VD_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		versions := []types.ObjectVersion{}
		for i := range 5 {
			dLgth := int64(i * 100)
			key := fmt.Sprintf("my-obj-%v", i)
			out, err := putObjectWithData(dLgth, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &key,
			}, s3client)
			if err != nil {
				return err
			}

			versions = append(versions, types.ObjectVersion{
				ETag:         out.res.ETag,
				IsLatest:     getBoolPtr(true),
				Key:          &key,
				Size:         &dLgth,
				VersionId:    getPtr("null"),
				StorageClass: types.ObjectVersionStorageClassStandard,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareVersions(versions, res.Versions) {
			return fmt.Errorf("expected object versions output to be %v, instead got %v",
				versions, res.Versions)
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
		return err
	})
}

func DeleteObject_directory_object_noslash(s *S3Conf) error {
	testName := "DeleteObject_directory_object_noslash"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj/"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		obj = "my-obj"
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		// the delete above should succeed, but the object should not be deleted
		// since it should not correctly match the directory name
		// so the below head object should also succeed
		obj = "my-obj/"
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		return err
	})
}

func DeleteObject_non_empty_dir_obj(s *S3Conf) error {
	testName := "DeleteObject_non_empty_dir_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objToDel := "foo/"
		nestedObj := objToDel + "bar"
		_, err := putObjects(s3client, []string{nestedObj, objToDel}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &objToDel,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if len(res.Contents) != 1 {
			return fmt.Errorf("expected the object list length to be 1, instead got %v",
				len(res.Contents))
		}
		if getString(res.Contents[0].Key) != nestedObj {
			return fmt.Errorf("expected the object key to be %v, instead got %v",
				nestedObj, getString(res.Contents[0].Key))
		}

		return nil
	})
}

func DeleteObject_directory_not_empty(s *S3Conf) error {
	testName := "DeleteObject_directory_not_empty"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "dir/my-obj"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		obj = "dir/"
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		// object servers will return no error, but the posix backend returns
		// a non-standard directory not empty. This test is a posix only test
		// to validate the specific error response.
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrDirectoryNotEmpty)); err != nil {
			return err
		}
		return nil
	})
}

func DeleteObject_non_existing_dir_object(s *S3Conf) error {
	testName := "DeleteObject_non_existing_dir_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		obj = "my-obj/"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		return err
	})
}

func DeleteObject_directory_object(s *S3Conf) error {
	testName := "DeleteObject_directory_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "foo/bar/"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		return err
	})
}

func DeleteObject_success(s *S3Conf) error {
	testName := "DeleteObject_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
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
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		req, err := createSignedReq(http.MethodDelete, s.endpoint,
			fmt.Sprintf("%v/%v", bucket, obj), s.awsID, s.awsSecret, "s3",
			s.awsRegion, nil, time.Now(), nil)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusNoContent {
			return fmt.Errorf("expected response status to be %v, instead got %v",
				http.StatusNoContent, resp.StatusCode)
		}

		return nil
	})
}

func DeleteObjects_empty_input(s *S3Conf) error {
	testName := "DeleteObjects_empty_input"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		contents, err := putObjects(s3client, []string{"foo", "bar", "baz"}, bucket)
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
			return fmt.Errorf("expected deleted object count 0, instead got %v",
				len(out.Deleted))
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

		if !compareObjects(contents, res.Contents) {
			return fmt.Errorf("expected the output to be %v, instead got %v",
				contents, res.Contents)
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

		if len(out.Deleted) != 2 {
			return fmt.Errorf("expected deleted object count 2, instead got %v",
				len(out.Deleted))
		}
		if len(out.Errors) != 0 {
			return fmt.Errorf("expected 0 errors, instead got %v, %v",
				len(out.Errors), out.Errors)
		}

		return nil
	})
}

func DeleteObjects_success(s *S3Conf) error {
	testName := "DeleteObjects_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objects, objToDel := []string{"obj1", "obj2", "obj3"}, []string{"foo", "bar", "baz"}
		contents, err := putObjects(s3client, append(objToDel, objects...), bucket)
		if err != nil {
			return err
		}

		delObjects := []types.ObjectIdentifier{}
		delResult := []types.DeletedObject{}
		for _, key := range objToDel {
			k := key
			delObjects = append(delObjects, types.ObjectIdentifier{Key: &k})
			delResult = append(delResult, types.DeletedObject{Key: &k})
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
			return fmt.Errorf("expected deleted object count 3, instead got %v",
				len(out.Deleted))
		}
		if len(out.Errors) != 0 {
			return fmt.Errorf("expected 2 errors, instead got %v",
				len(out.Errors))
		}

		if !compareDelObjects(delResult, out.Deleted) {
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

		if !compareObjects(contents[3:], res.Contents) {
			return fmt.Errorf("expected the output to be %v, instead got %v",
				contents[3:], res.Contents)
		}

		return nil
	})
}

func CopyObject_non_existing_dst_bucket(s *S3Conf) error {
	testName := "CopyObject_non_existing_dst_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
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
		_, err := putObjects(s3client, []string{srcObj}, bucket)
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

		userS3Client := cfg.GetClient()

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
		_, err := putObjects(s3client, []string{obj}, bucket)
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

func CopyObject_copy_to_itself_invalid_directive(s *S3Conf) error {
	testName := "CopyObject_copy_to_itself_invalid_directive"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:            &bucket,
			Key:               &obj,
			CopySource:        getPtr(fmt.Sprintf("%v/%v", bucket, obj)),
			MetadataDirective: types.MetadataDirective("invalid"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidMetadataDirective)); err != nil {
			return err
		}
		return nil
	})
}

func CopyObject_invalid_tagging_directive(s *S3Conf) error {
	testName := "CopyObject_invalid_tagging_directive"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:           &bucket,
			Key:              &obj,
			CopySource:       getPtr(fmt.Sprintf("%v/%v", bucket, obj)),
			TaggingDirective: types.TaggingDirective("invalid"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidTaggingDirective)); err != nil {
			return err
		}
		return nil
	})
}

func CopyObject_should_copy_tagging(s *S3Conf) error {
	testName := "CopyObject_should_copy_tagging"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj, dstObj := "source-object", "dest-object"
		tagging := "foo=bar&baz=quxx"

		_, err := putObjectWithData(100, &s3.PutObjectInput{
			Bucket:  &bucket,
			Key:     &srcObj,
			Tagging: &tagging,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        &dstObj,
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
			Bucket: &bucket,
			Key:    &dstObj,
		})
		cancel()
		if err != nil {
			return err
		}

		expectedTagSet := []types.Tag{
			{Key: getPtr("foo"), Value: getPtr("bar")},
			{Key: getPtr("baz"), Value: getPtr("quxx")},
		}

		if !areTagsSame(res.TagSet, expectedTagSet) {
			return fmt.Errorf("expected the tag set to be %v, instead got %v",
				expectedTagSet, res.TagSet)
		}

		return nil
	})
}

func CopyObject_should_replace_tagging(s *S3Conf) error {
	testName := "CopyObject_should_replace_tagging"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket:  &bucket,
			Key:     &obj,
			Tagging: getPtr("key=value&key1=value1"),
		}, s3client)
		if err != nil {
			return err
		}
		testTagging := func(taggging string, result map[string]string, expectedErr error) error {
			dstObj := "destination-object"
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
				Bucket:           &bucket,
				Key:              &dstObj,
				Tagging:          &taggging,
				CopySource:       getPtr(fmt.Sprintf("%v/%v", bucket, obj)),
				TaggingDirective: types.TaggingDirectiveReplace,
			})
			cancel()
			if err == nil && expectedErr != nil {
				return fmt.Errorf("expected err %w, instead got nil", expectedErr)
			}
			if err != nil {
				if expectedErr == nil {
					return err
				}
				switch eErr := expectedErr.(type) {
				case s3err.APIError:
					return checkApiErr(err, eErr)
				default:
					return fmt.Errorf("invalid err provided: %w", expectedErr)
				}
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
				Bucket: &bucket,
				Key:    &dstObj,
			})
			cancel()
			if err != nil {
				return err
			}

			if len(res.TagSet) != len(result) {
				return fmt.Errorf("tag lengths are not equal: (expected): %v, (got): %v",
					len(result), len(res.TagSet))
			}

			for _, tag := range res.TagSet {
				val, ok := result[getString(tag.Key)]
				if !ok {
					return fmt.Errorf("tag key not found: %v", getString(tag.Key))
				}

				if val != getString(tag.Value) {
					return fmt.Errorf("expected the %v tag value to be %v, instead got %v",
						getString(tag.Key), val, getString(tag.Value))
				}
			}

			return nil
		}

		for _, el := range []struct {
			tagging     string
			result      map[string]string
			expectedErr error
		}{
			// success cases
			{"&", map[string]string{}, nil},
			{"&&&", map[string]string{}, nil},
			{"key", map[string]string{"key": ""}, nil},
			{"key&", map[string]string{"key": ""}, nil},
			{"key=&", map[string]string{"key": ""}, nil},
			{"key=val&", map[string]string{"key": "val"}, nil},
			{"key1&key2", map[string]string{"key1": "", "key2": ""}, nil},
			{"key1=val1&key2=val2", map[string]string{"key1": "val1", "key2": "val2"}, nil},
			// invalid url-encoded
			{"=", nil, s3err.GetAPIError(s3err.ErrInvalidURLEncodedTagging)},
			{"key%", nil, s3err.GetAPIError(s3err.ErrInvalidURLEncodedTagging)},
			// duplicate keys
			{"key=val&key=val", nil, s3err.GetAPIError(s3err.ErrInvalidURLEncodedTagging)},
			// invalid tag keys
			{"key?=val", nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			{"key(=val", nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			{"key*=val", nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			{"key$=val", nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			{"key#=val", nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			{"key@=val", nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			{"key!=val", nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			// invalid tag values
			{"key=val?", nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{"key=val(", nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{"key=val*", nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{"key=val$", nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{"key=val#", nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{"key=val@", nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{"key=val!", nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			// success special chars
			{"key-key_key.key/key=value-value_value.value/value",
				map[string]string{"key-key_key.key/key": "value-value_value.value/value"},
				nil},
			// should handle supported encoded characters
			{"key%2E=value%2F", map[string]string{"key.": "value/"}, nil},
			{"key%2D=value%2B", map[string]string{"key-": "value+"}, nil},
			{"key++key=value++value", map[string]string{"key  key": "value  value"}, nil},
			{"key%20key=value%20value", map[string]string{"key key": "value value"}, nil},
			{"key%5Fkey=value%5Fvalue", map[string]string{"key_key": "value_value"}, nil},
		} {
			err := testTagging(el.tagging, el.result, el.expectedErr)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func CopyObject_to_itself_with_new_metadata(s *S3Conf) error {
	testName := "CopyObject_to_itself_with_new_metadata"

	meta := map[string]string{
		"Hello": "World",
	}

	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:            &bucket,
			Key:               &obj,
			CopySource:        getPtr(fmt.Sprintf("%v/%v", bucket, obj)),
			Metadata:          meta,
			MetadataDirective: types.MetadataDirectiveReplace,
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
			return fmt.Errorf("expected uploaded object metadata to be %v, instead got %v",
				meta, resp.Metadata)
		}

		// verify updating metadata has correct meta
		meta = map[string]string{
			"New": "Metadata",
		}
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:            &bucket,
			Key:               &obj,
			CopySource:        getPtr(fmt.Sprintf("%v/%v", bucket, obj)),
			Metadata:          meta,
			MetadataDirective: types.MetadataDirectiveReplace,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		resp, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		if !areMapsSame(resp.Metadata, meta) {
			return fmt.Errorf("expected uploaded object metadata to be %v, instead got %v",
				meta, resp.Metadata)
		}

		return nil
	})
}

func CopyObject_CopySource_starting_with_slash(s *S3Conf) error {
	testName := "CopyObject_CopySource_starting_with_slash"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dataLength, obj := int64(1234567), "src-obj"
		dstBucket := getBucketName()
		if err := setup(s, dstBucket); err != nil {
			return err
		}

		r, err := putObjectWithData(dataLength, &s3.PutObjectInput{
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
			CopySource: getPtr(fmt.Sprintf("/%v/%v", bucket, obj)),
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
		if out.ContentLength == nil {
			return fmt.Errorf("expected content-length to be set, instead got nil")
		}
		if *out.ContentLength != dataLength {
			return fmt.Errorf("expected content-length %v, instead got %v",
				dataLength, *out.ContentLength)
		}

		defer out.Body.Close()

		bdy, err := io.ReadAll(out.Body)
		if err != nil {
			return err
		}
		outCsum := sha256.Sum256(bdy)
		if outCsum != r.csum {
			return fmt.Errorf("invalid object data")
		}

		if err := teardown(s, dstBucket); err != nil {
			return err
		}

		return nil
	})
}

func CopyObject_non_existing_dir_object(s *S3Conf) error {
	testName := "CopyObject_non_existing_dir_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dataLength, obj := int64(1234567), "my-obj"
		dstBucket := getBucketName()
		err := setup(s, dstBucket)
		if err != nil {
			return err
		}

		_, err = putObjectWithData(dataLength, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		obj = "my-obj/"

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &dstBucket,
			Key:        &obj,
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, obj)),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchKey)); err != nil {
			return err
		}

		err = teardown(s, dstBucket)
		if err != nil {
			return nil
		}

		return nil
	})
}

func CopyObject_should_copy_meta_props(s *S3Conf) error {
	testName := "CopyObject_should_copy_meta_props"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj, dstObj := "source-object", "dest-object"

		cType, cEnc, cDesp, cLang, cLength := "application/json", "base64", "test-desp", "us", int64(100)
		cacheControl, expires := "no-cache", time.Now().Add(time.Hour*10)
		meta := map[string]string{
			"foo": "bar",
			"baz": "quxx",
		}

		_, err := putObjectWithData(cLength, &s3.PutObjectInput{
			Bucket:             &bucket,
			Key:                &srcObj,
			ContentDisposition: &cDesp,
			ContentEncoding:    &cEnc,
			ContentLanguage:    &cLang,
			ContentType:        &cType,
			CacheControl:       &cacheControl,
			Expires:            &expires,
			Metadata:           meta,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        &dstObj,
			CopySource: getPtr(bucket + "/" + srcObj),
		})
		cancel()
		if err != nil {
			return err
		}

		return checkObjectMetaProps(s3client, bucket, dstObj, ObjectMetaProps{
			ContentLength:      cLength,
			ContentType:        cType,
			ContentEncoding:    cEnc,
			ContentDisposition: cDesp,
			ContentLanguage:    cLang,
			CacheControl:       cacheControl,
			ExpiresString:      expires.UTC().Format(timefmt),
			Metadata:           meta,
		})
	})
}

func CopyObject_should_replace_meta_props(s *S3Conf) error {
	testName := "CopyObject_should_replace_meta_props"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj, dstObj := "source-object", "dest-object"
		expire := time.Now().Add(time.Minute * 10)
		contentLength := int64(200)

		_, err := putObjectWithData(contentLength, &s3.PutObjectInput{
			Bucket:             &bucket,
			Key:                &srcObj,
			ContentDisposition: getPtr("test"),
			ContentEncoding:    getPtr("test"),
			ContentLanguage:    getPtr("test"),
			ContentType:        getPtr("test"),
			CacheControl:       getPtr("test"),
			Expires:            &expire,
			Metadata: map[string]string{
				"key": "val",
			},
		}, s3client)
		if err != nil {
			return err
		}

		cType, cEnc, cDesp, cLang := "application/binary", "hex", "desp", "mex"
		cacheControl, expires := "no-cache", time.Now().Add(time.Hour*10)
		meta := map[string]string{
			"foo": "bar",
			"baz": "quxx",
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:             &bucket,
			Key:                &dstObj,
			CopySource:         getPtr(bucket + "/" + srcObj),
			MetadataDirective:  types.MetadataDirectiveReplace,
			ContentDisposition: &cDesp,
			ContentEncoding:    &cEnc,
			ContentLanguage:    &cLang,
			ContentType:        &cType,
			CacheControl:       &cacheControl,
			Expires:            &expires,
			Metadata:           meta,
		})
		cancel()
		if err != nil {
			return err
		}

		return checkObjectMetaProps(s3client, bucket, dstObj, ObjectMetaProps{
			ContentLength:      contentLength,
			ContentType:        cType,
			ContentEncoding:    cEnc,
			ContentDisposition: cDesp,
			ContentLanguage:    cLang,
			CacheControl:       cacheControl,
			ExpiresString:      expires.UTC().Format(timefmt),
			Metadata:           meta,
		})
	})
}

func CopyObject_invalid_legal_hold(s *S3Conf) error {
	testName := "CopyObject_invalid_legal_hold"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj, dstObj := "source-object", "dst-object"
		_, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:                    &bucket,
			Key:                       &dstObj,
			CopySource:                getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
			ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatus("invalid_status"),
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidLegalHoldStatus))
	}, withLock())
}
func CopyObject_invalid_object_lock_mode(s *S3Conf) error {
	testName := "CopyObject_invalid_object_lock_mode"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj, dstObj := "source-object", "dst-object"
		_, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		rDate := time.Now().Add(time.Hour * 20)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:                    &bucket,
			Key:                       &dstObj,
			CopySource:                getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
			ObjectLockRetainUntilDate: &rDate,
			ObjectLockMode:            types.ObjectLockMode("invalid_mode"),
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidObjectLockMode))
	}, withLock())
}

func CopyObject_with_legal_hold(s *S3Conf) error {
	testName := "CopyObject_with_legal_hold"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj, dstObj := "source-object", "dst-object"
		_, err := putObjectWithData(100, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:                    &bucket,
			Key:                       &dstObj,
			CopySource:                getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
			ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatusOn,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
			Bucket: &bucket,
			Key:    &dstObj,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.LegalHold.Status != types.ObjectLockLegalHoldStatusOn {
			return fmt.Errorf("expected the copied object legal hold status to be %v, instead got %v",
				types.ObjectLockLegalHoldStatusOn, res.LegalHold.Status)
		}

		err = changeBucketObjectLockStatus(s3client, bucket, false)
		if err != nil {
			return err
		}

		return nil
	}, withLock())
}

func CopyObject_with_retention_lock(s *S3Conf) error {
	testName := "CopyObject_with_retention_lock"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj, dstObj := "source-object", "dst-object"
		_, err := putObjectWithData(200, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		retDate := time.Now().Add(time.Hour * 7)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:                    &bucket,
			Key:                       &dstObj,
			CopySource:                getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
			ObjectLockMode:            types.ObjectLockModeGovernance,
			ObjectLockRetainUntilDate: &retDate,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
			Bucket: &bucket,
			Key:    &dstObj,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.Retention.Mode != types.ObjectLockRetentionModeGovernance {
			return fmt.Errorf("expected the copied object retention mode to be %v, instead got %v",
				types.ObjectLockRetentionModeGovernance, res.Retention.Mode)
		}
		if res.Retention.RetainUntilDate.UTC().Unix() != retDate.UTC().Unix() {
			return fmt.Errorf("expected the retention date to be %v, instead got %v",
				retDate.Format(time.RFC1123), res.Retention.RetainUntilDate.Format(time.RFC1123))
		}

		err = changeBucketObjectLockStatus(s3client, bucket, false)
		if err != nil {
			return err
		}

		return nil
	}, withLock())
}

func CopyObject_invalid_checksum_algorithm(s *S3Conf) error {
	testName := "CopyObject_invalid_checksum_algorithm"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:            &bucket,
			Key:               &obj,
			CopySource:        getPtr(fmt.Sprintf("%v/%v", bucket, obj)),
			ChecksumAlgorithm: types.ChecksumAlgorithm("invalid_checksum_algorithm"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidChecksumAlgorithm)); err != nil {
			return err
		}

		return nil
	})
}

func CopyObject_create_checksum_on_copy(s *S3Conf) error {
	testName := "CopyObject_create_checksum_on_copy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj := "source-object"
		dstObj := "destination-object"
		_, err := putObjectWithData(300, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:            &bucket,
			Key:               &dstObj,
			CopySource:        getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
			ChecksumAlgorithm: types.ChecksumAlgorithmSha256,
		})
		cancel()
		if err != nil {
			return err
		}

		if getString(res.CopyObjectResult.ChecksumSHA256) == "" {
			return fmt.Errorf("expected non nil sha256 checksum")
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:       &bucket,
			Key:          &dstObj,
			ChecksumMode: types.ChecksumModeEnabled,
		})
		cancel()
		if err != nil {
			return err
		}

		if getString(out.ChecksumSHA256) != getString(res.CopyObjectResult.ChecksumSHA256) {
			return fmt.Errorf("expected the sha256 checksum to be %v, instead got %v",
				getString(res.CopyObjectResult.ChecksumSHA256), getString(out.ChecksumSHA256))
		}

		return nil
	})
}

func CopyObject_should_copy_the_existing_checksum(s *S3Conf) error {
	testName := "CopyObject_should_copy_the_existing_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj := "source-object"
		dstObj := "destination-object"
		out, err := putObjectWithData(100, &s3.PutObjectInput{
			Bucket:            &bucket,
			Key:               &srcObj,
			ChecksumAlgorithm: types.ChecksumAlgorithmCrc32c,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        &dstObj,
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
		})
		cancel()
		if err != nil {
			return err
		}

		if res.CopyObjectResult.ChecksumCRC32C == nil {
			return fmt.Errorf("expected non empty crc32c checksum")
		}
		if getString(res.CopyObjectResult.ChecksumCRC32C) != getString(out.res.ChecksumCRC32C) {
			return fmt.Errorf("expected crc32c checksum to be %v, instead got %v",
				getString(out.res.ChecksumCRC32C), getString(res.CopyObjectResult.ChecksumCRC32C))
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:       &bucket,
			Key:          &dstObj,
			ChecksumMode: types.ChecksumModeEnabled,
		})
		cancel()
		if err != nil {
			return err
		}

		if getString(resp.ChecksumCRC32C) != getString(res.CopyObjectResult.ChecksumCRC32C) {
			return fmt.Errorf("expected crc32c checksum to be %v, instead got %v",
				getString(res.CopyObjectResult.ChecksumCRC32C), getString(resp.ChecksumCRC32C))
		}

		return nil
	})
}

func CopyObject_should_replace_the_existing_checksum(s *S3Conf) error {
	testName := "CopyObject_should_replace_the_existing_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj := "source-object"
		dstObj := "destination-object"

		_, err := putObjectWithData(100, &s3.PutObjectInput{
			Bucket:            &bucket,
			Key:               &srcObj,
			ChecksumAlgorithm: types.ChecksumAlgorithmCrc32,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:            &bucket,
			Key:               &dstObj,
			CopySource:        getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
			ChecksumAlgorithm: types.ChecksumAlgorithmSha1, // replace crc32 with sha1
		})
		cancel()
		if err != nil {
			return err
		}

		if res.CopyObjectResult.ChecksumSHA1 == nil {
			return fmt.Errorf("expected non empty sha1 checksum")
		}
		if res.CopyObjectResult.ChecksumCRC32 != nil {
			return fmt.Errorf("expected empty crc32 checksum, instead got %v",
				*res.CopyObjectResult.ChecksumCRC32)
		}

		return nil
	})
}

func CopyObject_to_itself_by_replacing_the_checksum(s *S3Conf) error {
	testName := "CopyObject_to_itself_by_replacing_the_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		_, err := putObjectWithData(400, &s3.PutObjectInput{
			Bucket:            &bucket,
			Key:               &obj,
			ChecksumAlgorithm: types.ChecksumAlgorithmSha256,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:            &bucket,
			Key:               &obj,
			CopySource:        getPtr(fmt.Sprintf("%v/%v", bucket, obj)),
			ChecksumAlgorithm: types.ChecksumAlgorithmCrc32, // replace sh256 with crc32
			MetadataDirective: types.MetadataDirectiveReplace,
		})
		cancel()
		if err != nil {
			return err
		}

		if out.CopyObjectResult.ChecksumCRC32 == nil {
			return fmt.Errorf("expected non empty crc32 checksum")
		}
		if out.CopyObjectResult.ChecksumCRC32C != nil {
			return fmt.Errorf("expected empty crc32c checksum")
		}
		if out.CopyObjectResult.ChecksumSHA1 != nil {
			return fmt.Errorf("expected empty sha1 checksum")
		}
		if out.CopyObjectResult.ChecksumSHA256 != nil {
			return fmt.Errorf("expected empty sha256 checksum")
		}
		if out.CopyObjectResult.ChecksumCRC64NVME != nil {
			return fmt.Errorf("expected empty crc64nvme checksum")
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:       &bucket,
			Key:          &obj,
			ChecksumMode: types.ChecksumModeEnabled,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.ChecksumCRC32 == nil {
			return fmt.Errorf("expected non empty crc32 checksum")
		}
		if res.ChecksumCRC32C != nil {
			return fmt.Errorf("expected empty crc32c checksum")
		}
		if res.ChecksumSHA1 != nil {
			return fmt.Errorf("expected empty sha1 checksum")
		}
		if res.ChecksumSHA256 != nil {
			return fmt.Errorf("expected empty sha256 checksum")
		}
		if res.ChecksumCRC64NVME != nil {
			return fmt.Errorf("expected empty crc64nvme checksum")
		}

		return nil
	})
}

func CopyObject_success(s *S3Conf) error {
	testName := "CopyObject_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dataLength, obj := int64(1234567), "my obj with spaces"
		dstBucket := getBucketName()
		err := setup(s, dstBucket)
		if err != nil {
			return err
		}

		r, err := putObjectWithData(dataLength, &s3.PutObjectInput{
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
		if out.ContentLength == nil {
			return fmt.Errorf("expected content-length to be set, instead got nil")
		}
		if *out.ContentLength != dataLength {
			return fmt.Errorf("expected content-length %v, instead got %v",
				dataLength, *out.ContentLength)
		}

		bdy, err := io.ReadAll(out.Body)
		if err != nil {
			return err
		}
		defer out.Body.Close()
		outCsum := sha256.Sum256(bdy)
		if outCsum != r.csum {
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
		tagging := types.Tagging{TagSet: []types.Tag{
			{Key: getPtr(genRandString(129)), Value: getPtr("val")},
		}}
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
			Bucket:  &bucket,
			Key:     &obj,
			Tagging: &tagging})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidTagKey)); err != nil {
			return err
		}

		tagging = types.Tagging{TagSet: []types.Tag{
			{Key: getPtr("key"), Value: getPtr(genRandString(257))},
		}}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
			Bucket:  &bucket,
			Key:     &obj,
			Tagging: &tagging})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidTagValue)); err != nil {
			return err
		}

		return nil
	})
}

func PutObjectTagging_duplicate_keys(s *S3Conf) error {
	testName := "PutObjectTagging_duplicate_keys"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		tagging := types.Tagging{
			TagSet: []types.Tag{
				{Key: getPtr("key-1"), Value: getPtr("value-1")},
				{Key: getPtr("key-2"), Value: getPtr("value-2")},
				{Key: getPtr("same-key"), Value: getPtr("value-3")},
				{Key: getPtr("same-key"), Value: getPtr("value-4")},
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
			Bucket:  &bucket,
			Key:     &obj,
			Tagging: &tagging,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrDuplicateTagKey)); err != nil {
			return err
		}

		return nil
	})
}

func PutObjectTagging_tag_count_limit(s *S3Conf) error {
	testName := "PutObjectTagging_tag_count_limit"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		tagSet := []types.Tag{}
		for i := range 11 {
			tagSet = append(tagSet, types.Tag{
				Key:   getPtr(fmt.Sprintf("key-%v", i)),
				Value: getPtr(genRandString(15)),
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
			Bucket: &bucket,
			Key:    &obj,
			Tagging: &types.Tagging{
				TagSet: tagSet,
			},
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectTaggingLimited))
	})
}

func PutObjectTagging_success(s *S3Conf) error {
	testName := "PutObjectTagging_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		tagging := types.Tagging{TagSet: []types.Tag{
			{Key: getPtr("key1"), Value: getPtr("val2")},
			{Key: getPtr("key2"), Value: getPtr("val2")},
		}}
		_, err := putObjects(s3client, []string{obj}, bucket)
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
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
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

func GetObjectTagging_invalid_parent(s *S3Conf) error {
	testName := "GetObjectTagging_invalid_parent"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "not-a-dir"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		obj = "not-a-dir/bad-obj"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchKey)); err != nil {
			return err
		}
		return nil
	})
}

func GetObjectTagging_success(s *S3Conf) error {
	testName := "PutObjectTagging_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		tagging := types.Tagging{TagSet: []types.Tag{
			{Key: getPtr("key1"), Value: getPtr("val2")},
			{Key: getPtr("key2"), Value: getPtr("val2")},
		}}
		_, err := putObjects(s3client, []string{obj}, bucket)
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
		_, err := putObjects(s3client, []string{obj}, bucket)
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

		req, err := createSignedReq(http.MethodDelete, s.endpoint,
			fmt.Sprintf("%v/%v?tagging", bucket, obj), s.awsID, s.awsSecret,
			"s3", s.awsRegion, nil, time.Now(), nil)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusNoContent {
			return fmt.Errorf("expected response status to be %v, instead got %v",
				http.StatusNoContent, resp.StatusCode)
		}

		return nil
	})
}

func DeleteObjectTagging_success(s *S3Conf) error {
	testName := "DeleteObjectTagging_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		tagging := types.Tagging{TagSet: []types.Tag{
			{Key: getPtr("key1"), Value: getPtr("val2")},
			{Key: getPtr("key2"), Value: getPtr("val2")},
		}}
		_, err := putObjects(s3client, []string{obj}, bucket)
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
		cType, cEnc, cDesp, cLang := "application/text", "testenc", "testdesp", "sp"
		cacheControl, expires := "no-cache", time.Now().Add(time.Hour*5)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:             &bucket,
			Key:                &obj,
			Metadata:           meta,
			ContentType:        &cType,
			ContentEncoding:    &cEnc,
			ContentDisposition: &cDesp,
			ContentLanguage:    &cLang,
			CacheControl:       &cacheControl,
			Expires:            &expires,
		})
		cancel()
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 100, 1, bucket, obj, *out.UploadId)
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
			return fmt.Errorf("expected uploaded object metadata to be %v, instead got %v",
				meta, resp.Metadata)
		}

		if getString(resp.ContentType) != cType {
			return fmt.Errorf("expected uploaded object content-type to be %v, instead got %v",
				cType, getString(resp.ContentType))
		}
		if getString(resp.ContentEncoding) != cEnc {
			return fmt.Errorf("expected uploaded object content-encoding to be %v, instead got %v",
				cEnc, getString(resp.ContentEncoding))
		}
		if getString(resp.ContentLanguage) != cLang {
			return fmt.Errorf("expected uploaded object content-language to be %v, instead got %v",
				cLang, getString(resp.ContentLanguage))
		}
		if getString(resp.ContentDisposition) != cDesp {
			return fmt.Errorf("expected uploaded object content-disposition to be %v, instead got %v",
				cDesp, getString(resp.ContentDisposition))
		}
		if getString(resp.CacheControl) != cacheControl {
			return fmt.Errorf("expected uploaded object cache-control to be %v, instead got %v",
				cacheControl, getString(resp.CacheControl))
		}
		if getString(resp.ExpiresString) != expires.UTC().Format(timefmt) {
			return fmt.Errorf("expected uploaded object content-encoding to be %v, instead got %v",
				expires.UTC().Format(timefmt), getString(resp.ExpiresString))
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

		parts, _, err := uploadParts(s3client, 100, 1, bucket, obj, *out.UploadId)
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
			return fmt.Errorf("expected uploaded object legal hold status to be %v, instead got %v",
				types.ObjectLockLegalHoldStatusOn, resp.ObjectLockLegalHoldStatus)
		}
		if resp.ObjectLockMode != types.ObjectLockModeGovernance {
			return fmt.Errorf("expected uploaded object lock mode to be %v, instead got %v",
				types.ObjectLockModeGovernance, resp.ObjectLockMode)
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

func CreateMultipartUpload_invalid_legal_hold(s *S3Conf) error {
	testName := "CreateMultipartUpload_invalid_legal_hold"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:                    &bucket,
			Key:                       getPtr("foo"),
			ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatus("invalid_status"),
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidLegalHoldStatus))
	}, withLock())
}

func CreateMultipartUpload_invalid_object_lock_mode(s *S3Conf) error {
	testName := "CreateMultipartUpload_invalid_object_lock_mode"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		rDate := time.Now().Add(time.Hour * 10)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:                    &bucket,
			Key:                       getPtr("foo"),
			ObjectLockMode:            types.ObjectLockMode("invalid_mode"),
			ObjectLockRetainUntilDate: &rDate,
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidObjectLockMode))
	}, withLock())
}

func CreateMultipartUpload_invalid_checksum_algorithm(s *S3Conf) error {
	testName := "CreateMultipartUpload_invalid_checksum_algorithm"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:            &bucket,
			Key:               getPtr("my-obj"),
			ChecksumAlgorithm: types.ChecksumAlgorithm("invalid_checksum_algorithm"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidChecksumAlgorithm)); err != nil {
			return err
		}

		return nil
	})
}

func CreateMultipartUpload_invalid_checksum_type(s *S3Conf) error {
	testName := "CreateMultipartUpload_invalid_checksum_type"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := createMp(s3client, bucket, "my-mp", withChecksumType(types.ChecksumType("invalid_checksum_type")))
		if err := checkApiErr(err, s3err.GetInvalidChecksumHeaderErr("x-amz-checksum-type")); err != nil {
			return err
		}

		return nil
	})
}

func CreateMultipartUpload_empty_checksum_algorithm_with_checksum_type(s *S3Conf) error {
	testName := "CreateMultipartUpload_empty_checksum_algorithm_with_checksum_type"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for _, el := range types.ChecksumTypeComposite.Values() {
			_, err := createMp(s3client, bucket, "my-mp", withChecksumType(el))
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrChecksumTypeWithAlgo)); err != nil {
				return err
			}
		}

		return nil
	})
}

func CreateMultipartUpload_valid_checksum_algorithm(s *S3Conf) error {
	testName := "CreateMultipartUpload_valid_checksum_algorithm"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:            &bucket,
			Key:               getPtr("my-obj"),
			ChecksumAlgorithm: types.ChecksumAlgorithmCrc32c,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.ChecksumAlgorithm != types.ChecksumAlgorithmCrc32c {
			return fmt.Errorf("expected the checksum algorithm to be %v, instead got %v",
				types.ChecksumAlgorithmCrc32c, res.ChecksumAlgorithm)
		}

		return nil
	})
}

func CreateMultipartUpload_with_tagging(s *S3Conf) error {
	testName := "CreateMultipartUpload_with_tagging"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		testTagging := func(tagging string, result map[string]string, expectedErr error) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			mp, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
				Bucket:  &bucket,
				Key:     &obj,
				Tagging: &tagging,
			})
			cancel()
			if err == nil && expectedErr != nil {
				return fmt.Errorf("expected err %w, instead got nil", expectedErr)
			}
			if err != nil {
				if expectedErr == nil {
					return err
				}
				switch eErr := expectedErr.(type) {
				case s3err.APIError:
					return checkApiErr(err, eErr)
				default:
					return fmt.Errorf("invalid err provided: %w", expectedErr)
				}
			}

			parts, _, err := uploadParts(s3client, 5*1024*1024, 1, bucket, obj, *mp.UploadId)
			if err != nil {
				return err
			}

			cParts := []types.CompletedPart{
				{
					ETag:          parts[0].ETag,
					PartNumber:    parts[0].PartNumber,
					ChecksumCRC32: parts[0].ChecksumCRC32,
				},
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
				Bucket:   &bucket,
				Key:      &obj,
				UploadId: mp.UploadId,
				MultipartUpload: &types.CompletedMultipartUpload{
					Parts: cParts,
				},
			})
			cancel()
			if err != nil {
				return err
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			if len(res.TagSet) != len(result) {
				return fmt.Errorf("tag lengths are not equal: (expected): %v, (got): %v",
					len(result), len(res.TagSet))
			}

			for _, tag := range res.TagSet {
				val, ok := result[getString(tag.Key)]
				if !ok {
					return fmt.Errorf("tag key not found: %v", getString(tag.Key))
				}

				if val != getString(tag.Value) {
					return fmt.Errorf("expected the %v tag value to be %v, instead got %v",
						getString(tag.Key), val, getString(tag.Value))
				}
			}

			return nil
		}

		for _, el := range []struct {
			tagging     string
			result      map[string]string
			expectedErr error
		}{
			// success cases
			{"&", map[string]string{}, nil},
			{"&&&", map[string]string{}, nil},
			{"key", map[string]string{"key": ""}, nil},
			{"key&", map[string]string{"key": ""}, nil},
			{"key=&", map[string]string{"key": ""}, nil},
			{"key=val&", map[string]string{"key": "val"}, nil},
			{"key1&key2", map[string]string{"key1": "", "key2": ""}, nil},
			{"key1=val1&key2=val2", map[string]string{"key1": "val1", "key2": "val2"}, nil},
			// invalid url-encoded
			{"=", nil, s3err.GetAPIError(s3err.ErrInvalidURLEncodedTagging)},
			{"key%", nil, s3err.GetAPIError(s3err.ErrInvalidURLEncodedTagging)},
			// duplicate keys
			{"key=val&key=val", nil, s3err.GetAPIError(s3err.ErrInvalidURLEncodedTagging)},
			// invalid tag keys
			{"key?=val", nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			{"key(=val", nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			{"key*=val", nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			{"key$=val", nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			{"key#=val", nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			{"key@=val", nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			{"key!=val", nil, s3err.GetAPIError(s3err.ErrInvalidTagKey)},
			// invalid tag values
			{"key=val?", nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{"key=val(", nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{"key=val*", nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{"key=val$", nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{"key=val#", nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{"key=val@", nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			{"key=val!", nil, s3err.GetAPIError(s3err.ErrInvalidTagValue)},
			// success special chars
			{"key-key_key.key/key=value-value_value.value/value",
				map[string]string{"key-key_key.key/key": "value-value_value.value/value"},
				nil},
			// should handle supported encoded characters
			{"key%2E=value%2F", map[string]string{"key.": "value/"}, nil},
			{"key%2D=value%2B", map[string]string{"key-": "value+"}, nil},
			{"key++key=value++value", map[string]string{"key  key": "value  value"}, nil},
			{"key%20key=value%20value", map[string]string{"key key": "value value"}, nil},
			{"key%5Fkey=value%5Fvalue", map[string]string{"key_key": "value_value"}, nil},
		} {
			err := testTagging(el.tagging, el.result, el.expectedErr)
			if err != nil {
				return err
			}
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

		if out.Bucket == nil {
			return fmt.Errorf("expected bucket name to be not nil")
		}
		if out.Key == nil {
			return fmt.Errorf("expected object name to be not nil")
		}
		if *out.Bucket != bucket {
			return fmt.Errorf("expected bucket name %v, instead got %v",
				bucket, *out.Bucket)
		}
		if *out.Key != obj {
			return fmt.Errorf("expected object name %v, instead got %v",
				obj, *out.Key)
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
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key := "my-obj"
		mp, err := createMp(s3client, bucket, key)
		if err != nil {
			return err
		}
		for _, el := range []int32{0, -1, 10001, 2300000} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
				Bucket:     &bucket,
				Key:        &key,
				UploadId:   mp.UploadId,
				PartNumber: &el,
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidPartNumber)); err != nil {
				return err
			}
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

func UploadPart_checksum_algorithm_and_header_mismatch(s *S3Conf) error {
	testName := "UploadPart_checksum_algorithm_and_header_mismatch"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		mp, err := createMp(s3client, bucket, obj, withChecksum(types.ChecksumAlgorithmCrc32))
		if err != nil {
			return err
		}

		partNumber := int32(1)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:            &bucket,
			Key:               &obj,
			ChecksumAlgorithm: types.ChecksumAlgorithmCrc32,
			ChecksumCRC32C:    getPtr("m0cB1Q=="),
			PartNumber:        &partNumber,
			UploadId:          mp.UploadId,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMultipleChecksumHeaders)); err != nil {
			return err
		}

		return nil
	})
}

func UploadPart_multiple_checksum_headers(s *S3Conf) error {
	testName := "UploadPart_multiple_checksum_headers"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		mp, err := createMp(s3client, bucket, obj, withChecksum(types.ChecksumAlgorithmCrc32c))
		if err != nil {
			return err
		}

		partNumber := int32(1)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:         &bucket,
			Key:            &obj,
			ChecksumSHA1:   getPtr("Kq5sNclPz7QV2+lfQIuc6R7oRu0="),
			ChecksumCRC32C: getPtr("m0cB1Q=="),
			UploadId:       mp.UploadId,
			PartNumber:     &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMultipleChecksumHeaders)); err != nil {
			return err
		}

		// multiple empty checksums
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:         &bucket,
			Key:            &obj,
			ChecksumSHA1:   getPtr(""),
			ChecksumCRC32C: getPtr(""),
			UploadId:       mp.UploadId,
			PartNumber:     &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMultipleChecksumHeaders)); err != nil {
			return err
		}

		return nil
	})
}

func UploadPart_invalid_checksum_header(s *S3Conf) error {
	testName := "UploadPart_invalid_checksum_header"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		partNumber := int32(1)

		for _, el := range []struct {
			algo      string
			crc32     *string
			crc32c    *string
			sha1      *string
			sha256    *string
			crc64nvme *string
		}{
			// CRC32 tests
			{
				algo:  "crc32",
				crc32: getPtr(""),
			},
			{
				algo:  "crc32",
				crc32: getPtr("invalid_base64!"), // invalid base64
			},
			{
				algo:  "crc32",
				crc32: getPtr("YXNrZGpoZ2tqYXNo"), // valid base64 but not crc32
			},
			// CRC32C tests
			{
				algo:   "crc32c",
				crc32c: getPtr(""),
			},
			{
				algo:   "crc32c",
				crc32c: getPtr("invalid_base64!"), // invalid base64
			},
			{
				algo:   "crc32c",
				crc32c: getPtr("c2RhZnNhZGZzZGFm"), // valid base64 but not crc32c
			},
			// SHA1 tests
			{
				algo: "sha1",
				sha1: getPtr(""),
			},
			{
				algo: "sha1",
				sha1: getPtr("invalid_base64!"), // invalid base64
			},
			{
				algo: "sha1",
				sha1: getPtr("c2RhZmRhc2Zkc2Fmc2RhZnNhZGZzYWRm"), // valid base64 but not sha1
			},
			// SHA256 tests
			{
				algo:   "sha256",
				sha256: getPtr(""),
			},
			{
				algo:   "sha256",
				sha256: getPtr("invalid_base64!"), // invalid base64
			},
			{
				algo:   "sha256",
				sha256: getPtr("ZGZnbmRmZ2hoZmRoZmdkaA=="), // valid base64 but not sha56
			},
			// CRC64NVME tests
			{
				algo:      "crc64nvme",
				crc64nvme: getPtr(""),
			},
			{
				algo:      "crc64nvme",
				crc64nvme: getPtr("invalid_base64!"), // invalid base64
			},
			{
				algo:      "crc64nvme",
				crc64nvme: getPtr("ZHNhZmRzYWZzZGFmZHNhZg=="), // valid base64 but not crc64nvme
			},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
				Bucket:            &bucket,
				Key:               &obj,
				ChecksumCRC32:     el.crc32,
				ChecksumCRC32C:    el.crc32c,
				ChecksumSHA1:      el.sha1,
				ChecksumSHA256:    el.sha256,
				ChecksumCRC64NVME: el.crc64nvme,
				PartNumber:        &partNumber,
				UploadId:          mp.UploadId,
			})
			cancel()
			if err := checkApiErr(err, s3err.GetInvalidChecksumHeaderErr(fmt.Sprintf("x-amz-checksum-%v", el.algo))); err != nil {
				return err
			}
		}

		return nil
	})
}

func UploadPart_checksum_algorithm_mistmatch_on_initialization(s *S3Conf) error {
	testName := "UploadPart_checksum_algorithm_mistmatch_on_initialization"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		mp, err := createMp(s3client, bucket, obj, withChecksum(types.ChecksumAlgorithmCrc32))
		if err != nil {
			return err
		}

		partNumber := int32(1)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:            &bucket,
			Key:               &obj,
			UploadId:          mp.UploadId,
			PartNumber:        &partNumber,
			ChecksumAlgorithm: types.ChecksumAlgorithmSha1,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetChecksumTypeMismatchErr(types.ChecksumAlgorithmCrc32, types.ChecksumAlgorithmSha1)); err != nil {
			return err
		}

		return nil
	})
}

func UploadPart_checksum_algorithm_mistmatch_on_initialization_with_value(s *S3Conf) error {
	testName := "UploadPart_checksum_algorithm_mistmatch_on_initialization_with_value"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		mp, err := createMp(s3client, bucket, obj, withChecksum(types.ChecksumAlgorithmCrc32))
		if err != nil {
			return err
		}

		partNumber := int32(1)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:         &bucket,
			Key:            &obj,
			UploadId:       mp.UploadId,
			PartNumber:     &partNumber,
			ChecksumSHA256: getPtr("uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek="),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetChecksumTypeMismatchErr(types.ChecksumAlgorithmCrc32, types.ChecksumAlgorithmSha256)); err != nil {
			return err
		}

		return nil
	})
}

func UploadPart_incorrect_checksums(s *S3Conf) error {
	testName := "UploadPart_incorrect_checksums"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		for _, el := range []struct {
			algo      types.ChecksumAlgorithm
			crc32     *string
			crc32c    *string
			sha1      *string
			sha256    *string
			crc64nvme *string
		}{
			{
				algo:  types.ChecksumAlgorithmCrc32,
				crc32: getPtr("DUoRhQ=="),
			},
			{
				algo:   types.ChecksumAlgorithmCrc32c,
				crc32c: getPtr("yZRlqg=="),
			},
			{
				algo: types.ChecksumAlgorithmSha1,
				sha1: getPtr("Kq5sNclPz7QV2+lfQIuc6R7oRu0="),
			},
			{
				algo:   types.ChecksumAlgorithmSha256,
				sha256: getPtr("uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek="),
			},
			{
				algo:      types.ChecksumAlgorithmCrc64nvme,
				crc64nvme: getPtr("MN2ofvMjpIQ="),
			},
		} {
			mp, err := createMp(s3client, bucket, obj, withChecksum(el.algo))
			if err != nil {
				return err
			}

			body := strings.NewReader("random string body")
			partNumber := int32(1)

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.UploadPart(ctx, &s3.UploadPartInput{
				Bucket:            &bucket,
				Key:               &obj,
				ChecksumCRC32:     el.crc32,
				ChecksumCRC32C:    el.crc32c,
				ChecksumSHA1:      el.sha1,
				ChecksumSHA256:    el.sha256,
				ChecksumCRC64NVME: el.crc64nvme,
				UploadId:          mp.UploadId,
				PartNumber:        &partNumber,
				Body:              body,
			})
			cancel()
			if err := checkApiErr(err, s3err.GetChecksumBadDigestErr(el.algo)); err != nil {
				return err
			}
		}

		return nil
	})
}

func UploadPart_with_checksums_success(s *S3Conf) error {
	testName := "UploadPart_with_checksums_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		for i, algo := range types.ChecksumAlgorithmCrc32.Values() {
			mp, err := createMp(s3client, bucket, obj, withChecksum(algo))
			if err != nil {
				return err
			}

			partNumber := int32(1)
			data := make([]byte, i*100)
			rand.Read(data)

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
				Bucket:            &bucket,
				Key:               &obj,
				ChecksumAlgorithm: algo,
				UploadId:          mp.UploadId,
				PartNumber:        &partNumber,
				Body:              bytes.NewReader(data),
			})
			cancel()
			if err != nil {
				return err
			}

			switch algo {
			case types.ChecksumAlgorithmCrc32:
				if res.ChecksumCRC32 == nil {
					return fmt.Errorf("expected non empty crc32 checksum in the response")
				}
			case types.ChecksumAlgorithmCrc32c:
				if res.ChecksumCRC32C == nil {
					return fmt.Errorf("expected non empty crc32c checksum in the response")
				}
			case types.ChecksumAlgorithmSha1:
				if res.ChecksumSHA1 == nil {
					return fmt.Errorf("expected non empty sha1 checksum in the response")
				}
			case types.ChecksumAlgorithmSha256:
				if res.ChecksumSHA256 == nil {
					return fmt.Errorf("expected non empty sha256 checksum in the response")
				}
			case types.ChecksumAlgorithmCrc64nvme:
				if res.ChecksumCRC64NVME == nil {
					return fmt.Errorf("expected non empty crc64nvme checksum in the response")
				}
			}
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
		if getString(res.ETag) == "" {
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
		_, err = putObjects(s3client, []string{srcObj}, srcBucket)
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
		_, err = putObjects(s3client, []string{srcObj}, srcBucket)
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
		_, err = putObjectWithData(int64(objSize), &s3.PutObjectInput{
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
			return fmt.Errorf("expected parts to be 1, instead got %v",
				len(res.Parts))
		}
		if res.Parts[0].PartNumber == nil || *res.Parts[0].PartNumber != 1 {
			return fmt.Errorf("expected part-number to be 1, instead got %v",
				res.Parts[0].PartNumber)
		}
		if res.Parts[0].Size == nil || *res.Parts[0].Size != int64(objSize) {
			return fmt.Errorf("expected part size to be %v, instead got %v",
				objSize, res.Parts[0].Size)
		}
		if getString(res.Parts[0].ETag) != getString(copyOut.CopyPartResult.ETag) {
			return fmt.Errorf("expected part etag to be %v, instead got %v",
				getString(copyOut.CopyPartResult.ETag), getString(res.Parts[0].ETag))
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_by_range_invalid_ranges(s *S3Conf) error {
	testName := "UploadPartCopy_by_range_invalid_ranges"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket, srcObj := "my-obj", getBucketName(), "src-obj"
		err := setup(s, srcBucket)
		if err != nil {
			return err
		}
		objSize := int64(5 * 1024 * 1024)
		_, err = putObjectWithData(objSize, &s3.PutObjectInput{
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

		uploadPartCopy := func(csRange string, ptNumber int32) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
				Bucket:          &bucket,
				CopySource:      getPtr(srcBucket + "/" + srcObj),
				UploadId:        out.UploadId,
				Key:             &obj,
				PartNumber:      &ptNumber,
				CopySourceRange: &csRange,
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidCopySourceRange)); err != nil {
				return err
			}

			return nil
		}

		for i, rg := range []string{
			"byte=100-200",
			"bytes=invalid-range",
			"bytes=200-100",
			"bytes=-2-300",
			"bytes=aa-12",
			"bytes=12-aa",
			"bytes=bb-",
		} {
			err := uploadPartCopy(rg, int32(i+1))
			if err != nil {
				return err
			}
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_exceeding_copy_source_range(s *S3Conf) error {
	testName := "UploadPartCopy_exceeding_copy_source_range"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket, srcObj := "my-obj", getBucketName(), "src-obj"
		err := setup(s, srcBucket)
		if err != nil {
			return err
		}
		objSize := int64(1000)
		_, err = putObjectWithData(objSize, &s3.PutObjectInput{
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

		uploadPartCopy := func(csRange string, ptNumber int32) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
				Bucket:          &bucket,
				CopySource:      getPtr(srcBucket + "/" + srcObj),
				UploadId:        out.UploadId,
				Key:             &obj,
				PartNumber:      &ptNumber,
				CopySourceRange: &csRange,
			})
			cancel()
			return checkApiErr(err, s3err.CreateExceedingRangeErr(objSize))
		}

		for i, rg := range []string{
			"bytes=100-1005",
			"bytes=1250-3000",
			"bytes=100-1000",
		} {
			err := uploadPartCopy(rg, int32(i+1))
			if err != nil {
				return err
			}
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
		_, err = putObjectWithData(int64(srcObjSize), &s3.PutObjectInput{
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
		if err := checkApiErr(err, s3err.CreateExceedingRangeErr(int64(srcObjSize))); err != nil {
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
		_, err = putObjectWithData(int64(objSize), &s3.PutObjectInput{
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
			return fmt.Errorf("expected parts to be 1, instead got %v",
				len(res.Parts))
		}
		if res.Parts[0].PartNumber == nil {
			return fmt.Errorf("expected part-number to be 1, instead got nil")
		}
		if *res.Parts[0].PartNumber != 1 {
			return fmt.Errorf("expected part-number to be 1, instead got %v",
				res.Parts[0].PartNumber)
		}
		if res.Parts[0].Size == nil {
			return fmt.Errorf("expected part size to be non nil, instead got nil")
		}
		if *res.Parts[0].Size != 101 {
			return fmt.Errorf("expected part size to be %v, instead got %v",
				101, res.Parts[0].Size)
		}
		if getString(res.Parts[0].ETag) != getString(copyOut.CopyPartResult.ETag) {
			return fmt.Errorf("expected part etag to be %v, instead got %v",
				getString(copyOut.CopyPartResult.ETag), getString(res.Parts[0].ETag))
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_should_copy_the_checksum(s *S3Conf) error {
	testName := "UploadPartCopy_should_copy_the_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		srcObj := "source-object"

		mp, err := createMp(s3client, bucket, obj, withChecksum(types.ChecksumAlgorithmCrc32))
		if err != nil {
			return err
		}

		out, err := putObjectWithData(300, &s3.PutObjectInput{
			Bucket:            &bucket,
			Key:               &srcObj,
			ChecksumAlgorithm: types.ChecksumAlgorithmCrc32,
		}, s3client)
		if err != nil {
			return err
		}

		partNumber := int32(1)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			Key:        &obj,
			UploadId:   mp.UploadId,
			PartNumber: &partNumber,
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
		})
		cancel()
		if err != nil {
			return err
		}

		if getString(res.CopyPartResult.ChecksumCRC32) != getString(out.res.ChecksumCRC32) {
			return fmt.Errorf("expected crc32 checksum to be %v, instead got %v",
				getString(out.res.ChecksumCRC32), getString(res.CopyPartResult.ChecksumCRC32))
		}
		if res.CopyPartResult.ChecksumCRC32C != nil {
			return fmt.Errorf("expected nil crc32c checksum, instead got %v",
				*res.CopyPartResult.ChecksumCRC32C)
		}
		if res.CopyPartResult.ChecksumSHA1 != nil {
			return fmt.Errorf("expected nil sha1 checksum, instead got %v",
				*res.CopyPartResult.ChecksumSHA1)
		}
		if res.CopyPartResult.ChecksumSHA256 != nil {
			return fmt.Errorf("expected nil sha256 checksum, instead got %v",
				*res.CopyPartResult.ChecksumSHA256)
		}
		if res.CopyPartResult.ChecksumCRC64NVME != nil {
			return fmt.Errorf("expected nil crc64nvme checksum, instead got %v",
				*res.CopyPartResult.ChecksumCRC64NVME)
		}

		return nil
	})
}

func UploadPartCopy_should_not_copy_the_checksum(s *S3Conf) error {
	testName := "UploadPartCopy_should_not_copy_the_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		srcObj := "source-object"

		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		_, err = putObjectWithData(300, &s3.PutObjectInput{
			Bucket:            &bucket,
			Key:               &srcObj,
			ChecksumAlgorithm: types.ChecksumAlgorithmSha1,
		}, s3client)
		if err != nil {
			return err
		}

		partNumber := int32(1)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			Key:        &obj,
			UploadId:   mp.UploadId,
			PartNumber: &partNumber,
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
		})
		cancel()
		if err != nil {
			return err
		}

		if res.CopyPartResult.ChecksumCRC32 != nil {
			return fmt.Errorf("expected nil crc32 checksum, instead got %v",
				*res.CopyPartResult.ChecksumCRC32)
		}
		if res.CopyPartResult.ChecksumCRC32C != nil {
			return fmt.Errorf("expected nil crc32c checksum, instead got %v",
				*res.CopyPartResult.ChecksumCRC32C)
		}
		if res.CopyPartResult.ChecksumSHA1 != nil {
			return fmt.Errorf("expected nil sha1 checksum, instead got %v",
				*res.CopyPartResult.ChecksumSHA1)
		}
		if res.CopyPartResult.ChecksumSHA256 != nil {
			return fmt.Errorf("expected nil sha256 checksum, instead got %v",
				*res.CopyPartResult.ChecksumSHA256)
		}
		if res.CopyPartResult.ChecksumCRC64NVME != nil {
			return fmt.Errorf("expected nil crc64nvme checksum, instead got %v",
				*res.CopyPartResult.ChecksumCRC64NVME)
		}

		return nil
	})
}

func UploadPartCopy_should_calculate_the_checksum(s *S3Conf) error {
	testName := "UploadPartCopy_should_calculate_the_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		srcObj := "source-object"

		mp, err := createMp(s3client, bucket, obj, withChecksum(types.ChecksumAlgorithmSha256))
		if err != nil {
			return err
		}

		_, err = putObjectWithData(300, &s3.PutObjectInput{
			Bucket:            &bucket,
			Key:               &srcObj,
			ChecksumAlgorithm: types.ChecksumAlgorithmSha1, // different from the mp checksum (sha256)
		}, s3client)
		if err != nil {
			return err
		}

		partNumber := int32(1)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			Key:        &obj,
			UploadId:   mp.UploadId,
			PartNumber: &partNumber,
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
		})
		cancel()
		if err != nil {
			return err
		}

		if res.CopyPartResult.ChecksumCRC32 != nil {
			return fmt.Errorf("expected nil crc32 checksum, instead got %v",
				*res.CopyPartResult.ChecksumCRC32)
		}
		if res.CopyPartResult.ChecksumCRC32C != nil {
			return fmt.Errorf("expected nil crc32c checksum, instead got %v",
				*res.CopyPartResult.ChecksumCRC32C)
		}
		if res.CopyPartResult.ChecksumCRC64NVME != nil {
			return fmt.Errorf("expected nil crc64nvme checksum, instead got %v",
				*res.CopyPartResult.ChecksumCRC64NVME)
		}
		if res.CopyPartResult.ChecksumSHA1 != nil {
			return fmt.Errorf("expected nil sha1 checksum, instead got %v",
				*res.CopyPartResult.ChecksumSHA1)
		}
		if getString(res.CopyPartResult.ChecksumSHA256) == "" {
			return fmt.Errorf("expected non empty sha256 checksum")
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

func ListParts_invalid_max_parts(s *S3Conf) error {
	testName := "ListParts_invalid_max_parts"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		invMaxParts := int32(-3)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
			MaxParts: &invMaxParts,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidMaxParts)); err != nil {
			return err
		}

		return nil
	})
}

func ListParts_default_max_parts(s *S3Conf) error {
	testName := "ListParts_default_max_parts"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
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

		if res.MaxParts == nil {
			return fmt.Errorf("unexpected nil max-parts")
		}
		if *res.MaxParts != 1000 {
			return fmt.Errorf("expected max parts to be 1000, instead got %v",
				*res.MaxParts)
		}

		return nil
	})
}

func ListParts_exceeding_max_parts(s *S3Conf) error {
	testName := "ListParts_exceeding_max_parts"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			UploadId: mp.UploadId,
			Key:      &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.MaxParts == nil {
			return fmt.Errorf("unexpected nil max-parts")
		}
		if *res.MaxParts != 1000 {
			return fmt.Errorf("expected max-parts to be %v, instead got %v",
				1000, *res.MaxParts)
		}

		return nil
	})
}

func ListParts_truncated(s *S3Conf) error {
	testName := "ListParts_truncated"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 25*1024*1024, 5, bucket, obj, *out.UploadId)
		if err != nil {
			return err
		}

		maxParts := int32(3)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
			MaxParts: &maxParts,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.IsTruncated == nil {
			return fmt.Errorf("unexpected nil is-truncated")
		}
		if res.MaxParts == nil {
			return fmt.Errorf("unexpected nil max-parts")
		}
		if !*res.IsTruncated {
			return fmt.Errorf("expected the result to be truncated")
		}
		if *res.MaxParts != maxParts {
			return fmt.Errorf("expected max-parts to be %v, instead got %v",
				maxParts, *res.MaxParts)
		}
		if getString(res.NextPartNumberMarker) != fmt.Sprint(*parts[2].PartNumber) {
			return fmt.Errorf("expected next part number marker to be %v, instead got %v",
				fmt.Sprint(*parts[2].PartNumber), getString(res.NextPartNumberMarker))
		}
		if !compareParts(parts[:3], res.Parts) {
			return fmt.Errorf("expected the parts data to be %v, instead got %v",
				parts[:3], res.Parts)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res2, err := s3client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:           &bucket,
			Key:              &obj,
			UploadId:         out.UploadId,
			PartNumberMarker: res.NextPartNumberMarker,
		})
		cancel()
		if err != nil {
			return err
		}

		if getString(res2.PartNumberMarker) != getString(res.NextPartNumberMarker) {
			return fmt.Errorf("expected part number marker to be %v, instead got %v",
				getString(res.NextPartNumberMarker), getString(res2.PartNumberMarker))
		}
		if !compareParts(parts[3:], res2.Parts) {
			return fmt.Errorf("expected the parts data to be %v, instead got %v",
				parts[3:], res2.Parts)
		}

		return nil
	})
}

func ListParts_with_checksums(s *S3Conf) error {
	testName := "ListParts_with_checksums"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		for i, algo := range types.ChecksumAlgorithmCrc32.Values() {
			mp, err := createMp(s3client, bucket, obj, withChecksum(algo))
			if err != nil {
				return err
			}

			parts, _, err := uploadParts(s3client, int64((i+1)*5*1024*1024), int64(i+1), bucket, obj, *mp.UploadId, withChecksum(algo))
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.ListParts(ctx, &s3.ListPartsInput{
				Bucket:   &bucket,
				Key:      &obj,
				UploadId: mp.UploadId,
			})
			cancel()
			if err != nil {
				return err
			}

			if !compareParts(parts, res.Parts) {
				return fmt.Errorf("expected the mp parts to be %v, instead got %v",
					parts, res.Parts)
			}
		}

		return nil
	})
}

func ListParts_null_checksums(s *S3Conf) error {
	testName := "ListParts_null_checksums"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		_, _, err = uploadParts(s3client, 20*1024*1024, 3, bucket, obj, *mp.UploadId)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.ChecksumType != types.ChecksumType("null") {
			return fmt.Errorf("expected the checksum type to be null, instead got %v", res.ChecksumType)
		}
		if res.ChecksumAlgorithm != types.ChecksumAlgorithm("null") {
			return fmt.Errorf("expected the checksum algorithm to be null, instead got %v", res.ChecksumAlgorithm)
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

		parts, _, err := uploadParts(s3client, 5*1024*1024, 5, bucket, obj, *out.UploadId)
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

		if res.StorageClass != types.StorageClassStandard {
			return fmt.Errorf("expected the storage class to be %v, instead got %v",
				types.StorageClassStandard, res.StorageClass)
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
			return fmt.Errorf("expected empty uploads, instead got %+v",
				out.Uploads)
		}

		return nil
	})
}

func ListMultipartUploads_invalid_max_uploads(s *S3Conf) error {
	testName := "ListMultipartUploads_invalid_max_uploads"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		maxUploads := int32(-3)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:     &bucket,
			MaxUploads: &maxUploads,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidMaxUploads)); err != nil {
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
			uploads = append(uploads, types.MultipartUpload{
				UploadId:     out.UploadId,
				Key:          out.Key,
				StorageClass: types.StorageClassStandard,
			})
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

		if out.IsTruncated == nil {
			return fmt.Errorf("unexpected nil is-truncated")
		}
		if out.MaxUploads == nil {
			return fmt.Errorf("unexpected nil max-uploads")
		}
		if !*out.IsTruncated {
			return fmt.Errorf("expected the output to be truncated")
		}
		if *out.MaxUploads != 2 {
			return fmt.Errorf("expected max-uploads to be 2, instead got %v",
				out.MaxUploads)
		}
		if ok := compareMultipartUploads(out.Uploads, uploads[:2]); !ok {
			return fmt.Errorf("expected multipart uploads to be %v, instead got %v",
				uploads[:2], out.Uploads)
		}
		if getString(out.NextKeyMarker) != getString(uploads[1].Key) {
			return fmt.Errorf("expected next-key-marker to be %v, instead got %v",
				getString(uploads[1].Key), getString(out.NextKeyMarker))
		}
		if getString(out.NextUploadIdMarker) != getString(uploads[1].UploadId) {
			return fmt.Errorf("expected next-upload-id-marker to be %v, instead got %v",
				getString(uploads[1].UploadId), getString(out.NextUploadIdMarker))
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
			return fmt.Errorf("expected multipart uploads to be %v, instead got %v",
				uploads[2:], out.Uploads)
		}

		return nil
	})
}

func ListMultipartUploads_exceeding_max_uploads(s *S3Conf) error {
	testName := "ListMultipartUploads_exceeding_max_uploads"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		maxUploads := int32(1343235)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:     &bucket,
			MaxUploads: &maxUploads,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.MaxUploads == nil {
			return fmt.Errorf("unexpected nil max-uploads")
		}
		if *res.MaxUploads != 1000 {
			return fmt.Errorf("expected max-uploads to be %v, instaed got %v",
				1000, *res.MaxUploads)
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
			KeyMarker: getPtr("wrong_object_key"),
		})
		cancel()
		if err != nil {
			return err
		}

		if len(out.Uploads) != 0 {
			return fmt.Errorf("expected empty list of multipart uploads, instead got %v",
				out.Uploads)
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
			uploads = append(uploads, types.MultipartUpload{
				UploadId:     out.UploadId,
				Key:          out.Key,
				StorageClass: types.StorageClassStandard,
			})
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
			return fmt.Errorf("expected multipart uploads to be %v, instead got %v",
				uploads, out.Uploads)
		}

		return nil
	})
}

func ListMultipartUploads_with_checksums(s *S3Conf) error {
	testName := "ListMultipartUploads_with_checksums"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		uploads := []types.MultipartUpload{}
		for _, el := range []struct {
			obj  string
			algo types.ChecksumAlgorithm
			t    types.ChecksumType
		}{
			{
				obj:  "obj-1",
				algo: types.ChecksumAlgorithmCrc32,
				t:    types.ChecksumTypeComposite,
			},
			{
				obj:  "obj-2",
				algo: types.ChecksumAlgorithmCrc32c,
				t:    types.ChecksumTypeFullObject,
			},
			{
				obj:  "obj-3",
				algo: types.ChecksumAlgorithmSha1,
				t:    types.ChecksumTypeComposite,
			},
			{
				obj:  "obj-4",
				algo: types.ChecksumAlgorithmSha256,
				t:    types.ChecksumTypeComposite,
			},
			{
				obj:  "obj-5",
				algo: types.ChecksumAlgorithmCrc64nvme,
				t:    types.ChecksumTypeFullObject,
			},
		} {
			key := el.obj
			mp, err := createMp(s3client, bucket, key, withChecksum(el.algo), withChecksumType(el.t))
			if err != nil {
				return err
			}

			uploads = append(uploads, types.MultipartUpload{
				Key:               &key,
				UploadId:          mp.UploadId,
				StorageClass:      types.StorageClassStandard,
				ChecksumAlgorithm: el.algo,
				ChecksumType:      el.t,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareMultipartUploads(res.Uploads, uploads) {
			return fmt.Errorf("expected the final multipart uploads to be %v, instead got %v",
				uploads, res.Uploads)
		}

		return nil
	})
}

func ListMultipartUploads_success(s *S3Conf) error {
	testName := "ListMultipartUploads_success"
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
				Key:          &obj1,
				UploadId:     out1.UploadId,
				StorageClass: types.StorageClassStandard,
			},
			{
				Key:          &obj2,
				UploadId:     out2.UploadId,
				StorageClass: types.StorageClassStandard,
			},
		}

		if len(out.Uploads) != 2 {
			return fmt.Errorf("expected 2 upload, instead got %v",
				len(out.Uploads))
		}
		if ok := compareMultipartUploads(out.Uploads, expected); !ok {
			return fmt.Errorf("expected uploads %v, instead got %v",
				expected, out.Uploads)
		}

		return nil
	})
}

func AbortMultipartUpload_non_existing_bucket(s *S3Conf) error {
	testName := "AbortMultipartUpload_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   getPtr("incorrect-bucket"),
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

		req, err := createSignedReq(http.MethodDelete, s.endpoint,
			fmt.Sprintf("%v/%v?uploadId=%v", bucket, obj, *out.UploadId),
			s.awsID, s.awsSecret, "s3", s.awsRegion, nil, time.Now(), nil)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusNoContent {
			return fmt.Errorf("expected response status to be %v, instead got %v",
				http.StatusNoContent, resp.StatusCode)
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

func CompleteMultipartUpload_incorrect_part_number(s *S3Conf) error {
	testName := "CompleteMultipartUpload_incorrect_part_number"
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
func CompleteMultipartUpload_invalid_checksum_type(s *S3Conf) error {
	testName := "CompleteMultipartUpload_invalid_checksum_type"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		mp, err := createMp(s3client, bucket, obj,
			withChecksum(types.ChecksumAlgorithmCrc32),
			withChecksumType(types.ChecksumTypeFullObject))
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 20*1024*1024, 4, bucket, obj,
			*mp.UploadId, withChecksum(types.ChecksumAlgorithmCrc32))
		if err != nil {
			return err
		}

		cParts := []types.CompletedPart{}
		for _, el := range parts {
			cParts = append(cParts, types.CompletedPart{
				ETag:          el.ETag,
				PartNumber:    el.PartNumber,
				ChecksumCRC32: el.ChecksumCRC32,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: cParts,
			},
			ChecksumType: types.ChecksumType("invalid_type"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetInvalidChecksumHeaderErr("x-amz-checksum-type")); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_invalid_checksum_part(s *S3Conf) error {
	testName := "CompleteMultipartUpload_invalid_checksum_part"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		mp, err := createMp(s3client, bucket, obj,
			withChecksum(types.ChecksumAlgorithmCrc32),
			withChecksumType(types.ChecksumTypeFullObject))
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 15*1024*1024, 3, bucket, obj,
			*mp.UploadId, withChecksum(types.ChecksumAlgorithmCrc32))
		if err != nil {
			return err
		}

		cParts := []types.CompletedPart{}
		for i, el := range parts {
			cParts = append(cParts, types.CompletedPart{
				ETag:          el.ETag,
				PartNumber:    el.PartNumber,
				ChecksumCRC32: el.ChecksumCRC32,
			})

			if i == 0 {
				cParts[0].ChecksumCRC32 = getPtr("invalid_checksum")
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: cParts,
			},
			ChecksumType: types.ChecksumTypeFullObject,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidChecksumPart)); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_multiple_checksum_part(s *S3Conf) error {
	testName := "CompleteMultipartUpload_multiple_checksum_part"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		mp, err := createMp(s3client, bucket, obj,
			withChecksum(types.ChecksumAlgorithmCrc32),
			withChecksumType(types.ChecksumTypeComposite))
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 15*1024*1024, 3, bucket, obj,
			*mp.UploadId, withChecksum(types.ChecksumAlgorithmCrc32))
		if err != nil {
			return err
		}

		cParts := []types.CompletedPart{}
		for i, el := range parts {
			cParts = append(cParts, types.CompletedPart{
				ETag:          el.ETag,
				PartNumber:    el.PartNumber,
				ChecksumCRC32: el.ChecksumCRC32,
			})

			if i == 0 {
				cParts[0].ChecksumSHA1 = getPtr("Kq5sNclPz7QV2+lfQIuc6R7oRu0=")
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: cParts,
			},
			ChecksumType: types.ChecksumTypeComposite,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidChecksumPart)); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_incorrect_checksum_part(s *S3Conf) error {
	testName := "CompleteMultipartUpload_incorrect_checksum_part"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		mp, err := createMp(s3client, bucket, obj,
			withChecksum(types.ChecksumAlgorithmSha256),
			withChecksumType(types.ChecksumTypeComposite))
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 15*1024*1024, 3, bucket, obj,
			*mp.UploadId, withChecksum(types.ChecksumAlgorithmSha256))
		if err != nil {
			return err
		}

		cParts := []types.CompletedPart{}
		for i, el := range parts {
			cParts = append(cParts, types.CompletedPart{
				ETag:           el.ETag,
				PartNumber:     el.PartNumber,
				ChecksumSHA256: el.ChecksumSHA256,
			})

			if i == 0 {
				cParts[0].ChecksumSHA256 = getPtr("n2alat9FhKiZXkZO18V2LLcZFM3IT8R7DjSMvK//7WU=")
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: cParts,
			},
			ChecksumType: types.ChecksumTypeComposite,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidPart)); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_different_checksum_part(s *S3Conf) error {
	testName := "CompleteMultipartUpload_different_checksum_part"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		mp, err := createMp(s3client, bucket, obj,
			withChecksum(types.ChecksumAlgorithmCrc32c),
			withChecksumType(types.ChecksumTypeFullObject))
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 15*1024*1024, 3, bucket, obj,
			*mp.UploadId, withChecksum(types.ChecksumAlgorithmCrc32c))
		if err != nil {
			return err
		}

		cParts := []types.CompletedPart{}
		for i, el := range parts {
			cParts = append(cParts, types.CompletedPart{
				ETag:           el.ETag,
				PartNumber:     el.PartNumber,
				ChecksumCRC32C: el.ChecksumCRC32C,
			})

			if i == 0 {
				cParts[0].ChecksumSHA256 = getPtr("n2alat9FhKiZXkZO18V2LLcZFM3IT8R7DjSMvK//7WU=")
				cParts[0].ChecksumCRC32C = nil
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: cParts,
			},
			ChecksumType: types.ChecksumTypeFullObject,
		})
		cancel()
		if err := checkApiErr(err, s3err.APIError{
			Code:           "BadDigest",
			Description:    "The sha256 you specified for part 1 did not match what we received.",
			HTTPStatusCode: http.StatusBadRequest,
		}); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_missing_part_checksum(s *S3Conf) error {
	testName := "CompleteMultipartUpload_missing_part_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		mp, err := createMp(s3client, bucket, obj,
			withChecksum(types.ChecksumAlgorithmSha1),
			withChecksumType(types.ChecksumTypeComposite))
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 15*1024*1024, 3, bucket, obj,
			*mp.UploadId, withChecksum(types.ChecksumAlgorithmSha1))
		if err != nil {
			return err
		}

		cParts := []types.CompletedPart{}
		for i, el := range parts {
			cParts = append(cParts, types.CompletedPart{
				ETag:         el.ETag,
				PartNumber:   el.PartNumber,
				ChecksumSHA1: el.ChecksumSHA1,
			})

			if i == 0 {
				cParts[0].ChecksumSHA1 = nil
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: cParts,
			},
			ChecksumType: types.ChecksumTypeComposite,
		})
		cancel()
		if err := checkApiErr(err, s3err.APIError{
			Code:           "InvalidRequest",
			Description:    "The upload was created using a sha1 checksum. The complete request must include the checksum for each part. It was missing for part 1 in the request.",
			HTTPStatusCode: http.StatusBadRequest,
		}); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_multiple_final_checksums(s *S3Conf) error {
	testName := "CompleteMultipartUpload_multiple_final_checksums"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		mp, err := createMp(s3client, bucket, obj, withChecksum(types.ChecksumAlgorithmCrc32))
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 5*1024*1024, 3, bucket, obj,
			*mp.UploadId, withChecksum(types.ChecksumAlgorithmCrc32),
			withChecksumType(types.ChecksumTypeFullObject))
		if err != nil {
			return err
		}

		cParts := []types.CompletedPart{}
		for _, el := range parts {
			cParts = append(cParts, types.CompletedPart{
				ETag:          el.ETag,
				PartNumber:    el.PartNumber,
				ChecksumCRC32: el.ChecksumCRC32C,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: cParts,
			},
			ChecksumCRC32:  getPtr("sGc9Hg=="),
			ChecksumCRC32C: getPtr("/2NsFg=="),
			ChecksumType:   types.ChecksumTypeFullObject,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMultipleChecksumHeaders)); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_invalid_final_checksums(s *S3Conf) error {
	testName := "CompleteMultipartUpload_invalid_final_checksums"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		for _, el := range []struct {
			algo types.ChecksumAlgorithm
			t    types.ChecksumType
		}{
			{
				algo: types.ChecksumAlgorithmCrc32,
				t:    types.ChecksumTypeComposite,
			},
			{
				algo: types.ChecksumAlgorithmCrc32c,
				t:    types.ChecksumTypeFullObject,
			},
			{
				algo: types.ChecksumAlgorithmSha1,
				t:    types.ChecksumTypeComposite,
			},
			{
				algo: types.ChecksumAlgorithmSha256,
				t:    types.ChecksumTypeComposite,
			},
			{
				algo: types.ChecksumAlgorithmCrc64nvme,
				t:    types.ChecksumTypeFullObject,
			},
		} {

			mp, err := createMp(s3client, bucket, obj, withChecksum(el.algo),
				withChecksumType(el.t))
			if err != nil {
				return err
			}

			parts, _, err := uploadParts(s3client, 15*1024*1024, 3, bucket, obj,
				*mp.UploadId, withChecksum(el.algo))
			if err != nil {
				return err
			}

			cParts := []types.CompletedPart{}
			for _, el := range parts {
				cParts = append(cParts, types.CompletedPart{
					ETag:              el.ETag,
					PartNumber:        el.PartNumber,
					ChecksumCRC32:     el.ChecksumCRC32C,
					ChecksumCRC32C:    el.ChecksumCRC32C,
					ChecksumSHA1:      el.ChecksumSHA1,
					ChecksumSHA256:    el.ChecksumSHA256,
					ChecksumCRC64NVME: el.ChecksumCRC64NVME,
				})
			}

			mpInput := &s3.CompleteMultipartUploadInput{
				Bucket:   &bucket,
				Key:      &obj,
				UploadId: mp.UploadId,
				MultipartUpload: &types.CompletedMultipartUpload{
					Parts: cParts,
				},
				ChecksumType: el.t,
			}

			switch el.algo {
			case types.ChecksumAlgorithmCrc32:
				mpInput.ChecksumCRC32 = getPtr("invalid_crc32")
			case types.ChecksumAlgorithmCrc32c:
				mpInput.ChecksumCRC32C = getPtr("invalid_crc32c")
			case types.ChecksumAlgorithmSha1:
				mpInput.ChecksumSHA1 = getPtr("invalid_sha1")
			case types.ChecksumAlgorithmSha256:
				mpInput.ChecksumSHA256 = getPtr("invalid_sha256")
			case types.ChecksumAlgorithmCrc64nvme:
				mpInput.ChecksumCRC64NVME = getPtr("invalid_crc64nvme")
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.CompleteMultipartUpload(ctx, mpInput)
			cancel()
			if err := checkApiErr(err, s3err.GetInvalidChecksumHeaderErr(fmt.Sprintf("x-amz-checksum-%v", strings.ToLower(string(el.algo))))); err != nil {
				return err
			}
		}

		return nil
	})
}

func CompleteMultipartUpload_incorrect_final_checksums(s *S3Conf) error {
	testName := "CompleteMultipartUpload_incorrect_final_checksums"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		for _, el := range []struct {
			algo types.ChecksumAlgorithm
			t    types.ChecksumType
		}{
			{
				algo: types.ChecksumAlgorithmCrc32,
				t:    types.ChecksumTypeComposite,
			},
			{
				algo: types.ChecksumAlgorithmCrc32c,
				t:    types.ChecksumTypeFullObject,
			},
			{
				algo: types.ChecksumAlgorithmSha1,
				t:    types.ChecksumTypeComposite,
			},
			{
				algo: types.ChecksumAlgorithmSha256,
				t:    types.ChecksumTypeComposite,
			},
			{
				algo: types.ChecksumAlgorithmCrc64nvme,
				t:    types.ChecksumTypeFullObject,
			},
		} {
			mp, err := createMp(s3client, bucket, obj, withChecksum(el.algo),
				withChecksumType(el.t))
			if err != nil {
				return err
			}

			parts, _, err := uploadParts(s3client, 15*1024*1024, 3, bucket, obj,
				*mp.UploadId, withChecksum(el.algo))
			if err != nil {
				return err
			}

			cParts := []types.CompletedPart{}
			for _, el := range parts {
				cParts = append(cParts, types.CompletedPart{
					ETag:              el.ETag,
					PartNumber:        el.PartNumber,
					ChecksumCRC32:     el.ChecksumCRC32,
					ChecksumCRC32C:    el.ChecksumCRC32C,
					ChecksumSHA1:      el.ChecksumSHA1,
					ChecksumSHA256:    el.ChecksumSHA256,
					ChecksumCRC64NVME: el.ChecksumCRC64NVME,
				})
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
				Bucket:   &bucket,
				Key:      &obj,
				UploadId: mp.UploadId,
				MultipartUpload: &types.CompletedMultipartUpload{
					Parts: cParts,
				},
				// Provide one of the parts checksum. In any case
				// the final checksum will differ from one of the parts checksum
				ChecksumCRC32:     cParts[0].ChecksumCRC32,
				ChecksumCRC32C:    cParts[0].ChecksumCRC32C,
				ChecksumSHA1:      cParts[0].ChecksumSHA1,
				ChecksumSHA256:    cParts[0].ChecksumSHA256,
				ChecksumCRC64NVME: cParts[0].ChecksumCRC64NVME,
				ChecksumType:      el.t,
			})
			cancel()
			if err := checkApiErr(err, s3err.GetChecksumBadDigestErr(el.algo)); err != nil {
				return err
			}
		}

		return nil
	})
}

func CompleteMultipartUpload_should_calculate_the_final_checksum_full_object(s *S3Conf) error {
	testName := "CompleteMultipartUpload_should_calculate_the_final_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		for _, el := range []struct {
			algo types.ChecksumAlgorithm
			t    types.ChecksumType
		}{
			{
				algo: types.ChecksumAlgorithmCrc32,
				t:    types.ChecksumTypeFullObject,
			},
			{
				algo: types.ChecksumAlgorithmCrc32c,
				t:    types.ChecksumTypeFullObject,
			},
			{
				algo: types.ChecksumAlgorithmCrc64nvme,
				t:    types.ChecksumTypeFullObject,
			},
		} {
			mp, err := createMp(s3client, bucket, obj, withChecksum(el.algo), withChecksumType(el.t))
			if err != nil {
				return err
			}

			parts, csum, err := uploadParts(s3client, 15*1024*1024, 3, bucket,
				obj, *mp.UploadId, withChecksum(el.algo))
			if err != nil {
				return err
			}

			cParts := []types.CompletedPart{}
			for _, el := range parts {
				cParts = append(cParts, types.CompletedPart{
					ETag:              el.ETag,
					PartNumber:        el.PartNumber,
					ChecksumCRC32:     el.ChecksumCRC32,
					ChecksumCRC32C:    el.ChecksumCRC32C,
					ChecksumSHA1:      el.ChecksumSHA1,
					ChecksumSHA256:    el.ChecksumSHA256,
					ChecksumCRC64NVME: el.ChecksumCRC64NVME,
				})
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
				Bucket:   &bucket,
				Key:      &obj,
				UploadId: mp.UploadId,
				MultipartUpload: &types.CompletedMultipartUpload{
					Parts: cParts,
				},
				ChecksumType: el.t,
			})
			cancel()
			if err != nil {
				return err
			}

			switch el.algo {
			case types.ChecksumAlgorithmCrc32:
				if getString(res.ChecksumCRC32) != csum {
					return fmt.Errorf("expected the final crc32 checksum to be %v, instead got %v",
						csum, getString(res.ChecksumCRC32))
				}
			case types.ChecksumAlgorithmCrc32c:
				if getString(res.ChecksumCRC32C) != csum {
					return fmt.Errorf("expected the final crc32c checksum to be %v, instead got %v",
						csum, getString(res.ChecksumCRC32C))
				}
			case types.ChecksumAlgorithmCrc64nvme:
				if getString(res.ChecksumCRC64NVME) != csum {
					return fmt.Errorf("expected the final crc64nvme checksum to be %v, instead got %v",
						csum, getString(res.ChecksumCRC64NVME))
				}
			}
		}

		return nil
	})
}

func CompleteMultipartUpload_should_verify_the_final_checksum(s *S3Conf) error {
	testName := "CompleteMultipartUpload_should_verify_the_final_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		for _, el := range []struct {
			algo types.ChecksumAlgorithm
			t    types.ChecksumType
		}{
			{
				algo: types.ChecksumAlgorithmCrc32,
				t:    types.ChecksumTypeFullObject,
			},
			{
				algo: types.ChecksumAlgorithmCrc32c,
				t:    types.ChecksumTypeFullObject,
			},
			{
				algo: types.ChecksumAlgorithmCrc64nvme,
				t:    types.ChecksumTypeFullObject,
			},
		} {
			mp, err := createMp(s3client, bucket, obj, withChecksum(el.algo),
				withChecksumType(el.t))
			if err != nil {
				return err
			}

			parts, csum, err := uploadParts(s3client, 15*1024*1024, 3, bucket,
				obj, *mp.UploadId, withChecksum(el.algo))
			if err != nil {
				return err
			}

			cParts := []types.CompletedPart{}
			for _, el := range parts {
				cParts = append(cParts, types.CompletedPart{
					ETag:              el.ETag,
					PartNumber:        el.PartNumber,
					ChecksumCRC32:     el.ChecksumCRC32,
					ChecksumCRC32C:    el.ChecksumCRC32C,
					ChecksumSHA1:      el.ChecksumSHA1,
					ChecksumSHA256:    el.ChecksumSHA256,
					ChecksumCRC64NVME: el.ChecksumCRC64NVME,
				})
			}

			mpInput := &s3.CompleteMultipartUploadInput{
				Bucket:   &bucket,
				Key:      &obj,
				UploadId: mp.UploadId,
				MultipartUpload: &types.CompletedMultipartUpload{
					Parts: cParts,
				},
				ChecksumType: el.t,
			}

			switch el.algo {
			case types.ChecksumAlgorithmCrc32:
				mpInput.ChecksumCRC32 = &csum
			case types.ChecksumAlgorithmCrc32c:
				mpInput.ChecksumCRC32C = &csum
			case types.ChecksumAlgorithmCrc64nvme:
				mpInput.ChecksumCRC64NVME = &csum
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.CompleteMultipartUpload(ctx, mpInput)
			cancel()
			if err != nil {
				return err
			}

			switch el.algo {
			case types.ChecksumAlgorithmCrc32:
				if getString(res.ChecksumCRC32) != csum {
					return fmt.Errorf("expected the final crc32 checksum to be %v, instead got %v",
						csum, getString(res.ChecksumCRC32))
				}
			case types.ChecksumAlgorithmCrc32c:
				if getString(res.ChecksumCRC32C) != csum {
					return fmt.Errorf("expected the final crc32c checksum to be %v, instead got %v",
						csum, getString(res.ChecksumCRC32C))
				}
			case types.ChecksumAlgorithmCrc64nvme:
				if getString(res.ChecksumCRC64NVME) != csum {
					return fmt.Errorf("expected the final crc64nvme checksum to be %v, instead got %v",
						csum, getString(res.ChecksumCRC64NVME))
				}
			}
		}

		return nil
	})
}

func CompleteMultipartUpload_checksum_type_mismatch(s *S3Conf) error {
	testName := "CompleteMultipartUpload_checksum_type_mismatch"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		mp, err := createMp(s3client, bucket, obj,
			withChecksum(types.ChecksumAlgorithmCrc32),
			withChecksumType(types.ChecksumTypeFullObject))
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 20*1024*1024, 4, bucket, obj,
			*mp.UploadId, withChecksum(types.ChecksumAlgorithmCrc32))
		if err != nil {
			return err
		}

		cParts := []types.CompletedPart{}
		for _, el := range parts {
			cParts = append(cParts, types.CompletedPart{
				ETag:          el.ETag,
				PartNumber:    el.PartNumber,
				ChecksumCRC32: el.ChecksumCRC32,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: cParts,
			},
			ChecksumType: types.ChecksumTypeComposite,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetChecksumTypeMismatchOnMpErr(types.ChecksumTypeFullObject)); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_should_ignore_the_final_checksum(s *S3Conf) error {
	testName := "CompleteMultipartUpload_should_ignore_the_final_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 20*1024*1024, 4, bucket, obj, *mp.UploadId)
		if err != nil {
			return err
		}

		cParts := []types.CompletedPart{}
		for _, el := range parts {
			cParts = append(cParts, types.CompletedPart{
				ETag:       el.ETag,
				PartNumber: el.PartNumber,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: cParts,
			},
			ChecksumSHA1: getPtr("Kq5sNclPz7QV2+lfQIuc6R7oRu0="), // should ignore this
		})
		cancel()
		if err != nil {
			return err
		}

		if res.ChecksumCRC32 != nil {
			return fmt.Errorf("expected nil crc32 checksum, insted got %v",
				*res.ChecksumCRC32)
		}
		if res.ChecksumCRC32C != nil {
			return fmt.Errorf("expected nil crc32c checksum, insted got %v",
				*res.ChecksumCRC32C)
		}
		if res.ChecksumSHA1 != nil {
			return fmt.Errorf("expected nil sha1 checksum, insted got %v",
				*res.ChecksumSHA1)
		}
		if res.ChecksumSHA256 != nil {
			return fmt.Errorf("expected nil sha256 checksum, insted got %v",
				*res.ChecksumSHA256)
		}
		if res.ChecksumCRC64NVME != nil {
			return fmt.Errorf("expected nil crc64nvme checksum, insted got %v",
				*res.ChecksumSHA256)
		}

		return nil
	})
}

func CompleteMultipartUpload_should_succeed_without_final_checksum_type(s *S3Conf) error {
	testName := "CompleteMultipartUpload_should_succeed_without_final_checksum_type"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		mp, err := createMp(s3client, bucket, obj,
			withChecksum(types.ChecksumAlgorithmCrc64nvme),
			withChecksumType(types.ChecksumTypeFullObject))
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 20*1024*1024, 4, bucket, obj,
			*mp.UploadId, withChecksum(types.ChecksumAlgorithmCrc64nvme))
		if err != nil {
			return err
		}

		cParts := []types.CompletedPart{}
		for _, el := range parts {
			cParts = append(cParts, types.CompletedPart{
				ETag:              el.ETag,
				PartNumber:        el.PartNumber,
				ChecksumCRC64NVME: el.ChecksumCRC64NVME,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: cParts,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if res.ChecksumType != types.ChecksumTypeFullObject {
			return fmt.Errorf("expected the final checksum type to be %v, instead got %v",
				types.ChecksumTypeFullObject, res.ChecksumType)
		}
		if getString(res.ChecksumCRC64NVME) == "" {
			return fmt.Errorf("expected non empty crc64nvme checksum")
		}

		return nil
	})
}

func CompleteMultipartUpload_small_upload_size(s *S3Conf) error {
	testName := "CompleteMultipartUpload_small_upload_size"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		// The uploaded parts size is 256 < 5 Mib (the minimum allowed size)
		parts, _, err := uploadParts(s3client, 1024, 4, bucket, obj, *mp.UploadId)
		if err != nil {
			return err
		}

		cParts := []types.CompletedPart{}

		for _, el := range parts {
			cParts = append(cParts, types.CompletedPart{
				PartNumber: el.PartNumber,
				ETag:       el.ETag,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: cParts,
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrEntityTooSmall)); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_empty_parts(s *S3Conf) error {
	testName := "CompleteMultipartUpload_empty_parts"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		_, _, err = uploadParts(s3client, 5*1024*1024, 1, bucket, obj, *mp.UploadId)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: []types.CompletedPart{}, // empty parts list
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrEmptyParts)); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_incorrect_parts_order(s *S3Conf) error {
	testName := "CompleteMultipartUpload_incorrect_parts_order"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 15*1024*1024, 3, bucket, obj, *out.UploadId)
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

		compParts[0], compParts[1] = compParts[1], compParts[0]

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: compParts,
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidPartOrder)); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_mpu_object_size(s *S3Conf) error {
	testName := "CompleteMultipartUpload_mpu_object_size"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		mpuSize := int64(23 * 1024 * 1024) // 23 mib
		parts, _, err := uploadParts(s3client, mpuSize, 4, bucket, obj, *mp.UploadId)
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

		invMpuSize := int64(-1) // invalid MpuObjectSize
		// Initially provide invalid MpuObjectSize: -3
		input := &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: compParts,
			},
			MpuObjectSize: &invMpuSize,
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, input)
		cancel()
		if err := checkApiErr(err, s3err.GetInvalidMpObjectSizeErr(invMpuSize)); err != nil {
			return err
		}

		incorMpuSize := int64(213123) // incorrect object size
		input.MpuObjectSize = &incorMpuSize

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, input)
		cancel()
		if err := checkApiErr(err, s3err.GetIncorrectMpObjectSizeErr(mpuSize, incorMpuSize)); err != nil {
			return err
		}

		// Correct value for MpuObjectSize
		input.MpuObjectSize = &mpuSize
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, input)
		cancel()
		if err != nil {
			return err
		}

		// Make sure the object has been uploaded with proper size
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.ContentLength == nil {
			return fmt.Errorf("expected non nil Content-Length")
		}
		if *res.ContentLength != mpuSize {
			return fmt.Errorf("expected the uploaded object size to be %v, instead got %v",
				mpuSize, *res.ContentLength)
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

		parts, _, err := uploadParts(s3client, 5*1024*1024, 1, bucket, obj, *out.UploadId)
		if err != nil {
			return err
		}

		invPartNumber := int32(-4)

		compParts := []types.CompletedPart{}
		for _, el := range parts {
			compParts = append(compParts, types.CompletedPart{
				ETag:       el.ETag,
				PartNumber: &invPartNumber,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: compParts,
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidCompleteMpPartNumber)); err != nil {
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

		objSize := int64(25 * 1024 * 1024)
		parts, csum, err := uploadParts(s3client, objSize, 5, bucket, obj, *out.UploadId)
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

		if getString(res.Key) != obj {
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

		if getString(resp.ETag) != getString(res.ETag) {
			return fmt.Errorf("expected the uploaded object etag to be %v, instead got %v",
				getString(res.ETag), getString(resp.ETag))
		}
		if resp.ContentLength == nil {
			return fmt.Errorf("expected (head object) non nil Content-Length")
		}
		if *resp.ContentLength != int64(objSize) {
			return fmt.Errorf("expected the uploaded object size to be %v, instead got %v",
				objSize, resp.ContentLength)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		defer cancel()
		rget, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		if err != nil {
			return err
		}

		if rget.ContentLength == nil {
			return fmt.Errorf("expected (get object) non nil Content-Length")
		}
		if *rget.ContentLength != int64(objSize) {
			return fmt.Errorf("expected the object content-length to be %v, instead got %v",
				objSize, *rget.ContentLength)
		}

		bdy, err := io.ReadAll(rget.Body)
		if err != nil {
			return err
		}
		defer rget.Body.Close()

		sum := sha256.Sum256(bdy)
		getsum := hex.EncodeToString(sum[:])

		if csum != getsum {
			return fmt.Errorf("expected the object checksum to be %v, instead got %v",
				csum, getsum)
		}

		return nil
	})
}

type mpinfo struct {
	uploadId *string
	parts    []types.CompletedPart
}

func CompleteMultipartUpload_racey_success(s *S3Conf) error {
	testName := "CompleteMultipartUpload_racey_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		var mu sync.RWMutex
		uploads := make([]mpinfo, 10)
		sums := make([]string, 10)
		objSize := int64(25 * 1024 * 1024)

		eg := errgroup.Group{}
		for i := range 10 {
			func(i int) {
				eg.Go(func() error {
					out, err := createMp(s3client, bucket, obj)
					if err != nil {
						return err
					}

					parts, csum, err := uploadParts(s3client, objSize, 5, bucket, obj, *out.UploadId)
					mu.Lock()
					sums[i] = csum
					mu.Unlock()
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

					mu.Lock()
					uploads[i] = mpinfo{
						uploadId: out.UploadId,
						parts:    compParts,
					}
					mu.Unlock()
					return nil
				})
			}(i)
		}

		err := eg.Wait()
		if err != nil {
			return err
		}

		eg = errgroup.Group{}
		for i := range 10 {
			func(i int) {
				eg.Go(func() error {
					ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
					mu.RLock()
					res, err := s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
						Bucket:   &bucket,
						Key:      &obj,
						UploadId: uploads[i].uploadId,
						MultipartUpload: &types.CompletedMultipartUpload{
							Parts: uploads[i].parts,
						},
					})
					mu.RUnlock()
					cancel()
					if err != nil {
						fmt.Println("GOT ERROR: ", err)
						return err
					}

					if getString(res.Key) != obj {
						return fmt.Errorf("expected object key to be %v, instead got %v",
							obj, getString(res.Key))
					}

					return nil
				})
			}(i)
		}

		err = eg.Wait()
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		defer cancel()
		out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		if err != nil {
			return err
		}

		if out.ContentLength == nil {
			return fmt.Errorf("expected (get object) non nil Content-Length")
		}
		if *out.ContentLength != int64(objSize) {
			return fmt.Errorf("expected the object content-length to be %v, instead got %v",
				objSize, *out.ContentLength)
		}

		bdy, err := io.ReadAll(out.Body)
		if err != nil {
			return err
		}
		defer out.Body.Close()

		sum := sha256.Sum256(bdy)
		csum := hex.EncodeToString(sum[:])

		mu.RLock()
		defer mu.RUnlock()
		for _, s := range sums {
			if csum == s {
				return nil
			}
		}
		return fmt.Errorf("expected the object checksum to be one of %v, instead got %v",
			sums, csum)
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

func PutBucketAcl_disabled(s *S3Conf) error {
	testName := "PutBucketAcl_disabled"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket:    &bucket,
			ACL:       types.BucketCannedACLPublicRead,
			GrantRead: &s.awsID,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAclNotSupported)); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketAcl_none_of_the_options_specified(s *S3Conf) error {
	testName := "PutBucketAcl_none_of_the_options_specified"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMissingSecurityHeader)); err != nil {
			return err
		}
		return nil
	}, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
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
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrBothCannedAndHeaderGrants)); err != nil {
			return err
		}

		return nil
	}, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
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
						Permission: types.PermissionFullControl,
					},
				},
				Owner: &types.Owner{
					ID: &s.awsID,
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrUnexpectedContent)); err != nil {
			return err
		}

		return nil
	}, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
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
						Permission: types.PermissionFullControl,
					},
				},
				Owner: &types.Owner{
					ID: &s.awsID,
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrUnexpectedContent)); err != nil {
			return err
		}

		return nil
	}, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
}

func PutBucketAcl_invalid_owner(s *S3Conf) error {
	testName := "PutBucketAcl_invalid_owner"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		usr := user{
			access: "grt1",
			secret: "grt1secret",
			role:   "user",
		}

		if err := createUsers(s, []user{usr}); err != nil {
			return err
		}

		if err := changeBucketsOwner(s, []string{bucket}, usr.access); err != nil {
			return err
		}

		userClient := getUserS3Client(usr, s)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := userClient.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			AccessControlPolicy: &types.AccessControlPolicy{
				Grants: []types.Grant{
					{
						Grantee: &types.Grantee{
							ID:   getPtr(usr.access),
							Type: types.TypeCanonicalUser,
						},
						Permission: types.PermissionRead,
					},
				},
				Owner: &types.Owner{
					ID: getPtr("invalidOwner"),
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.APIError{
			Code:           "InvalidArgument",
			Description:    "Invalid id",
			HTTPStatusCode: http.StatusBadRequest,
		}); err != nil {
			return err
		}

		return nil
	}, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
}

func PutBucketAcl_invalid_owner_not_in_body(s *S3Conf) error {
	testName := "PutBucketAcl_invalid_owner_not_in_body"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			AccessControlPolicy: &types.AccessControlPolicy{
				Grants: []types.Grant{
					{
						Grantee: &types.Grantee{
							Type: types.TypeCanonicalUser,
							ID:   getPtr("grt1"),
						},
						Permission: types.PermissionRead,
					},
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMalformedACL)); err != nil {
			return err
		}

		return nil
	}, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
}

func PutBucketAcl_invalid_empty_owner_id_in_body(s *S3Conf) error {
	testName := "PutBucketAcl_invalid_empty_owner_id_in_body"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			AccessControlPolicy: &types.AccessControlPolicy{
				Grants: []types.Grant{
					{
						Grantee: &types.Grantee{
							Type: types.TypeCanonicalUser,
							ID:   getPtr("grt1"),
						},
						Permission: types.PermissionRead,
					},
				},
				// Empty owner ID
				Owner: &types.Owner{},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMalformedACL)); err != nil {
			return err
		}

		return nil
	}, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
}

func PutBucketAcl_invalid_permission_in_body(s *S3Conf) error {
	testName := "PutBucketAcl_invalid_permission_in_body"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			AccessControlPolicy: &types.AccessControlPolicy{
				Grants: []types.Grant{
					{
						Grantee: &types.Grantee{
							Type: types.TypeCanonicalUser,
							ID:   getPtr("grt1"),
						},
						Permission: types.Permission("invalid_permission"),
					},
				},
				Owner: &types.Owner{
					ID: &s.awsID,
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMalformedACL)); err != nil {
			return err
		}

		return nil
	}, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
}

func PutBucketAcl_invalid_grantee_type_in_body(s *S3Conf) error {
	testName := "PutBucketAcl_invalid_grantee_type_in_body"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			AccessControlPolicy: &types.AccessControlPolicy{
				Grants: []types.Grant{
					{
						Grantee: &types.Grantee{
							Type: types.Type("invalid_type"),
							ID:   getPtr("grt1"),
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
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMalformedACL)); err != nil {
			return err
		}

		return nil
	}, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
}

func PutBucketAcl_empty_grantee_ID_in_body(s *S3Conf) error {
	testName := "PutBucketAcl_empty_grantee_ID_in_body"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			AccessControlPolicy: &types.AccessControlPolicy{
				Grants: []types.Grant{
					{
						Grantee: &types.Grantee{
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
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMalformedACL)); err != nil {
			return err
		}

		return nil
	}, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
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
		userClient := newConf.GetClient()

		_, err = putObjects(userClient, []string{"my-obj"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		return nil
	}, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
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
		userClient := newConf.GetClient()

		_, err = putObjects(userClient, []string{"my-obj"}, bucket)
		if err != nil {
			return err
		}

		return nil
	}, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
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
		userClient := newConf.GetClient()

		_, err = putObjects(userClient, []string{"my-obj"}, bucket)
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
	}, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
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
		userClient := newConf.GetClient()

		_, err = putObjects(userClient, []string{"my-obj"}, bucket)
		if err != nil {
			return err
		}

		return nil
	}, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
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

func GetBucketAcl_translation_canned_public_read(s *S3Conf) error {
	testName := "GetBucketAcl_translation_canned_public_read"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		grants := []types.Grant{
			{
				Grantee: &types.Grantee{
					ID:   &s.awsID,
					Type: types.TypeCanonicalUser,
				},
				Permission: types.PermissionFullControl,
			},
			{
				Grantee: &types.Grantee{
					ID:   getPtr("all-users"),
					Type: types.TypeGroup,
				},
				Permission: types.PermissionRead,
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			ACL:    types.BucketCannedACLPublicRead,
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
			return fmt.Errorf("expected grants to be %v, instead got %v",
				grants, out.Grants)
		}
		if getString(out.Owner.ID) != s.awsID {
			return fmt.Errorf("expected bucket owner to be %v, instead got %v",
				s.awsID, getString(out.Owner.ID))
		}

		return nil
	}, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
}

func GetBucketAcl_translation_canned_public_read_write(s *S3Conf) error {
	testName := "GetBucketAcl_translation_canned_public_read_write"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		grants := []types.Grant{
			{
				Grantee: &types.Grantee{
					ID:   &s.awsID,
					Type: types.TypeCanonicalUser,
				},
				Permission: types.PermissionFullControl,
			},
			{
				Grantee: &types.Grantee{
					ID:   getPtr("all-users"),
					Type: types.TypeGroup,
				},
				Permission: types.PermissionRead,
			},
			{
				Grantee: &types.Grantee{
					ID:   getPtr("all-users"),
					Type: types.TypeGroup,
				},
				Permission: types.PermissionWrite,
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			ACL:    types.BucketCannedACLPublicReadWrite,
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
			return fmt.Errorf("expected grants to be %v, instead got %v",
				grants, out.Grants)
		}
		if getString(out.Owner.ID) != s.awsID {
			return fmt.Errorf("expected bucket owner to be %v, instead got %v",
				s.awsID, getString(out.Owner.ID))
		}

		return nil
	}, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
}

func GetBucketAcl_translation_canned_private(s *S3Conf) error {
	testName := "GetBucketAcl_translation_canned_private"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		grants := []types.Grant{
			{
				Grantee: &types.Grantee{
					ID:   &s.awsID,
					Type: types.TypeCanonicalUser,
				},
				Permission: types.PermissionFullControl,
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			ACL:    types.BucketCannedACLPrivate,
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
			return fmt.Errorf("expected grants to be %v, instead got %v",
				grants, out.Grants)
		}
		if getString(out.Owner.ID) != s.awsID {
			return fmt.Errorf("expected bucket owner to be %v, instead got %v",
				s.awsID, getString(out.Owner.ID))
		}

		return nil
	}, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
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
		userClient := newConf.GetClient()

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

		grants = append([]types.Grant{
			{
				Grantee: &types.Grantee{
					ID:   &s.awsID,
					Type: types.TypeCanonicalUser,
				},
				Permission: types.PermissionFullControl,
			},
		}, grants...)

		if ok := compareGrants(out.Grants, grants); !ok {
			return fmt.Errorf("expected grants to be %v, instead got %v",
				grants, out.Grants)
		}
		if getString(out.Owner.ID) != s.awsID {
			return fmt.Errorf("expected bucket owner to be %v, instead got %v",
				s.awsID, getString(out.Owner.ID))
		}

		return nil
	}, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
}

func PutBucketPolicy_non_existing_bucket(s *S3Conf) error {
	testName := "PutBucketPolicy_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		doc := genPolicyDoc("Allow", `"*"`, `"s3:*"`, fmt.Sprintf(`"arn:aws:s3:::%v"`, bucket))
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: getPtr("non-existing-bucket"),
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_invalid_json(s *S3Conf) error {
	testName := "PutBucketPolicy_invalid_json"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for _, doc := range []string{
			"{true}",
			"{asdfsdaf",
			`{"Principal": "*" `,
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
				Bucket: &bucket,
				Policy: &doc,
			})
			cancel()
			if err := checkApiErr(err, getMalformedPolicyError("This policy contains invalid Json")); err != nil {
				return err
			}
		}

		for _, doc := range []string{
			"false",
			"invalid_json",
			"bucketPolicy",
			`"Statement": []}`,
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
				Bucket: &bucket,
				Policy: &doc,
			})
			cancel()
			if err := checkApiErr(err, getMalformedPolicyError("Policies must be valid JSON and the first byte must be '{'")); err != nil {
				return err
			}
		}

		return nil
	})
}

func PutBucketPolicy_statement_not_provided(s *S3Conf) error {
	testName := "PutBucketPolicy_statement_not_provided"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		doc := `{}`

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()
		if err := checkApiErr(err, getMalformedPolicyError("Missing required field Statement")); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_empty_statement(s *S3Conf) error {
	testName := "PutBucketPolicy_empty_statement"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		doc := `{"Statement": []}`

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()
		if err := checkApiErr(err, getMalformedPolicyError("Could not parse the policy: Statement is empty!")); err != nil {
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

		if err := checkApiErr(err, getMalformedPolicyError("Invalid effect: invalid_effect")); err != nil {
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

		if err := checkApiErr(err, getMalformedPolicyError("Policy has invalid action")); err != nil {
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

		if err := checkApiErr(err, getMalformedPolicyError("Policy has invalid action")); err != nil {
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

		if err := checkApiErr(err, getMalformedPolicyError("Policy has invalid action")); err != nil {
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

		if err := checkApiErr(err, getMalformedPolicyError("Policy has invalid action")); err != nil {
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

		if err := checkApiErr(err, getMalformedPolicyError("Policy has invalid action")); err != nil {
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

		if err := checkApiErr(err, getMalformedPolicyError("Invalid principal in policy")); err != nil {
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

		if err := checkApiErr(err, getMalformedPolicyError("Invalid principal in policy")); err != nil {
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

		if err := checkApiErr(err, getMalformedPolicyError("Invalid principal in policy")); err != nil {
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

		if err := checkApiErr(err, getMalformedPolicyError("Invalid principal in policy")); err != nil {
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

		if err := checkApiErr(err, getMalformedPolicyError("Invalid principal in policy")); err != nil {
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

		if err := checkApiErr(err, getMalformedPolicyError("Invalid principal in policy")); err != nil {
			return err
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

		if err := checkApiErr(err, getMalformedPolicyError("Policy has invalid resource")); err != nil {
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

		if err := checkApiErr(err, getMalformedPolicyError("Policy has invalid resource")); err != nil {
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

		if err := checkApiErr(err, getMalformedPolicyError("Policy has invalid resource")); err != nil {
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

		if err := checkApiErr(err, getMalformedPolicyError("Policy has invalid resource")); err != nil {
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
		if err != nil {
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

		if err := checkApiErr(err, getMalformedPolicyError("Policy has invalid resource")); err != nil {
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
		if err := checkApiErr(err, getMalformedPolicyError("Action does not apply to any resource(s) in statement")); err != nil {
			return err
		}

		return nil
	})
}

func PutBucketPolicy_bucket_action_on_object_resource(s *S3Conf) error {
	testName := "PutBucketPolicy_bucket_action_on_object_resource"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		resource := fmt.Sprintf(`"arn:aws:s3:::%v/*"`, bucket)
		doc := genPolicyDoc("Allow", `["*"]`, `"s3:DeleteBucket"`, resource)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError("Action does not apply to any resource(s) in statement")); err != nil {
			return err
		}
		return nil
	})
}
func PutBucketPolicy_explicit_deny(s *S3Conf) error {
	testName := "PutBucketPolicy_explicit_deny"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		user2 := user{"grt2", "grt2secret", "user"}
		err := createUsers(s, []user{
			{"grt1", "grt1secret", "user"},
			user2,
		})
		if err != nil {
			return err
		}

		resource := fmt.Sprintf("arn:aws:s3:::%v", bucket)
		resourceWildCard := fmt.Sprintf("%v/*", resource)
		resourcePrefix := fmt.Sprintf("%v/someprefix/*", resource)

		policy := fmt.Sprintf(`{
				"Statement": [
					{
						"Action": [
							"s3:*"
						],
						"Effect": "Allow",
						"Principal": [
							"grt1"
						],
						"Resource": [
							"%v",
							"%v"
						]
					},
					{
						"Action": [
							"s3:*"
						],
						"Effect": "Allow",
						"Principal": [
							"grt2"
						],
						"Resource": [
							"%v",
							"%v"
						]
					},
					{
						"Action": [
							"s3:*"
						],
						"Effect": "Deny",
						"Principal": [
							"grt2"
						],
						"Resource": "%v"
					}
				]
			}`, resourcePrefix, resource, resourceWildCard, resource, resourcePrefix)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &policy,
		})
		cancel()
		if err != nil {
			return err
		}

		userClient := getUserS3Client(user2, s)

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    getPtr("someprefix/hello"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		return nil
	})
}

func PutBucketPolicy_multi_wildcard_resource(s *S3Conf) error {
	testName := "PutBucketPolicy_multi_wildcard_resource"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		usr := user{"grt1", "grt1secret", "user"}
		if err := createUsers(s, []user{usr}); err != nil {
			return err
		}

		resource := fmt.Sprintf(`["arn:aws:s3:::%v/*/*", "arn:aws:s3:::%v"]`, bucket, bucket)
		principal := fmt.Sprintf("\"%v\"", usr.access)
		doc := genPolicyDoc("Allow", principal, `"s3:*"`, resource)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()
		if err != nil {
			return err
		}

		userClient := getUserS3Client(usr, s)
		_, err = putObjects(userClient, []string{"foo"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		_, err = putObjects(userClient, []string{"bar/quxx", "foo/bar/baz", "foo/bar/xyz/quxx"}, bucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func PutBucketPolicy_any_char_match(s *S3Conf) error {
	testName := "PutBucketPolicy_any_char_match"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		usr := user{"grt1", "grt1secret", "user"}
		if err := createUsers(s, []user{usr}); err != nil {
			return err
		}

		resource := fmt.Sprintf(`["arn:aws:s3:::%v/m?-obj/*"]`, bucket)
		principal := fmt.Sprintf("\"%v\"", usr.access)
		doc := genPolicyDoc("Allow", principal, `"s3:*"`, resource)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()
		if err != nil {
			return err
		}

		userClient := getUserS3Client(usr, s)
		_, err = putObjects(userClient, []string{"myy-obj/hello", "rand/foo", "my-objj/bar"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		_, err = putObjects(userClient, []string{"my-obj/hello", "mk-obj/foo", "m--obj/bar"}, bucket)
		if err != nil {
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
			Bucket: getPtr("non-existing-bucket"),
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
			Bucket: getPtr("non-existing-bucket"),
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
			return fmt.Errorf("expected lock status to be %v, instead got %v",
				config.ObjectLockEnabled, respConfig.ObjectLockEnabled)
		}
		if respConfig.Rule == nil {
			return fmt.Errorf("got nil object lock rule")
		}
		if respConfig.Rule.DefaultRetention == nil {
			return fmt.Errorf("got nil object lock default retention")
		}
		if respConfig.Rule.DefaultRetention.Days == nil {
			return fmt.Errorf("expected lock config days to be not nil")
		}
		if *respConfig.Rule.DefaultRetention.Days != *config.Rule.DefaultRetention.Days {
			return fmt.Errorf("expected lock config days to be %v, instead got %v",
				*config.Rule.DefaultRetention.Days, *respConfig.Rule.DefaultRetention.Days)
		}
		if respConfig.Rule.DefaultRetention.Mode != config.Rule.DefaultRetention.Mode {
			return fmt.Errorf("expected lock config mode to be %v, instead got %v",
				config.Rule.DefaultRetention.Mode, respConfig.Rule.DefaultRetention.Mode)
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

		_, err := putObjects(s3client, []string{key}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
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

		_, err = putObjects(s3client, []string{key}, bucket)
		if err != nil {
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
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
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
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
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
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
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

		_, err := putObjects(s3client, []string{key}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
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

func GetObjectRetention_disabled_lock(s *S3Conf) error {
	testName := "GetObjectRetention_disabled_lock"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key := "my-obj"
		_, err := putObjects(s3client, []string{key}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
			Bucket: &bucket,
			Key:    &key,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidBucketObjectLockConfiguration)); err != nil {
			return err
		}

		return nil
	})
}

func GetObjectRetention_unset_config(s *S3Conf) error {
	testName := "GetObjectRetention_unset_config"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key := "my-obj"
		_, err := putObjects(s3client, []string{key}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
			Bucket: &bucket,
			Key:    &key,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchObjectLockConfiguration)); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func GetObjectRetention_success(s *S3Conf) error {
	testName := "GetObjectRetention_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		if err := changeBucketObjectLockStatus(s3client, bucket, true); err != nil {
			return err
		}
		key := "my-obj"
		_, err := putObjects(s3client, []string{key}, bucket)
		if err != nil {
			return err
		}

		date := time.Now().Add(time.Hour * 3)
		retention := types.ObjectLockRetention{
			Mode:            types.ObjectLockRetentionModeCompliance,
			RetainUntilDate: &date,
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
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
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMalformedXML)); err != nil {
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

		_, err := putObjects(s3client, []string{key}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
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

		_, err = putObjects(s3client, []string{key}, bucket)
		if err != nil {
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

		_, err := putObjects(s3client, []string{key}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
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

func GetObjectLegalHold_disabled_lock(s *S3Conf) error {
	testName := "GetObjectLegalHold_disabled_lock"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key := "my-obj"
		_, err := putObjects(s3client, []string{key}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
			Bucket: &bucket,
			Key:    &key,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidBucketObjectLockConfiguration)); err != nil {
			return err
		}

		return nil
	})
}

func GetObjectLegalHold_unset_config(s *S3Conf) error {
	testName := "GetObjectLegalHold_unset_config"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key := "my-obj"
		_, err := putObjects(s3client, []string{key}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
			Bucket: &bucket,
			Key:    &key,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchObjectLockConfiguration)); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func GetObjectLegalHold_success(s *S3Conf) error {
	testName := "GetObjectLegalHold_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		if err := changeBucketObjectLockStatus(s3client, bucket, true); err != nil {
			return err
		}
		key := "my-obj"
		_, err := putObjects(s3client, []string{key}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
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
			return fmt.Errorf("expected legal hold status to be On, instead got %v",
				resp.LegalHold.Status)
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

		_, err = putObjects(s3client, []string{object}, bucket)
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

		_, err = putObjects(s3client, []string{object}, bucket)
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

		_, err = putObjects(s3client, []string{object}, bucket)
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

		_, err = putObjects(s3client, []string{obj1, obj2, obj3}, bucket)
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

		_, err := putObjects(s3client, []string{object}, bucket)
		if err != nil {
			return err
		}

		date := time.Now().Add(time.Hour * 3)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
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

		_, err := putObjects(s3client, []string{object}, bucket)
		if err != nil {
			return err
		}

		date := time.Now().Add(time.Hour * 3)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
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

		_, err := putObjects(s3client, []string{object}, bucket)
		if err != nil {
			return err
		}

		date := time.Now().Add(time.Hour * 3)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
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

		_, err := putObjects(s3client, []string{object}, bucket)
		if err != nil {
			return err
		}

		date := time.Now().Add(time.Hour * 3)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
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

		_, err := putObjects(s3client, objs, bucket)
		if err != nil {
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

		_, err := putObjects(s3client, []string{object}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
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

		_, err = putObjects(s3client, []string{object}, bucket)
		if err := checkSdkApiErr(err, "InvalidRequest"); err != nil {
			return err
		}
		// client sdk regression issue prevents getting full error message,
		// change back to below once this is fixed:
		// https://github.com/aws/aws-sdk-go-v2/issues/2921
		// if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
		// 	return err
		// }

		if err := changeBucketObjectLockStatus(s3client, bucket, false); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func WORMProtection_root_bypass_governance_retention_delete_object(s *S3Conf) error {
	testName := "WORMProtection_root_bypass_governance_retention_delete_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		retDate := time.Now().Add(time.Hour * 48)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &obj,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeGovernance,
				RetainUntilDate: &retDate,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if err := checkWORMProtection(s3client, bucket, obj); err != nil {
			return err
		}

		policy := genPolicyDoc("Allow", fmt.Sprintf(`"%v"`, s.awsID), `["s3:BypassGovernanceRetention"]`, fmt.Sprintf(`"arn:aws:s3:::%v/*"`, bucket))

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &policy,
		})
		cancel()
		if err != nil {
			return err
		}

		bypass := true
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:                    &bucket,
			Key:                       &obj,
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

		_, err = putObjects(cfg.GetClient(), []string{"my-obj"}, bucket)
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

		_, err = putObjects(cfg.GetClient(), []string{"my-obj"}, bucket)
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

		_, err = putObjects(cfg.GetClient(), []string{"my-obj"}, bucket)
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
		_, err = putObjects(user1Client, []string{"my-obj"}, bucket)
		if err != nil {
			return err
		}

		user2Client := getUserS3Client(usr2, s)

		_, err = putObjects(user2Client, []string{"my-obj"}, bucket)
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
		_, err := putObjects(s3client, []string{obj}, bucket)
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
		policy := fmt.Sprintf(`{
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
		}`, bucket, bucket, bucket)

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

func AccessControl_bucket_ownership_to_user(s *S3Conf) error {
	testName := "AccessControl_bucket_ownership_to_user"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		usr := user{
			access: "grt1",
			secret: "grt1secret",
			role:   "user",
		}

		if err := createUsers(s, []user{usr}); err != nil {
			return err
		}

		if err := changeBucketsOwner(s, []string{bucket}, usr.access); err != nil {
			return err
		}

		userClient := getUserS3Client(usr, s)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := userClient.HeadBucket(ctx, &s3.HeadBucketInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		return nil
	})
}

func AccessControl_root_PutBucketAcl(s *S3Conf) error {
	testName := "AccessControl_root_PutBucketAcl"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		usr := user{
			access: "grt1",
			secret: "grt1secret",
			role:   "user",
		}

		if err := createUsers(s, []user{usr}); err != nil {
			return err
		}

		if err := changeBucketsOwner(s, []string{bucket}, usr.access); err != nil {
			return err
		}

		userClient := getUserS3Client(usr, s)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := userClient.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			ACL:    types.BucketCannedACLPrivate,
		})
		cancel()
		if err != nil {
			return err
		}

		return nil
	}, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
}

func AccessControl_user_PutBucketAcl_with_policy_access(s *S3Conf) error {
	testName := "AccessControl_user_PutBucketAcl_with_policy_access"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		usr := user{
			access: "grt1",
			secret: "grt1secret",
			role:   "user",
		}

		if err := createUsers(s, []user{usr}); err != nil {
			return err
		}

		policy := genPolicyDoc("Allow", fmt.Sprintf(`"%v"`, usr.access), `"s3:PutBucketAcl"`, fmt.Sprintf(`"arn:aws:s3:::%v"`, bucket))

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &policy,
		})
		cancel()
		if err != nil {
			return err
		}

		userClient := getUserS3Client(usr, s)
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			ACL:    types.BucketCannedACLPublicRead,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		expectedGrants := []types.Grant{
			{
				Grantee: &types.Grantee{
					ID:   &s.awsID,
					Type: types.TypeCanonicalUser,
				},
				Permission: types.PermissionFullControl,
			},
			{
				Grantee: &types.Grantee{
					ID:   getPtr("all-users"),
					Type: types.TypeGroup,
				},
				Permission: types.PermissionRead,
			},
		}

		if !compareGrants(res.Grants, expectedGrants) {
			return fmt.Errorf("expected the resulting grants to be %v, instead got %v",
				expectedGrants, res.Grants)
		}

		return nil
	}, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
}

func AccessControl_copy_object_with_starting_slash_for_user(s *S3Conf) error {
	testName := "AccessControl_copy_object_with_starting_slash_for_user"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		usr := user{
			access: "grt1",
			secret: "grt1secret",
			role:   "user",
		}

		if err := changeBucketsOwner(s, []string{bucket}, usr.access); err != nil {
			return err
		}

		copySource := fmt.Sprintf("/%v/%v", bucket, obj)
		meta := map[string]string{
			"key1": "val1",
		}

		userClient := getUserS3Client(usr, s)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:            &bucket,
			Key:               &obj,
			CopySource:        &copySource,
			Metadata:          meta,
			MetadataDirective: types.MetadataDirectiveReplace,
		})
		cancel()
		if err != nil {
			return err
		}

		return nil
	})
}

// Public bucket tests
func PublicBucket_default_privet_bucket(s *S3Conf) error {
	testName := "PublicBucket_default_privet_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		partNumber := int32(1)

		for _, test := range []PublicBucketTestCase{
			{
				Action: "ListBuckets",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListBuckets(ctx, &s3.ListBucketsInput{})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "HeadBucket",
				Call: func(ctx context.Context) error {
					_, err := s3client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetBucketAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "CreateBucket",
				Call: func(ctx context.Context) error {
					_, err := s3client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: getPtr("new-bucket")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "PutBucketAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
						Bucket: &bucket,
						ACL:    types.BucketCannedACLPublicRead,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "DeleteBucket",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutBucketVersioning",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{
						Bucket: &bucket,
						VersioningConfiguration: &types.VersioningConfiguration{
							Status: types.BucketVersioningStatusSuspended,
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetBucketVersioning",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutBucketPolicy",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &bucket, Policy: getPtr("{}")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetBucketPolicy",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteBucketPolicy",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketPolicy(ctx, &s3.DeleteBucketPolicyInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutBucketOwnershipControls",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketOwnershipControls(ctx, &s3.PutBucketOwnershipControlsInput{
						Bucket: &bucket,
						OwnershipControls: &types.OwnershipControls{
							Rules: []types.OwnershipControlsRule{
								{
									ObjectOwnership: types.ObjectOwnershipBucketOwnerEnforced,
								},
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousPutBucketOwnership),
			},
			{
				Action: "GetBucketOwnershipControls",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketOwnershipControls(ctx, &s3.GetBucketOwnershipControlsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousGetBucketOwnership),
			},
			{
				Action: "DeleteBucketOwnershipControls",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketOwnershipControls(ctx, &s3.DeleteBucketOwnershipControlsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousPutBucketOwnership),
			},
			{
				Action: "PutBucketCors",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketCors(ctx, &s3.PutBucketCorsInput{
						Bucket: &bucket,
						CORSConfiguration: &types.CORSConfiguration{
							CORSRules: []types.CORSRule{
								{
									AllowedMethods: []string{http.MethodPut},
									AllowedOrigins: []string{"my origin"},
								},
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetBucketCors",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketCors(ctx, &s3.GetBucketCorsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteBucketCors",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketCors(ctx, &s3.DeleteBucketCorsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "CreateMultipartUpload",
				Call: func(ctx context.Context) error {
					_, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: &bucket, Key: getPtr("object-key")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousCreateMp),
			},
			{
				Action: "CompleteMultipartUpload",
				Call: func(ctx context.Context) error {
					_, err := s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{Bucket: &bucket, Key: getPtr("object-key"), UploadId: getPtr("upload-id")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "AbortMultipartUpload",
				Call: func(ctx context.Context) error {
					_, err := s3client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: &bucket, Key: getPtr("object-key"), UploadId: getPtr("upload-id")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "ListMultipartUploads",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "ListParts",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListParts(ctx, &s3.ListPartsInput{Bucket: &bucket, Key: getPtr("object-key"), UploadId: getPtr("upload-id")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "UploadPart",
				Call: func(ctx context.Context) error {
					_, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
						Bucket:     &bucket,
						Key:        getPtr("object-key"),
						UploadId:   getPtr("upload-id"),
						PartNumber: &partNumber,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "UploadPartCopy",
				Call: func(ctx context.Context) error {
					_, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
						Bucket:     &bucket,
						Key:        getPtr("object-key"),
						UploadId:   getPtr("upload-id"),
						PartNumber: &partNumber,
						CopySource: getPtr("source-bucket/source-key")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "HeadObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: getPtr("object-key")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("object-key")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectAcl(ctx, &s3.GetObjectAclInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectAttributes",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						ObjectAttributes: []types.ObjectAttributes{
							types.ObjectAttributesEtag,
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "CopyObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
						Bucket:     &bucket,
						Key:        getPtr("copy-key"),
						CopySource: getPtr("bucket-name/object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousCopyObject),
			},
			{
				Action: "ListObjects",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "ListObjectsV2",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteObjects",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
						Bucket: &bucket,
						Delete: &types.Delete{
							Objects: []types.ObjectIdentifier{
								{Key: getPtr("object-key")},
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectAcl(ctx, &s3.PutObjectAclInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						ACL:    types.ObjectCannedACLPublicRead,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "ListObjectVersions",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "RestoreObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.RestoreObject(ctx, &s3.RestoreObjectInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						RestoreRequest: &types.RestoreRequest{
							Days: aws.Int32(1),
							GlacierJobParameters: &types.GlacierJobParameters{
								Tier: types.TierStandard,
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "SelectObjectContent",
				Call: func(ctx context.Context) error {
					_, err := s3client.SelectObjectContent(ctx, &s3.SelectObjectContentInput{
						Bucket:         &bucket,
						Key:            getPtr("object-key"),
						ExpressionType: types.ExpressionTypeSql,
						Expression:     getPtr("SELECT * FROM S3Object"),
						InputSerialization: &types.InputSerialization{
							CSV: &types.CSVInput{},
						},
						OutputSerialization: &types.OutputSerialization{
							CSV: &types.CSVOutput{},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "GetBucketTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutBucketTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
						Bucket: &bucket,
						Tagging: &types.Tagging{
							TagSet: []types.Tag{{Key: getPtr("key"), Value: getPtr("value")}},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteBucketTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketTagging(ctx, &s3.DeleteBucketTaggingInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						Tagging: &types.Tagging{
							TagSet: []types.Tag{{Key: getPtr("key"), Value: getPtr("value")}},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteObjectTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteObjectTagging(ctx, &s3.DeleteObjectTaggingInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectLockConfiguration",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
						Bucket: &bucket,
						ObjectLockConfiguration: &types.ObjectLockConfiguration{
							ObjectLockEnabled: types.ObjectLockEnabledEnabled,
							Rule: &types.ObjectLockRule{
								DefaultRetention: &types.DefaultRetention{
									Days: aws.Int32(1),
									Mode: types.ObjectLockRetentionModeCompliance,
								},
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectLockConfiguration",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectRetention",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						Retention: &types.ObjectLockRetention{
							Mode:            types.ObjectLockRetentionModeCompliance,
							RetainUntilDate: aws.Time(time.Now().Add(24 * time.Hour)),
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectRetention",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectLegalHold",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						LegalHold: &types.ObjectLockLegalHold{
							Status: types.ObjectLockLegalHoldStatusOn,
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectLegalHold",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			err := test.Call(ctx)
			cancel()
			if err == nil && test.ExpectedErr != nil {
				return fmt.Errorf("%v: expected err %v, instead got successful response", test.Action, test.ExpectedErr)
			}
			if err != nil {
				if test.ExpectedErr == nil {
					return fmt.Errorf("%v: expected no error, instead got %v", test.Action, err)
				}

				apiErr, ok := test.ExpectedErr.(s3err.APIError)
				if !ok {
					return fmt.Errorf("invalid error type provided in the test, expected s3err.APIError")
				}

				// The head requests doesn't have request body, thus only the status needs to be checked
				if test.Action == "HeadBucket" || test.Action == "HeadObject" {
					if err := checkSdkApiErr(err, http.StatusText(apiErr.HTTPStatusCode)); err != nil {
						return err
					}
					continue
				}

				if err := checkApiErr(err, apiErr); err != nil {
					return err
				}
			}
		}

		return nil
	}, withAnonymousClient())
}

func PublicBucket_public_bucket_policy(s *S3Conf) error {
	testName := "PublicBucket_public_bucket_policy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		rootClient := s.GetClient()
		// Grant public access to the bucket for bucket operations
		err := grantPublicBucketPolicy(rootClient, bucket, policyTypeBucket)
		if err != nil {
			return err
		}
		partNumber := int32(1)

		for _, test := range []PublicBucketTestCase{
			{
				Action: "ListBuckets",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListBuckets(ctx, &s3.ListBucketsInput{})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "HeadBucket",
				Call: func(ctx context.Context) error {
					_, err := s3client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetBucketAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "CreateBucket",
				Call: func(ctx context.Context) error {
					_, err := s3client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: getPtr("new-bucket")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "PutBucketAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
						Bucket: &bucket,
						ACL:    types.BucketCannedACLPublicRead,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "PutBucketPolicy",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &bucket, Policy: getPtr("{}")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrMethodNotAllowed),
			},
			{
				Action: "GetBucketPolicy",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrMethodNotAllowed),
			},
			{
				Action: "DeleteBucketPolicy",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketPolicy(ctx, &s3.DeleteBucketPolicyInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrMethodNotAllowed),
			},
			{
				Action: "PutBucketOwnershipControls",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketOwnershipControls(ctx, &s3.PutBucketOwnershipControlsInput{
						Bucket: &bucket,
						OwnershipControls: &types.OwnershipControls{
							Rules: []types.OwnershipControlsRule{
								{
									ObjectOwnership: types.ObjectOwnershipBucketOwnerEnforced,
								},
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousPutBucketOwnership),
			},
			{
				Action: "GetBucketOwnershipControls",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketOwnershipControls(ctx, &s3.GetBucketOwnershipControlsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousGetBucketOwnership),
			},
			{
				Action: "DeleteBucketOwnershipControls",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketOwnershipControls(ctx, &s3.DeleteBucketOwnershipControlsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousPutBucketOwnership),
			},
			{
				Action: "PutBucketCors",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketCors(ctx, &s3.PutBucketCorsInput{
						Bucket: &bucket,
						CORSConfiguration: &types.CORSConfiguration{
							CORSRules: []types.CORSRule{
								{
									AllowedMethods: []string{http.MethodPut},
									AllowedOrigins: []string{"my origin"},
								},
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrNotImplemented),
			},
			{
				Action: "GetBucketCors",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketCors(ctx, &s3.GetBucketCorsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrNotImplemented),
			},
			{
				Action: "DeleteBucketCors",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketCors(ctx, &s3.DeleteBucketCorsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrNotImplemented),
			},
			{
				Action: "CreateMultipartUpload",
				Call: func(ctx context.Context) error {
					_, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: &bucket, Key: getPtr("object-key")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousCreateMp),
			},
			{
				Action: "CompleteMultipartUpload",
				Call: func(ctx context.Context) error {
					_, err := s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{Bucket: &bucket, Key: getPtr("object-key"), UploadId: getPtr("upload-id")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "AbortMultipartUpload",
				Call: func(ctx context.Context) error {
					_, err := s3client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: &bucket, Key: getPtr("object-key"), UploadId: getPtr("upload-id")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "ListMultipartUploads",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "ListParts",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListParts(ctx, &s3.ListPartsInput{Bucket: &bucket, Key: getPtr("object-key"), UploadId: getPtr("upload-id")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "UploadPart",
				Call: func(ctx context.Context) error {
					_, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
						Bucket:     &bucket,
						Key:        getPtr("object-key"),
						UploadId:   getPtr("upload-id"),
						PartNumber: &partNumber,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "UploadPartCopy",
				Call: func(ctx context.Context) error {
					_, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
						Bucket:     &bucket,
						Key:        getPtr("object-key"),
						UploadId:   getPtr("upload-id"),
						PartNumber: &partNumber,
						CopySource: getPtr("source-bucket/source-key")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "HeadObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: getPtr("object-key")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("object-key")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectAcl(ctx, &s3.GetObjectAclInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectAttributes",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						ObjectAttributes: []types.ObjectAttributes{
							types.ObjectAttributesEtag,
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "CopyObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
						Bucket:     &bucket,
						Key:        getPtr("copy-key"),
						CopySource: getPtr("bucket-name/object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousCopyObject),
			},
			{
				Action: "ListObjects",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "ListObjectsV2",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "DeleteObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteObjects",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
						Bucket: &bucket,
						Delete: &types.Delete{
							Objects: []types.ObjectIdentifier{
								{Key: getPtr("object-key")},
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectAcl(ctx, &s3.PutObjectAclInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						ACL:    types.ObjectCannedACLPublicRead,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "ListObjectVersions",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "RestoreObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.RestoreObject(ctx, &s3.RestoreObjectInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						RestoreRequest: &types.RestoreRequest{
							Days: aws.Int32(1),
							GlacierJobParameters: &types.GlacierJobParameters{
								Tier: types.TierStandard,
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "SelectObjectContent",
				Call: func(ctx context.Context) error {
					_, err := s3client.SelectObjectContent(ctx, &s3.SelectObjectContentInput{
						Bucket:         &bucket,
						Key:            getPtr("object-key"),
						ExpressionType: types.ExpressionTypeSql,
						Expression:     getPtr("SELECT * FROM S3Object"),
						InputSerialization: &types.InputSerialization{
							CSV: &types.CSVInput{},
						},
						OutputSerialization: &types.OutputSerialization{
							CSV: &types.CSVOutput{},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "PutBucketTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
						Bucket: &bucket,
						Tagging: &types.Tagging{
							TagSet: []types.Tag{{Key: getPtr("key"), Value: getPtr("value")}},
						},
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetBucketTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "DeleteBucketTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketTagging(ctx, &s3.DeleteBucketTaggingInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetObjectTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						Tagging: &types.Tagging{
							TagSet: []types.Tag{{Key: getPtr("key"), Value: getPtr("value")}},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteObjectTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteObjectTagging(ctx, &s3.DeleteObjectTaggingInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectLockConfiguration",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
						Bucket: &bucket,
						ObjectLockConfiguration: &types.ObjectLockConfiguration{
							ObjectLockEnabled: types.ObjectLockEnabledEnabled,
							Rule: &types.ObjectLockRule{
								DefaultRetention: &types.DefaultRetention{
									Days: aws.Int32(1),
									Mode: types.ObjectLockRetentionModeGovernance,
								},
							},
						},
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetObjectLockConfiguration",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "PutObjectRetention",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						Retention: &types.ObjectLockRetention{
							Mode:            types.ObjectLockRetentionModeCompliance,
							RetainUntilDate: aws.Time(time.Now().Add(24 * time.Hour)),
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectRetention",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectLegalHold",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						LegalHold: &types.ObjectLockLegalHold{
							Status: types.ObjectLockLegalHoldStatusOn,
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectLegalHold",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteBucket",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: nil,
			},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			err := test.Call(ctx)
			cancel()
			if err == nil && test.ExpectedErr != nil {
				return fmt.Errorf("%v: expected err %v, instead got successful response", test.Action, test.ExpectedErr)
			}
			if err != nil {
				if test.ExpectedErr == nil {
					return fmt.Errorf("%v: expected no error, instead got %v", test.Action, err)
				}

				apiErr, ok := test.ExpectedErr.(s3err.APIError)
				if !ok {
					return fmt.Errorf("invalid error type provided in the test, expected s3err.APIError")
				}

				// The head requests doesn't have request body, thus only the status needs to be checked
				if test.Action == "HeadBucket" || test.Action == "HeadObject" {
					if err := checkSdkApiErr(err, http.StatusText(apiErr.HTTPStatusCode)); err != nil {
						return err
					}
					continue
				}

				if err := checkApiErr(err, apiErr); err != nil {
					return err
				}
			}
		}

		return nil
	}, withAnonymousClient(), withLock(), withSkipTearDown())
}

func PublicBucket_public_object_policy(s *S3Conf) error {
	testName := "PublicBucket_public_object_policy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		rootClient := s.GetClient()
		// Grant public access to the bucket for bucket operations
		err := grantPublicBucketPolicy(rootClient, bucket, policyTypeObject)
		if err != nil {
			return err
		}

		mpKey := "my-mp"

		mp1, err := createMp(rootClient, bucket, mpKey)
		if err != nil {
			return err
		}

		mp2, err := createMp(rootClient, bucket, mpKey)
		if err != nil {
			return err
		}

		partNumber := int32(1)
		var partEtag *string

		for _, test := range []PublicBucketTestCase{
			{
				Action: "ListBuckets",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListBuckets(ctx, &s3.ListBucketsInput{})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "HeadBucket",
				Call: func(ctx context.Context) error {
					_, err := s3client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetBucketAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "CreateBucket",
				Call: func(ctx context.Context) error {
					_, err := s3client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: getPtr("new-bucket")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "PutBucketAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
						Bucket: &bucket,
						ACL:    types.BucketCannedACLPublicRead,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "PutBucketPolicy",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &bucket, Policy: getPtr("{}")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetBucketPolicy",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteBucketPolicy",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketPolicy(ctx, &s3.DeleteBucketPolicyInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutBucketOwnershipControls",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketOwnershipControls(ctx, &s3.PutBucketOwnershipControlsInput{
						Bucket: &bucket,
						OwnershipControls: &types.OwnershipControls{
							Rules: []types.OwnershipControlsRule{
								{
									ObjectOwnership: types.ObjectOwnershipBucketOwnerEnforced,
								},
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousPutBucketOwnership),
			},
			{
				Action: "GetBucketOwnershipControls",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketOwnershipControls(ctx, &s3.GetBucketOwnershipControlsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousGetBucketOwnership),
			},
			{
				Action: "DeleteBucketOwnershipControls",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketOwnershipControls(ctx, &s3.DeleteBucketOwnershipControlsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousPutBucketOwnership),
			},
			{
				Action: "PutBucketCors",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketCors(ctx, &s3.PutBucketCorsInput{
						Bucket: &bucket,
						CORSConfiguration: &types.CORSConfiguration{
							CORSRules: []types.CORSRule{
								{
									AllowedMethods: []string{http.MethodPut},
									AllowedOrigins: []string{"my origin"},
								},
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetBucketCors",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketCors(ctx, &s3.GetBucketCorsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteBucketCors",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketCors(ctx, &s3.DeleteBucketCorsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "CreateMultipartUpload",
				Call: func(ctx context.Context) error {
					_, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: &bucket, Key: getPtr("object-key")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousCreateMp),
			},
			{
				Action: "AbortMultipartUpload",
				Call: func(ctx context.Context) error {
					_, err := s3client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
						Bucket:   &bucket,
						Key:      &mpKey,
						UploadId: mp1.UploadId,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "ListMultipartUploads",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "ListParts",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListParts(ctx, &s3.ListPartsInput{
						Bucket:   &bucket,
						Key:      &mpKey,
						UploadId: mp2.UploadId,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "UploadPart",
				Call: func(ctx context.Context) error {
					partBuffer := make([]byte, 5*1024*1024)
					rand.Read(partBuffer)
					res, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
						Bucket:     &bucket,
						Key:        &mpKey,
						UploadId:   mp2.UploadId,
						PartNumber: &partNumber,
						Body:       bytes.NewReader(partBuffer),
					})
					if err == nil {
						partEtag = res.ETag
					}
					return err
				},
				ExpectedErr: nil,
			},
			//FIXME: should be fixed after implementing the source bucket public access check
			// return AccessDenied for now
			{
				Action: "UploadPartCopy",
				Call: func(ctx context.Context) error {
					_, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
						Bucket:     &bucket,
						Key:        &mpKey,
						UploadId:   mp2.UploadId,
						PartNumber: &partNumber,
						CopySource: getPtr("source-bucket/source-key")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "CompleteMultipartUpload",
				Call: func(ctx context.Context) error {
					_, err := s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
						Bucket:   &bucket,
						Key:      &mpKey,
						UploadId: mp2.UploadId,
						MultipartUpload: &types.CompletedMultipartUpload{
							Parts: []types.CompletedPart{
								{
									ETag:       partEtag,
									PartNumber: &partNumber,
								},
							},
						},
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "PutObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
						Bucket: &bucket,
						Key:    &mpKey,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "HeadObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &mpKey})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &mpKey})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetObjectAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectAcl(ctx, &s3.GetObjectAclInput{
						Bucket: &bucket,
						Key:    &mpKey,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrNotImplemented),
			},
			{
				Action: "GetObjectAttributes",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
						Bucket: &bucket,
						Key:    &mpKey,
						ObjectAttributes: []types.ObjectAttributes{
							types.ObjectAttributesEtag,
						},
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "CopyObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
						Bucket:     &bucket,
						Key:        getPtr("copy-key"),
						CopySource: getPtr("bucket-name/object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousCopyObject),
			},
			{
				Action: "ListObjects",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "ListObjectsV2",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			// FIXME: should be fixed with https://github.com/versity/versitygw/issues/1327
			{
				Action: "DeleteObjects",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
						Bucket: &bucket,
						Delete: &types.Delete{
							Objects: []types.ObjectIdentifier{
								{Key: getPtr("object-key")},
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectAcl(ctx, &s3.PutObjectAclInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						ACL:    types.ObjectCannedACLPublicRead,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "ListObjectVersions",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "RestoreObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.RestoreObject(ctx, &s3.RestoreObjectInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						RestoreRequest: &types.RestoreRequest{
							Days: aws.Int32(1),
							GlacierJobParameters: &types.GlacierJobParameters{
								Tier: types.TierStandard,
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrNotImplemented),
			},
			{
				Action: "SelectObjectContent",
				Call: func(ctx context.Context) error {
					_, err := s3client.SelectObjectContent(ctx, &s3.SelectObjectContentInput{
						Bucket:         &bucket,
						Key:            getPtr("object-key"),
						ExpressionType: types.ExpressionTypeSql,
						Expression:     getPtr("SELECT * FROM S3Object"),
						InputSerialization: &types.InputSerialization{
							CSV: &types.CSVInput{},
						},
						OutputSerialization: &types.OutputSerialization{
							CSV: &types.CSVOutput{},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "PutBucketTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
						Bucket: &bucket,
						Tagging: &types.Tagging{
							TagSet: []types.Tag{{Key: getPtr("key"), Value: getPtr("value")}},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetBucketTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteBucketTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketTagging(ctx, &s3.DeleteBucketTaggingInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
						Bucket: &bucket,
						Key:    &mpKey,
						Tagging: &types.Tagging{
							TagSet: []types.Tag{{Key: getPtr("key"), Value: getPtr("value")}},
						},
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetObjectTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
						Bucket: &bucket,
						Key:    &mpKey,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "DeleteObjectTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteObjectTagging(ctx, &s3.DeleteObjectTaggingInput{
						Bucket: &bucket,
						Key:    &mpKey,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "PutObjectLockConfiguration",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
						Bucket: &bucket,
						ObjectLockConfiguration: &types.ObjectLockConfiguration{
							ObjectLockEnabled: types.ObjectLockEnabledEnabled,
							Rule: &types.ObjectLockRule{
								DefaultRetention: &types.DefaultRetention{
									Days: aws.Int32(1),
									Mode: types.ObjectLockRetentionModeGovernance,
								},
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectLockConfiguration",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectRetention",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
						Bucket: &bucket,
						Key:    &mpKey,
						Retention: &types.ObjectLockRetention{
							Mode:            types.ObjectLockRetentionModeGovernance,
							RetainUntilDate: aws.Time(time.Now().Add(24 * time.Hour)),
						},
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetObjectRetention",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
						Bucket: &bucket,
						Key:    &mpKey,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "PutObjectLegalHold",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
						Bucket: &bucket,
						Key:    &mpKey,
						LegalHold: &types.ObjectLockLegalHold{
							Status: types.ObjectLockLegalHoldStatusOff,
						},
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetObjectLegalHold",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
						Bucket: &bucket,
						Key:    &mpKey,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "DeleteObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
						Bucket:                    &bucket,
						Key:                       &mpKey,
						BypassGovernanceRetention: getBoolPtr(true),
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "DeleteBucket",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			err := test.Call(ctx)
			cancel()
			if err == nil && test.ExpectedErr != nil {
				return fmt.Errorf("%v: expected err %v, instead got successful response", test.Action, test.ExpectedErr)
			}
			if err != nil {
				if test.ExpectedErr == nil {
					return fmt.Errorf("%v: expected no error, instead got %v", test.Action, err)
				}

				apiErr, ok := test.ExpectedErr.(s3err.APIError)
				if !ok {
					return fmt.Errorf("invalid error type provided in the test, expected s3err.APIError")
				}

				// The head requests doesn't have request body, thus only the status needs to be checked
				if test.Action == "HeadBucket" || test.Action == "HeadObject" {
					if err := checkSdkApiErr(err, http.StatusText(apiErr.HTTPStatusCode)); err != nil {
						return err
					}
					continue
				}

				if err := checkApiErr(err, apiErr); err != nil {
					return err
				}
			}
		}

		// disable object lock on the bucket
		err = changeBucketObjectLockStatus(rootClient, bucket, false)
		if err != nil {
			return err
		}

		return nil
	}, withAnonymousClient(), withLock())
}

func PublicBucket_public_acl(s *S3Conf) error {
	testName := "PublicBucket_public_acl"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		partNumber := int32(1)
		var etag *string
		obj := "my-obj"

		// grant public access with acl
		rootClient := s.GetClient()
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := rootClient.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			ACL:    types.BucketCannedACLPublicReadWrite,
		})
		cancel()
		if err != nil {
			return err
		}

		mp, err := createMp(rootClient, bucket, obj)
		if err != nil {
			return err
		}

		for _, test := range []PublicBucketTestCase{
			{
				Action: "ListBuckets",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListBuckets(ctx, &s3.ListBucketsInput{})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "HeadBucket",
				Call: func(ctx context.Context) error {
					_, err := s3client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetBucketAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "CreateBucket",
				Call: func(ctx context.Context) error {
					_, err := s3client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: getPtr("new-bucket")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "PutBucketAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
						Bucket: &bucket,
						ACL:    types.BucketCannedACLPublicRead,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "DeleteBucket",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			//FIXME: implement tests for versioning enabled gateway
			// {
			// 	Action: "PutBucketVersioning",
			// 	Call: func(ctx context.Context) error {
			// 		_, err := s3client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{
			// 			Bucket: &bucket,
			// 			VersioningConfiguration: &types.VersioningConfiguration{
			// 				Status: types.BucketVersioningStatusSuspended,
			// 			},
			// 		})
			// 		return err
			// 	},
			// 	ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			// },
			// {
			// 	Action: "GetBucketVersioning",
			// 	Call: func(ctx context.Context) error {
			// 		_, err := s3client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: &bucket})
			// 		return err
			// 	},
			// 	ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			// },
			{
				Action: "PutBucketPolicy",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &bucket, Policy: getPtr("{}")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetBucketPolicy",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteBucketPolicy",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketPolicy(ctx, &s3.DeleteBucketPolicyInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutBucketOwnershipControls",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketOwnershipControls(ctx, &s3.PutBucketOwnershipControlsInput{
						Bucket: &bucket,
						OwnershipControls: &types.OwnershipControls{
							Rules: []types.OwnershipControlsRule{
								{
									ObjectOwnership: types.ObjectOwnershipBucketOwnerEnforced,
								},
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousPutBucketOwnership),
			},
			{
				Action: "GetBucketOwnershipControls",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketOwnershipControls(ctx, &s3.GetBucketOwnershipControlsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousGetBucketOwnership),
			},
			{
				Action: "DeleteBucketOwnershipControls",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketOwnershipControls(ctx, &s3.DeleteBucketOwnershipControlsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousPutBucketOwnership),
			},
			{
				Action: "PutBucketCors",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketCors(ctx, &s3.PutBucketCorsInput{
						Bucket: &bucket,
						CORSConfiguration: &types.CORSConfiguration{
							CORSRules: []types.CORSRule{
								{
									AllowedMethods: []string{http.MethodPut},
									AllowedOrigins: []string{"my origin"},
								},
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetBucketCors",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketCors(ctx, &s3.GetBucketCorsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteBucketCors",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketCors(ctx, &s3.DeleteBucketCorsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "CreateMultipartUpload",
				Call: func(ctx context.Context) error {
					_, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: &bucket, Key: getPtr("object-key")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousCreateMp),
			},
			{
				Action: "AbortMultipartUpload",
				Call: func(ctx context.Context) error {
					_, err := s3client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
						Bucket:   &bucket,
						Key:      &obj,
						UploadId: mp.UploadId,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "ListMultipartUploads",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "ListParts",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListParts(ctx, &s3.ListPartsInput{Bucket: &bucket, Key: getPtr("object-key"), UploadId: getPtr("upload-id")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "UploadPart",
				Call: func(ctx context.Context) error {
					partBuffer := make([]byte, 5*1024*1024)
					rand.Read(partBuffer)
					res, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
						Bucket:     &bucket,
						Key:        &obj,
						UploadId:   mp.UploadId,
						PartNumber: &partNumber,
						Body:       bytes.NewReader(partBuffer),
					})
					if err == nil {
						etag = res.ETag
					}
					return err
				},
				ExpectedErr: nil,
			},
			//FIXME: should be fixed after implementing the source bucket public access check
			// return AccessDenied for now
			{
				Action: "UploadPartCopy",
				Call: func(ctx context.Context) error {
					_, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
						Bucket:     &bucket,
						Key:        &obj,
						UploadId:   mp.UploadId,
						PartNumber: &partNumber,
						CopySource: getPtr("source-bucket/source-key")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "CompleteMultipartUpload",
				Call: func(ctx context.Context) error {
					_, err := s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
						Bucket:   &bucket,
						Key:      &obj,
						UploadId: mp.UploadId,
						MultipartUpload: &types.CompletedMultipartUpload{
							Parts: []types.CompletedPart{
								{
									ETag:       etag,
									PartNumber: &partNumber,
								},
							},
						},
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "PutObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
						Bucket: &bucket,
						Key:    &obj,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "HeadObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &obj})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &obj})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetObjectAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectAcl(ctx, &s3.GetObjectAclInput{
						Bucket: &bucket,
						Key:    &obj,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrNotImplemented),
			},
			{
				Action: "GetObjectAttributes",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
						Bucket: &bucket,
						Key:    &obj,
						ObjectAttributes: []types.ObjectAttributes{
							types.ObjectAttributesEtag,
						},
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "CopyObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
						Bucket:     &bucket,
						Key:        getPtr("copy-key"),
						CopySource: getPtr("bucket-name/object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousCopyObject),
			},
			{
				Action: "ListObjects",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "ListObjectsV2",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "DeleteObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
						Bucket: &bucket,
						Key:    &obj,
					})
					return err
				},
				ExpectedErr: nil,
			},
			// FIXME: should be fixed with https://github.com/versity/versitygw/issues/1327
			{
				Action: "DeleteObjects",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
						Bucket: &bucket,
						Delete: &types.Delete{
							Objects: []types.ObjectIdentifier{
								{Key: getPtr("object-key")},
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectAcl(ctx, &s3.PutObjectAclInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						ACL:    types.ObjectCannedACLPublicRead,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "ListObjectVersions",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "RestoreObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.RestoreObject(ctx, &s3.RestoreObjectInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						RestoreRequest: &types.RestoreRequest{
							Days: aws.Int32(1),
							GlacierJobParameters: &types.GlacierJobParameters{
								Tier: types.TierStandard,
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "SelectObjectContent",
				Call: func(ctx context.Context) error {
					_, err := s3client.SelectObjectContent(ctx, &s3.SelectObjectContentInput{
						Bucket:         &bucket,
						Key:            getPtr("object-key"),
						ExpressionType: types.ExpressionTypeSql,
						Expression:     getPtr("SELECT * FROM S3Object"),
						InputSerialization: &types.InputSerialization{
							CSV: &types.CSVInput{},
						},
						OutputSerialization: &types.OutputSerialization{
							CSV: &types.CSVOutput{},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "GetBucketTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutBucketTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
						Bucket: &bucket,
						Tagging: &types.Tagging{
							TagSet: []types.Tag{{Key: getPtr("key"), Value: getPtr("value")}},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteBucketTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketTagging(ctx, &s3.DeleteBucketTaggingInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						Tagging: &types.Tagging{
							TagSet: []types.Tag{{Key: getPtr("key"), Value: getPtr("value")}},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteObjectTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteObjectTagging(ctx, &s3.DeleteObjectTaggingInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectLockConfiguration",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
						Bucket: &bucket,
						ObjectLockConfiguration: &types.ObjectLockConfiguration{
							ObjectLockEnabled: types.ObjectLockEnabledEnabled,
							Rule: &types.ObjectLockRule{
								DefaultRetention: &types.DefaultRetention{
									Days: aws.Int32(1),
									Mode: types.ObjectLockRetentionModeCompliance,
								},
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectLockConfiguration",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectRetention",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						Retention: &types.ObjectLockRetention{
							Mode:            types.ObjectLockRetentionModeCompliance,
							RetainUntilDate: aws.Time(time.Now().Add(24 * time.Hour)),
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectRetention",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectLegalHold",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						LegalHold: &types.ObjectLockLegalHold{
							Status: types.ObjectLockLegalHoldStatusOn,
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectLegalHold",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			err := test.Call(ctx)
			cancel()
			if err == nil && test.ExpectedErr != nil {
				return fmt.Errorf("%v: expected err %v, instead got successful response", test.Action, test.ExpectedErr)
			}
			if err != nil {
				if test.ExpectedErr == nil {
					return fmt.Errorf("%v: expected no error, instead got %v", test.Action, err)
				}

				apiErr, ok := test.ExpectedErr.(s3err.APIError)
				if !ok {
					return fmt.Errorf("invalid error type provided in the test, expected s3err.APIError")
				}

				// The head requests doesn't have request body, thus only the status needs to be checked
				if test.Action == "HeadBucket" || test.Action == "HeadObject" {
					if err := checkSdkApiErr(err, http.StatusText(apiErr.HTTPStatusCode)); err != nil {
						return fmt.Errorf("%v: %w", test.Action, err)
					}
					continue
				}

				if err := checkApiErr(err, apiErr); err != nil {
					return fmt.Errorf("%v: %w", test.Action, err)
				}
			}
		}

		return nil
	}, withAnonymousClient(), withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
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

	out, err := execCommand(s.getAdminCommand("-a", usr.access, "-s", usr.secret, "-er", s.endpoint, "delete-user", "-a", "random_access")...)
	if err == nil {
		failF("%v: expected cmd error", testName)
		return fmt.Errorf("%v: expected cmd error", testName)
	}
	if !strings.Contains(string(out), s3err.GetAPIError(s3err.ErrAdminAccessDenied).Code) {
		failF("%v: expected response error message to be %v, instead got %s",
			testName, s3err.GetAPIError(s3err.ErrAdminAccessDenied).Error(), out)
		return fmt.Errorf("%v: expected response error message to be %v, instead got %s",
			testName, s3err.GetAPIError(s3err.ErrAdminAccessDenied).Error(), out)
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

	out, err := execCommand(s.getAdminCommand("-a", usr.access, "-s", usr.secret, "-er", s.endpoint, "delete-user", "-a", "random_access")...)
	if err == nil {
		failF("%v: expected cmd error", testName)
		return fmt.Errorf("%v: expected cmd error", testName)
	}
	if !strings.Contains(string(out), s3err.GetAPIError(s3err.ErrAdminAccessDenied).Code) {
		failF("%v: expected response error message to be %v, instead got %s",
			testName, s3err.GetAPIError(s3err.ErrAdminAccessDenied).Error(), out)
		return fmt.Errorf("%v: expected response error message to be %v, instead got %s",
			testName, s3err.GetAPIError(s3err.ErrAdminAccessDenied).Error(), out)
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

		if getString(resp.Owner.ID) != usr.access {
			return fmt.Errorf("expected the bucket owner to be %v, instead got %v",
				usr.access, getString(resp.Owner.ID))
		}

		return nil
	})
}

func IAM_ChangeBucketOwner_back_to_root(s *S3Conf) error {
	testName := "IAM_ChangeBucketOwner_back_to_root"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		usr := user{
			access: "grt1",
			secret: "grt1secret",
			role:   "user",
		}

		if err := createUsers(s, []user{usr}); err != nil {
			return err
		}

		// Change the bucket ownership to a random user
		if err := changeBucketsOwner(s, []string{bucket}, usr.access); err != nil {
			return err
		}

		// Change the bucket ownership back to the root user
		if err := changeBucketsOwner(s, []string{bucket}, s.awsID); err != nil {
			return err
		}

		return nil
	})
}

func IAM_ListBuckets(s *S3Conf) error {
	testName := "IAM_ListBuckets"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := listBuckets(s)
		if err != nil {
			return err
		}

		return nil
	})
}

// Posix related tests
func PutObject_overwrite_dir_obj(s *S3Conf) error {
	testName := "PutObject_overwrite_dir_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"foo/", "foo"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrExistingObjectIsDirectory)); err != nil {
			return err
		}
		return nil
	})
}

func PutObject_overwrite_file_obj(s *S3Conf) error {
	testName := "PutObject_overwrite_file_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"foo", "foo/"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectParentIsFile)); err != nil {
			return err
		}
		return nil
	})
}

func PutObject_overwrite_file_obj_with_nested_obj(s *S3Conf) error {
	testName := "PutObject_overwrite_file_obj_with_nested_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"foo", "foo/bar"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectParentIsFile)); err != nil {
			return err
		}
		return nil
	})
}

func PutObject_dir_obj_with_data(s *S3Conf) error {
	testName := "PutObject_dir_obj_with_data"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjectWithData(int64(20), &s3.PutObjectInput{
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

func PutObject_name_too_long(s *S3Conf) error {
	testName := "PutObject_name_too_long"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key := genRandString(300)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &key,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrKeyTooLong)); err != nil {
			return err
		}

		return nil
	})
}

func HeadObject_name_too_long(s *S3Conf) error {
	testName := "HeadObject_name_too_long"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    getPtr(genRandString(300)),
		})
		cancel()
		if err := checkSdkApiErr(err, "BadRequest"); err != nil {
			return err
		}

		return nil
	})
}

func DeleteObject_name_too_long(s *S3Conf) error {
	testName := "DeleteObject_name_too_long"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    getPtr(genRandString(300)),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrKeyTooLong)); err != nil {
			return err
		}
		return nil
	})
}

func CopyObject_overwrite_same_dir_object(s *S3Conf) error {
	testName := "CopyObject_overwrite_same_dir_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"foo/"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        getPtr("foo"),
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, "foo/")),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrExistingObjectIsDirectory)); err != nil {
			return err
		}

		return nil
	})
}

func CopyObject_overwrite_same_file_object(s *S3Conf) error {
	testName := "CopyObject_overwrite_same_file_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"foo"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        getPtr("foo/"),
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, "foo")),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectParentIsFile)); err != nil {
			return err
		}

		return nil
	})
}

// Versioning tests
func PutBucketVersioning_non_existing_bucket(s *S3Conf) error {
	testName := "PutBucketVersioning_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketVersioningStatus(s3client, getBucketName(), types.BucketVersioningStatusSuspended)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func PutBucketVersioning_invalid_status(s *S3Conf) error {
	testName := "PutBucketVersioning_invalid_status"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatus("invalid_status"))
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMalformedXML)); err != nil {
			return err
		}

		return nil
	})
}

func PutBucketVersioning_success_enabled(s *S3Conf) error {
	testName := "PutBucketVersioning_success_enabled"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusEnabled)
		if err != nil {
			return err
		}

		return nil
	})
}

func PutBucketVersioning_success_suspended(s *S3Conf) error {
	testName := "PutBucketVersioning_success_suspended"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusSuspended)
		if err != nil {
			return err
		}

		return nil
	})
}

func GetBucketVersioning_non_existing_bucket(s *S3Conf) error {
	testName := "GetBucketVersioning_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: getPtr(getBucketName()),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func GetBucketVersioning_empty_response(s *S3Conf) error {
	testName := "GetBucketVersioning_empty_response"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.Status != "" {
			return fmt.Errorf("expected empty versioning status, instead got %v",
				res.Status)
		}
		if res.MFADelete != "" {
			return fmt.Errorf("expected empty mfa delete status, instead got %v",
				res.MFADelete)
		}

		return nil
	})
}

func GetBucketVersioning_success(s *S3Conf) error {
	testName := "GetBucketVersioning_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.Status != types.BucketVersioningStatusEnabled {
			return fmt.Errorf("expected bucket versioning status to be %v, instead got %v",
				types.BucketVersioningStatusEnabled, res.Status)
		}
		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_DeleteBucket_not_empty(s *S3Conf) error {
	testName := "Versioning_DeleteBucket_not_empty"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := createObjVersions(s3client, bucket, obj, 2)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteBucket(ctx, &s3.DeleteBucketInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrVersionedBucketNotEmpty)); err != nil {
			return err
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_PutObject_suspended_null_versionId_obj(s *S3Conf) error {
	testName := "Versioning_PutObject_suspended_null_versionId_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := putObjectWithData(1222, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		if getString(out.res.VersionId) != nullVersionId {
			return fmt.Errorf("expected the uploaded object versionId to be %v, instead got %v",
				nullVersionId, getString(out.res.VersionId))
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusSuspended))
}

func Versioning_PutObject_null_versionId_obj(s *S3Conf) error {
	testName := "Versioning_PutObject_null_versionId_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, lgth := "my-obj", int64(1234)
		out, err := putObjectWithData(lgth, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		// Enable bucket versioning
		err = putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusEnabled)
		if err != nil {
			return err
		}

		versions, err := createObjVersions(s3client, bucket, obj, 4)
		if err != nil {
			return err
		}

		versions = append(versions, types.ObjectVersion{
			ETag:         out.res.ETag,
			IsLatest:     getBoolPtr(false),
			Key:          &obj,
			Size:         &lgth,
			VersionId:    &nullVersionId,
			StorageClass: types.ObjectVersionStorageClassStandard,
		})

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareVersions(versions, res.Versions) {
			return fmt.Errorf("expected the listed versions to be %v, instead got %v",
				versions, res.Versions)
		}

		return nil
	})
}

func Versioning_PutObject_overwrite_null_versionId_obj(s *S3Conf) error {
	testName := "Versioning_PutObject_overwrite_null_versionId_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjectWithData(int64(1233), &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		// Enable bucket versioning
		err = putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusEnabled)
		if err != nil {
			return err
		}

		versions, err := createObjVersions(s3client, bucket, obj, 4)
		if err != nil {
			return err
		}

		// Set bucket versioning status to Suspended
		err = putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusSuspended)
		if err != nil {
			return err
		}

		lgth := int64(3200)
		out, err := putObjectWithData(lgth, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		if getString(out.res.VersionId) != nullVersionId {
			return fmt.Errorf("expected the uploaded object versionId to be %v, insted got %v",
				nullVersionId, getString(out.res.VersionId))
		}

		versions[0].IsLatest = getBoolPtr(false)

		versions = append([]types.ObjectVersion{
			{
				ETag:         out.res.ETag,
				IsLatest:     getBoolPtr(true),
				Key:          &obj,
				Size:         &lgth,
				VersionId:    &nullVersionId,
				StorageClass: types.ObjectVersionStorageClassStandard,
				ChecksumType: out.res.ChecksumType,
			},
		}, versions...)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareVersions(versions, res.Versions) {
			return fmt.Errorf("expected the listed versions to be %v, instead got %v",
				versions, res.Versions)
		}

		return nil
	})
}

func Versioning_PutObject_success(s *S3Conf) error {
	testName := "Versioning_PutObject_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
		})
		cancel()
		if err != nil {
			return err
		}

		if res.VersionId == nil || *res.VersionId == "" {
			return fmt.Errorf("expected the versionId to be returned")
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_CopyObject_success(s *S3Conf) error {
	testName := "Versioning_CopyObject_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dstObj := "dst-obj"
		srcBucket, srcObj := getBucketName(), "src-obj"

		if err := setup(s, srcBucket); err != nil {
			return err
		}

		dstObjVersions, err := createObjVersions(s3client, bucket, dstObj, 1)
		if err != nil {
			return err
		}

		srcObjLen := int64(2345)
		_, err = putObjectWithData(srcObjLen, &s3.PutObjectInput{
			Bucket: &srcBucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        &dstObj,
			CopySource: getPtr(fmt.Sprintf("%v/%v", srcBucket, srcObj)),
		})
		cancel()
		if err != nil {
			return err
		}

		if err := teardown(s, srcBucket); err != nil {
			return err
		}

		if out.VersionId == nil || *out.VersionId == "" {
			return fmt.Errorf("expected non empty versionId in the result")
		}

		dstObjVersions[0].IsLatest = getBoolPtr(false)
		versions := append([]types.ObjectVersion{
			{
				ETag:         out.CopyObjectResult.ETag,
				IsLatest:     getBoolPtr(true),
				Key:          &dstObj,
				Size:         &srcObjLen,
				VersionId:    out.VersionId,
				StorageClass: types.ObjectVersionStorageClassStandard,
				ChecksumType: out.CopyObjectResult.ChecksumType,
			},
		}, dstObjVersions...)

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareVersions(versions, res.Versions) {
			return fmt.Errorf("expected the resulting versions to be %v, instead got %v",
				versions, res.Versions)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_CopyObject_non_existing_version_id(s *S3Conf) error {
	testName := "Versioning_CopyObject_non_existing_version_id"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dstBucket, dstObj := getBucketName(), "my-obj"
		srcObj := "my-obj"

		if err := setup(s, dstBucket); err != nil {
			return err
		}

		_, err := createObjVersions(s3client, bucket, srcObj, 1)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket: &dstBucket,
			Key:    &dstObj,
			CopySource: getPtr(fmt.Sprintf("%v/%v?versionId=invalid_versionId",
				bucket, srcObj)),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchVersion)); err != nil {
			return err
		}

		if err := teardown(s, dstBucket); err != nil {
			return err
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_CopyObject_from_an_object_version(s *S3Conf) error {
	testName := "Versioning_CopyObject_from_an_object_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcBucket, srcObj, dstObj := getBucketName(), "my-obj", "my-dst-obj"
		if err := setup(s, srcBucket, withVersioning(types.BucketVersioningStatusEnabled)); err != nil {
			return err
		}

		srcObjVersions, err := createObjVersions(s3client, srcBucket, srcObj, 1)
		if err != nil {
			return err
		}
		srcObjVersion := srcObjVersions[0]

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        &dstObj,
			CopySource: getPtr(fmt.Sprintf("%v/%v?versionId=%v", srcBucket, srcObj, *srcObjVersion.VersionId)),
		})
		cancel()
		if err != nil {
			return err
		}

		if err := teardown(s, srcBucket); err != nil {
			return err
		}

		if out.VersionId == nil || *out.VersionId == "" {
			return fmt.Errorf("expected non empty versionId")
		}
		if out.CopySourceVersionId == nil {
			return fmt.Errorf("expected non nil CopySourceVersionId")
		}
		if *out.CopySourceVersionId != *srcObjVersion.VersionId {
			return fmt.Errorf("expected the SourceVersionId to be %v, instead got %v",
				*srcObjVersion.VersionId, *out.CopySourceVersionId)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:    &bucket,
			Key:       &dstObj,
			VersionId: out.VersionId,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.ContentLength == nil {
			return fmt.Errorf("expected non nil ContentLength")
		}
		if res.VersionId == nil {
			return fmt.Errorf("expected non nil VersionId")
		}
		if *res.ContentLength != *srcObjVersion.Size {
			return fmt.Errorf("expected the copied object size to be %v, instead got %v",
				*srcObjVersion.Size, *res.ContentLength)
		}
		if *res.VersionId != *out.VersionId {
			return fmt.Errorf("expected the copied object versionId to be %v, instead got %v",
				*out.VersionId, *res.VersionId)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_CopyObject_special_chars(s *S3Conf) error {
	testName := "Versioning_CopyObject_special_chars"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj, dstBucket, dstObj := "foo?bar", getBucketName(), "bar&foo"
		err := setup(s, dstBucket)
		if err != nil {
			return err
		}

		srcObjVersions, err := createObjVersions(s3client, bucket, srcObj, 1)
		if err != nil {
			return err
		}

		srcObjVersionId := *srcObjVersions[0].VersionId

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        &dstObj,
			CopySource: getPtr(fmt.Sprintf("%v/%v?versionId=%v", bucket, srcObj, srcObjVersionId)),
		})
		cancel()
		if err != nil {
			return err
		}

		if res.VersionId == nil || *res.VersionId == "" {
			return fmt.Errorf("expected non empty versionId")
		}
		if res.CopySourceVersionId == nil {
			return fmt.Errorf("expected non nil CopySourceVersionId")
		}
		if *res.CopySourceVersionId != srcObjVersionId {
			return fmt.Errorf("expected the SourceVersionId to be %v, instead got %v",
				srcObjVersionId, *res.CopySourceVersionId)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:    &bucket,
			Key:       &dstObj,
			VersionId: res.VersionId,
		})
		cancel()
		if err != nil {
			return err
		}

		if out.VersionId == nil {
			return fmt.Errorf("expected non nil VersionId")
		}
		if *out.VersionId != *res.VersionId {
			return fmt.Errorf("expected the copied object versionId to be %v, instead got %v",
				*res.VersionId, *out.VersionId)
		}

		err = teardown(s, dstBucket)
		if err != nil {
			return err
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_HeadObject_invalid_versionId(s *S3Conf) error {
	testName := "Versioning_HeadObject_invalid_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dLen := int64(2000)
		obj := "my-obj"
		_, err := putObjectWithData(dLen, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: getPtr("invalid_version_id"),
		})
		cancel()
		if err := checkSdkApiErr(err, "BadRequest"); err != nil {
			return err
		}
		return nil
	})
}

func Versioning_HeadObject_invalid_parent(s *S3Conf) error {
	testName := "Versioning_HeadObject_invalid_parent"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dLen := int64(2000)
		obj := "not-a-dir"
		r, err := putObjectWithData(dLen, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		obj = "not-a-dir/bad-obj"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: r.res.VersionId,
		})
		cancel()
		if err := checkSdkApiErr(err, "NotFound"); err != nil {
			return err
		}
		return nil
	})
}

func Versioning_HeadObject_success(s *S3Conf) error {
	testName := "Versioning_HeadObject_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dLen := int64(2000)
		obj := "my-obj"
		r, err := putObjectWithData(dLen, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: r.res.VersionId,
		})
		cancel()
		if err != nil {
			return err
		}

		if out.ContentLength == nil {
			return fmt.Errorf("expected non nil ContentLength")
		}
		if out.VersionId == nil {
			return fmt.Errorf("expected non nil VersionId")
		}
		if *out.ContentLength != dLen {
			return fmt.Errorf("expected the object content-length to be %v, instead got %v",
				dLen, *out.ContentLength)
		}
		if *out.VersionId != *r.res.VersionId {
			return fmt.Errorf("expected the versionId to be %v, instead got %v",
				*r.res.VersionId, *out.VersionId)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_HeadObject_without_versionId(s *S3Conf) error {
	testName := "Versioning_HeadObject_without_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		versions, err := createObjVersions(s3client, bucket, obj, 3)
		if err != nil {
			return err
		}

		lastVersion := versions[0]

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		if getString(res.VersionId) != *lastVersion.VersionId {
			return fmt.Errorf("expected versionId to be %v, instead got %v",
				*lastVersion.VersionId, getString(res.VersionId))
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_HeadObject_delete_marker(s *S3Conf) error {
	testName := "Versioning_HeadObject_delete_marker"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dLen := int64(2000)
		obj := "my-obj"
		_, err := putObjectWithData(dLen, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		if out.VersionId == nil || *out.VersionId == "" {
			return fmt.Errorf("expected non empty versionId")
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: out.VersionId,
		})
		cancel()
		if err := checkSdkApiErr(err, "MethodNotAllowed"); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err := checkSdkApiErr(err, "NotFound"); err != nil {
			return err
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_GetObject_invalid_versionId(s *S3Conf) error {
	testName := "Versioning_GetObject_invalid_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dLen := int64(2000)
		obj := "my-obj"
		_, err := putObjectWithData(dLen, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: getPtr("invalid_version_id"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidVersionId)); err != nil {
			return err
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_GetObject_success(s *S3Conf) error {
	testName := "Versioning_GetObject_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dLen := int64(2000)
		obj := "my-obj"
		r, err := putObjectWithData(dLen, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		// Get the object by versionId
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: r.res.VersionId,
		})
		defer cancel()
		if err != nil {
			return err
		}

		if out.ContentLength == nil {
			return fmt.Errorf("expected non nil ContentLength")
		}
		if out.VersionId == nil {
			return fmt.Errorf("expected non nil VersionId")
		}
		if *out.ContentLength != dLen {
			return fmt.Errorf("expected the object content-length to be %v, instead got %v",
				dLen, *out.ContentLength)
		}
		if *out.VersionId != *r.res.VersionId {
			return fmt.Errorf("expected the versionId to be %v, instead got %v",
				*r.res.VersionId, *out.VersionId)
		}

		bdy, err := io.ReadAll(out.Body)
		if err != nil {
			return err
		}
		out.Body.Close()

		outCsum := sha256.Sum256(bdy)
		if outCsum != r.csum {
			return fmt.Errorf("incorrect output content")
		}

		// Get the object without versionId
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		defer cancel()
		if err != nil {
			return err
		}

		if out.ContentLength == nil {
			return fmt.Errorf("expected non nil ContentLength")
		}
		if out.VersionId == nil {
			return fmt.Errorf("expected non nil VersionId")
		}
		if *out.ContentLength != dLen {
			return fmt.Errorf("expected the object content-length to be %v, instead got %v",
				dLen, *out.ContentLength)
		}
		if *out.VersionId != *r.res.VersionId {
			return fmt.Errorf("expected the versionId to be %v, instead got %v",
				*r.res.VersionId, *out.VersionId)
		}

		bdy, err = io.ReadAll(out.Body)
		if err != nil {
			return err
		}
		out.Body.Close()

		outCsum = sha256.Sum256(bdy)
		if outCsum != r.csum {
			return fmt.Errorf("incorrect output content")
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_GetObject_delete_marker_without_versionId(s *S3Conf) error {
	testName := "Versioning_GetObject_delete_marker_without_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjectWithData(1234, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		err = putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusEnabled)
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
		cancel()
		if err := checkSdkApiErr(err, "NoSuchKey"); err != nil {
			return err
		}

		return nil
	})
}

func Versioning_GetObject_delete_marker(s *S3Conf) error {
	testName := "Versioning_GetObject_delete_marker"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dLen := int64(2000)
		obj := "my-obj"
		_, err := putObjectWithData(dLen, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		if out.VersionId == nil || *out.VersionId == "" {
			return fmt.Errorf("expected non empty versionId")
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: out.VersionId,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMethodNotAllowed)); err != nil {
			return err
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_GetObject_null_versionId_obj(s *S3Conf) error {
	testName := "Versioning_GetObject_null_versionId_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, lgth := "my-obj", int64(234)
		out, err := putObjectWithData(lgth, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		err = putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusEnabled)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: &nullVersionId,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.ContentLength == nil {
			return fmt.Errorf("expected non nil ContentLength")
		}
		if res.VersionId == nil {
			return fmt.Errorf("expected non nil VersionId")
		}
		if res.ETag == nil {
			return fmt.Errorf("expected non nil ETag")
		}
		if *res.ContentLength != lgth {
			return fmt.Errorf("expected the Content-Length to be %v, instead got %v",
				lgth, *res.ContentLength)
		}
		if *res.VersionId != nullVersionId {
			return fmt.Errorf("expected the versionId to be %v, insted got %v",
				nullVersionId, *res.VersionId)
		}
		if *res.ETag != *out.res.ETag {
			return fmt.Errorf("expecte the ETag to be %v, instead got %v",
				*out.res.ETag, *res.ETag)
		}

		return nil
	})
}

func Versioning_GetObjectAttributes_object_version(s *S3Conf) error {
	testName := "Versioning_GetObjectAttributes_object_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		versions, err := createObjVersions(s3client, bucket, obj, 1)
		if err != nil {
			return err
		}
		version := versions[0]

		getObjAttrs := func(versionId *string) (*s3.GetObjectAttributesOutput, error) {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: versionId,
				ObjectAttributes: []types.ObjectAttributes{
					types.ObjectAttributesEtag,
				},
			})
			cancel()
			return res, err
		}

		// By specifying the versionId
		res, err := getObjAttrs(version.VersionId)
		if err != nil {
			return err
		}

		if getString(res.ETag) != strings.Trim(*version.ETag, "\"") {
			return fmt.Errorf("expected the uploaded object ETag to be %v, instead got %v",
				strings.Trim(*version.ETag, "\""), getString(res.ETag))
		}
		if getString(res.VersionId) != *version.VersionId {
			return fmt.Errorf("expected the uploaded versionId to be %v, instead got %v",
				*version.VersionId, getString(res.VersionId))
		}

		// Without versionId
		res, err = getObjAttrs(nil)
		if err != nil {
			return err
		}

		if getString(res.ETag) != strings.Trim(*version.ETag, "\"") {
			return fmt.Errorf("expected the uploaded object ETag to be %v, instead got %v",
				strings.Trim(*version.ETag, "\""), getString(res.ETag))
		}
		if getString(res.VersionId) != *version.VersionId {
			return fmt.Errorf("expected the uploaded object versionId to be %v, instead got %v",
				*version.VersionId, getString(res.VersionId))
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_GetObjectAttributes_delete_marker(s *S3Conf) error {
	testName := "Versioning_GetObjectAttributes_delete_marker"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := createObjVersions(s3client, bucket, obj, 1)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: res.VersionId,
			ObjectAttributes: []types.ObjectAttributes{
				types.ObjectAttributesEtag,
			},
		})
		cancel()
		if err := checkSdkApiErr(err, "NoSuchKey"); err != nil {
			return err
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_DeleteObject_delete_object_version(s *S3Conf) error {
	testName := "Versioning_DeleteObject_delete_object_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		oLen := int64(1000)
		obj := "my-obj"
		r, err := putObjectWithData(oLen, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		versionId := r.res.VersionId
		if versionId == nil || *versionId == "" {
			return fmt.Errorf("expected non empty versionId")
		}

		_, err = putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: versionId,
		})
		cancel()
		if err != nil {
			return err
		}

		if out.VersionId == nil {
			return fmt.Errorf("expected non nil versionId")
		}
		if *out.VersionId != *versionId {
			return fmt.Errorf("expected deleted object versionId to be %v, instead got %v",
				*versionId, *out.VersionId)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_DeleteObject_non_existing_object(s *S3Conf) error {
	testName := "Versioning_DeleteObject_non_existing_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		ctx, canel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		canel()
		if err != nil {
			return err
		}

		ctx, canel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: getPtr("non_existing_version_id"),
		})
		canel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidVersionId)); err != nil {
			return err
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_DeleteObject_delete_a_delete_marker(s *S3Conf) error {
	testName := "Versioning_DeleteObject_delete_a_delete_marker"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		oLen := int64(1000)
		obj := "my-obj"
		_, err := putObjectWithData(oLen, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		if out.DeleteMarker == nil || !*out.DeleteMarker {
			return fmt.Errorf("expected the response DeleteMarker to be true")
		}
		if out.VersionId == nil || *out.VersionId == "" {
			return fmt.Errorf("expected non empty versionId")
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: out.VersionId,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.DeleteMarker == nil || !*res.DeleteMarker {
			return fmt.Errorf("expected the response DeleteMarker to be true")
		}
		if res.VersionId == nil {
			return fmt.Errorf("expected non empty versionId")
		}
		if *res.VersionId != *out.VersionId {
			return fmt.Errorf("expected the versionId to be %v, instead got %v",
				*out.VersionId, *res.VersionId)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_Delete_null_versionId_object(s *S3Conf) error {
	testName := "Versioning_Delete_null_versionId_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, nObjLgth := "my-obj", int64(3211)
		_, err := putObjectWithData(nObjLgth, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		err = putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusEnabled)
		if err != nil {
			return err
		}

		_, err = createObjVersions(s3client, bucket, obj, 3)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: getPtr(nullVersionId),
		})
		cancel()
		if err != nil {
			return err
		}
		if getString(res.VersionId) != nullVersionId {
			return fmt.Errorf("expected the versionId to be %v, instead got %v",
				nullVersionId, getString(res.VersionId))
		}

		return nil
	})
}

func Versioning_DeleteObject_nested_dir_object(s *S3Conf) error {
	testName := "Versioning_DeleteObject_nested_dir_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "foo/bar/baz"
		out, err := putObjectWithData(1000, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: out.res.VersionId,
		})
		cancel()
		if err != nil {
			return err
		}

		if getString(res.VersionId) != getString(out.res.VersionId) {
			return fmt.Errorf("expected the versionId to be %v, instead got %v",
				getString(out.res.VersionId), getString(res.VersionId))
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteBucket(ctx, &s3.DeleteBucketInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		// Then create the bucket back to not get error on teardown
		if err := setup(s, bucket); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func Versioning_DeleteObject_suspended(s *S3Conf) error {
	testName := "Versioning_DeleteObject_suspended"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		versions, err := createObjVersions(s3client, bucket, obj, 1)
		if err != nil {
			return err
		}
		versions[0].IsLatest = getBoolPtr(false)

		err = putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusSuspended)
		if err != nil {
			return err
		}

		for range 5 {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			if res.DeleteMarker == nil {
				return fmt.Errorf("expected the delete marker to be true")
			}
			if !*res.DeleteMarker {
				return fmt.Errorf("expected the delete marker to be true, instead got %v",
					*res.DeleteMarker)
			}
			if res.VersionId == nil {
				return fmt.Errorf("expected non nil versionId")
			}
			if *res.VersionId != nullVersionId {
				return fmt.Errorf("expected the versionId to be %v, instead got %v",
					nullVersionId, *res.VersionId)
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		delMarkers := []types.DeleteMarkerEntry{
			{
				IsLatest:  getBoolPtr(true),
				Key:       &obj,
				VersionId: &nullVersionId,
			},
		}

		if !compareVersions(versions, res.Versions) {
			return fmt.Errorf("expected the versions to be %v, instead got %v",
				versions, res.Versions)
		}
		if !compareDelMarkers(res.DeleteMarkers, delMarkers) {
			return fmt.Errorf("expected the delete markers to be %v, instead got %v",
				delMarkers, res.DeleteMarkers)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_DeleteObjects_success(s *S3Conf) error {
	testName := "Versioning_DeleteObjects_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj1, obj2, obj3 := "foo", "bar", "baz"

		obj1Version, err := createObjVersions(s3client, bucket, obj1, 1)
		if err != nil {
			return err
		}
		obj2Version, err := createObjVersions(s3client, bucket, obj2, 1)
		if err != nil {
			return err
		}
		obj3Version, err := createObjVersions(s3client, bucket, obj3, 1)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: &bucket,
			Delete: &types.Delete{
				Objects: []types.ObjectIdentifier{
					{
						Key:       obj1Version[0].Key,
						VersionId: obj1Version[0].VersionId,
					},
					{
						Key: obj2Version[0].Key,
					},
					{
						Key: obj3Version[0].Key,
					},
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		delResult := []types.DeletedObject{
			{
				Key:          obj1Version[0].Key,
				VersionId:    obj1Version[0].VersionId,
				DeleteMarker: getBoolPtr(false),
			},
			{
				Key:          obj2Version[0].Key,
				DeleteMarker: getBoolPtr(true),
			},
			{
				Key:          obj3Version[0].Key,
				DeleteMarker: getBoolPtr(true),
			},
		}

		if len(out.Errors) != 0 {
			return fmt.Errorf("errors occurred during the deletion: %v",
				out.Errors)
		}
		if !compareDelObjects(delResult, out.Deleted) {
			return fmt.Errorf("expected the deleted objects to be %v, instead got %v",
				delResult, out.Deleted)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		obj2Version[0].IsLatest = getBoolPtr(false)
		obj3Version[0].IsLatest = getBoolPtr(false)
		versions := append(obj2Version, obj3Version...)

		delMarkers := []types.DeleteMarkerEntry{
			{
				IsLatest:  getBoolPtr(true),
				Key:       out.Deleted[1].Key,
				VersionId: out.Deleted[1].DeleteMarkerVersionId,
			},
			{
				IsLatest:  getBoolPtr(true),
				Key:       out.Deleted[2].Key,
				VersionId: out.Deleted[2].DeleteMarkerVersionId,
			},
		}
		if !compareVersions(versions, res.Versions) {
			return fmt.Errorf("expected the resulting versions to be %v, instead got %v",
				versions, res.Versions)
		}
		if !compareDelMarkers(delMarkers, res.DeleteMarkers) {
			return fmt.Errorf("expected the resulting delete markers to be %v, instead got %v",
				delMarkers, res.DeleteMarkers)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_DeleteObjects_delete_deleteMarkers(s *S3Conf) error {
	testName := "Versioning_DeleteObjects_delete_deleteMarkers"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj1, obj2 := "foo", "bar"

		obj1Version, err := createObjVersions(s3client, bucket, obj1, 1)
		if err != nil {
			return err
		}
		obj2Version, err := createObjVersions(s3client, bucket, obj2, 1)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: &bucket,
			Delete: &types.Delete{
				Objects: []types.ObjectIdentifier{
					{
						Key: obj1Version[0].Key,
					},
					{
						Key: obj2Version[0].Key,
					},
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		delResult := []types.DeletedObject{
			{
				Key:          obj1Version[0].Key,
				DeleteMarker: getBoolPtr(true),
			},
			{
				Key:          obj2Version[0].Key,
				DeleteMarker: getBoolPtr(true),
			},
		}

		if len(out.Errors) != 0 {
			return fmt.Errorf("errors occurred during the deletion: %v",
				out.Errors)
		}
		if !compareDelObjects(delResult, out.Deleted) {
			return fmt.Errorf("expected the deleted objects to be %v, instead got %v",
				delResult, out.Deleted)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: &bucket,
			Delete: &types.Delete{
				Objects: []types.ObjectIdentifier{
					{
						Key:       out.Deleted[0].Key,
						VersionId: out.Deleted[0].VersionId,
					},
					{
						Key:       out.Deleted[1].Key,
						VersionId: out.Deleted[1].VersionId,
					},
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}
		if len(out.Errors) != 0 {
			return fmt.Errorf("errors occurred during the deletion: %v",
				out.Errors)
		}

		delResult = []types.DeletedObject{
			{
				Key:                   out.Deleted[0].Key,
				DeleteMarker:          getBoolPtr(true),
				DeleteMarkerVersionId: out.Deleted[0].VersionId,
				VersionId:             out.Deleted[0].VersionId,
			},
			{
				Key:                   out.Deleted[1].Key,
				DeleteMarker:          getBoolPtr(true),
				DeleteMarkerVersionId: out.Deleted[1].VersionId,
				VersionId:             out.Deleted[1].VersionId,
			},
		}

		if !compareDelObjects(delResult, res.Deleted) {
			return fmt.Errorf("expected the deleted objects to be %v, instead got %v",
				delResult, res.Deleted)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func ListObjectVersions_non_existing_bucket(s *S3Conf) error {
	testName := "ListObjectVersions_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: getPtr(getBucketName()),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func ListObjectVersions_list_single_object_versions(s *S3Conf) error {
	testName := "ListObjectVersions_list_single_object_versions"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-obj"
		versions, err := createObjVersions(s3client, bucket, object, 5)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareVersions(versions, out.Versions) {
			return fmt.Errorf("expected the resulting versions to be %v, instead got %v",
				versions, out.Versions)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func ListObjectVersions_list_multiple_object_versions(s *S3Conf) error {
	testName := "ListObjectVersions_list_multiple_object_versions"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj1, obj2, obj3 := "foo", "bar", "baz"

		obj1Versions, err := createObjVersions(s3client, bucket, obj1, 4)
		if err != nil {
			return err
		}
		obj2Versions, err := createObjVersions(s3client, bucket, obj2, 3)
		if err != nil {
			return err
		}
		obj3Versions, err := createObjVersions(s3client, bucket, obj3, 5)
		if err != nil {
			return err
		}

		versions := append(append(obj2Versions, obj3Versions...), obj1Versions...)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareVersions(versions, out.Versions) {
			return fmt.Errorf("expected the resulting versions to be %v, instead got %v",
				versions, out.Versions)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func ListObjectVersions_multiple_object_versions_truncated(s *S3Conf) error {
	testName := "ListObjectVersions_multiple_object_versions_truncated"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj1, obj2, obj3 := "foo", "bar", "baz"

		obj1Versions, err := createObjVersions(s3client, bucket, obj1, 4)
		if err != nil {
			return err
		}
		obj2Versions, err := createObjVersions(s3client, bucket, obj2, 3)
		if err != nil {
			return err
		}
		obj3Versions, err := createObjVersions(s3client, bucket, obj3, 5)
		if err != nil {
			return err
		}

		versions := append(append(obj2Versions, obj3Versions...), obj1Versions...)
		maxKeys := int32(5)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket:  &bucket,
			MaxKeys: &maxKeys,
		})
		cancel()
		if err != nil {
			return err
		}

		if out.Name == nil {
			return fmt.Errorf("expected the bucket name to be %v, instead got nil",
				bucket)
		}
		if *out.Name != bucket {
			return fmt.Errorf("expected the bucket name to be %v, instead got %v",
				bucket, *out.Name)
		}
		if out.IsTruncated == nil || !*out.IsTruncated {
			return fmt.Errorf("expected the output to be truncated")
		}
		if out.MaxKeys == nil {
			return fmt.Errorf("expected the max-keys to be %v, instead got nil",
				maxKeys)
		}
		if *out.MaxKeys != maxKeys {
			return fmt.Errorf("expected the max-keys to be %v, instead got %v",
				maxKeys, *out.MaxKeys)
		}
		if getString(out.NextKeyMarker) != getString(versions[maxKeys-1].Key) {
			return fmt.Errorf("expected the NextKeyMarker to be %v, instead got %v",
				getString(versions[maxKeys-1].Key), getString(out.NextKeyMarker))
		}
		if getString(out.NextVersionIdMarker) != getString(versions[maxKeys-1].VersionId) {
			return fmt.Errorf("expected the NextVersionIdMarker to be %v, instead got %v",
				getString(versions[maxKeys-1].VersionId), getString(out.NextVersionIdMarker))
		}

		if !compareVersions(versions[:maxKeys], out.Versions) {
			return fmt.Errorf("expected the resulting object versions to be %v, instead got %v",
				versions[:maxKeys], out.Versions)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err = s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket:          &bucket,
			KeyMarker:       out.NextKeyMarker,
			VersionIdMarker: out.NextVersionIdMarker,
		})
		cancel()
		if err != nil {
			return err
		}

		if out.Name == nil {
			return fmt.Errorf("expected the bucket name to be %v, instead got nil",
				bucket)
		}
		if *out.Name != bucket {
			return fmt.Errorf("expected the bucket name to be %v, instead got %v",
				bucket, *out.Name)
		}
		if out.IsTruncated != nil && *out.IsTruncated {
			return fmt.Errorf("expected the output not to be truncated")
		}
		if getString(out.KeyMarker) != getString(versions[maxKeys-1].Key) {
			return fmt.Errorf("expected the KeyMarker to be %v, instead got %v",
				getString(versions[maxKeys-1].Key), getString(out.KeyMarker))
		}
		if getString(out.VersionIdMarker) != getString(versions[maxKeys-1].VersionId) {
			return fmt.Errorf("expected the VersionIdMarker to be %v, instead got %v",
				getString(versions[maxKeys-1].VersionId), getString(out.VersionIdMarker))
		}

		if !compareVersions(versions[maxKeys:], out.Versions) {
			return fmt.Errorf("expected the resulting object versions to be %v, instead got %v",
				versions[maxKeys:], out.Versions)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func ListObjectVersions_with_delete_markers(s *S3Conf) error {
	testName := "ListObjectVersions_with_delete_markers"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		versions, err := createObjVersions(s3client, bucket, obj, 1)
		if err != nil {
			return err
		}

		versions[0].IsLatest = getBoolPtr(false)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		delMarkers := []types.DeleteMarkerEntry{}
		delMarkers = append(delMarkers, types.DeleteMarkerEntry{
			Key:       &obj,
			VersionId: out.VersionId,
			IsLatest:  getBoolPtr(true),
		})

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareVersions(versions, res.Versions) {
			return fmt.Errorf("expected the resulting versions to be %v, instead got %v",
				versions, res.Versions)
		}
		if !compareDelMarkers(res.DeleteMarkers, delMarkers) {
			return fmt.Errorf("expected the resulting delete markers to be %v, instead got %v",
				delMarkers, res.DeleteMarkers)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func ListObjectVersions_containing_null_versionId_obj(s *S3Conf) error {
	testName := "ListObjectVersions_containing_null_versionId_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		versions, err := createObjVersions(s3client, bucket, obj, 3)
		if err != nil {
			return err
		}

		err = putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusSuspended)
		if err != nil {
			return err
		}

		objLgth := int64(543)
		out, err := putObjectWithData(objLgth, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		if getString(out.res.VersionId) != nullVersionId {
			return fmt.Errorf("expected the uploaded object versionId to be %v, instead got %v",
				nullVersionId, getString(out.res.VersionId))
		}

		versions[0].IsLatest = getBoolPtr(false)

		versions = append([]types.ObjectVersion{
			{
				ETag:         out.res.ETag,
				IsLatest:     getBoolPtr(false),
				Key:          &obj,
				Size:         &objLgth,
				VersionId:    &nullVersionId,
				StorageClass: types.ObjectVersionStorageClassStandard,
			},
		}, versions...)

		err = putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusEnabled)
		if err != nil {
			return err
		}

		newVersions, err := createObjVersions(s3client, bucket, obj, 4)
		if err != nil {
			return err
		}

		versions = append(newVersions, versions...)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareVersions(versions, res.Versions) {
			return fmt.Errorf("expected the listed object versions to be %v, instead got %v",
				versions, res.Versions)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func ListObjectVersions_single_null_versionId_object(s *S3Conf) error {
	testName := "ListObjectVersions_single_null_versionId_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, objLgth := "my-obj", int64(890)
		out, err := putObjectWithData(objLgth, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		err = putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusEnabled)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		versions := []types.ObjectVersion{
			{
				ETag:         out.res.ETag,
				Key:          &obj,
				StorageClass: types.ObjectVersionStorageClassStandard,
				IsLatest:     getBoolPtr(false),
				Size:         &objLgth,
				VersionId:    &nullVersionId,
			},
		}
		delMarkers := []types.DeleteMarkerEntry{
			{
				IsLatest:  getBoolPtr(true),
				Key:       &obj,
				VersionId: res.VersionId,
			},
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareDelMarkers(resp.DeleteMarkers, delMarkers) {
			return fmt.Errorf("expected the delete markers list to be %v, instaed got %v",
				delMarkers, resp.DeleteMarkers)
		}
		if !compareVersions(versions, resp.Versions) {
			return fmt.Errorf("expected the object versions list to be %v, instead got %v",
				versions, resp.Versions)
		}

		return nil
	})
}

func ListObjectVersions_checksum(s *S3Conf) error {
	testName := "ListObjectVersions_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		versions := []types.ObjectVersion{}
		for i, algo := range types.ChecksumAlgorithmCrc32.Values() {
			vers, err := createObjVersions(s3client, bucket, fmt.Sprintf("obj-%v", i), 1, withChecksumAlgo(algo))
			if err != nil {
				return err
			}

			versions = append(versions, vers...)
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareVersions(versions, res.Versions) {
			return fmt.Errorf("expected the versions to be %+v, instead got %+v",
				versions, res.Versions)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_Multipart_Upload_success(s *S3Conf) error {
	testName := "Versioning_Multipart_Upload_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		objSize := int64(25 * 1024 * 1024)
		parts, _, err := uploadParts(s3client, objSize, 5, bucket, obj, *out.UploadId)
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

		if res.Key == nil {
			return fmt.Errorf("expected the object key to be %v, instead got nil",
				obj)
		}
		if *res.Key != obj {
			return fmt.Errorf("expected object key to be %v, instead got %v",
				obj, *res.Key)
		}
		if res.Bucket == nil {
			return fmt.Errorf("expected the bucket name to be %v, instead got nil",
				bucket)
		}
		if *res.Bucket != bucket {
			return fmt.Errorf("expected the bucket name to be %v, instead got %v",
				bucket, *res.Bucket)
		}
		if res.ETag == nil || *res.ETag == "" {
			return fmt.Errorf("expected non-empty ETag")
		}
		if res.VersionId == nil || *res.VersionId == "" {
			return fmt.Errorf("expected non-empty versionId")
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: res.VersionId,
		})
		cancel()
		if err != nil {
			return err
		}

		if resp.ETag == nil || *resp.ETag == "" {
			return fmt.Errorf("expected (head object) non-empty ETag")
		}
		if *resp.ETag != *res.ETag {
			return fmt.Errorf("expected the uploaded object etag to be %v, instead got %v",
				*res.ETag, *resp.ETag)
		}
		if resp.ContentLength == nil {
			return fmt.Errorf("expected (head object) non nil content length")
		}
		if *resp.ContentLength != int64(objSize) {
			return fmt.Errorf("expected the uploaded object size to be %v, instead got %v",
				objSize, resp.ContentLength)
		}
		if resp.VersionId == nil {
			return fmt.Errorf("expected (head object) non nil versionId")
		}
		if *resp.VersionId != *res.VersionId {
			return fmt.Errorf("expected the versionId to be %v, instead got %v",
				*res.VersionId, *resp.VersionId)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_Multipart_Upload_overwrite_an_object(s *S3Conf) error {
	testName := "Versioning_Multipart_Upload_overwrite_an_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		objVersions, err := createObjVersions(s3client, bucket, obj, 2)
		if err != nil {
			return err
		}
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		objSize := int64(25 * 1024 * 1024)
		parts, _, err := uploadParts(s3client, objSize, 5, bucket, obj, *out.UploadId)
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

		if res.Key == nil {
			return fmt.Errorf("expected the object key to be %v, instead got nil",
				obj)
		}
		if *res.Key != obj {
			return fmt.Errorf("expected object key to be %v, instead got %v",
				obj, *res.Key)
		}
		if res.Bucket == nil {
			return fmt.Errorf("expected the bucket name to be %v, instead got nil",
				bucket)
		}
		if *res.Bucket != bucket {
			return fmt.Errorf("expected the bucket name to be %v, instead got %v",
				bucket, *res.Bucket)
		}
		if res.ETag == nil || *res.ETag == "" {
			return fmt.Errorf("expected non-empty ETag")
		}
		if res.VersionId == nil || *res.VersionId == "" {
			return fmt.Errorf("expected non-empty versionId")
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		size := int64(objSize)

		objVersions[0].IsLatest = getBoolPtr(false)
		versions := append([]types.ObjectVersion{
			{
				Key:          &obj,
				VersionId:    res.VersionId,
				ETag:         res.ETag,
				IsLatest:     getBoolPtr(true),
				Size:         &size,
				StorageClass: types.ObjectVersionStorageClassStandard,
			},
		}, objVersions...)

		if !compareVersions(versions, resp.Versions) {
			return fmt.Errorf("expected the resulting versions to be %v, instead got %v",
				versions, resp.Versions)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_UploadPartCopy_non_existing_versionId(s *S3Conf) error {
	testName := "Versioning_UploadPartCopy_non_existing_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dstBucket, dstObj, srcObj := getBucketName(), "dst-obj", "src-obj"

		lgth := int64(100)
		_, err := putObjectWithData(lgth, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		if err := setup(s, dstBucket); err != nil {
			return err
		}

		mp, err := createMp(s3client, dstBucket, dstObj)
		if err != nil {
			return err
		}

		pNumber := int32(1)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &dstBucket,
			Key:        &dstObj,
			UploadId:   mp.UploadId,
			PartNumber: &pNumber,
			CopySource: getPtr(fmt.Sprintf("%v/%v?versionId=invalid_versionId",
				bucket, srcObj)),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchVersion)); err != nil {
			return err
		}

		if err := teardown(s, dstBucket); err != nil {
			return err
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_UploadPartCopy_from_an_object_version(s *S3Conf) error {
	testName := "Versioning_UploadPartCopy_from_an_object_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj, dstBucket, obj := "my-obj", getBucketName(), "dst-obj"
		err := setup(s, dstBucket)
		if err != nil {
			return err
		}

		srcObjVersions, err := createObjVersions(s3client, bucket, srcObj, 1)
		if err != nil {
			return err
		}
		srcObjVersion := srcObjVersions[0]

		out, err := createMp(s3client, dstBucket, obj)
		if err != nil {
			return err
		}

		partNumber := int32(1)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		copyOut, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &dstBucket,
			CopySource: getPtr(fmt.Sprintf("%v/%v?versionId=%v", bucket, srcObj, *srcObjVersion.VersionId)),
			UploadId:   out.UploadId,
			Key:        &obj,
			PartNumber: &partNumber,
		})
		cancel()
		if err != nil {
			return err
		}

		if getString(copyOut.CopySourceVersionId) != getString(srcObjVersion.VersionId) {
			return fmt.Errorf("expected the copy-source-version-id to be %v, instead got %v",
				getString(srcObjVersion.VersionId), getString(copyOut.CopySourceVersionId))
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &dstBucket,
			Key:      &obj,
			UploadId: out.UploadId,
		})
		cancel()
		if err != nil {
			return err
		}

		if len(res.Parts) != 1 {
			return fmt.Errorf("expected parts to be 1, instead got %v",
				len(res.Parts))
		}
		if res.Parts[0].PartNumber == nil {
			return fmt.Errorf("expected part-number to be non nil")
		}
		if *res.Parts[0].PartNumber != partNumber {
			return fmt.Errorf("expected part-number to be %v, instead got %v",
				partNumber, res.Parts[0].PartNumber)
		}
		if res.Parts[0].Size == nil {
			return fmt.Errorf("expected part size to be non nil")
		}
		if *res.Parts[0].Size != *srcObjVersion.Size {
			return fmt.Errorf("expected part size to be %v, instead got %v",
				*srcObjVersion.Size, res.Parts[0].Size)
		}
		if getString(res.Parts[0].ETag) != getString(copyOut.CopyPartResult.ETag) {
			return fmt.Errorf("expected part etag to be %v, instead got %v",
				getString(copyOut.CopyPartResult.ETag), getString(res.Parts[0].ETag))
		}

		if err := teardown(s, dstBucket); err != nil {
			return err
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_Enable_object_lock(s *S3Conf) error {
	testName := "Versioning_Enable_object_lock"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.Status != types.BucketVersioningStatusEnabled {
			return fmt.Errorf("expected the bucket versioning status to be %v, instead got %v",
				types.BucketVersioningStatusEnabled, res.Status)
		}

		return nil
	}, withLock())
}

func Versioning_status_switch_to_suspended_with_object_lock(s *S3Conf) error {
	testName := "Versioning_status_switch_to_suspended_with_object_lock"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusSuspended)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrSuspendedVersioningNotAllowed)); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func Versioning_PutObjectRetention_invalid_versionId(s *S3Conf) error {
	testName := "Versioning_PutObjectRetention_invalid_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := createObjVersions(s3client, bucket, obj, 3)
		if err != nil {
			return err
		}

		rDate := time.Now().Add(time.Hour * 48)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: getPtr("invalid_versionId"),
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeGovernance,
				RetainUntilDate: &rDate,
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidVersionId)); err != nil {
			return err
		}

		return nil
	}, withLock(), withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_GetObjectRetention_invalid_versionId(s *S3Conf) error {
	testName := "Versioning_GetObjectRetention_invalid_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := createObjVersions(s3client, bucket, obj, 3)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: getPtr("invalid_versionId"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidVersionId)); err != nil {
			return err
		}

		return nil
	}, withLock(), withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_Put_GetObjectRetention_success(s *S3Conf) error {
	testName := "Versioning_Put_GetObjectRetention_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		objVersions, err := createObjVersions(s3client, bucket, obj, 3)
		if err != nil {
			return err
		}
		objVersion := objVersions[1]

		rDate := time.Now().Add(time.Hour * 48)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: objVersion.VersionId,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeGovernance,
				RetainUntilDate: &rDate,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: objVersion.VersionId,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.Retention.Mode != types.ObjectLockRetentionModeGovernance {
			return fmt.Errorf("expected the object retention mode to be %v, instead got %v",
				types.ObjectLockRetentionModeGovernance, res.Retention.Mode)
		}

		if err := changeBucketObjectLockStatus(s3client, bucket, false); err != nil {
			return err
		}

		return nil
	}, withLock(), withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_PutObjectLegalHold_invalid_versionId(s *S3Conf) error {
	testName := "Versioning_PutObjectLegalHold_invalid_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := createObjVersions(s3client, bucket, obj, 3)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: getPtr("invalid_versionId"),
			LegalHold: &types.ObjectLockLegalHold{
				Status: types.ObjectLockLegalHoldStatusOn,
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidVersionId)); err != nil {
			return err
		}

		return nil
	}, withLock(), withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_GetObjectLegalHold_invalid_versionId(s *S3Conf) error {
	testName := "Versioning_GetObjectLegalHold_invalid_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := createObjVersions(s3client, bucket, obj, 3)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: getPtr("invalid_versionId"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidVersionId)); err != nil {
			return err
		}

		return nil
	}, withLock(), withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_Put_GetObjectLegalHold_success(s *S3Conf) error {
	testName := "Versioning_Put_GetObjectLegalHold_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		objVersions, err := createObjVersions(s3client, bucket, obj, 3)
		if err != nil {
			return err
		}
		objVersion := objVersions[1]

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: objVersion.VersionId,
			LegalHold: &types.ObjectLockLegalHold{
				Status: types.ObjectLockLegalHoldStatusOn,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: objVersion.VersionId,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.LegalHold.Status != types.ObjectLockLegalHoldStatusOn {
			return fmt.Errorf("expected the object version legal hold status to be %v, instead got %v",
				types.ObjectLockLegalHoldStatusOn, res.LegalHold.Status)
		}

		if err := changeBucketObjectLockStatus(s3client, bucket, false); err != nil {
			return err
		}

		return nil
	}, withLock(), withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_WORM_obj_version_locked_with_legal_hold(s *S3Conf) error {
	testName := "Versioning_WORM_obj_version_locked_with_legal_hold"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		objVersions, err := createObjVersions(s3client, bucket, obj, 2)
		if err != nil {
			return err
		}
		version := objVersions[1]

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: version.VersionId,
			LegalHold: &types.ObjectLockLegalHold{
				Status: types.ObjectLockLegalHoldStatusOn,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: version.VersionId,
		})
		cancel()
		if err := checkSdkApiErr(err, "InvalidRequest"); err != nil {
			return err
		}
		// client sdk regression issue prevents getting full error message,
		// change back to below once this is fixed:
		// https://github.com/aws/aws-sdk-go-v2/issues/2921
		// if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
		// 	return err
		// }

		if err := changeBucketObjectLockStatus(s3client, bucket, false); err != nil {
			return err
		}

		return nil
	}, withLock(), withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_WORM_obj_version_locked_with_governance_retention(s *S3Conf) error {
	testName := "Versioning_WORM_obj_version_locked_with_governance_retention"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		objVersions, err := createObjVersions(s3client, bucket, obj, 2)
		if err != nil {
			return err
		}
		version := objVersions[0]

		rDate := time.Now().Add(time.Hour * 48)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: version.VersionId,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeGovernance,
				RetainUntilDate: &rDate,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: version.VersionId,
		})
		cancel()
		if err := checkSdkApiErr(err, "InvalidRequest"); err != nil {
			return err
		}
		// client sdk regression issue prevents getting full error message,
		// change back to below once this is fixed:
		// https://github.com/aws/aws-sdk-go-v2/issues/2921
		// if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
		// 	return err
		// }

		if err := changeBucketObjectLockStatus(s3client, bucket, false); err != nil {
			return err
		}

		return nil
	}, withLock(), withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_WORM_obj_version_locked_with_compliance_retention(s *S3Conf) error {
	testName := "Versioning_WORM_obj_version_locked_with_compliance_retention"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		objVersions, err := createObjVersions(s3client, bucket, obj, 2)
		if err != nil {
			return err
		}
		version := objVersions[0]

		rDate := time.Now().Add(time.Hour * 48)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: version.VersionId,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeCompliance,
				RetainUntilDate: &rDate,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: version.VersionId,
		})
		cancel()
		if err := checkSdkApiErr(err, "InvalidRequest"); err != nil {
			return err
		}
		// client sdk regression issue prevents getting full error message,
		// change back to below once this is fixed:
		// https://github.com/aws/aws-sdk-go-v2/issues/2921
		// if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
		// 	return err
		// }

		if err := changeBucketObjectLockStatus(s3client, bucket, false); err != nil {
			return err
		}

		return nil
	}, withLock(), withVersioning(types.BucketVersioningStatusEnabled))
}

func VersioningDisabled_GetBucketVersioning_not_configured(s *S3Conf) error {
	testName := "VersioningDisabled_GetBucketVersioning_not_configured"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusEnabled)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrVersioningNotConfigured)); err != nil {
			return err
		}

		return nil
	})
}

func VersioningDisabled_PutBucketVersioning_not_configured(s *S3Conf) error {
	testName := "VersioningDisabled_PutBucketVersioning_not_configured"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrVersioningNotConfigured)); err != nil {
			return err
		}

		return nil
	})
}

func Versioning_concurrent_upload_object(s *S3Conf) error {
	testName := "Versioninig_concurrent_upload_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		versionCount := 5
		// Channel to collect errors
		errCh := make(chan error, versionCount)

		uploadVersion := func(wg *sync.WaitGroup) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.PutObject(ctx, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				// Send error to the channel
				errCh <- err
				return
			}

			fmt.Printf("uploaded object successfully: versionId: %v\n", *res.VersionId)
		}

		wg := &sync.WaitGroup{}
		wg.Add(versionCount)

		for range versionCount {
			go uploadVersion(wg)
		}

		wg.Wait()
		close(errCh)

		// Check if there were any errors
		for err := range errCh {
			if err != nil {
				fmt.Printf("error uploading an object: %v\n", err.Error())
				return err
			}
		}

		// List object versions after all uploads
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if len(res.Versions) != versionCount {
			return fmt.Errorf("expected %v object versions, instead got %v",
				versionCount, len(res.Versions))
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}
