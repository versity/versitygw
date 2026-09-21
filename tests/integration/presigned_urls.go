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
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

func PresignedAuth_security_token_with_permanent_credentials(s *S3Conf) error {
	testName := "PresignedAuth_security_token_with_permanent_credentials"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
		cancel()
		if err != nil {
			return err
		}

		uri := v4req.URL + "&X-Amz-Security-Token=my_token"

		req, err := http.NewRequest(v4req.Method, uri, nil)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrInvalidToken))
	})
}

func PresignedAuth_unsupported_algorithm(s *S3Conf) error {
	testName := "PresignedAuth_unsupported_algorithm"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
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

		return checkHTTPResponseApiErr(resp, s3err.QueryAuthErrors.UnsupportedAlgorithm())
	})
}

func PresignedAuth_ECDSA_not_supported(s *S3Conf) error {
	testName := "PresignedAuth_ECDSA_not_supported"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
		cancel()
		if err != nil {
			return err
		}

		uri := strings.Replace(v4req.URL, "AWS4-HMAC-SHA256", "AWS4-ECDSA-P256-SHA256", 1)

		req, err := http.NewRequest(v4req.Method, uri, nil)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.QueryAuthErrors.OnlyHMACSupported())
	})
}

func PresignedAuth_missing_signature_query_param(s *S3Conf) error {
	testName := "PresignedAuth_missing_signature_query_param"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
		cancel()
		if err != nil {
			return err
		}

		urlParsed, err := url.Parse(v4req.URL)
		if err != nil {
			return err
		}

		queries := urlParsed.Query()
		queries.Del("X-Amz-Signature")
		urlParsed.RawQuery = queries.Encode()

		req, err := http.NewRequest(v4req.Method, urlParsed.String(), nil)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.QueryAuthErrors.MissingRequiredParams())
	})
}

func PresignedAuth_missing_credentials_query_param(s *S3Conf) error {
	testName := "PresignedAuth_missing_credentials_query_param"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
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

		return checkHTTPResponseApiErr(resp, s3err.QueryAuthErrors.MissingRequiredParams())
	})
}

func PresignedAuth_malformed_creds_invalid_parts(s *S3Conf) error {
	testName := "PresignedAuth_malformed_creds_invalid_parts"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
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

		return checkHTTPResponseApiErr(resp, s3err.QueryAuthErrors.MalformedCredential(""))
	})
}

func PresignedAuth_creds_invalid_terminal(s *S3Conf) error {
	testName := "PresignedAuth_creds_invalid_terminal"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
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

		return checkHTTPResponseApiErr(resp, s3err.QueryAuthErrors.IncorrectTerminal("", "aws5_request"))
	})
}

func PresignedAuth_creds_incorrect_service(s *S3Conf) error {
	testName := "PresignedAuth_creds_incorrect_service"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
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

		return checkHTTPResponseApiErr(resp, s3err.QueryAuthErrors.IncorrectService("", "sns"))
	})
}

func PresignedAuth_creds_incorrect_region(s *S3Conf) error {
	testName := "PresignedAuth_creds_incorrect_region"
	return presignedAuthHandler(s, testName, func(_ *s3.PresignClient, bucket string) error {
		cfg := *s

		if cfg.awsRegion == "us-east-1" {
			cfg.awsRegion = "us-west-1"
		} else {
			cfg.awsRegion = "us-east-1"
		}

		client := cfg.GetPresignClient()

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
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

		return checkHTTPResponseApiErr(resp, s3err.QueryAuthErrors.IncorrectRegion(s.awsRegion, cfg.awsRegion))
	})
}

func PresignedAuth_creds_invalid_date(s *S3Conf) error {
	testName := "PresignedAuth_creds_invalid_date"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
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

		return checkHTTPResponseApiErr(resp, s3err.QueryAuthErrors.InvalidDateFormat("", "32234Z34"))
	})
}

func PresignedAuth_non_existing_access_key_id(s *S3Conf) error {
	testName := "PresignedAuth_non_existing_access_key_id"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient, bucket string) error {
		accessKeyID := "a_rarely_existing_access_key_id890asd6f807as6ydf870say"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
		cancel()
		if err != nil {
			return err
		}

		uri, err := changeAuthCred(v4req.URL, accessKeyID, credAccess)
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

		return checkHTTPResponseApiErr(resp, s3err.GetInvalidAccessKeyIdErr(accessKeyID))
	})
}

func PresignedAuth_missing_date_query(s *S3Conf) error {
	testName := "PresignedAuth_missing_date_query"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
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

		return checkHTTPResponseApiErr(resp, s3err.QueryAuthErrors.MissingRequiredParams())
	})
}

func PresignedAuth_dates_mismatch(s *S3Conf) error {
	testName := "PresignedAuth_dates_mismatch"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
		cancel()
		if err != nil {
			return err
		}

		urlParsed, err := url.Parse(v4req.URL)
		if err != nil {
			return err
		}

		tDate := urlParsed.Query().Get("X-Amz-Date")
		date := tDate[:8]

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

		return checkHTTPResponseApiErr(resp, s3err.QueryAuthErrors.DateMismatch("20060102", date))
	})
}

func PresignedAuth_missing_signed_headers_query_param(s *S3Conf) error {
	testName := "PresignedAuth_missing_signed_headers_query_param"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
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

		return checkHTTPResponseApiErr(resp, s3err.QueryAuthErrors.MissingRequiredParams())
	})
}

func PresignedAuth_unsigned_required_header(s *S3Conf) error {
	testName := "PresignedAuth_unsigned_required_header"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignPutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("my-obj")})
		cancel()
		if err != nil {
			return err
		}

		req, err := http.NewRequest(v4req.Method, v4req.URL, nil)
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

func PresignedAuth_unsigned_non_required_header(s *S3Conf) error {
	testName := "PresignedAuth_unsigned_non_required_header"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignPutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("my-obj")})
		cancel()
		if err != nil {
			return err
		}

		req, err := http.NewRequest(v4req.Method, v4req.URL, nil)
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

func PresignedAuth_missing_expiration_query_param(s *S3Conf) error {
	testName := "PresignedAuth_missing_expiration_query_param"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
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

		return checkHTTPResponseApiErr(resp, s3err.QueryAuthErrors.MissingRequiredParams())
	})
}

func PresignedAuth_invalid_expiration_query_param(s *S3Conf) error {
	testName := "PresignedAuth_invalid_expiration_query_param"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
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

		return checkHTTPResponseApiErr(resp, s3err.QueryAuthErrors.ExpiresNumber())
	})
}

func PresignedAuth_negative_expiration_query_param(s *S3Conf) error {
	testName := "PresignedAuth_negative_expiration_query_param"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
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

		return checkHTTPResponseApiErr(resp, s3err.QueryAuthErrors.ExpiresNegative())
	})
}

func PresignedAuth_exceeding_expiration_query_param(s *S3Conf) error {
	testName := "PresignedAuth_exceeding_expiration_query_param"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
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

		return checkHTTPResponseApiErr(resp, s3err.QueryAuthErrors.ExpiresTooLarge())
	})
}

func PresignedAuth_expired_request(s *S3Conf) error {
	testName := "PresignedAuth_expired_request"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
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
		xAmzExpires, err := strconv.Atoi(queries.Get("X-Amz-Expires"))
		if err != nil {
			return err
		}

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

		if err := checkHTTPResponseApiErr(resp, s3err.GetExpiredPresignedURLError(xAmzExpires, "", "")); err != nil {
			return err
		}

		return nil
	})
}

func PresignedAuth_incorrect_secret_key(s *S3Conf) error {
	testName := "PresignedAuth_incorrect_secret_key"
	return presignedAuthHandler(s, testName, func(_ *s3.PresignClient, bucket string) error {
		cfg := *s
		cfg.awsSecret += "x"
		client := cfg.GetPresignClient()

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		v4req, err := client.PresignDeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
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

		if err := checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrSignatureDoesNotMatch)); err != nil {
			return err
		}

		return nil
	})
}

func PresignedAuth_sigv2_not_supported(s *S3Conf) error {
	testName := "PresignedAuth_sigv2_not_supported"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		expires := time.Now().UTC().Add(time.Hour).Unix()
		uri := fmt.Sprintf("%s/%s/object?AWSAccessKeyId=%s&Expires=%d&Signature=my-signature", s.endpoint, bucket, s.awsID, expires)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, uri, nil)
		if err != nil {
			cancel()
			return err
		}

		resp, err := s.httpClient.Do(req)
		cancel()
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrUnsupportedAuthorizationMechanism))
	})
}

func PresignedAuth_PutObject_success(s *S3Conf) error {
	testName := "PresignedAuth_PutObject_success"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient, bucket string) error {
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

		return nil
	})
}

func PresignedAuth_Put_GetObject_with_data(s *S3Conf) error {
	testName := "PresignedAuth_Put_GetObject_with_data"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient, bucket string) error {
		obj := "my-obj"

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

		req.Header = v4GetReq.SignedHeader

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

		return nil
	})
}

func PresignedAuth_Put_GetObject_with_UTF8_chars(s *S3Conf) error {
	testName := "PresignedAuth_Put_GetObject_with_UTF8_chars"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient, bucket string) error {
		obj := "my-$%^&*;"
		if s.windowsTests {
			// '*' is not a valid filename character on Windows
			obj = "my-$%^&;"
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

		req.Header = v4GetReq.SignedHeader

		resp, err = s.httpClient.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("expected get object response status to be %v, instead got %v", http.StatusOK, resp.StatusCode)
		}

		return nil
	})
}

func PresignedAuth_UploadPart(s *S3Conf) error {
	testName := "PresignedAuth_UploadPart"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient, bucket string) error {
		key, partNumber := "my-mp", int32(1)

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

		return nil
	})
}

// PresignedAuth_PutObject_strips_aws_chunked_content_encoding checks that
// aws-chunked is dropped from the stored Content-Encoding on a presigned PUT.
func PresignedAuth_PutObject_strips_aws_chunked_content_encoding(s *S3Conf) error {
	testName := "PresignedAuth_PutObject_strips_aws_chunked_content_encoding"
	return presignedAuthHandler(s, testName, func(client *s3.PresignClient, bucket string) error {
		s3client := s.GetClient()
		for i, test := range []struct {
			contentEncoding string
			stored          string
		}{
			// nothing is left, so no Content-Encoding is stored at all
			{"aws-chunked", ""},
			{"aws-chunked,gzip", "gzip"},
			// the remaining codings keep their order
			{"gzip,aws-chunked,br", "gzip,br"},
			{"AWS-Chunked", ""},
			// the token has to match in full
			{"aws-chunked-custom", "aws-chunked-custom"},
			{"gzip", "gzip"},
		} {
			object := fmt.Sprintf("presigned-obj-%v", i)

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			v4req, err := client.PresignPutObject(ctx, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &object,
			})
			cancel()
			if err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}

			req, err := http.NewRequest(v4req.Method, v4req.URL, strings.NewReader("hello world"))
			if err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}
			req.Header.Set("Content-Encoding", test.contentEncoding)

			resp, err := s.httpClient.Do(req)
			if err != nil {
				return fmt.Errorf("test %v failed to send the request: %w", i+1, err)
			}
			resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("test %v: expected the response status code to be %v, instead got %v",
					i+1, http.StatusOK, resp.StatusCode)
			}

			stored, err := getStoredContentEncoding(s3client, bucket, object)
			if err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}
			if stored != test.stored {
				return fmt.Errorf("test %v: expected the stored content encoding to be %q, instead got %q",
					i+1, test.stored, stored)
			}
		}

		return nil
	})
}

// PresignedAuth_CopyObject_strips_aws_chunked_content_encoding checks that
// aws-chunked is dropped from the stored Content-Encoding on a presigned copy.
func PresignedAuth_CopyObject_strips_aws_chunked_content_encoding(s *S3Conf) error {
	testName := "PresignedAuth_CopyObject_strips_aws_chunked_content_encoding"
	return presignedAuthHandler(s, testName, func(_ *s3.PresignClient, bucket string) error {
		s3client := s.GetClient()
		srcObj := "copy-source"

		// the source carries a coding of its own, so a stored value can only
		// have come from the copy request
		_, err := putObjectWithData(int64(len("hello world")), &s3.PutObjectInput{
			Bucket:          &bucket,
			Key:             &srcObj,
			ContentEncoding: getPtr("br"),
		}, s3client)
		if err != nil {
			return err
		}

		for i, test := range []struct {
			contentEncoding string
			stored          string
		}{
			{"aws-chunked", ""},
			{"aws-chunked,gzip", "gzip"},
			{"gzip,aws-chunked,br", "gzip,br"},
			{"AWS-Chunked", ""},
			// the token has to match in full
			{"aws-chunked-custom", "aws-chunked-custom"},
			{"gzip", "gzip"},
		} {
			object := fmt.Sprintf("copy-dst-%v", i)

			req, err := createPresignedReq(http.MethodPut, s.endpoint,
				fmt.Sprintf("%s/%s", bucket, object), s.awsID, s.awsSecret, s.awsRegion, time.Now(),
				map[string]string{
					"X-Amz-Copy-Source":        fmt.Sprintf("/%s/%s", bucket, srcObj),
					"X-Amz-Metadata-Directive": string(types.MetadataDirectiveReplace),
					"Content-Encoding":         test.contentEncoding,
				})
			if err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}

			resp, err := s.httpClient.Do(req)
			if err != nil {
				return fmt.Errorf("test %v failed to send the request: %w", i+1, err)
			}
			resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("test %v: expected the response status code to be %v, instead got %v",
					i+1, http.StatusOK, resp.StatusCode)
			}

			stored, err := getStoredContentEncoding(s3client, bucket, object)
			if err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}
			if stored != test.stored {
				return fmt.Errorf("test %v: expected the stored content encoding to be %q, instead got %q",
					i+1, test.stored, stored)
			}
		}

		return nil
	})
}

// PresignedAuth_CreateMultipartUpload_strips_aws_chunked_content_encoding checks
// that aws-chunked is dropped from the Content-Encoding a presigned
// CreateMultipartUpload stores for the completed object.
func PresignedAuth_CreateMultipartUpload_strips_aws_chunked_content_encoding(s *S3Conf) error {
	testName := "PresignedAuth_CreateMultipartUpload_strips_aws_chunked_content_encoding"
	return presignedAuthHandler(s, testName, func(_ *s3.PresignClient, bucket string) error {
		s3client := s.GetClient()
		for i, test := range []struct {
			contentEncoding string
			stored          string
		}{
			{"aws-chunked", ""},
			{"aws-chunked,gzip", "gzip"},
			{"gzip,aws-chunked,br", "gzip,br"},
			{"AWS-Chunked", ""},
			// the token has to match in full
			{"aws-chunked-custom", "aws-chunked-custom"},
			{"gzip", "gzip"},
		} {
			object := fmt.Sprintf("mp-obj-%v", i)

			req, err := createPresignedReq(http.MethodPost, s.endpoint,
				fmt.Sprintf("%s/%s?uploads=", bucket, object),
				s.awsID, s.awsSecret, s.awsRegion, time.Now(),
				map[string]string{"Content-Encoding": test.contentEncoding})
			if err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}

			resp, err := s.httpClient.Do(req)
			if err != nil {
				return fmt.Errorf("test %v failed to send the request: %w", i+1, err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return fmt.Errorf("test %v failed to read the response body: %w", i+1, err)
			}
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("test %v: expected the response status code to be %v, instead got %v",
					i+1, http.StatusOK, resp.StatusCode)
			}

			var out s3response.InitiateMultipartUploadResult
			if err := xml.Unmarshal(body, &out); err != nil {
				return fmt.Errorf("test %v failed to parse the response body: %w", i+1, err)
			}

			// the parts carry no Content-Encoding: the completed object can
			// only inherit what the create named
			parts, _, err := uploadParts(s3client, 5*1024*1024, 1, bucket, object, out.UploadId)
			if err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}

			compParts := []types.CompletedPart{}
			for _, el := range parts {
				compParts = append(compParts, types.CompletedPart{
					ETag:       el.ETag,
					PartNumber: el.PartNumber,
				})
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
				Bucket:          &bucket,
				Key:             &object,
				UploadId:        &out.UploadId,
				MultipartUpload: &types.CompletedMultipartUpload{Parts: compParts},
			})
			cancel()
			if err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}

			stored, err := getStoredContentEncoding(s3client, bucket, object)
			if err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}
			if stored != test.stored {
				return fmt.Errorf("test %v: expected the stored content encoding to be %q, instead got %q",
					i+1, test.stored, stored)
			}
		}

		return nil
	})
}
