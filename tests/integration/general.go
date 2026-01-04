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
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

var (
	shortTimeout  = 30 * time.Second
	longTimeout   = 60 * time.Second
	iso8601Format = "20060102T150405Z"
	timefmt       = "Mon, 02 Jan 2006 15:04:05 GMT"
	nullVersionId = "null"
)

// router tests
func RouterPutPartNumberWithoutUploadId(s *S3Conf) error {
	testName := "RouterPutPartNumberWithoutUploadId"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		req, err := http.NewRequest(http.MethodPut, s.endpoint+"/bucket/object", nil)
		if err != nil {
			return err
		}

		query := req.URL.Query()
		query.Add("partNumber", "1")
		req.URL.RawQuery = query.Encode()

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		if err := checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrMissingUploadId)); err != nil {
			return err
		}

		return nil
	})
}

func RouterPostRoot(s *S3Conf) error {
	testName := "RouterPostRoot"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		req, err := http.NewRequest(http.MethodPost, s.endpoint+"/", nil)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		if err := checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrMethodNotAllowed)); err != nil {
			return err
		}

		return nil
	})
}

func RouterPostObjectWithoutQuery(s *S3Conf) error {
	testName := "RouterPostObjectWithoutQuery"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		req, err := http.NewRequest(http.MethodPost, s.endpoint+"/bucket/object", nil)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		if err := checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrMethodNotAllowed)); err != nil {
			return err
		}

		return nil
	})
}

func RouterPUTObjectOnlyUploadId(s *S3Conf) error {
	testName := "RouterPUTObjectOnlyUploadId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		req, err := http.NewRequest(http.MethodPut, s.endpoint+"/bucket/object", nil)
		if err != nil {
			return err
		}

		query := req.URL.Query()
		query.Add("uploadId", "my-upload-id")
		req.URL.RawQuery = query.Encode()

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		if err := checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrMethodNotAllowed)); err != nil {
			return err
		}

		return nil
	})
}

func RouterGetUploadsWithKey(s *S3Conf) error {
	testName := "RouterGetUploadsWithKey"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		req, err := http.NewRequest(http.MethodGet, s.endpoint+"/bucket/object?uploads", nil)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrGetUploadsWithKey))
	})
}

func RouterCopySourceNotAllowed(s *S3Conf) error {
	testName := "RouterCopySourceNotAllowed"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		for _, method := range []string{
			http.MethodPost,
			http.MethodDelete,
			http.MethodGet,
			http.MethodHead,
		} {
			for _, path := range []string{
				"/bucket",
				"/bucket/object",
			} {
				if method == http.MethodPost {
					// the error for POST request occurs only when uploadId is there
					path += "?uploadId=something"
				}

				req, err := http.NewRequest(method, s.endpoint+path, nil)
				if err != nil {
					return fmt.Errorf("failed to make %s request to %s", method, path)
				}

				req.Header.Add("x-amz-copy-source", "bucket/object")

				resp, err := s.httpClient.Do(req)
				if err != nil {
					return fmt.Errorf("failed to send %s request to %s", method, path)
				}

				if method == http.MethodHead {
					// for head requests only check the status code
					if resp.StatusCode != http.StatusBadRequest {
						return fmt.Errorf("expected 400 status code for HEAD %s request, instead got %v", path, resp.StatusCode)
					}
				} else {
					if err := checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrCopySourceNotAllowed)); err != nil {
						return fmt.Errorf("%s %s: %w", method, path, err)
					}
				}
			}
		}

		return nil
	})
}

func RouterListVersionsWithKey(s *S3Conf) error {
	testName := "RouterListVersionsWithKey"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		req, err := http.NewRequest(http.MethodGet, s.endpoint+"/bucket/object?versions", nil)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrVersionsWithKey))
	})
}

// CORS middleware tests
func CORSMiddleware_invalid_method(s *S3Conf) error {
	testName := "CORSMiddleware_invalid_method"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketCors(s3client, &s3.PutBucketCorsInput{
			Bucket: &bucket,
			CORSConfiguration: &types.CORSConfiguration{
				CORSRules: []types.CORSRule{
					{
						AllowedOrigins: []string{"http://www.example.com"},
						AllowedMethods: []string{http.MethodPut},
					},
				},
			},
		})
		if err != nil {
			return err
		}

		// create a PutObject signed request
		req, err := createSignedReq(http.MethodPut, s.endpoint, bucket+"/my-obj", s.awsID, s.awsSecret, "s3", s.awsRegion, nil, time.Now(), map[string]string{
			"Origin":                        "http://www.example.com",
			"Access-Control-Request-Method": "invalid_method",
		})
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		result, err := extractCORSHeaders(resp)
		if err != nil {
			return err
		}

		return checkApiErr(result.err, s3err.GetInvalidCORSMethodErr("invalid_method"))
	})
}

func CORSMiddleware_invalid_headers(s *S3Conf) error {
	testName := "CORSMiddleware_invalid_headers"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketCors(s3client, &s3.PutBucketCorsInput{
			Bucket: &bucket,
			CORSConfiguration: &types.CORSConfiguration{
				CORSRules: []types.CORSRule{
					{
						AllowedOrigins: []string{"http://www.example.com"},
						AllowedMethods: []string{http.MethodPut},
					},
				},
			},
		})
		if err != nil {
			return err
		}

		// create a PutObject signed request
		req, err := createSignedReq(http.MethodPut, s.endpoint, bucket+"/my-obj", s.awsID, s.awsSecret, "s3", s.awsRegion, nil, time.Now(), map[string]string{
			"Origin":                         "http://www.example.com",
			"Access-Control-Request-Headers": "invalid header",
		})
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		result, err := extractCORSHeaders(resp)
		if err != nil {
			return err
		}

		return checkApiErr(result.err, s3err.GetInvalidCORSRequestHeaderErr("invalid header"))
	})
}

func CORSMiddleware_access_forbidden(s *S3Conf) error {
	testName := "CORSMiddleware_access_forbidden"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketCors(s3client, &s3.PutBucketCorsInput{
			Bucket: &bucket,
			CORSConfiguration: &types.CORSConfiguration{
				CORSRules: []types.CORSRule{
					{
						AllowedOrigins: []string{"http://example.com", "https://example.com"},
						AllowedMethods: []string{http.MethodGet},
						AllowedHeaders: []string{"X-Amz-Date", "X-Amz-Content-Sha256"},
					},
					{
						AllowedOrigins: []string{"*"},
						AllowedMethods: []string{http.MethodHead},
					},
				},
			},
		})
		if err != nil {
			return err
		}

		for _, test := range []struct {
			origin  string
			method  string
			headers string
		}{
			// origin deson't match
			{"http://non-matching-origin.net", http.MethodGet, "X-Amz-Date"},
			// method doesn't match
			{"http://example.com", http.MethodPut, "X-Amz-Content-Sha256"},
			// header doesn't match
			{"http://example.com", http.MethodGet, "X-Amz-Expected-Bucket-Owner"},
			// extra header
			{"http://example.com", http.MethodGet, "X-Amz-Date,X-Amz-Content-Sha256,Extra-Header"},
			// extra header (2nd rule)
			{"https://any-origin.com", http.MethodHead, "X-Amz-Extra-Header"},
			// origin match, method not (2nd rule)
			{"https://any-origin.com", http.MethodPost, ""},
		} {
			req, err := createSignedReq(http.MethodPut, s.endpoint, bucket+"/my-obj", s.awsID, s.awsSecret, "s3", s.awsRegion, nil, time.Now(), map[string]string{
				"Origin":                         test.origin,
				"Access-Control-Request-Headers": test.headers,
				"Access-Control-Request-Method":  test.method,
			})
			if err != nil {
				return err
			}

			resp, err := s.httpClient.Do(req)
			if err != nil {
				return err
			}

			res, err := extractCORSHeaders(resp)
			if err != nil {
				return err
			}

			// no error expected, all the headers should be empty
			if err := comparePreflightResult(&PreflightResult{}, res); err != nil {
				return err
			}
		}

		return nil
	})
}

func CORSMiddleware_access_granted(s *S3Conf) error {
	testName := "CORSMiddleware_access_granted"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketCors(s3client, &s3.PutBucketCorsInput{
			Bucket: &bucket,
			CORSConfiguration: &types.CORSConfiguration{
				CORSRules: []types.CORSRule{
					{
						AllowedOrigins: []string{"http://example.com", "https://example.com"},
						AllowedMethods: []string{http.MethodGet, http.MethodHead},
						AllowedHeaders: []string{"X-Amz-Date", "X-Amz-Content-Sha256"},
						ExposeHeaders:  []string{"Content-Type", "Content-Length"},
						MaxAgeSeconds:  getPtr(int32(100)),
					},
					{
						AllowedOrigins: []string{"*"},
						AllowedMethods: []string{http.MethodHead},
						AllowedHeaders: []string{"X-Amz-Meta-Something"},
					},
					{
						AllowedOrigins: []string{"something.net"},
						AllowedMethods: []string{http.MethodPost, http.MethodPut},
						AllowedHeaders: []string{"Authorization"},
						ExposeHeaders:  []string{"Content-Disposition", "Content-Encoding"},
						MaxAgeSeconds:  getPtr(int32(3000)),
						ID:             getPtr("unique_id"),
					},
				},
			},
		})
		if err != nil {
			return err
		}

		varyHdr := "Origin, Access-Control-Request-Headers, Access-Control-Request-Method"

		for _, test := range []struct {
			origin  string
			method  string
			headers string
			result  PreflightResult
		}{
			// first rule matches
			{"http://example.com", http.MethodGet, "X-Amz-Date", PreflightResult{"http://example.com", "GET, HEAD", "x-amz-date, x-amz-content-sha256", "Content-Type, Content-Length", "100", "true", varyHdr, nil}},
			{"http://example.com", http.MethodGet, "X-Amz-Content-Sha256", PreflightResult{"http://example.com", "GET, HEAD", "x-amz-date, x-amz-content-sha256", "Content-Type, Content-Length", "100", "true", varyHdr, nil}},
			{"http://example.com", http.MethodHead, "", PreflightResult{"http://example.com", "GET, HEAD", "", "Content-Type, Content-Length", "100", "true", varyHdr, nil}},
			{"https://example.com", http.MethodGet, "X-Amz-Date,X-Amz-Content-Sha256", PreflightResult{"https://example.com", "GET, HEAD", "x-amz-date, x-amz-content-sha256", "Content-Type, Content-Length", "100", "true", varyHdr, nil}},
			// second rule matches
			{"http://anything.com", http.MethodHead, "X-Amz-Meta-Something", PreflightResult{"*", "HEAD", "x-amz-meta-something", "", "", "false", varyHdr, nil}},
			{"hello.com", http.MethodHead, "", PreflightResult{"*", "HEAD", "", "", "", "false", varyHdr, nil}},
			// third rule matches
			{"something.net", http.MethodPut, "Authorization", PreflightResult{"something.net", "POST, PUT", "authorization", "Content-Disposition, Content-Encoding", "3000", "true", varyHdr, nil}},
			{"something.net", http.MethodPost, "", PreflightResult{"something.net", "POST, PUT", "", "Content-Disposition, Content-Encoding", "3000", "true", varyHdr, nil}},
		} {
			req, err := createSignedReq(http.MethodPut, s.endpoint, bucket+"/my-obj", s.awsID, s.awsSecret, "s3", s.awsRegion, nil, time.Now(), map[string]string{
				"Origin":                         test.origin,
				"Access-Control-Request-Headers": test.headers,
				"Access-Control-Request-Method":  test.method,
			})
			if err != nil {
				return err
			}

			resp, err := s.httpClient.Do(req)
			if err != nil {
				return err
			}

			res, err := extractCORSHeaders(resp)
			if err != nil {
				return err
			}

			if err := comparePreflightResult(&test.result, res); err != nil {
				return err
			}
		}

		return nil
	})
}
