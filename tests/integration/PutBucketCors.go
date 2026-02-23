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

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

func PutBucketCors_non_existing_bucket(s *S3Conf) error {
	testName := "PutBucketCors_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketCors(s3client, &s3.PutBucketCorsInput{
			Bucket: getPtr("non-existing-bucket"),
			CORSConfiguration: &types.CORSConfiguration{
				CORSRules: []types.CORSRule{
					{
						AllowedOrigins: []string{"http://origin.com"},
						AllowedMethods: []string{http.MethodGet},
					},
				},
			},
		})
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket))
	})
}

func PutBucketCors_empty_cors_rules(s *S3Conf) error {
	testName := "PutBucketCors_empty_cors_rules"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketCors(s3client, &s3.PutBucketCorsInput{
			Bucket: &bucket,
			CORSConfiguration: &types.CORSConfiguration{
				CORSRules: []types.CORSRule{},
			},
		})
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrMalformedXML))
	})
}

func PutBucketCors_invalid_allowed_origins(s *S3Conf) error {
	testName := "PutBucketCors_invalid_allowed_origins"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for i, test := range []struct {
			allowedOrigins []string
			expectedErr    s3err.APIError
		}{
			// empty allowed origins
			{[]string{}, s3err.GetAPIError(s3err.ErrMalformedXML)},
			// multiple wildcards
			{[]string{"*example.com*"}, s3err.GetMultipleWildcardCORSOriginErr("*example.com*")},
			{[]string{"http://127.0.0.1:7070", "https://*:7070/*"}, s3err.GetMultipleWildcardCORSOriginErr("https://*:7070/*")},
			{[]string{"a/really/*/long/*/path/*"}, s3err.GetMultipleWildcardCORSOriginErr("a/really/*/long/*/path/*")},
			{[]string{"http://***", "www.example.net"}, s3err.GetMultipleWildcardCORSOriginErr("http://***")},
		} {
			err := putBucketCors(s3client, &s3.PutBucketCorsInput{
				Bucket: &bucket,
				CORSConfiguration: &types.CORSConfiguration{
					CORSRules: []types.CORSRule{
						{
							AllowedOrigins: test.allowedOrigins,
							AllowedMethods: []string{http.MethodPost},
							AllowedHeaders: []string{"x-amz-expected-bucket-owner"},
							ExposeHeaders:  []string{"x-vgw-something"},
						},
					},
				},
			})
			if err := checkApiErr(err, test.expectedErr); err != nil {
				return fmt.Errorf("test %v failed: %w", i+1, err)
			}
		}

		return nil
	})
}

func PutBucketCors_invalid_method(s *S3Conf) error {
	testName := "PutBucketCors_invalid_method"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for _, test := range []struct {
			allowedMethods []string
			expectedErr    s3err.APIError
		}{
			// empty array
			{[]string{}, s3err.GetAPIError(s3err.ErrMalformedXML)},
			// empty method
			{[]string{""}, s3err.GetUnsopportedCORSMethodErr("")},
			// invalid methods
			{[]string{"get"}, s3err.GetUnsopportedCORSMethodErr("get")},
			{[]string{"put"}, s3err.GetUnsopportedCORSMethodErr("put")},
			{[]string{"post"}, s3err.GetUnsopportedCORSMethodErr("post")},
			{[]string{"head"}, s3err.GetUnsopportedCORSMethodErr("head")},
			{[]string{"delete"}, s3err.GetUnsopportedCORSMethodErr("delete")},
			{[]string{http.MethodGet, http.MethodPatch}, s3err.GetUnsopportedCORSMethodErr(http.MethodPatch)},
			{[]string{http.MethodPost, http.MethodOptions}, s3err.GetUnsopportedCORSMethodErr(http.MethodOptions)},
			{[]string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete, "invalid_method"}, s3err.GetUnsopportedCORSMethodErr("invalid_method")},
		} {
			err := putBucketCors(s3client, &s3.PutBucketCorsInput{
				Bucket: &bucket,
				CORSConfiguration: &types.CORSConfiguration{
					CORSRules: []types.CORSRule{
						{
							AllowedOrigins: []string{"http://origin.com"},
							AllowedMethods: test.allowedMethods,
							AllowedHeaders: []string{"X-Amz-Date"},
							ExposeHeaders:  []string{"Authorization"},
						},
					},
				},
			})

			if err := checkApiErr(err, test.expectedErr); err != nil {
				return err
			}
		}

		return nil
	})
}

func PutBucketCors_invalid_header(s *S3Conf) error {
	testName := "PutBucketCors_invalid_header"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for _, test := range []struct {
			invalidHeader string
			headers       []string
		}{
			{"invalid header", []string{"X-Amz-Date", "X-Amz-Content-Sha256", "invalid header"}},
			{"X-Custom:Header", []string{"Authorization", "X-Custom:Header"}},
			{"X(Custom)", []string{"Content-Length", "X(Custom)"}},
			{"Bad/Header", []string{"Content-Encoding", "Bad/Header"}},
			{"X[Key]", []string{"Date", "X[Key]"}},
			{"Bad=Name", []string{"X-Amz-Custome-Header", "Bad=Name"}},
			{`X"Quote"`, []string{`X"Quote"`}},
		} {
			// first check for allowed headers
			cfg := &types.CORSConfiguration{
				CORSRules: []types.CORSRule{
					{
						AllowedOrigins: []string{"http://origin.com"},
						AllowedMethods: []string{http.MethodPost},
						AllowedHeaders: test.headers,
						ExposeHeaders:  []string{"Authorization"},
					},
				},
			}

			err := putBucketCors(s3client, &s3.PutBucketCorsInput{
				Bucket:            &bucket,
				CORSConfiguration: cfg,
			})
			if err := checkApiErr(err, s3err.GetInvalidCORSHeaderErr(test.invalidHeader)); err != nil {
				return err
			}

			// second check for expose headers
			cfg.CORSRules[0].AllowedHeaders = []string{"X-Amz-Date"} // set to any valid header
			cfg.CORSRules[0].ExposeHeaders = test.headers

			err = putBucketCors(s3client, &s3.PutBucketCorsInput{
				Bucket:            &bucket,
				CORSConfiguration: cfg,
			})
			if err := checkApiErr(err, s3err.GetInvalidCORSHeaderErr(test.invalidHeader)); err != nil {
				return err
			}
		}

		return nil
	})
}

func PutBucketCors_md5(s *S3Conf) error {
	testName := "PutBucketCors_md5"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		cfg := &types.CORSConfiguration{
			CORSRules: []types.CORSRule{
				{
					AllowedOrigins: []string{"http://origin.com", "something.net"},
					AllowedMethods: []string{http.MethodPost, http.MethodPut, http.MethodHead},
					AllowedHeaders: []string{"X-Amz-Date", "X-Amz-Meta-Something", "Content-Type"},
					ExposeHeaders:  []string{"Authorization", "Content-Disposition"},
					MaxAgeSeconds:  getPtr(int32(125)),
					ID:             getPtr("my-id"),
				},
			},
		}

		for i, test := range []struct {
			md5 string
			err error
		}{
			// invalid content-md5
			{"invalid", s3err.GetAPIError(s3err.ErrInvalidDigest)},
			// incorrect content-md5
			{"uU0nuZNNPgilLlLX2n2r+s==", s3err.GetAPIError(s3err.ErrBadDigest)},
			// correct content-md5
			{"liZChnDYdpG46exsGGaBhg==", nil},
		} {
			err := putBucketCors(s3client, &s3.PutBucketCorsInput{
				Bucket:            &bucket,
				CORSConfiguration: cfg,
				ContentMD5:        &test.md5,
			})
			if test.err == nil && err != nil {
				return fmt.Errorf("test %v failed: expected no error but got %v", i+1, err)
			}
			if test.err != nil {
				apiErr, ok := test.err.(s3err.APIError)
				if !ok {
					return fmt.Errorf("test %v failed: expected s3err.APIError", i+1)
				}

				if err := checkApiErr(err, apiErr); err != nil {
					return fmt.Errorf("test %v failed: %v", i+1, err)
				}
			}
		}

		return nil
	})
}

func PutBucketCors_success(s *S3Conf) error {
	testName := "PutBucketCors_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		maxAgePositive, maxAgeNegative := int32(3000), int32(-100)
		return putBucketCors(s3client, &s3.PutBucketCorsInput{
			Bucket: &bucket,
			CORSConfiguration: &types.CORSConfiguration{
				CORSRules: []types.CORSRule{
					{
						AllowedOrigins: []string{"http://origin.com"},
						AllowedMethods: []string{http.MethodPost, http.MethodPut},
						AllowedHeaders: []string{"X-Amz-Date"},
						ExposeHeaders:  []string{"Authorization"},
						// weirdely negative max age seconds are also considered valid
						MaxAgeSeconds: &maxAgeNegative,
					},
					{
						AllowedOrigins: []string{"*"},
						AllowedMethods: []string{http.MethodDelete, http.MethodGet, http.MethodHead},
						AllowedHeaders: []string{"Content-Type", "Content-Encoding", "Content-MD5"},
						ExposeHeaders:  []string{"Authorization", "X-Amz-Date", "X-Amz-Conten-Sha256"},
						ID:             getPtr("id"),
						MaxAgeSeconds:  &maxAgePositive,
					},
					{
						AllowedOrigins: []string{"http://example.com", "https://something.net", "http://*origin.com"},
						AllowedMethods: []string{http.MethodGet},
					},
				},
			},
		})
	})
}
