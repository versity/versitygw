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
	"net/http"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

func PreflightOPTIONS_non_existing_bucket(s *S3Conf) error {
	testName := "PreflightOPTIONS_non_existing_bucket"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		res, err := makeOPTIONSRequest(s, "non-existing-bucket", "http://localhost:7070", http.MethodPost, "X-Amz-Date")
		if err != nil {
			return err
		}
		return checkApiErr(res.err, s3err.GetAPIError(s3err.ErrNoSuchBucket))
	})
}

func PreflightOPTIONS_missing_origin(s *S3Conf) error {
	testName := "PreflightOPTIONS_missing_origin"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		res, err := makeOPTIONSRequest(s, bucket, "", http.MethodGet, "X-Custom-Header")
		if err != nil {
			return err
		}
		return checkApiErr(res.err, s3err.GetAPIError(s3err.ErrMissingCORSOrigin))
	})
}

func PreflightOPTIONS_invalid_request_method(s *S3Conf) error {
	testName := "PreflightOPTIONS_invalid_request_method"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for _, method := range []string{
			// should be case sensitive, all with capital letters
			"get", "Get", "GEt", "geT",
			"post", "Post", "POSt", "posT",
			"put", "Put", "pUt", "puT",
			"head", "Head", "HEAd", "heAD",
			// unsupported methods
			"PATCH", "CONNECT", "OPTIONS",
			// nonsense strings
			"something", "invalid_method", "method",
		} {
			res, err := makeOPTIONSRequest(s, bucket, "www.my-origin.com", method, "X-Custom-Header")
			if err != nil {
				return err
			}
			if err := checkApiErr(res.err, s3err.GetInvalidCORSMethodErr(method)); err != nil {
				return err
			}
		}

		return nil
	})
}

func PreflightOPTIONS_invalid_request_headers(s *S3Conf) error {
	testName := "PreflightOPTIONS_invalid_request_headers"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for _, test := range []struct {
			invalidHeader string
			headers       string
		}{
			{"invalid header", "X-Amz-Date,X-Amz-Content-Sha256,invalid header"}, // invalid 'space' in header name
			{"X-Custom:Header", "Authorization,X-Custom:Header"},                 // invalid char :
			{"X(Custom)", "Content-Length,X(Custom)"},                            // invalid char ()
			{" Bad/Header", "Content-Encoding, Bad/Header"},                      // extra 'space', invalid char /
			{"X[Key]", "Date,X[Key]"},                                            // invalid char '[]'
			{"Bad=Name", "X-Amz-Custome-Header,Bad=Name"},                        // invalid char =
			{`X"Quote"`, `X"Quote"`},                                             // invalid quote "
			{"NonAsciiŁ", "Content-Length,NonAsciiŁ"},                            // non-ASCII character
			{"Emoji😀", "X-Emoji,Emoji😀"},                                         // emoji invalid
			{"bad@char", "Accept-Encoding,bad@char"},                             // @ is invalid
			{"tab\tchar", "tab\tchar,X-Something-Valid"},                         // invalid encodign \t
		} {
			res, err := makeOPTIONSRequest(s, bucket, "www.my-origin.com", http.MethodGet, test.headers)
			if err != nil {
				return err
			}
			if err := checkApiErr(res.err, s3err.GetInvalidCORSRequestHeaderErr(test.invalidHeader)); err != nil {
				return err
			}
		}
		return nil
	})
}

func PreflightOPTIONS_unset_bucket_cors(s *S3Conf) error {
	testName := "PreflightOPTIONS_unset_bucket_cors"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		res, err := makeOPTIONSRequest(s, bucket, "http://example.com", http.MethodPost, "X-Amz-Date,Date")
		if err != nil {
			return err
		}
		return checkApiErr(res.err, s3err.GetAPIError(s3err.ErrCORSIsNotEnabled))
	})
}

func PreflightOPTIONS_access_forbidden(s *S3Conf) error {
	testName := "PreflightOPTIONS_access_forbidden"
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
					{
						AllowedOrigins: []string{"http://origin*"},
						AllowedMethods: []string{http.MethodPost},
						AllowedHeaders: []string{"Authorization"},
					},
					{
						AllowedOrigins: []string{"http://something.com"},
						AllowedMethods: []string{http.MethodPut},
						AllowedHeaders: []string{"X-Amz-*"},
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
			// third rule: headers doesn't match
			{"https://origin.com", http.MethodPost, "Content-Length"},
			// third rule: extra header
			{"https://origin.com", http.MethodPost, "Authorization,Content-Disposition"},
			// third rule: origin doesn't match
			{"https://www.origin.com", http.MethodPost, "Authorization"},
			// forth rule: header doesn't match the wildcard
			{"https://something.com", http.MethodPut, "Authorization"},
			{"https://something.com", http.MethodPut, "X-Amz"},
			{"https://something.com", http.MethodPut, "X-Amz-Date,Content-Length"},
		} {
			res, err := makeOPTIONSRequest(s, bucket, test.origin, test.method, test.headers)
			if err != nil {
				return err
			}

			if err := checkApiErr(res.err, s3err.GetAPIError(s3err.ErrCORSForbidden)); err != nil {
				return err
			}
		}

		return nil
	})
}

func PreflightOPTIONS_access_granted(s *S3Conf) error {
	testName := "PreflightOPTIONS_access_granted"
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
					{
						AllowedOrigins: []string{"http://www*"},
						AllowedMethods: []string{http.MethodGet},
						AllowedHeaders: []string{"x-amz-server-side-encryption"},
						ExposeHeaders:  []string{"X-Amz-Expected-Bucket-Owner"},
						MaxAgeSeconds:  getPtr(int32(5000)),
					},
					{
						AllowedOrigins: []string{"http://uniquie-origin.net"},
						AllowedMethods: []string{http.MethodPost, http.MethodPut},
						AllowedHeaders: []string{"X-Amz-*-Suffix"},
						ExposeHeaders:  []string{"Authorization", "Content-Type"},
						MaxAgeSeconds:  getPtr(int32(2000)),
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
			{"http://example.com", http.MethodGet, "X-Amz-Date", PreflightResult{"http://example.com", "GET, HEAD", "x-amz-date", "Content-Type, Content-Length", "100", "true", varyHdr, nil}},
			{"http://example.com", http.MethodGet, "X-Amz-Content-Sha256", PreflightResult{"http://example.com", "GET, HEAD", "x-amz-content-sha256", "Content-Type, Content-Length", "100", "true", varyHdr, nil}},
			{"http://example.com", http.MethodHead, "", PreflightResult{"http://example.com", "GET, HEAD", "", "Content-Type, Content-Length", "100", "true", varyHdr, nil}},
			{"https://example.com", http.MethodGet, "X-Amz-Date,X-Amz-Content-Sha256", PreflightResult{"https://example.com", "GET, HEAD", "x-amz-date, x-amz-content-sha256", "Content-Type, Content-Length", "100", "true", varyHdr, nil}},
			// second rule matches: origin is a wildcard
			{"http://anything.com", http.MethodHead, "X-Amz-Meta-Something", PreflightResult{"*", "HEAD", "x-amz-meta-something", "", "", "false", varyHdr, nil}},
			{"hello.com", http.MethodHead, "", PreflightResult{"*", "HEAD", "", "", "", "false", varyHdr, nil}},
			// third rule matches
			{"something.net", http.MethodPut, "Authorization", PreflightResult{"something.net", "POST, PUT", "authorization", "Content-Disposition, Content-Encoding", "3000", "true", varyHdr, nil}},
			{"something.net", http.MethodPost, "", PreflightResult{"something.net", "POST, PUT", "", "Content-Disposition, Content-Encoding", "3000", "true", varyHdr, nil}},
			// forth rule matches: origin contains wildcard
			{"http://www.hello.world.com", http.MethodGet, "", PreflightResult{"http://www.hello.world.com", "GET", "", "X-Amz-Expected-Bucket-Owner", "5000", "true", varyHdr, nil}},
			{"http://www.example.com", http.MethodGet, "x-amz-server-side-encryption", PreflightResult{"http://www.example.com", "GET", "x-amz-server-side-encryption", "X-Amz-Expected-Bucket-Owner", "5000", "true", varyHdr, nil}},
			// fifth rule matches: allowed headers contains wildcard
			{"http://uniquie-origin.net", http.MethodPost, "X-Amz-anything-Suffix", PreflightResult{"http://uniquie-origin.net", "POST, PUT", "x-amz-anything-suffix", "Authorization, Content-Type", "2000", "true", varyHdr, nil}},
			{"http://uniquie-origin.net", http.MethodPut, "X-Amz-yyy-xxx-Suffix", PreflightResult{"http://uniquie-origin.net", "POST, PUT", "x-amz-yyy-xxx-suffix", "Authorization, Content-Type", "2000", "true", varyHdr, nil}},
		} {
			err := testOPTIONSEdnpoint(s, bucket, test.origin, test.method, test.headers, &test.result)
			if err != nil {
				return err
			}
		}

		return nil
	})
}
