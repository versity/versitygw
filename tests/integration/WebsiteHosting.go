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
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

// WebsiteHosting_error_document_served tests that a missing website object
// serves the configured error document while preserving the original 404 status.
func WebsiteHosting_error_document_served(s *S3Conf) error {
	testName := "WebsiteHosting_error_document_served"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketWebsiteConfig(s3client, bucket, &types.WebsiteConfiguration{
			IndexDocument: &types.IndexDocument{
				Suffix: getPtr("index.html"),
			},
			ErrorDocument: &types.ErrorDocument{
				Key: getPtr("error.html"),
			},
		})
		if err != nil {
			return err
		}
		if err := grantPublicBucketPolicy(s3client, bucket, policyTypeObject); err != nil {
			return err
		}

		errorContent := "<html><body>Custom Error Page</body></html>"
		_, err = putObjectWithData(int64(len(errorContent)), &s3.PutObjectInput{
			Bucket:      &bucket,
			Key:         getPtr("error.html"),
			Body:        strings.NewReader(errorContent),
			ContentType: getPtr("text/html"),
		}, s3client)
		if err != nil {
			return err
		}

		resp, err := websiteGet(s, bucket, "nonexistent-key", nil)
		if err != nil {
			return err
		}

		if got := resp.Header.Get("Content-Type"); got != "text/html" {
			return fmt.Errorf("expected text/html Content-Type, got %q", got)
		}
		return checkWebsiteResponse(resp, http.StatusNotFound, []byte(errorContent))
	})
}

// WebsiteHosting_error_document_not_found tests that a missing configured
// error document returns the complete website NoSuchKey error response.
func WebsiteHosting_error_document_not_found(s *S3Conf) error {
	testName := "WebsiteHosting_error_document_not_found"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketWebsiteConfig(s3client, bucket, &types.WebsiteConfiguration{
			IndexDocument: &types.IndexDocument{
				Suffix: getPtr("index.html"),
			},
			ErrorDocument: &types.ErrorDocument{
				Key: getPtr("error.html"),
			},
		})
		if err != nil {
			return err
		}
		if err := grantPublicBucketPolicy(s3client, bucket, policyTypeObject); err != nil {
			return err
		}

		resp, err := websiteGet(s, bucket, "nonexistent-key", nil)
		if err != nil {
			return err
		}

		return checkWebsiteErrorResponse(resp, s3err.GetAPIError(s3err.ErrNoSuchKey))
	})
}

// WebsiteHosting_no_error_document tests that a website bucket without an
// error document returns the complete website NoSuchKey error response.
func WebsiteHosting_no_error_document(s *S3Conf) error {
	testName := "WebsiteHosting_no_error_document"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketWebsiteConfig(s3client, bucket, &types.WebsiteConfiguration{
			IndexDocument: &types.IndexDocument{
				Suffix: getPtr("index.html"),
			},
		})
		if err != nil {
			return err
		}
		if err := grantPublicBucketPolicy(s3client, bucket, policyTypeObject); err != nil {
			return err
		}

		resp, err := websiteGet(s, bucket, "nonexistent-key", nil)
		if err != nil {
			return err
		}

		return checkWebsiteErrorResponse(resp, s3err.GetAPIError(s3err.ErrNoSuchKey))
	})
}

// WebsiteHosting_private_object_and_error_document tests that website hosting
// does not serve either the requested object or the configured error document
// unless public object access has been granted.
func WebsiteHosting_private_object_and_error_document(s *S3Conf) error {
	testName := "WebsiteHosting_private_object_and_error_document"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketWebsiteConfig(s3client, bucket, &types.WebsiteConfiguration{
			IndexDocument: &types.IndexDocument{
				Suffix: getPtr("index.html"),
			},
			ErrorDocument: &types.ErrorDocument{
				Key: getPtr("error.html"),
			},
		})
		if err != nil {
			return err
		}
		privateError := "private error"
		_, err = putObjectWithData(int64(len(privateError)), &s3.PutObjectInput{
			Bucket:      &bucket,
			Key:         getPtr("error.html"),
			Body:        strings.NewReader(privateError),
			ContentType: getPtr("text/html"),
		}, s3client)
		if err != nil {
			return err
		}

		resp, err := websiteGet(s, bucket, "private.html", nil)
		if err != nil {
			return err
		}

		return checkWebsiteErrorResponse(resp, s3err.GetAPIError(s3err.ErrAccessDenied))
	})
}

// WebsiteHosting_routing_rule_post_request_redirect tests that a post-request
// routing rule matching a 404 issues a redirect instead of serving an error.
func WebsiteHosting_routing_rule_post_request_redirect(s *S3Conf) error {
	testName := "WebsiteHosting_routing_rule_post_request_redirect"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketWebsiteConfig(s3client, bucket, &types.WebsiteConfiguration{
			IndexDocument: &types.IndexDocument{
				Suffix: getPtr("index.html"),
			},
			ErrorDocument: &types.ErrorDocument{
				Key: getPtr("error.html"),
			},
			RoutingRules: []types.RoutingRule{
				{
					Condition: &types.Condition{
						HttpErrorCodeReturnedEquals: getPtr("404"),
					},
					Redirect: &types.Redirect{
						HostName:         getPtr("fallback.example.com"),
						ReplaceKeyWith:   getPtr("not-found"),
						HttpRedirectCode: getPtr("302"),
					},
				},
			},
		})
		if err != nil {
			return err
		}
		if err := grantPublicBucketPolicy(s3client, bucket, policyTypeObject); err != nil {
			return err
		}

		resp, err := websiteGet(s, bucket, "missing-page", nil)
		if err != nil {
			return err
		}

		wantLocation, err := websiteAbsoluteURL(s, "fallback.example.com", "not-found")
		if err != nil {
			return err
		}
		if got := resp.Header.Get("Location"); got != wantLocation {
			return fmt.Errorf("expected Location %q, got %q", wantLocation, got)
		}
		return checkWebsiteResponse(resp, http.StatusFound, []byte(http.StatusText(http.StatusFound)))
	})
}

// WebsiteHosting_routing_rule_pre_request_redirect tests that a key-prefix
// routing rule redirects before public access or object existence is checked.
func WebsiteHosting_routing_rule_pre_request_redirect(s *S3Conf) error {
	testName := "WebsiteHosting_routing_rule_pre_request_redirect"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketWebsiteConfig(s3client, bucket, &types.WebsiteConfiguration{
			IndexDocument: &types.IndexDocument{
				Suffix: getPtr("index.html"),
			},
			RoutingRules: []types.RoutingRule{
				{
					Condition: &types.Condition{
						KeyPrefixEquals: getPtr("old-docs/"),
					},
					Redirect: &types.Redirect{
						ReplaceKeyPrefixWith: getPtr("new-docs/"),
						HttpRedirectCode:     getPtr("301"),
					},
				},
			},
		})
		if err != nil {
			return err
		}

		resp, err := websiteGet(s, bucket, "old-docs/page.html", nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		wantLocation, err := websiteURL(s, bucket, "new-docs/page.html")
		if err != nil {
			return err
		}
		if got := resp.Header.Get("Location"); got != wantLocation {
			return fmt.Errorf("expected Location %q, got %q", wantLocation, got)
		}
		return checkWebsiteResponse(resp, http.StatusMovedPermanently, []byte(http.StatusText(http.StatusMovedPermanently)))
	})
}

// WebsiteHosting_routing_rule_prefix_and_error_redirect tests a routing rule
// with both KeyPrefixEquals and HttpErrorCodeReturnedEquals conditions.
func WebsiteHosting_routing_rule_prefix_and_error_redirect(s *S3Conf) error {
	testName := "WebsiteHosting_routing_rule_prefix_and_error_redirect"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketWebsiteConfig(s3client, bucket, &types.WebsiteConfiguration{
			IndexDocument: &types.IndexDocument{
				Suffix: getPtr("index.html"),
			},
			ErrorDocument: &types.ErrorDocument{
				Key: getPtr("error.html"),
			},
			RoutingRules: []types.RoutingRule{
				{
					Condition: &types.Condition{
						KeyPrefixEquals:             getPtr("old/"),
						HttpErrorCodeReturnedEquals: getPtr("404"),
					},
					Redirect: &types.Redirect{
						ReplaceKeyPrefixWith: getPtr("archived/"),
						HttpRedirectCode:     getPtr("307"),
					},
				},
			},
		})
		if err != nil {
			return err
		}
		if err := grantPublicBucketPolicy(s3client, bucket, policyTypeObject); err != nil {
			return err
		}

		resp, err := websiteGet(s, bucket, "old/missing.html?ref=1", nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		wantLocation, err := websiteURL(s, bucket, "archived/missing.html?ref=1")
		if err != nil {
			return err
		}
		if got := resp.Header.Get("Location"); got != wantLocation {
			return fmt.Errorf("expected Location %q, got %q", wantLocation, got)
		}
		return checkWebsiteResponse(resp, http.StatusTemporaryRedirect, []byte(http.StatusText(http.StatusTemporaryRedirect)))
	})
}

// WebsiteHosting_routing_rule_no_match_serves_error_document tests that routing
// rules which do not match fall back to the configured error document.
func WebsiteHosting_routing_rule_no_match_serves_error_document(s *S3Conf) error {
	testName := "WebsiteHosting_routing_rule_no_match_serves_error_document"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketWebsiteConfig(s3client, bucket, &types.WebsiteConfiguration{
			IndexDocument: &types.IndexDocument{
				Suffix: getPtr("index.html"),
			},
			ErrorDocument: &types.ErrorDocument{
				Key: getPtr("error.html"),
			},
			RoutingRules: []types.RoutingRule{
				{
					Condition: &types.Condition{
						KeyPrefixEquals:             getPtr("docs/"),
						HttpErrorCodeReturnedEquals: getPtr("404"),
					},
					Redirect: &types.Redirect{
						ReplaceKeyPrefixWith: getPtr("archive/"),
					},
				},
			},
		})
		if err != nil {
			return err
		}
		if err := grantPublicBucketPolicy(s3client, bucket, policyTypeObject); err != nil {
			return err
		}
		errorContent := "<html><body>fallback error</body></html>"
		_, err = putObjectWithData(int64(len(errorContent)), &s3.PutObjectInput{
			Bucket:      &bucket,
			Key:         getPtr("error.html"),
			Body:        strings.NewReader(errorContent),
			ContentType: getPtr("text/html"),
		}, s3client)
		if err != nil {
			return err
		}

		resp, err := websiteGet(s, bucket, "images/missing.png", nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		return checkWebsiteResponse(resp, http.StatusNotFound, []byte(errorContent))
	})
}

// WebsiteHosting_redirect_all_requests tests RedirectAllRequestsTo, including
// path and query preservation, without requiring public object access.
func WebsiteHosting_redirect_all_requests(s *S3Conf) error {
	testName := "WebsiteHosting_redirect_all_requests"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketWebsiteConfig(s3client, bucket, &types.WebsiteConfiguration{
			RedirectAllRequestsTo: &types.RedirectAllRequestsTo{
				HostName: getPtr("www.example.com"),
				Protocol: types.ProtocolHttps,
			},
		})
		if err != nil {
			return err
		}

		resp, err := websiteGet(s, bucket, "any/path/here?tracking=1", nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if got, want := resp.Header.Get("Location"), "https://www.example.com/any/path/here?tracking=1"; got != want {
			return fmt.Errorf("expected Location %q, got %q", want, got)
		}
		return checkWebsiteResponse(resp, http.StatusMovedPermanently, []byte(http.StatusText(http.StatusMovedPermanently)))
	})
}

// WebsiteHosting_index_document tests root and directory-style index document
// resolution through the website endpoint.
func WebsiteHosting_index_document(s *S3Conf) error {
	testName := "WebsiteHosting_index_document"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketWebsiteConfig(s3client, bucket, &types.WebsiteConfiguration{
			IndexDocument: &types.IndexDocument{
				Suffix: getPtr("index.html"),
			},
		})
		if err != nil {
			return err
		}
		if err := grantPublicBucketPolicy(s3client, bucket, policyTypeObject); err != nil {
			return err
		}

		indexContent := "<html><body>Welcome</body></html>"
		_, err = putObjectWithData(int64(len(indexContent)), &s3.PutObjectInput{
			Bucket:      &bucket,
			Key:         getPtr("index.html"),
			Body:        strings.NewReader(indexContent),
			ContentType: getPtr("text/html"),
		}, s3client)
		if err != nil {
			return err
		}
		docsContent := "<html><body>Docs Home</body></html>"
		_, err = putObjectWithData(int64(len(docsContent)), &s3.PutObjectInput{
			Bucket:      &bucket,
			Key:         getPtr("docs/index.html"),
			Body:        strings.NewReader(docsContent),
			ContentType: getPtr("text/html"),
		}, s3client)
		if err != nil {
			return err
		}

		for _, test := range []struct {
			path string
			body string
		}{
			{"/", indexContent},
			{"docs/", docsContent},
		} {
			resp, err := websiteGet(s, bucket, test.path, nil)
			if err != nil {
				return err
			}

			err = checkWebsiteResponse(resp, http.StatusOK, []byte(test.body))
			resp.Body.Close()
			if err != nil {
				return fmt.Errorf("%s: %w", test.path, err)
			}
		}

		return nil
	})
}

// WebsiteHosting_index_error_document_and_routing_rules covers a combined
// website configuration with index, error document, pre-rule, and post-rule.
func WebsiteHosting_index_error_document_and_routing_rules(s *S3Conf) error {
	testName := "WebsiteHosting_index_error_document_and_routing_rules"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketWebsiteConfig(s3client, bucket, &types.WebsiteConfiguration{
			IndexDocument: &types.IndexDocument{
				Suffix: getPtr("index.html"),
			},
			ErrorDocument: &types.ErrorDocument{
				Key: getPtr("error.html"),
			},
			RoutingRules: []types.RoutingRule{
				{
					Condition: &types.Condition{
						KeyPrefixEquals: getPtr("legacy/"),
					},
					Redirect: &types.Redirect{
						ReplaceKeyPrefixWith: getPtr("docs/"),
						HttpRedirectCode:     getPtr("301"),
					},
				},
				{
					Condition: &types.Condition{
						HttpErrorCodeReturnedEquals: getPtr("404"),
					},
					Redirect: &types.Redirect{
						HostName:         getPtr("fallback.example.com"),
						ReplaceKeyWith:   getPtr("missing"),
						HttpRedirectCode: getPtr("302"),
					},
				},
			},
		})
		if err != nil {
			return err
		}
		if err := grantPublicBucketPolicy(s3client, bucket, policyTypeObject); err != nil {
			return err
		}
		indexContent := "<html><body>combined index</body></html>"
		_, err = putObjectWithData(int64(len(indexContent)), &s3.PutObjectInput{
			Bucket:      &bucket,
			Key:         getPtr("index.html"),
			Body:        strings.NewReader(indexContent),
			ContentType: getPtr("text/html"),
		}, s3client)
		if err != nil {
			return err
		}
		combinedError := "combined error"
		_, err = putObjectWithData(int64(len(combinedError)), &s3.PutObjectInput{
			Bucket:      &bucket,
			Key:         getPtr("error.html"),
			Body:        strings.NewReader(combinedError),
			ContentType: getPtr("text/html"),
		}, s3client)
		if err != nil {
			return err
		}

		indexResp, err := websiteGet(s, bucket, "/", nil)
		if err != nil {
			return err
		}
		if err := checkWebsiteResponse(indexResp, http.StatusOK, []byte(indexContent)); err != nil {
			return err
		}
		indexResp.Body.Close()

		preResp, err := websiteGet(s, bucket, "legacy/page.html", nil)
		if err != nil {
			return err
		}
		wantPreLocation, err := websiteURL(s, bucket, "docs/page.html")
		if err != nil {
			preResp.Body.Close()
			return err
		}
		if got := preResp.Header.Get("Location"); got != wantPreLocation {
			preResp.Body.Close()
			return fmt.Errorf("expected pre-rule Location %q, got %q", wantPreLocation, got)
		}
		if err := checkWebsiteResponse(preResp, http.StatusMovedPermanently, []byte(http.StatusText(http.StatusMovedPermanently))); err != nil {
			return err
		}

		postResp, err := websiteGet(s, bucket, "unknown.html", nil)
		if err != nil {
			return err
		}
		wantPostLocation, err := websiteAbsoluteURL(s, "fallback.example.com", "missing")
		if err != nil {
			postResp.Body.Close()
			return err
		}
		if got := postResp.Header.Get("Location"); got != wantPostLocation {
			postResp.Body.Close()
			return fmt.Errorf("expected post-rule Location %q, got %q", wantPostLocation, got)
		}
		if err := checkWebsiteResponse(postResp, http.StatusFound, []byte(http.StatusText(http.StatusFound))); err != nil {
			return err
		}

		return nil
	})
}

func WebsiteHosting_options_preflight_access_granted(s *S3Conf) error {
	testName := "WebsiteHosting_options_preflight_access_granted"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketCors(s3client, &s3.PutBucketCorsInput{
			Bucket: &bucket,
			CORSConfiguration: &types.CORSConfiguration{
				CORSRules: []types.CORSRule{
					{
						AllowedOrigins: []string{"https://client.example"},
						AllowedMethods: []string{http.MethodGet, http.MethodHead},
						AllowedHeaders: []string{"Content-Type", "X-Amz-Date"},
						ExposeHeaders:  []string{"Content-Length"},
						MaxAgeSeconds:  getPtr(int32(42)),
					},
				},
			},
		})
		if err != nil {
			return err
		}

		resp, err := websiteOptions(s, bucket, "index.html", map[string]string{
			"Origin":                         "https://client.example",
			"Access-Control-Request-Method":  http.MethodGet,
			"Access-Control-Request-Headers": "content-type, X-Amz-Date",
		})
		if err != nil {
			return err
		}

		corsHeaders, err := extractCORSHeaders(resp)
		if err != nil {
			return err
		}
		if err := comparePreflightResult(&PreflightResult{
			Origin:           "https://client.example",
			Methods:          "GET, HEAD",
			AllowHeaders:     "content-type, x-amz-date",
			ExposeHeaders:    "Content-Length, ETag",
			MaxAge:           "42",
			AllowCredentials: "true",
			Vary:             "Origin, Access-Control-Request-Headers, Access-Control-Request-Method",
		}, corsHeaders); err != nil {
			return err
		}

		return checkWebsiteResponse(resp, http.StatusOK, nil)
	})
}

func WebsiteHosting_get_cors_headers(s *S3Conf) error {
	testName := "WebsiteHosting_get_cors_headers"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketWebsiteConfig(s3client, bucket, &types.WebsiteConfiguration{
			IndexDocument: &types.IndexDocument{
				Suffix: getPtr("index.html"),
			},
		})
		if err != nil {
			return err
		}
		if err := grantPublicBucketPolicy(s3client, bucket, policyTypeObject); err != nil {
			return err
		}

		indexContent := "<html><body>CORS GET</body></html>"
		_, err = putObjectWithData(int64(len(indexContent)), &s3.PutObjectInput{
			Bucket:      &bucket,
			Key:         getPtr("index.html"),
			Body:        strings.NewReader(indexContent),
			ContentType: getPtr("text/html"),
		}, s3client)
		if err != nil {
			return err
		}

		maxAge := int32(42)
		err = putBucketCors(s3client, &s3.PutBucketCorsInput{
			Bucket: &bucket,
			CORSConfiguration: &types.CORSConfiguration{
				CORSRules: []types.CORSRule{
					{
						AllowedOrigins: []string{"https://client.example"},
						AllowedMethods: []string{http.MethodGet, http.MethodHead},
						ExposeHeaders:  []string{"Content-Length"},
						MaxAgeSeconds:  &maxAge,
					},
				},
			},
		})
		if err != nil {
			return err
		}

		resp, err := websiteGet(s, bucket, "/", map[string]string{
			"Origin": "https://client.example",
		})
		if err != nil {
			return err
		}

		corsHeaders, err := extractCORSHeaders(resp)
		if err != nil {
			resp.Body.Close()
			return err
		}
		if err := comparePreflightResult(&PreflightResult{
			Origin:           "https://client.example",
			Methods:          "GET, HEAD",
			ExposeHeaders:    "Content-Length, ETag, x-amz-storage-class",
			MaxAge:           "42",
			AllowCredentials: "true",
			Vary:             "Origin, Access-Control-Request-Headers, Access-Control-Request-Method",
		}, corsHeaders); err != nil {
			resp.Body.Close()
			return err
		}

		return checkWebsiteResponse(resp, http.StatusOK, []byte(indexContent))
	})
}

func WebsiteHosting_head_cors_headers(s *S3Conf) error {
	testName := "WebsiteHosting_head_cors_headers"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketWebsiteConfig(s3client, bucket, &types.WebsiteConfiguration{
			IndexDocument: &types.IndexDocument{
				Suffix: getPtr("index.html"),
			},
		})
		if err != nil {
			return err
		}
		if err := grantPublicBucketPolicy(s3client, bucket, policyTypeObject); err != nil {
			return err
		}

		headContent := "<html><body>CORS HEAD</body></html>"
		_, err = putObjectWithData(int64(len(headContent)), &s3.PutObjectInput{
			Bucket:      &bucket,
			Key:         getPtr("head.html"),
			Body:        strings.NewReader(headContent),
			ContentType: getPtr("text/html"),
		}, s3client)
		if err != nil {
			return err
		}

		err = putBucketCors(s3client, &s3.PutBucketCorsInput{
			Bucket: &bucket,
			CORSConfiguration: &types.CORSConfiguration{
				CORSRules: []types.CORSRule{
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

		resp, err := websiteHead(s, bucket, "head.html", map[string]string{
			"Origin": "https://client.example",
		})
		if err != nil {
			return err
		}

		corsHeaders, err := extractCORSHeaders(resp)
		if err != nil {
			resp.Body.Close()
			return err
		}
		if err := comparePreflightResult(&PreflightResult{
			Origin:           "*",
			Methods:          "HEAD",
			ExposeHeaders:    "ETag, x-amz-storage-class",
			AllowCredentials: "false",
			Vary:             "Origin, Access-Control-Request-Headers, Access-Control-Request-Method",
		}, corsHeaders); err != nil {
			resp.Body.Close()
			return err
		}

		return checkWebsiteResponse(resp, http.StatusOK, nil)
	})
}

func WebsiteHosting_options_preflight_access_forbidden(s *S3Conf) error {
	testName := "WebsiteHosting_options_preflight_access_forbidden"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketCors(s3client, &s3.PutBucketCorsInput{
			Bucket: &bucket,
			CORSConfiguration: &types.CORSConfiguration{
				CORSRules: []types.CORSRule{
					{
						AllowedOrigins: []string{"https://client.example"},
						AllowedMethods: []string{http.MethodHead},
					},
				},
			},
		})
		if err != nil {
			return err
		}

		resp, err := websiteOptions(s, bucket, "index.html", map[string]string{
			"Origin":                        "https://client.example",
			"Access-Control-Request-Method": http.MethodGet,
		})
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		return checkWebsiteErrorResponse(resp,
			s3err.GetAccessForbiddenErr(s3err.ErrCORSForbidden, http.MethodOptions, s3err.ResourceTypeObject))
	})
}

func WebsiteHosting_options_preflight_missing_origin(s *S3Conf) error {
	testName := "WebsiteHosting_options_preflight_missing_origin"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		resp, err := websiteOptions(s, bucket, "index.html", map[string]string{
			"Access-Control-Request-Method": http.MethodGet,
		})
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		return checkWebsiteErrorResponse(resp, s3err.GetAPIError(s3err.ErrMissingCORSOrigin))
	})
}
