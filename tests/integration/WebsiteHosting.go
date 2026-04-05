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
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// WebsiteHosting_error_document_served tests that when a website-enabled
// bucket has an error document configured, requesting a non-existing key
// returns the error document content with the original 404 status code.
func WebsiteHosting_error_document_served(s *S3Conf) error {
	testName := "WebsiteHosting_error_document_served"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		// Configure website with error document
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketWebsite(ctx, &s3.PutBucketWebsiteInput{
			Bucket: &bucket,
			WebsiteConfiguration: &types.WebsiteConfiguration{
				IndexDocument: &types.IndexDocument{
					Suffix: getPtr("index.html"),
				},
				ErrorDocument: &types.ErrorDocument{
					Key: getPtr("error.html"),
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		// Upload the error document
		errorContent := "<html><body>Custom Error Page</body></html>"
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:      &bucket,
			Key:         getPtr("error.html"),
			Body:        strings.NewReader(errorContent),
			ContentType: getPtr("text/html"),
		})
		cancel()
		if err != nil {
			return err
		}

		// Request a non-existing key via raw HTTP to see the error document body
		req, err := createSignedReq(
			http.MethodGet,
			s.endpoint,
			fmt.Sprintf("%v/nonexistent-key", bucket),
			s.awsID, s.awsSecret, "s3", s.awsRegion,
			nil, time.Now(), nil,
		)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNotFound {
			return fmt.Errorf("expected status 404, got %v", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		if string(body) != errorContent {
			return fmt.Errorf("expected error document content %q, got %q", errorContent, string(body))
		}

		return nil
	})
}

// WebsiteHosting_error_document_not_found tests that when the configured
// error document itself does not exist, the original S3 error is returned.
func WebsiteHosting_error_document_not_found(s *S3Conf) error {
	testName := "WebsiteHosting_error_document_not_found"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		// Configure website with error document (but don't upload it)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketWebsite(ctx, &s3.PutBucketWebsiteInput{
			Bucket: &bucket,
			WebsiteConfiguration: &types.WebsiteConfiguration{
				IndexDocument: &types.IndexDocument{
					Suffix: getPtr("index.html"),
				},
				ErrorDocument: &types.ErrorDocument{
					Key: getPtr("error.html"),
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		// Request a non-existing key - should get standard S3 error since error doc doesn't exist
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    getPtr("nonexistent-key"),
		})
		cancel()

		return checkSdkApiErr(err, "NoSuchKey")
	})
}

// WebsiteHosting_no_error_document tests that when website is enabled
// but no error document is configured, the standard S3 error is returned.
func WebsiteHosting_no_error_document(s *S3Conf) error {
	testName := "WebsiteHosting_no_error_document"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		// Configure website without error document
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketWebsite(ctx, &s3.PutBucketWebsiteInput{
			Bucket: &bucket,
			WebsiteConfiguration: &types.WebsiteConfiguration{
				IndexDocument: &types.IndexDocument{
					Suffix: getPtr("index.html"),
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		// Request a non-existing key - should get standard S3 error
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    getPtr("nonexistent-key"),
		})
		cancel()

		return checkSdkApiErr(err, "NoSuchKey")
	})
}

// WebsiteHosting_routing_rule_post_request_redirect tests that a post-request
// routing rule (matching on error code) issues a redirect instead of serving
// the error or error document.
func WebsiteHosting_routing_rule_post_request_redirect(s *S3Conf) error {
	testName := "WebsiteHosting_routing_rule_post_request_redirect"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		// Configure website with a post-request routing rule for 404
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketWebsite(ctx, &s3.PutBucketWebsiteInput{
			Bucket: &bucket,
			WebsiteConfiguration: &types.WebsiteConfiguration{
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
			},
		})
		cancel()
		if err != nil {
			return err
		}

		// Make a raw HTTP request (don't follow redirects)
		req, err := createSignedReq(
			http.MethodGet,
			s.endpoint,
			fmt.Sprintf("%v/missing-page", bucket),
			s.awsID, s.awsSecret, "s3", s.awsRegion,
			nil, time.Now(), nil,
		)
		if err != nil {
			return err
		}

		noRedirectClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		resp, err := noRedirectClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusFound {
			return fmt.Errorf("expected status 302, got %v", resp.StatusCode)
		}

		location := resp.Header.Get("Location")
		if location == "" {
			return fmt.Errorf("expected Location header, got none")
		}

		// The redirect should point to fallback.example.com/not-found
		if !strings.Contains(location, "fallback.example.com") || !strings.Contains(location, "not-found") {
			return fmt.Errorf("expected redirect to fallback.example.com/not-found, got %q", location)
		}

		return nil
	})
}

// WebsiteHosting_routing_rule_pre_request_redirect tests that a pre-request
// routing rule (matching on key prefix only) issues a redirect before the
// object is fetched.
func WebsiteHosting_routing_rule_pre_request_redirect(s *S3Conf) error {
	testName := "WebsiteHosting_routing_rule_pre_request_redirect"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		// Configure website with a pre-request routing rule
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketWebsite(ctx, &s3.PutBucketWebsiteInput{
			Bucket: &bucket,
			WebsiteConfiguration: &types.WebsiteConfiguration{
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
			},
		})
		cancel()
		if err != nil {
			return err
		}

		// Make a raw HTTP request for old-docs/page (don't follow redirects)
		req, err := createSignedReq(
			http.MethodGet,
			s.endpoint,
			fmt.Sprintf("%v/old-docs/page.html", bucket),
			s.awsID, s.awsSecret, "s3", s.awsRegion,
			nil, time.Now(), nil,
		)
		if err != nil {
			return err
		}

		noRedirectClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		resp, err := noRedirectClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusMovedPermanently {
			return fmt.Errorf("expected status 301, got %v", resp.StatusCode)
		}

		location := resp.Header.Get("Location")
		if location == "" {
			return fmt.Errorf("expected Location header, got none")
		}

		// The redirect should rewrite old-docs/ -> new-docs/
		if !strings.Contains(location, "new-docs/page.html") {
			return fmt.Errorf("expected redirect to contain new-docs/page.html, got %q", location)
		}

		return nil
	})
}

// WebsiteHosting_redirect_all_requests tests the RedirectAllRequestsTo
// configuration, which should redirect any request to the specified host.
func WebsiteHosting_redirect_all_requests(s *S3Conf) error {
	testName := "WebsiteHosting_redirect_all_requests"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		// Configure redirect-all
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketWebsite(ctx, &s3.PutBucketWebsiteInput{
			Bucket: &bucket,
			WebsiteConfiguration: &types.WebsiteConfiguration{
				RedirectAllRequestsTo: &types.RedirectAllRequestsTo{
					HostName: getPtr("www.example.com"),
					Protocol: types.ProtocolHttps,
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		// Make a raw HTTP request (don't follow redirects)
		req, err := createSignedReq(
			http.MethodGet,
			s.endpoint,
			fmt.Sprintf("%v/any/path/here", bucket),
			s.awsID, s.awsSecret, "s3", s.awsRegion,
			nil, time.Now(), nil,
		)
		if err != nil {
			return err
		}

		noRedirectClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		resp, err := noRedirectClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusMovedPermanently {
			return fmt.Errorf("expected status 301, got %v", resp.StatusCode)
		}

		location := resp.Header.Get("Location")
		if !strings.HasPrefix(location, "https://www.example.com/") {
			return fmt.Errorf("expected redirect to https://www.example.com/, got %q", location)
		}

		if !strings.Contains(location, "any/path/here") {
			return fmt.Errorf("expected redirect to preserve path, got %q", location)
		}

		return nil
	})
}

// WebsiteHosting_index_document tests that requesting a directory-like
// path on a website-enabled bucket serves the index document.
func WebsiteHosting_index_document(s *S3Conf) error {
	testName := "WebsiteHosting_index_document"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		// Configure website
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketWebsite(ctx, &s3.PutBucketWebsiteInput{
			Bucket: &bucket,
			WebsiteConfiguration: &types.WebsiteConfiguration{
				IndexDocument: &types.IndexDocument{
					Suffix: getPtr("index.html"),
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		// Upload index document at root
		indexContent := "<html><body>Welcome</body></html>"
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:      &bucket,
			Key:         getPtr("index.html"),
			Body:        strings.NewReader(indexContent),
			ContentType: getPtr("text/html"),
		})
		cancel()
		if err != nil {
			return err
		}

		// Request the root (empty key) via raw HTTP
		req, err := createSignedReq(
			http.MethodGet,
			s.endpoint,
			fmt.Sprintf("%v/", bucket),
			s.awsID, s.awsSecret, "s3", s.awsRegion,
			nil, time.Now(), nil,
		)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("expected status 200, got %v; body: %s", resp.StatusCode, body)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		if !bytes.Equal(body, []byte(indexContent)) {
			return fmt.Errorf("expected index document content %q, got %q", indexContent, string(body))
		}

		return nil
	})
}
