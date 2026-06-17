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

package website

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

type websiteTestBackend struct {
	backend.BackendUnsupported

	websiteConfig   []byte
	corsConfig      []byte
	corsErr         error
	objects         map[string]string
	objectRedirects map[string]string
	objectErrors    map[string]error
	public          bool
	calls           []string
}

func (b *websiteTestBackend) record(call string) {
	b.calls = append(b.calls, call)
}

func (b *websiteTestBackend) GetBucketWebsite(_ context.Context, _ string) ([]byte, error) {
	b.record("GetBucketWebsite")
	return b.websiteConfig, nil
}

func (b *websiteTestBackend) GetBucketCors(_ context.Context, _ string) ([]byte, error) {
	b.record("GetBucketCors")
	if b.corsErr != nil {
		return nil, b.corsErr
	}
	if b.corsConfig == nil {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchCORSConfiguration)
	}
	return b.corsConfig, nil
}

func (b *websiteTestBackend) GetBucketPolicy(_ context.Context, _ string) ([]byte, error) {
	b.record("GetBucketPolicy")
	return nil, s3err.GetAPIError(s3err.ErrNoSuchBucketPolicy)
}

func (b *websiteTestBackend) GetBucketAcl(_ context.Context, _ *s3.GetBucketAclInput) ([]byte, error) {
	b.record("GetBucketAcl")
	acl := auth.ACL{Owner: "owner"}
	if b.public {
		acl.Grantees = []auth.Grantee{
			{
				Permission: auth.PermissionRead,
				Access:     "all-users",
				Type:       types.TypeGroup,
			},
		}
	}

	data, err := json.Marshal(acl)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (b *websiteTestBackend) HeadObject(_ context.Context, input *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
	b.record("HeadObject")
	if input == nil || input.Key == nil {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if err, ok := b.objectErrors[*input.Key]; ok {
		return nil, err
	}
	body, ok := b.objects[*input.Key]
	if !ok {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}

	length := int64(len(body))
	contentType := "text/html"
	redirectLocation := redirectPtr(b.objectRedirects[*input.Key])
	return &s3.HeadObjectOutput{
		ContentLength:           &length,
		ContentType:             &contentType,
		WebsiteRedirectLocation: redirectLocation,
	}, nil
}

func (b *websiteTestBackend) GetObject(_ context.Context, input *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	b.record("GetObject")
	if input == nil || input.Key == nil {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if err, ok := b.objectErrors[*input.Key]; ok {
		return nil, err
	}
	body, ok := b.objects[*input.Key]
	if !ok {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}

	length := int64(len(body))
	contentType := "text/html"
	redirectLocation := redirectPtr(b.objectRedirects[*input.Key])
	return &s3.GetObjectOutput{
		Body:                    io.NopCloser(strings.NewReader(body)),
		ContentLength:           &length,
		ContentType:             &contentType,
		WebsiteRedirectLocation: redirectLocation,
	}, nil
}

func redirectPtr(location string) *string {
	if location == "" {
		return nil
	}
	return &location
}

func TestWebsiteHandlerRoutingRuleOrder(t *testing.T) {
	tests := []struct {
		name         string
		rules        []s3response.RoutingRule
		wantStatus   int
		wantLocation string
	}{
		{
			name: "key prefix rule before 404 rule wins",
			rules: []s3response.RoutingRule{
				{
					Condition: &s3response.RoutingRuleCondition{
						KeyPrefixEquals: "old/",
					},
					Redirect: &s3response.Redirect{
						ReplaceKeyPrefixWith: "new/",
						HttpRedirectCode:     "301",
					},
				},
				{
					Condition: &s3response.RoutingRuleCondition{
						HttpErrorCodeReturnedEquals: "404",
					},
					Redirect: &s3response.Redirect{
						ReplaceKeyWith:   "error.html",
						HttpRedirectCode: "302",
					},
				},
			},
			wantStatus:   http.StatusMovedPermanently,
			wantLocation: "http://site.test/new/missing.html",
		},
		{
			name: "key prefix rule wins pre-fetch even when 404 rule comes first",
			rules: []s3response.RoutingRule{
				{
					Condition: &s3response.RoutingRuleCondition{
						HttpErrorCodeReturnedEquals: "404",
					},
					Redirect: &s3response.Redirect{
						ReplaceKeyWith:   "error.html",
						HttpRedirectCode: "302",
					},
				},
				{
					Condition: &s3response.RoutingRuleCondition{
						KeyPrefixEquals: "old/",
					},
					Redirect: &s3response.Redirect{
						ReplaceKeyPrefixWith: "new/",
						HttpRedirectCode:     "301",
					},
				},
			},
			wantStatus:   http.StatusMovedPermanently,
			wantLocation: "http://site.test/new/missing.html",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := newWebsiteTestBackend(t, s3response.WebsiteConfiguration{
				IndexDocument: &s3response.IndexDocument{Suffix: "index.html"},
				RoutingRules:  tt.rules,
			}, nil, true)

			resp := websiteRequest(t, be, "/old/missing.html")
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
			if got := resp.Header.Get("Location"); got != tt.wantLocation {
				t.Fatalf("Location = %q, want %q", got, tt.wantLocation)
			}
			if containsCall(be.calls, "GetObject") {
				t.Fatal("GetObject was called for a redirect response")
			}
		})
	}
}

func TestWebsiteHandlerRoutingRuleBothConditions(t *testing.T) {
	config := s3response.WebsiteConfiguration{
		IndexDocument: &s3response.IndexDocument{Suffix: "index.html"},
		RoutingRules: []s3response.RoutingRule{
			{
				Condition: &s3response.RoutingRuleCondition{
					KeyPrefixEquals:             "old/",
					HttpErrorCodeReturnedEquals: "404",
				},
				Redirect: &s3response.Redirect{
					ReplaceKeyPrefixWith: "new/",
					HttpRedirectCode:     "302",
				},
			},
		},
	}

	t.Run("missing object with matching prefix redirects", func(t *testing.T) {
		be := newWebsiteTestBackend(t, config, nil, true)
		resp := websiteRequest(t, be, "/old/missing.html")
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusFound {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
		}
		if got := resp.Header.Get("Location"); got != "http://site.test/new/missing.html" {
			t.Fatalf("Location = %q", got)
		}
	})

	t.Run("existing object with matching prefix does not redirect", func(t *testing.T) {
		be := newWebsiteTestBackend(t, config, map[string]string{
			"old/existing.html": "served",
		}, true)
		resp := websiteRequest(t, be, "/old/existing.html")
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		if got := readBody(t, resp); got != "served" {
			t.Fatalf("body = %q, want %q", got, "served")
		}
		if got := resp.Header.Get("Location"); got != "" {
			t.Fatalf("unexpected Location header %q", got)
		}
	})

	t.Run("missing object with wrong prefix does not redirect", func(t *testing.T) {
		be := newWebsiteTestBackend(t, config, nil, true)
		resp := websiteRequest(t, be, "/other/missing.html")
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
		}
		if got := resp.Header.Get("Location"); got != "" {
			t.Fatalf("unexpected Location header %q", got)
		}
	})
}

func TestWebsiteHandlerObjectRedirectLocation(t *testing.T) {
	be := newWebsiteTestBackend(t, s3response.WebsiteConfiguration{
		IndexDocument: &s3response.IndexDocument{Suffix: "index.html"},
	}, map[string]string{
		"old.html": "old",
	}, true)
	be.objectRedirects["old.html"] = "/new.html"

	resp := websiteRequest(t, be, "/old.html")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusMovedPermanently)
	}
	if got := resp.Header.Get("Location"); got != "/new.html" {
		t.Fatalf("Location = %q, want %q", got, "/new.html")
	}
	if got := readBody(t, resp); got != "" {
		t.Fatalf("body = %q, want empty body", got)
	}
}

func TestWebsiteHandlerPrefetchRoutingPrecedesObjectRedirect(t *testing.T) {
	be := newWebsiteTestBackend(t, s3response.WebsiteConfiguration{
		IndexDocument: &s3response.IndexDocument{Suffix: "index.html"},
		RoutingRules: []s3response.RoutingRule{
			{
				Condition: &s3response.RoutingRuleCondition{
					KeyPrefixEquals: "old/",
				},
				Redirect: &s3response.Redirect{
					ReplaceKeyPrefixWith: "new/",
					HttpRedirectCode:     "302",
				},
			},
		},
	}, map[string]string{
		"old/page.html": "old",
	}, true)
	be.objectRedirects["old/page.html"] = "/object-redirect.html"

	resp := websiteRequest(t, be, "/old/page.html")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	if got := resp.Header.Get("Location"); got != "http://site.test/new/page.html" {
		t.Fatalf("Location = %q", got)
	}
	if containsCall(be.calls, "GetObject") {
		t.Fatal("GetObject was called before pre-fetch routing completed")
	}
}

func TestWebsiteHandlerRedirectConstruction(t *testing.T) {
	tests := []struct {
		name         string
		rule         s3response.RoutingRule
		path         string
		wantLocation string
	}{
		{
			name: "ReplaceKeyWith replaces full key",
			rule: s3response.RoutingRule{
				Condition: &s3response.RoutingRuleCondition{
					HttpErrorCodeReturnedEquals: "404",
				},
				Redirect: &s3response.Redirect{
					ReplaceKeyWith: "error.html",
				},
			},
			path:         "/a/b/c.html",
			wantLocation: "http://site.test/error.html",
		},
		{
			name: "ReplaceKeyPrefixWith replaces matching prefix",
			rule: s3response.RoutingRule{
				Condition: &s3response.RoutingRuleCondition{
					KeyPrefixEquals: "old/",
				},
				Redirect: &s3response.Redirect{
					ReplaceKeyPrefixWith: "new/",
				},
			},
			path:         "/old/a/b.html",
			wantLocation: "http://site.test/new/a/b.html",
		},
		{
			name: "HostName Protocol and query string are preserved",
			rule: s3response.RoutingRule{
				Condition: &s3response.RoutingRuleCondition{
					KeyPrefixEquals: "old/",
				},
				Redirect: &s3response.Redirect{
					HostName:             "example.com",
					Protocol:             "https",
					ReplaceKeyPrefixWith: "new/",
				},
			},
			path:         "/old/page.html?x=1&y=2",
			wantLocation: "https://example.com/new/page.html?x=1&y=2",
		},
		{
			name: "query string is preserved with current endpoint host",
			rule: s3response.RoutingRule{
				Condition: &s3response.RoutingRuleCondition{
					KeyPrefixEquals: "old/",
				},
				Redirect: &s3response.Redirect{
					ReplaceKeyPrefixWith: "new/",
				},
			},
			path:         "/old/page.html?x=1&y=2",
			wantLocation: "http://site.test/new/page.html?x=1&y=2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := newWebsiteTestBackend(t, s3response.WebsiteConfiguration{
				IndexDocument: &s3response.IndexDocument{Suffix: "index.html"},
				RoutingRules:  []s3response.RoutingRule{tt.rule},
			}, nil, true)

			resp := websiteRequest(t, be, tt.path)
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusMovedPermanently {
				t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusMovedPermanently)
			}
			if got := resp.Header.Get("Location"); got != tt.wantLocation {
				t.Fatalf("Location = %q, want %q", got, tt.wantLocation)
			}
		})
	}
}

func TestWebsiteHandlerPostErrorRoutingUsesOriginalKeyBeforeIndexExpansion(t *testing.T) {
	be := newWebsiteTestBackend(t, s3response.WebsiteConfiguration{
		IndexDocument: &s3response.IndexDocument{Suffix: "index.html"},
		RoutingRules: []s3response.RoutingRule{
			{
				Condition: &s3response.RoutingRuleCondition{
					KeyPrefixEquals:             "blog/",
					HttpErrorCodeReturnedEquals: "404",
				},
				Redirect: &s3response.Redirect{
					ReplaceKeyPrefixWith: "archive/",
					HttpRedirectCode:     "302",
				},
			},
		},
	}, nil, true)

	resp := websiteRequest(t, be, "/blog/")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	if got := resp.Header.Get("Location"); got != "http://site.test/archive/" {
		t.Fatalf("Location = %q, want %q", got, "http://site.test/archive/")
	}
	if countCalls(be.calls, "GetObject") != 1 {
		t.Fatalf("GetObject calls = %d, want 1; calls: %v", countCalls(be.calls, "GetObject"), be.calls)
	}
}

func TestWebsiteHandlerObjectStore5xxBypassesRoutingAndErrorDocument(t *testing.T) {
	be := newWebsiteTestBackend(t, s3response.WebsiteConfiguration{
		IndexDocument: &s3response.IndexDocument{Suffix: "index.html"},
		ErrorDocument: &s3response.ErrorDocument{Key: "error.html"},
		RoutingRules: []s3response.RoutingRule{
			{
				Condition: &s3response.RoutingRuleCondition{
					HttpErrorCodeReturnedEquals: "500",
				},
				Redirect: &s3response.Redirect{
					ReplaceKeyWith:   "elsewhere.html",
					HttpRedirectCode: "302",
				},
			},
		},
	}, map[string]string{
		"error.html": "custom error document",
	}, true)
	be.objectErrors = map[string]error{
		"boom.html": s3err.GetAPIError(s3err.ErrInternalError),
	}

	resp := websiteRequest(t, be, "/boom.html")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
	if got := resp.Header.Get("Location"); got != "" {
		t.Fatalf("unexpected Location header %q", got)
	}
	if got := resp.Header.Get("x-amz-error-code"); got != "InternalError" {
		t.Fatalf("x-amz-error-code = %q, want %q", got, "InternalError")
	}
	if got := countCalls(be.calls, "GetObject"); got != 1 {
		t.Fatalf("GetObject calls = %d, want 1; calls: %v", got, be.calls)
	}
}

func TestWebsiteHandlerPublicAccessDeniedPreventsObjectReadAndCanRoute(t *testing.T) {
	be := newWebsiteTestBackend(t, s3response.WebsiteConfiguration{
		IndexDocument: &s3response.IndexDocument{Suffix: "index.html"},
		RoutingRules: []s3response.RoutingRule{
			{
				Condition: &s3response.RoutingRuleCondition{
					HttpErrorCodeReturnedEquals: "403",
				},
				Redirect: &s3response.Redirect{
					ReplaceKeyWith:   "denied.html",
					HttpRedirectCode: "302",
				},
			},
		},
	}, map[string]string{
		"private.html": "secret",
	}, false)

	resp := websiteRequest(t, be, "/private.html")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	if got := resp.Header.Get("Location"); got != "http://site.test/denied.html" {
		t.Fatalf("Location = %q", got)
	}
	if containsCall(be.calls, "HeadObject") {
		t.Fatal("HeadObject was called after public access was denied")
	}
	if containsCall(be.calls, "GetObject") {
		t.Fatal("GetObject was called after public access was denied")
	}
}

func TestWebsiteHandlerVerifiesPublicAccessBeforeGetObject(t *testing.T) {
	be := newWebsiteTestBackend(t, s3response.WebsiteConfiguration{
		IndexDocument: &s3response.IndexDocument{Suffix: "index.html"},
	}, map[string]string{
		"index.html": "home",
	}, true)

	resp := websiteRequest(t, be, "/")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := readBody(t, resp); got != "home" {
		t.Fatalf("body = %q, want %q", got, "home")
	}

	verifyIdx := firstCallIndex(be.calls, "GetBucketAcl")
	getObjectIdx := firstCallIndex(be.calls, "GetObject")
	if verifyIdx == -1 {
		t.Fatal("expected public access verification to read bucket ACL")
	}
	if getObjectIdx == -1 {
		t.Fatal("expected GetObject call")
	}
	if verifyIdx > getObjectIdx {
		t.Fatalf("GetObject happened before public access verification: %v", be.calls)
	}
}

func TestWebsiteHandlerHeadUsesHeadObjectAndReturnsHeadersOnly(t *testing.T) {
	be := newWebsiteTestBackend(t, s3response.WebsiteConfiguration{
		IndexDocument: &s3response.IndexDocument{Suffix: "index.html"},
	}, map[string]string{
		"index.html": "home",
	}, true)

	resp := websiteRequestWithMethod(t, be, http.MethodHead, "/")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := resp.Header.Get("Content-Length"); got != "4" {
		t.Fatalf("Content-Length = %q, want %q", got, "4")
	}
	if got := resp.Header.Get("Content-Type"); got != "text/html" {
		t.Fatalf("Content-Type = %q, want %q", got, "text/html")
	}
	if got := readBody(t, resp); got != "" {
		t.Fatalf("body = %q, want empty body", got)
	}
	if containsCall(be.calls, "GetObject") {
		t.Fatalf("GetObject was called for HEAD request: %v", be.calls)
	}
	if !containsCall(be.calls, "HeadObject") {
		t.Fatalf("HeadObject was not called for HEAD request: %v", be.calls)
	}
}

func TestWebsiteHandlerGetValidatesBucketName(t *testing.T) {
	be := newWebsiteTestBackend(t, s3response.WebsiteConfiguration{
		IndexDocument: &s3response.IndexDocument{Suffix: "index.html"},
	}, nil, true)

	resp := websiteRequestWithHostAndHeaders(t, be, http.MethodGet, "bad_bucket", "/", nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if got := resp.Header.Get("x-amz-error-code"); got != "InvalidBucketName" {
		t.Fatalf("x-amz-error-code = %q", got)
	}
	if len(be.calls) != 0 {
		t.Fatalf("invalid bucket should not call backend, got calls: %v", be.calls)
	}
}

func TestWebsiteHandlerNoBucketInRequestSetsLocation(t *testing.T) {
	be := newWebsiteTestBackend(t, s3response.WebsiteConfiguration{
		IndexDocument: &s3response.IndexDocument{Suffix: "index.html"},
	}, nil, true)

	resp := websiteRequestWithDomainHostAndHeaders(t, be, "site.test", http.MethodGet, "wrong.test:8080", "/", nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusMovedPermanently)
	}
	if got := resp.Header.Get("Location"); got != "http://site.test:8080/" {
		t.Fatalf("Location = %q, want %q", got, "http://site.test:8080/")
	}
	if got := resp.Header.Get("x-amz-error-code"); got != "WebsiteRedirect" {
		t.Fatalf("x-amz-error-code = %q, want %q", got, "WebsiteRedirect")
	}
	if len(be.calls) != 0 {
		t.Fatalf("request without bucket should not call backend, got calls: %v", be.calls)
	}
}

func TestWebsiteHandlerHeadValidatesObjectName(t *testing.T) {
	be := newWebsiteTestBackend(t, s3response.WebsiteConfiguration{
		IndexDocument: &s3response.IndexDocument{Suffix: "index.html"},
	}, nil, true)

	resp := websiteRequestWithHeaders(t, be, http.MethodHead, "/../../private.html", nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if got := resp.Header.Get("x-amz-error-code"); got != "400" {
		t.Fatalf("x-amz-error-code = %q", got)
	}
	if len(be.calls) != 0 {
		t.Fatalf("invalid object should not call backend, got calls: %v", be.calls)
	}
}

func TestWebsiteHandlerGetAppliesBucketCORS(t *testing.T) {
	corsConfig, err := xml.Marshal(auth.CORSConfiguration{
		Rules: []auth.CORSRule{
			{
				AllowedOrigins: []auth.CORSOrigin{"https://client.example"},
				AllowedMethods: []auth.CORSHTTPMethod{http.MethodGet, http.MethodHead},
				ExposeHeaders:  []auth.CORSHeader{"Content-Length"},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal cors config: %v", err)
	}

	be := newWebsiteTestBackend(t, s3response.WebsiteConfiguration{
		IndexDocument: &s3response.IndexDocument{Suffix: "index.html"},
	}, map[string]string{
		"index.html": "home",
	}, true)
	be.corsConfig = corsConfig

	resp := websiteRequestWithHeaders(t, be, http.MethodGet, "/", map[string]string{
		"Origin": "https://client.example",
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://client.example" {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Methods"); got != "GET, HEAD" {
		t.Fatalf("Access-Control-Allow-Methods = %q", got)
	}
	if got := resp.Header.Get("Access-Control-Expose-Headers"); got != "Content-Length, ETag, x-amz-storage-class" {
		t.Fatalf("Access-Control-Expose-Headers = %q", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("Access-Control-Allow-Credentials = %q", got)
	}
	if got := resp.Header.Get("Vary"); got != "Origin, Access-Control-Request-Headers, Access-Control-Request-Method" {
		t.Fatalf("Vary = %q", got)
	}
	if got := readBody(t, resp); got != "home" {
		t.Fatalf("body = %q, want %q", got, "home")
	}
	if !containsCall(be.calls, "GetBucketCors") {
		t.Fatalf("GetBucketCors was not called: %v", be.calls)
	}
}

func TestWebsiteHandlerHeadAppliesBucketCORS(t *testing.T) {
	corsConfig, err := xml.Marshal(auth.CORSConfiguration{
		Rules: []auth.CORSRule{
			{
				AllowedOrigins: []auth.CORSOrigin{"https://client.example"},
				AllowedMethods: []auth.CORSHTTPMethod{http.MethodHead},
				ExposeHeaders:  []auth.CORSHeader{"Content-Length"},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal cors config: %v", err)
	}

	be := newWebsiteTestBackend(t, s3response.WebsiteConfiguration{
		IndexDocument: &s3response.IndexDocument{Suffix: "index.html"},
	}, map[string]string{
		"index.html": "home",
	}, true)
	be.corsConfig = corsConfig

	resp := websiteRequestWithHeaders(t, be, http.MethodHead, "/", map[string]string{
		"Origin": "https://client.example",
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://client.example" {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Methods"); got != "HEAD" {
		t.Fatalf("Access-Control-Allow-Methods = %q", got)
	}
	if got := resp.Header.Get("Access-Control-Expose-Headers"); got != "Content-Length, ETag, x-amz-storage-class" {
		t.Fatalf("Access-Control-Expose-Headers = %q", got)
	}
	if got := readBody(t, resp); got != "" {
		t.Fatalf("body = %q, want empty body", got)
	}
	if !containsCall(be.calls, "GetBucketCors") {
		t.Fatalf("GetBucketCors was not called: %v", be.calls)
	}
	if containsCall(be.calls, "GetObject") {
		t.Fatalf("GetObject was called for HEAD request: %v", be.calls)
	}
}

func TestWebsiteHandlerOptionsAccessGranted(t *testing.T) {
	maxAge := int32(42)
	corsConfig, err := xml.Marshal(auth.CORSConfiguration{
		Rules: []auth.CORSRule{
			{
				AllowedOrigins: []auth.CORSOrigin{"https://client.example"},
				AllowedMethods: []auth.CORSHTTPMethod{http.MethodGet, http.MethodHead},
				AllowedHeaders: []auth.CORSHeader{"Content-Type", "X-Amz-Date"},
				ExposeHeaders:  []auth.CORSHeader{"Content-Length"},
				MaxAgeSeconds:  &maxAge,
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal cors config: %v", err)
	}

	be := newWebsiteTestBackend(t, s3response.WebsiteConfiguration{
		IndexDocument: &s3response.IndexDocument{Suffix: "index.html"},
	}, map[string]string{
		"index.html": "home",
	}, true)
	be.corsConfig = corsConfig

	resp := websiteRequestWithHeaders(t, be, http.MethodOptions, "/index.html", map[string]string{
		"Origin":                         "https://client.example",
		"Access-Control-Request-Method":  http.MethodGet,
		"Access-Control-Request-Headers": "content-type, X-Amz-Date",
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://client.example" {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Methods"); got != "GET, HEAD" {
		t.Fatalf("Access-Control-Allow-Methods = %q", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Headers"); got != "content-type, x-amz-date" {
		t.Fatalf("Access-Control-Allow-Headers = %q", got)
	}
	if got := resp.Header.Get("Access-Control-Expose-Headers"); got != "Content-Length" {
		t.Fatalf("Access-Control-Expose-Headers = %q", got)
	}
	if got := resp.Header.Get("Access-Control-Max-Age"); got != "42" {
		t.Fatalf("Access-Control-Max-Age = %q", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("Access-Control-Allow-Credentials = %q", got)
	}
	if got := resp.Header.Get("Vary"); got != "Origin, Access-Control-Request-Headers, Access-Control-Request-Method" {
		t.Fatalf("Vary = %q", got)
	}
	if got := readBody(t, resp); got != "" {
		t.Fatalf("body = %q, want empty body", got)
	}
	if !containsCall(be.calls, "GetBucketCors") {
		t.Fatalf("GetBucketCors was not called: %v", be.calls)
	}
	for _, unexpected := range []string{"GetBucketWebsite", "GetObject", "HeadObject", "GetBucketAcl"} {
		if containsCall(be.calls, unexpected) {
			t.Fatalf("%s was called for OPTIONS request: %v", unexpected, be.calls)
		}
	}
}

func TestWebsiteHandlerOptionsMissingOrigin(t *testing.T) {
	be := newWebsiteTestBackend(t, s3response.WebsiteConfiguration{
		IndexDocument: &s3response.IndexDocument{Suffix: "index.html"},
	}, nil, true)

	resp := websiteRequestWithHeaders(t, be, http.MethodOptions, "/", map[string]string{
		"Access-Control-Request-Method": http.MethodGet,
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if got := resp.Header.Get("x-amz-error-code"); got != "BadRequest" {
		t.Fatalf("x-amz-error-code = %q", got)
	}
	if containsCall(be.calls, "GetBucketCors") {
		t.Fatalf("GetBucketCors was called despite missing origin: %v", be.calls)
	}
}

func TestWebsiteHandlerOptionsInvalidRequestMethod(t *testing.T) {
	be := newWebsiteTestBackend(t, s3response.WebsiteConfiguration{
		IndexDocument: &s3response.IndexDocument{Suffix: "index.html"},
	}, nil, true)

	resp := websiteRequestWithHeaders(t, be, http.MethodOptions, "/", map[string]string{
		"Origin":                        "https://client.example",
		"Access-Control-Request-Method": http.MethodOptions,
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if got := resp.Header.Get("x-amz-error-code"); got != "BadRequest" {
		t.Fatalf("x-amz-error-code = %q", got)
	}
	if containsCall(be.calls, "GetBucketCors") {
		t.Fatalf("GetBucketCors was called despite invalid request method: %v", be.calls)
	}
}

func TestWebsiteHandlerOptionsUnsetBucketCORS(t *testing.T) {
	be := newWebsiteTestBackend(t, s3response.WebsiteConfiguration{
		IndexDocument: &s3response.IndexDocument{Suffix: "index.html"},
	}, nil, true)
	be.corsErr = s3err.GetAPIError(s3err.ErrNoSuchCORSConfiguration)

	resp := websiteRequestWithHeaders(t, be, http.MethodOptions, "/", map[string]string{
		"Origin":                        "https://client.example",
		"Access-Control-Request-Method": http.MethodGet,
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if got := resp.Header.Get("x-amz-error-code"); got != "AccessForbidden" {
		t.Fatalf("x-amz-error-code = %q", got)
	}
	body := readBody(t, resp)
	for _, want := range []string{
		"<li>Method: OPTIONS</li>",
		"<li>ResourceType: BUCKET</li>",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q: %s", want, body)
		}
	}
}

func TestWebsiteHandlerOptionsAccessForbidden(t *testing.T) {
	corsConfig, err := xml.Marshal(auth.CORSConfiguration{
		Rules: []auth.CORSRule{
			{
				AllowedOrigins: []auth.CORSOrigin{"https://client.example"},
				AllowedMethods: []auth.CORSHTTPMethod{http.MethodHead},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal cors config: %v", err)
	}

	be := newWebsiteTestBackend(t, s3response.WebsiteConfiguration{
		IndexDocument: &s3response.IndexDocument{Suffix: "index.html"},
	}, nil, true)
	be.corsConfig = corsConfig

	resp := websiteRequestWithHeaders(t, be, http.MethodOptions, "/index.html", map[string]string{
		"Origin":                        "https://client.example",
		"Access-Control-Request-Method": http.MethodGet,
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if got := resp.Header.Get("x-amz-error-code"); got != "AccessForbidden" {
		t.Fatalf("x-amz-error-code = %q", got)
	}
	body := readBody(t, resp)
	for _, want := range []string{
		"<li>Method: OPTIONS</li>",
		"<li>ResourceType: OBJECT</li>",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q: %s", want, body)
		}
	}
}

func TestWebsiteHandlerMethodNotAllowed(t *testing.T) {
	be := newWebsiteTestBackend(t, s3response.WebsiteConfiguration{
		IndexDocument: &s3response.IndexDocument{Suffix: "index.html"},
	}, nil, true)

	resp := websiteRequestWithMethod(t, be, http.MethodPut, "/some-key")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
	if got := resp.Header.Get("Allow"); got != "GET, HEAD, OPTIONS" {
		t.Fatalf("Allow = %q, want %q", got, "GET, HEAD, OPTIONS")
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", got)
	}
	if got := resp.Header.Get("Server"); got != "VERSITYGW" {
		t.Fatalf("Server = %q, want %q", got, "VERSITYGW")
	}

	body := readBody(t, resp)
	for _, want := range []string{
		"<li>Code: MethodNotAllowed</li>",
		"<li>Method: PUT</li>",
		"<li>ResourceType: OBJECT</li>",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("method not allowed body missing %q: %s", want, body)
		}
	}
	if containsCall(be.calls, "GetBucketWebsite") {
		t.Fatalf("unmatched method should not load website config: %v", be.calls)
	}
}

func newWebsiteTestBackend(t *testing.T, config s3response.WebsiteConfiguration, objects map[string]string, public bool) *websiteTestBackend {
	t.Helper()

	data, err := xml.Marshal(config)
	if err != nil {
		t.Fatalf("marshal website config: %v", err)
	}
	if objects == nil {
		objects = map[string]string{}
	}

	return &websiteTestBackend{
		websiteConfig:   data,
		objects:         objects,
		objectRedirects: map[string]string{},
		public:          public,
	}
}

func websiteRequest(t *testing.T, be backend.Backend, path string) *http.Response {
	t.Helper()

	return websiteRequestWithMethod(t, be, http.MethodGet, path)
}

func websiteRequestWithMethod(t *testing.T, be backend.Backend, method, path string) *http.Response {
	t.Helper()

	return websiteRequestWithHeaders(t, be, method, path, nil)
}

func websiteRequestWithHeaders(t *testing.T, be backend.Backend, method, path string, headers map[string]string) *http.Response {
	t.Helper()

	return websiteRequestWithHostAndHeaders(t, be, method, "site.test", path, headers)
}

func websiteRequestWithHostAndHeaders(t *testing.T, be backend.Backend, method, host, path string, headers map[string]string) *http.Response {
	t.Helper()

	return websiteRequestWithDomainHostAndHeaders(t, be, "", method, host, path, headers)
}

func websiteRequestWithDomainHostAndHeaders(t *testing.T, be backend.Backend, domain, method, host, path string, headers map[string]string) *http.Response {
	t.Helper()

	app := fiber.New(fiber.Config{ServerHeader: "VERSITYGW"})
	registerWebsiteRoutes(app, be, domain)

	req := httptest.NewRequest(method, path, nil)
	req.Host = host
	req.Header.Set("Host", host)
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 0, FailOnTimeout: false})
	if err != nil {
		t.Fatalf("website request failed: %v", err)
	}
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return string(body)
}

func containsCall(calls []string, want string) bool {
	return firstCallIndex(calls, want) != -1
}

func countCalls(calls []string, want string) int {
	var count int
	for _, call := range calls {
		if call == want {
			count++
		}
	}
	return count
}

func firstCallIndex(calls []string, want string) int {
	for i, call := range calls {
		if call == want {
			return i
		}
	}
	return -1
}
