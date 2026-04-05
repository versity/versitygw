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

package s3response

import (
	"encoding/xml"
	"testing"

	"github.com/versity/versitygw/s3err"
)

func TestWebsiteConfiguration_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  WebsiteConfiguration
		wantErr bool
		errCode s3err.ErrorCode
	}{
		{
			name: "valid index document only",
			config: WebsiteConfiguration{
				IndexDocument: &IndexDocument{Suffix: "index.html"},
			},
		},
		{
			name: "valid index and error document",
			config: WebsiteConfiguration{
				IndexDocument: &IndexDocument{Suffix: "index.html"},
				ErrorDocument: &ErrorDocument{Key: "error.html"},
			},
		},
		{
			name: "valid redirect all requests",
			config: WebsiteConfiguration{
				RedirectAllRequestsTo: &RedirectAllRequestsTo{
					HostName: "example.com",
					Protocol: "https",
				},
			},
		},
		{
			name: "valid routing rules",
			config: WebsiteConfiguration{
				IndexDocument: &IndexDocument{Suffix: "index.html"},
				RoutingRules: []RoutingRule{
					{
						Condition: &RoutingRuleCondition{
							KeyPrefixEquals: "docs/",
						},
						Redirect: Redirect{
							ReplaceKeyPrefixWith: "documents/",
						},
					},
				},
			},
		},
		{
			name:    "missing index document",
			config:  WebsiteConfiguration{},
			wantErr: true,
			errCode: s3err.ErrInvalidWebsiteConfiguration,
		},
		{
			name: "empty index suffix",
			config: WebsiteConfiguration{
				IndexDocument: &IndexDocument{Suffix: ""},
			},
			wantErr: true,
			errCode: s3err.ErrInvalidWebsiteSuffix,
		},
		{
			name: "index suffix with slash",
			config: WebsiteConfiguration{
				IndexDocument: &IndexDocument{Suffix: "dir/index.html"},
			},
			wantErr: true,
			errCode: s3err.ErrInvalidWebsiteSuffix,
		},
		{
			name: "redirect all with index document",
			config: WebsiteConfiguration{
				RedirectAllRequestsTo: &RedirectAllRequestsTo{HostName: "example.com"},
				IndexDocument:         &IndexDocument{Suffix: "index.html"},
			},
			wantErr: true,
			errCode: s3err.ErrInvalidWebsiteConfiguration,
		},
		{
			name: "redirect all with empty hostname",
			config: WebsiteConfiguration{
				RedirectAllRequestsTo: &RedirectAllRequestsTo{HostName: ""},
			},
			wantErr: true,
			errCode: s3err.ErrInvalidWebsiteConfiguration,
		},
		{
			name: "redirect all with invalid protocol",
			config: WebsiteConfiguration{
				RedirectAllRequestsTo: &RedirectAllRequestsTo{
					HostName: "example.com",
					Protocol: "ftp",
				},
			},
			wantErr: true,
			errCode: s3err.ErrInvalidWebsiteConfiguration,
		},
		{
			name: "routing rule with both replace key fields",
			config: WebsiteConfiguration{
				IndexDocument: &IndexDocument{Suffix: "index.html"},
				RoutingRules: []RoutingRule{
					{
						Redirect: Redirect{
							ReplaceKeyWith:       "newkey",
							ReplaceKeyPrefixWith: "newprefix/",
						},
					},
				},
			},
			wantErr: true,
			errCode: s3err.ErrInvalidWebsiteConfiguration,
		},
		{
			name: "routing rule with invalid redirect code",
			config: WebsiteConfiguration{
				IndexDocument: &IndexDocument{Suffix: "index.html"},
				RoutingRules: []RoutingRule{
					{
						Redirect: Redirect{
							HttpRedirectCode: "200",
						},
					},
				},
			},
			wantErr: true,
			errCode: s3err.ErrInvalidWebsiteRedirectCode,
		},
		{
			name: "routing rule with valid redirect code",
			config: WebsiteConfiguration{
				IndexDocument: &IndexDocument{Suffix: "index.html"},
				RoutingRules: []RoutingRule{
					{
						Redirect: Redirect{
							HttpRedirectCode: "301",
							HostName:         "example.com",
						},
					},
				},
			},
		},
		{
			name: "error document with empty key",
			config: WebsiteConfiguration{
				IndexDocument: &IndexDocument{Suffix: "index.html"},
				ErrorDocument: &ErrorDocument{Key: ""},
			},
			wantErr: true,
			errCode: s3err.ErrInvalidWebsiteConfiguration,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				apiErr, ok := err.(s3err.APIError)
				if !ok {
					// wrapped error from routing rule validation
					return
				}
				expectedErr := s3err.GetAPIError(tt.errCode)
				if apiErr.Code != expectedErr.Code {
					t.Errorf("expected error code %q, got %q", expectedErr.Code, apiErr.Code)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestWebsiteConfiguration_XMLRoundTrip(t *testing.T) {
	original := WebsiteConfiguration{
		IndexDocument: &IndexDocument{Suffix: "index.html"},
		ErrorDocument: &ErrorDocument{Key: "error.html"},
		RoutingRules: []RoutingRule{
			{
				Condition: &RoutingRuleCondition{
					KeyPrefixEquals:             "docs/",
					HttpErrorCodeReturnedEquals: "404",
				},
				Redirect: Redirect{
					HostName:             "example.com",
					Protocol:             "https",
					HttpRedirectCode:     "301",
					ReplaceKeyPrefixWith: "documents/",
				},
			},
		},
	}

	data, err := xml.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var parsed WebsiteConfiguration
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if parsed.IndexDocument == nil || parsed.IndexDocument.Suffix != "index.html" {
		t.Error("IndexDocument.Suffix mismatch")
	}
	if parsed.ErrorDocument == nil || parsed.ErrorDocument.Key != "error.html" {
		t.Error("ErrorDocument.Key mismatch")
	}
	if len(parsed.RoutingRules) != 1 {
		t.Fatalf("expected 1 routing rule, got %d", len(parsed.RoutingRules))
	}
	rule := parsed.RoutingRules[0]
	if rule.Condition == nil || rule.Condition.KeyPrefixEquals != "docs/" {
		t.Error("RoutingRule Condition.KeyPrefixEquals mismatch")
	}
	if rule.Redirect.HostName != "example.com" {
		t.Error("RoutingRule Redirect.HostName mismatch")
	}
	if rule.Redirect.ReplaceKeyPrefixWith != "documents/" {
		t.Error("RoutingRule Redirect.ReplaceKeyPrefixWith mismatch")
	}
}

func TestParseWebsiteConfigOutput(t *testing.T) {
	xmlData := `<WebsiteConfiguration>
		<IndexDocument><Suffix>index.html</Suffix></IndexDocument>
		<ErrorDocument><Key>error.html</Key></ErrorDocument>
	</WebsiteConfiguration>`

	config, err := ParseWebsiteConfigOutput([]byte(xmlData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if config.IndexDocument == nil || config.IndexDocument.Suffix != "index.html" {
		t.Error("IndexDocument.Suffix mismatch")
	}
	if config.ErrorDocument == nil || config.ErrorDocument.Key != "error.html" {
		t.Error("ErrorDocument.Key mismatch")
	}
}

func TestParseWebsiteConfigOutput_InvalidXML(t *testing.T) {
	_, err := ParseWebsiteConfigOutput([]byte("not xml"))
	if err == nil {
		t.Fatal("expected error for invalid XML")
	}
}

func TestWebsiteConfiguration_MatchPreRequestRule(t *testing.T) {
	tests := []struct {
		name     string
		config   WebsiteConfiguration
		key      string
		wantNil  bool
		wantHost string // expected redirect HostName if matched
	}{
		{
			name: "no routing rules",
			config: WebsiteConfiguration{
				IndexDocument: &IndexDocument{Suffix: "index.html"},
			},
			key:     "docs/page.html",
			wantNil: true,
		},
		{
			name: "key prefix match",
			config: WebsiteConfiguration{
				IndexDocument: &IndexDocument{Suffix: "index.html"},
				RoutingRules: []RoutingRule{
					{
						Condition: &RoutingRuleCondition{
							KeyPrefixEquals: "docs/",
						},
						Redirect: Redirect{
							HostName: "docs.example.com",
						},
					},
				},
			},
			key:      "docs/page.html",
			wantHost: "docs.example.com",
		},
		{
			name: "key prefix does not match",
			config: WebsiteConfiguration{
				IndexDocument: &IndexDocument{Suffix: "index.html"},
				RoutingRules: []RoutingRule{
					{
						Condition: &RoutingRuleCondition{
							KeyPrefixEquals: "docs/",
						},
						Redirect: Redirect{
							HostName: "docs.example.com",
						},
					},
				},
			},
			key:     "images/photo.jpg",
			wantNil: true,
		},
		{
			name: "unconditional rule (no condition)",
			config: WebsiteConfiguration{
				IndexDocument: &IndexDocument{Suffix: "index.html"},
				RoutingRules: []RoutingRule{
					{
						Redirect: Redirect{
							HostName: "redirect.example.com",
						},
					},
				},
			},
			key:      "anything",
			wantHost: "redirect.example.com",
		},
		{
			name: "skips post-request rules",
			config: WebsiteConfiguration{
				IndexDocument: &IndexDocument{Suffix: "index.html"},
				RoutingRules: []RoutingRule{
					{
						Condition: &RoutingRuleCondition{
							HttpErrorCodeReturnedEquals: "404",
							KeyPrefixEquals:             "docs/",
						},
						Redirect: Redirect{
							HostName: "error.example.com",
						},
					},
				},
			},
			key:     "docs/page.html",
			wantNil: true,
		},
		{
			name: "first matching rule wins",
			config: WebsiteConfiguration{
				IndexDocument: &IndexDocument{Suffix: "index.html"},
				RoutingRules: []RoutingRule{
					{
						Condition: &RoutingRuleCondition{
							KeyPrefixEquals: "docs/",
						},
						Redirect: Redirect{
							HostName: "first.example.com",
						},
					},
					{
						Condition: &RoutingRuleCondition{
							KeyPrefixEquals: "docs/api/",
						},
						Redirect: Redirect{
							HostName: "second.example.com",
						},
					},
				},
			},
			key:      "docs/api/endpoint",
			wantHost: "first.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := tt.config.MatchPreRequestRule(tt.key)
			if tt.wantNil {
				if rule != nil {
					t.Fatalf("expected nil, got rule with redirect to %q", rule.Redirect.HostName)
				}
				return
			}
			if rule == nil {
				t.Fatal("expected a matching rule, got nil")
			}
			if rule.Redirect.HostName != tt.wantHost {
				t.Errorf("expected redirect host %q, got %q", tt.wantHost, rule.Redirect.HostName)
			}
		})
	}
}

func TestWebsiteConfiguration_MatchPostRequestRule(t *testing.T) {
	tests := []struct {
		name          string
		config        WebsiteConfiguration
		key           string
		httpErrorCode string
		wantNil       bool
		wantHost      string
	}{
		{
			name: "no routing rules",
			config: WebsiteConfiguration{
				IndexDocument: &IndexDocument{Suffix: "index.html"},
			},
			key:           "page.html",
			httpErrorCode: "404",
			wantNil:       true,
		},
		{
			name: "error code match",
			config: WebsiteConfiguration{
				IndexDocument: &IndexDocument{Suffix: "index.html"},
				RoutingRules: []RoutingRule{
					{
						Condition: &RoutingRuleCondition{
							HttpErrorCodeReturnedEquals: "404",
						},
						Redirect: Redirect{
							HostName: "notfound.example.com",
						},
					},
				},
			},
			key:           "page.html",
			httpErrorCode: "404",
			wantHost:      "notfound.example.com",
		},
		{
			name: "error code does not match",
			config: WebsiteConfiguration{
				IndexDocument: &IndexDocument{Suffix: "index.html"},
				RoutingRules: []RoutingRule{
					{
						Condition: &RoutingRuleCondition{
							HttpErrorCodeReturnedEquals: "404",
						},
						Redirect: Redirect{
							HostName: "notfound.example.com",
						},
					},
				},
			},
			key:           "page.html",
			httpErrorCode: "403",
			wantNil:       true,
		},
		{
			name: "error code and key prefix both match",
			config: WebsiteConfiguration{
				IndexDocument: &IndexDocument{Suffix: "index.html"},
				RoutingRules: []RoutingRule{
					{
						Condition: &RoutingRuleCondition{
							HttpErrorCodeReturnedEquals: "404",
							KeyPrefixEquals:             "docs/",
						},
						Redirect: Redirect{
							HostName: "docs-error.example.com",
						},
					},
				},
			},
			key:           "docs/missing.html",
			httpErrorCode: "404",
			wantHost:      "docs-error.example.com",
		},
		{
			name: "error code matches but key prefix does not",
			config: WebsiteConfiguration{
				IndexDocument: &IndexDocument{Suffix: "index.html"},
				RoutingRules: []RoutingRule{
					{
						Condition: &RoutingRuleCondition{
							HttpErrorCodeReturnedEquals: "404",
							KeyPrefixEquals:             "docs/",
						},
						Redirect: Redirect{
							HostName: "docs-error.example.com",
						},
					},
				},
			},
			key:           "images/missing.jpg",
			httpErrorCode: "404",
			wantNil:       true,
		},
		{
			name: "skips pre-request rules (no error code condition)",
			config: WebsiteConfiguration{
				IndexDocument: &IndexDocument{Suffix: "index.html"},
				RoutingRules: []RoutingRule{
					{
						Condition: &RoutingRuleCondition{
							KeyPrefixEquals: "docs/",
						},
						Redirect: Redirect{
							HostName: "pre-request.example.com",
						},
					},
				},
			},
			key:           "docs/page.html",
			httpErrorCode: "404",
			wantNil:       true,
		},
		{
			name: "skips rules with no condition",
			config: WebsiteConfiguration{
				IndexDocument: &IndexDocument{Suffix: "index.html"},
				RoutingRules: []RoutingRule{
					{
						Redirect: Redirect{
							HostName: "unconditional.example.com",
						},
					},
				},
			},
			key:           "page.html",
			httpErrorCode: "404",
			wantNil:       true,
		},
		{
			name: "first matching rule wins",
			config: WebsiteConfiguration{
				IndexDocument: &IndexDocument{Suffix: "index.html"},
				RoutingRules: []RoutingRule{
					{
						Condition: &RoutingRuleCondition{
							HttpErrorCodeReturnedEquals: "404",
						},
						Redirect: Redirect{
							HostName: "first.example.com",
						},
					},
					{
						Condition: &RoutingRuleCondition{
							HttpErrorCodeReturnedEquals: "404",
							KeyPrefixEquals:             "docs/",
						},
						Redirect: Redirect{
							HostName: "second.example.com",
						},
					},
				},
			},
			key:           "docs/page.html",
			httpErrorCode: "404",
			wantHost:      "first.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := tt.config.MatchPostRequestRule(tt.key, tt.httpErrorCode)
			if tt.wantNil {
				if rule != nil {
					t.Fatalf("expected nil, got rule with redirect to %q", rule.Redirect.HostName)
				}
				return
			}
			if rule == nil {
				t.Fatal("expected a matching rule, got nil")
			}
			if rule.Redirect.HostName != tt.wantHost {
				t.Errorf("expected redirect host %q, got %q", tt.wantHost, rule.Redirect.HostName)
			}
		})
	}
}
