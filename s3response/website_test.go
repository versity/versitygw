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

package s3response

import (
	"errors"
	"testing"

	"github.com/versity/versitygw/s3err"
)

func TestWebsiteConfiguration_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  WebsiteConfiguration
		wantErr bool
		errCode string
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
			errCode: "MalformedXML",
		},
		{
			name: "empty index suffix",
			config: WebsiteConfiguration{
				IndexDocument: &IndexDocument{Suffix: ""},
			},
			wantErr: true,
			errCode: "InvalidArgument",
		},
		{
			name: "index suffix with slash",
			config: WebsiteConfiguration{
				IndexDocument: &IndexDocument{Suffix: "dir/index.html"},
			},
			wantErr: true,
			errCode: "InvalidArgument",
		},
		{
			name: "redirect all with index document",
			config: WebsiteConfiguration{
				RedirectAllRequestsTo: &RedirectAllRequestsTo{HostName: "example.com"},
				IndexDocument:         &IndexDocument{Suffix: "index.html"},
			},
			wantErr: true,
			errCode: "MalformedXML",
		},
		{
			name: "redirect all with empty hostname",
			config: WebsiteConfiguration{
				RedirectAllRequestsTo: &RedirectAllRequestsTo{HostName: ""},
			},
			wantErr: true,
			errCode: "MalformedXML",
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
			errCode: "InvalidRequest",
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
			errCode: "InvalidRequest",
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
			errCode: "InvalidRequest",
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
			errCode: "InvalidArgument",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				var apiErr s3err.S3Error
				if !errors.As(err, &apiErr) {
					t.Fatalf("expected S3 error, got %T: %v", err, err)
				}
				if apiErr.BaseError().Code != tt.errCode {
					t.Errorf("expected error code %q, got %q", tt.errCode, apiErr.BaseError().Code)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestWebsiteConfiguration_MatchPrefetchRoutingRuleUsesPrefixOnlyRules(t *testing.T) {
	config := WebsiteConfiguration{
		IndexDocument: &IndexDocument{Suffix: "index.html"},
		RoutingRules: []RoutingRule{
			{
				Condition: &RoutingRuleCondition{
					HttpErrorCodeReturnedEquals: "404",
				},
				Redirect: Redirect{
					HostName: "error.example.com",
				},
			},
			{
				Condition: &RoutingRuleCondition{
					KeyPrefixEquals:             "old/",
					HttpErrorCodeReturnedEquals: "404",
				},
				Redirect: Redirect{
					HostName: "both.example.com",
				},
			},
			{
				Condition: &RoutingRuleCondition{
					KeyPrefixEquals: "old/",
				},
				Redirect: Redirect{
					HostName: "prefix.example.com",
				},
			},
		},
	}

	rule := config.MatchPrefetchRoutingRule("old/page.html")
	if rule == nil {
		t.Fatal("expected a matching rule, got nil")
	}
	if rule.Redirect.HostName != "prefix.example.com" {
		t.Fatalf("expected prefix-only rule to match, got %q", rule.Redirect.HostName)
	}
}

func TestRoutingRuleCondition_MatchesUsesAndLogic(t *testing.T) {
	condition := RoutingRuleCondition{
		KeyPrefixEquals:             "old/",
		HttpErrorCodeReturnedEquals: "404",
	}

	tests := []struct {
		name       string
		key        string
		statusCode int
		want       bool
	}{
		{
			name:       "both match",
			key:        "old/missing.html",
			statusCode: 404,
			want:       true,
		},
		{
			name:       "prefix only",
			key:        "old/existing.html",
			statusCode: 200,
			want:       false,
		},
		{
			name:       "status only",
			key:        "other/missing.html",
			statusCode: 404,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := condition.Matches(tt.key, tt.statusCode); got != tt.want {
				t.Fatalf("Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}
