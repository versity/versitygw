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
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

const maxWebsiteConfigSize = 131072

func PutBucketWebsite_non_existing_bucket(s *S3Conf) error {
	testName := "PutBucketWebsite_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketWebsite(ctx, &s3.PutBucketWebsiteInput{
			Bucket: getPtr("non-existing-bucket"),
			WebsiteConfiguration: &types.WebsiteConfiguration{
				IndexDocument: &types.IndexDocument{
					Suffix: getPtr("index.html"),
				},
			},
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket))
	})
}

func PutBucketWebsite_empty_suffix(s *S3Conf) error {
	testName := "PutBucketWebsite_empty_suffix"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketWebsite(ctx, &s3.PutBucketWebsiteInput{
			Bucket: &bucket,
			WebsiteConfiguration: &types.WebsiteConfiguration{
				IndexDocument: &types.IndexDocument{
					Suffix: getPtr(""),
				},
			},
		})
		cancel()
		return checkApiErr(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgIndexDocumentSuffix, ""))
	})
}

func PutBucketWebsite_suffix_with_slash(s *S3Conf) error {
	testName := "PutBucketWebsite_suffix_with_slash"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketWebsite(ctx, &s3.PutBucketWebsiteInput{
			Bucket: &bucket,
			WebsiteConfiguration: &types.WebsiteConfiguration{
				IndexDocument: &types.IndexDocument{
					Suffix: getPtr("/index.html"),
				},
			},
		})
		cancel()
		return checkApiErr(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgIndexDocumentSuffix, "/index.html"))
	})
}

func PutBucketWebsite_invalid_redirect_protocol(s *S3Conf) error {
	testName := "PutBucketWebsite_invalid_redirect_protocol"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketWebsite(ctx, &s3.PutBucketWebsiteInput{
			Bucket: &bucket,
			WebsiteConfiguration: &types.WebsiteConfiguration{
				RedirectAllRequestsTo: &types.RedirectAllRequestsTo{
					HostName: getPtr("example.com"),
					Protocol: types.Protocol("ftp"),
				},
			},
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidWebsiteRedirectProtocol))
	})
}

func PutBucketWebsite_redirectAll_index_error_routingRules(s *S3Conf) error {
	testName := "PutBucketWebsite_redirectAll_index_error_routingRules"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for _, test := range []struct {
			name   string
			config *types.WebsiteConfiguration
		}{
			{
				name: "index document",
				config: &types.WebsiteConfiguration{
					RedirectAllRequestsTo: &types.RedirectAllRequestsTo{
						HostName: getPtr("example.com"),
					},
					IndexDocument: &types.IndexDocument{
						Suffix: getPtr("index.html"),
					},
				},
			},
			{
				name: "error document",
				config: &types.WebsiteConfiguration{
					RedirectAllRequestsTo: &types.RedirectAllRequestsTo{
						HostName: getPtr("example.com"),
					},
					ErrorDocument: &types.ErrorDocument{
						Key: getPtr("error.html"),
					},
				},
			},
			{
				name: "routing rules",
				config: &types.WebsiteConfiguration{
					RedirectAllRequestsTo: &types.RedirectAllRequestsTo{
						HostName: getPtr("example.com"),
					},
					RoutingRules: []types.RoutingRule{
						{
							Redirect: &types.Redirect{
								HostName: getPtr("redirect.example.com"),
							},
						},
					},
				},
			},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.PutBucketWebsite(ctx, &s3.PutBucketWebsiteInput{
				Bucket:               &bucket,
				WebsiteConfiguration: test.config,
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMalformedXML)); err != nil {
				return fmt.Errorf("%s: %w", test.name, err)
			}
		}

		return nil
	})
}

func PutBucketWebsite_invalid_routing_rule_protocol(s *S3Conf) error {
	testName := "PutBucketWebsite_invalid_routing_rule_protocol"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketWebsite(ctx, &s3.PutBucketWebsiteInput{
			Bucket: &bucket,
			WebsiteConfiguration: &types.WebsiteConfiguration{
				IndexDocument: &types.IndexDocument{
					Suffix: getPtr("index.html"),
				},
				RoutingRules: []types.RoutingRule{
					{
						Redirect: &types.Redirect{
							HostName: getPtr("example.com"),
							Protocol: types.Protocol("ftp"),
						},
					},
				},
			},
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidWebsiteRedirectProtocol))
	})
}

func PutBucketWebsite_empty_error_document_key(s *S3Conf) error {
	testName := "PutBucketWebsite_empty_error_document_key"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketWebsite(ctx, &s3.PutBucketWebsiteInput{
			Bucket: &bucket,
			WebsiteConfiguration: &types.WebsiteConfiguration{
				IndexDocument: &types.IndexDocument{
					Suffix: getPtr("index.html"),
				},
				ErrorDocument: &types.ErrorDocument{
					Key: getPtr(""),
				},
			},
		})
		cancel()
		return checkApiErr(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgErrorDocumentKey, ""))
	})
}

func PutBucketWebsite_too_many_routing_rules(s *S3Conf) error {
	testName := "PutBucketWebsite_too_many_routing_rules"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		routingRules := make([]types.RoutingRule, 51)
		for i := range routingRules {
			routingRules[i] = types.RoutingRule{
				Condition: &types.Condition{
					KeyPrefixEquals: getPtr(fmt.Sprintf("prefix-%d/", i)),
				},
				Redirect: &types.Redirect{
					ReplaceKeyPrefixWith: getPtr(fmt.Sprintf("replacement-%d/", i)),
				},
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketWebsite(ctx, &s3.PutBucketWebsiteInput{
			Bucket: &bucket,
			WebsiteConfiguration: &types.WebsiteConfiguration{
				IndexDocument: &types.IndexDocument{
					Suffix: getPtr("index.html"),
				},
				RoutingRules: routingRules,
			},
		})
		cancel()
		return checkApiErr(err, s3err.GetWebsiteRoutingRulesLimitedErr(51))
	})
}

func PutBucketWebsite_routing_rule_replace_key_and_prefix(s *S3Conf) error {
	testName := "PutBucketWebsite_routing_rule_replace_key_and_prefix"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketWebsite(ctx, &s3.PutBucketWebsiteInput{
			Bucket: &bucket,
			WebsiteConfiguration: &types.WebsiteConfiguration{
				IndexDocument: &types.IndexDocument{
					Suffix: getPtr("index.html"),
				},
				RoutingRules: []types.RoutingRule{
					{
						Redirect: &types.Redirect{
							ReplaceKeyWith:       getPtr("replacement.html"),
							ReplaceKeyPrefixWith: getPtr("replacement-prefix/"),
						},
					},
				},
			},
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrBothReplaceKeyAndPrefix))
	})
}

func PutBucketWebsite_invalid_http_redirect_code(s *S3Conf) error {
	testName := "PutBucketWebsite_invalid_http_redirect_code"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for _, test := range []struct {
			code        string
			expectedErr s3err.S3Error
		}{
			{code: "300", expectedErr: s3err.GetInvalidRedirectCodeErr(300)},
			{code: "306", expectedErr: s3err.GetInvalidRedirectCodeErr(306)},
			{code: "309", expectedErr: s3err.GetInvalidRedirectCodeErr(309)},
			{code: "399", expectedErr: s3err.GetInvalidRedirectCodeErr(399)},
			{code: "jibberish", expectedErr: s3err.GetAPIError(s3err.ErrMalformedXML)},
			{code: "3xx", expectedErr: s3err.GetAPIError(s3err.ErrMalformedXML)},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.PutBucketWebsite(ctx, &s3.PutBucketWebsiteInput{
				Bucket: &bucket,
				WebsiteConfiguration: &types.WebsiteConfiguration{
					IndexDocument: &types.IndexDocument{
						Suffix: getPtr("index.html"),
					},
					RoutingRules: []types.RoutingRule{
						{
							Redirect: &types.Redirect{
								HostName:         getPtr("example.com"),
								HttpRedirectCode: getPtr(test.code),
							},
						},
					},
				},
			})
			cancel()
			if err := checkApiErr(err, test.expectedErr); err != nil {
				return fmt.Errorf("code %q: %w", test.code, err)
			}
		}

		return nil
	})
}

func PutBucketWebsite_invalid_http_error_code(s *S3Conf) error {
	testName := "PutBucketWebsite_invalid_http_error_code"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for _, test := range []struct {
			code        string
			expectedErr s3err.S3Error
		}{
			{code: "399", expectedErr: s3err.GetInvalidHTTPErrorCodeErr(399)},
			{code: "418", expectedErr: s3err.GetInvalidHTTPErrorCodeErr(418)},
			{code: "499", expectedErr: s3err.GetInvalidHTTPErrorCodeErr(499)},
			{code: "506", expectedErr: s3err.GetInvalidHTTPErrorCodeErr(506)},
			{code: "jibberish", expectedErr: s3err.GetAPIError(s3err.ErrMalformedXML)},
			{code: "4xx", expectedErr: s3err.GetAPIError(s3err.ErrMalformedXML)},
		} {
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
								HttpErrorCodeReturnedEquals: getPtr(test.code),
							},
							Redirect: &types.Redirect{
								HostName: getPtr("example.com"),
							},
						},
					},
				},
			})
			cancel()
			if err := checkApiErr(err, test.expectedErr); err != nil {
				return fmt.Errorf("code %q: %w", test.code, err)
			}
		}

		return nil
	})
}

func PutBucketWebsite_request_too_large(s *S3Conf) error {
	testName := "PutBucketWebsite_request_too_large"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		longValue := strings.Repeat("a", 2048)
		routingRules := make([]types.RoutingRule, 50)
		for i := range routingRules {
			routingRules[i] = types.RoutingRule{
				Condition: &types.Condition{
					KeyPrefixEquals: getPtr(fmt.Sprintf("prefix-%d-%s", i, longValue)),
				},
				Redirect: &types.Redirect{
					HostName:         getPtr("example.com"),
					ReplaceKeyWith:   getPtr(fmt.Sprintf("replacement-%d-%s", i, longValue)),
					HttpRedirectCode: getPtr("301"),
				},
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketWebsite(ctx, &s3.PutBucketWebsiteInput{
			Bucket: &bucket,
			WebsiteConfiguration: &types.WebsiteConfiguration{
				IndexDocument: &types.IndexDocument{
					Suffix: getPtr("index.html"),
				},
				RoutingRules: routingRules,
			},
		})
		cancel()
		return checkApiErr(err, s3err.GetMaxMessageLengthExceeded(maxWebsiteConfigSize))
	})
}

func PutBucketWebsite_success(s *S3Conf) error {
	testName := "PutBucketWebsite_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
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

		return nil
	})
}

func PutBucketWebsite_success_redirect_all(s *S3Conf) error {
	testName := "PutBucketWebsite_success_redirect_all"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketWebsite(ctx, &s3.PutBucketWebsiteInput{
			Bucket: &bucket,
			WebsiteConfiguration: &types.WebsiteConfiguration{
				RedirectAllRequestsTo: &types.RedirectAllRequestsTo{
					HostName: getPtr("example.com"),
					Protocol: types.ProtocolHttps,
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
