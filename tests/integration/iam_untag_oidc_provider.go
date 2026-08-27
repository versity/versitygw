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
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/versity/versitygw/iamapi/iamerr"
)

func IAMUntagOpenIDConnectProvider_missing_arn(s *S3Conf) error {
	testName := "IAMUntagOpenIDConnectProvider_missing_arn"
	body := []byte(url.Values{
		"Action":           {"UntagOpenIDConnectProvider"},
		"Version":          {"2010-05-08"},
		"TagKeys.member.1": {"env"},
	}.Encode())
	return authHandler(s, &authConfig{
		testName: testName,
		method:   http.MethodPost,
		service:  "iam",
		region:   iamAuthRegion,
		body:     body,
		date:     time.Now().UTC(),
		headers:  map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	}, func(req *http.Request) error {
		return checkIAMAuthRequest(s, req, iamerr.MissingValue("openIDConnectProviderArn"))
	})
}

func IAMUntagOpenIDConnectProvider_invalid_arn(s *S3Conf) error {
	testName := "IAMUntagOpenIDConnectProvider_invalid_arn"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		tests := []struct {
			name string
			arn  string
			want iamerr.Error
		}{
			{"too_short", strings.Repeat("a", 19), iamerr.ValueTooShort("openIDConnectProviderArn", 20)},
			{"too_long", strings.Repeat("a", 2049), iamerr.ValueTooLong("openIDConnectProviderArn", 2048)},
			{"wrong_resource_type", "arn:aws:iam::000000000000:role/some-role", iamerr.ValidationError("Invalid resource type in ARN")},
			{"foreign_account_id", "arn:aws:iam::123456789012:oidc-provider/example.com", iamerr.AccessDeniedOIDCProvider("000000000000", "arn:aws:iam::123456789012:oidc-provider/example.com")},
		}
		for _, tt := range tests {
			_, err := untagOIDCProvider(client, &iam.UntagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: aws.String(tt.arn),
				TagKeys:                  []string{"env"},
			})
			if checkErr := checkIAMApiErr(err, tt.want); checkErr != nil {
				return fmt.Errorf("%s: %w", tt.name, checkErr)
			}
		}
		return nil
	})
}

func IAMUntagOpenIDConnectProvider_missing_tag_keys(s *S3Conf) error {
	testName := "IAMUntagOpenIDConnectProvider_missing_tag_keys"
	body := []byte(url.Values{
		"Action":                   {"UntagOpenIDConnectProvider"},
		"Version":                  {"2010-05-08"},
		"OpenIDConnectProviderArn": {oidcProviderArn("https://validprovider.example.com")},
	}.Encode())
	return authHandler(s, &authConfig{
		testName: testName,
		method:   http.MethodPost,
		service:  "iam",
		region:   iamAuthRegion,
		body:     body,
		date:     time.Now().UTC(),
		headers:  map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	}, func(req *http.Request) error {
		return checkIAMAuthRequest(s, req, iamerr.MissingValue("tagKeys"))
	})
}

func IAMUntagOpenIDConnectProvider_invalid_tag_key(s *S3Conf) error {
	testName := "IAMUntagOpenIDConnectProvider_invalid_tag_key"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn := oidcProviderArn("https://validprovider.example.com")
		for _, tagKey := range []string{"", strings.Repeat("k", 129), "invalid*key"} {
			_, err := untagOIDCProvider(client, &iam.UntagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: &arn,
				TagKeys:                  []string{tagKey},
			})
			if checkErr := checkIAMApiErr(err, iamerr.GetAPIError(iamerr.ErrInvalidTagKeys)); checkErr != nil {
				return fmt.Errorf("tag key %q: %w", tagKey, checkErr)
			}
		}
		return nil
	})
}

func IAMUntagOpenIDConnectProvider_too_many_tag_keys(s *S3Conf) error {
	testName := "IAMUntagOpenIDConnectProvider_too_many_tag_keys"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		tagKeys := make([]string, 0, maxIAMTagMembersPerRequest+1)
		for i := range maxIAMTagMembersPerRequest + 1 {
			tagKeys = append(tagKeys, fmt.Sprintf("key%d", i+1))
		}

		_, err := untagOIDCProvider(client, &iam.UntagOpenIDConnectProviderInput{
			OpenIDConnectProviderArn: aws.String(oidcProviderArn("https://validprovider.example.com")),
			TagKeys:                  tagKeys,
		})
		return checkIAMApiErr(err, iamerr.GetAPIError(iamerr.ErrTooManyTagKeys))
	})
}

func IAMUntagOpenIDConnectProvider_non_existing_provider(s *S3Conf) error {
	testName := "IAMUntagOpenIDConnectProvider_non_existing_provider"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn := oidcProviderArn("https://" + genRandString(16) + ".example.com")
		_, err := untagOIDCProvider(client, &iam.UntagOpenIDConnectProviderInput{
			OpenIDConnectProviderArn: &arn,
			TagKeys:                  []string{"env"},
		})
		return checkIAMApiErr(err, iamerr.NoSuchEntityOIDCProviderDelete(arn))
	})
}

func IAMUntagOpenIDConnectProvider_success(s *S3Conf) error {
	testName := "IAMUntagOpenIDConnectProvider_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn, err := createTestOIDCProvider(client)
		if err != nil {
			return err
		}

		checkErr := func() error {
			if _, err := tagOIDCProvider(client, &iam.TagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: &arn,
				Tags:                     iamTagList(map[string]string{"env": "prod", "team": "storage", "owner": "alice"}),
			}); err != nil {
				return err
			}

			out, err := untagOIDCProvider(client, &iam.UntagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: &arn,
				TagKeys:                  []string{"env", "owner"},
			})
			if err != nil {
				return err
			}
			if requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata); !ok || requestID == "" {
				return fmt.Errorf("expected UntagOpenIDConnectProvider response request id")
			}

			return checkIAMOIDCProviderTags(client, arn, map[string]string{"team": "storage"})
		}()

		deleteErr := deleteOIDCProvider(client, arn)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

// IAMUntagOpenIDConnectProvider_removal_is_idempotent covers the two ways a
// request can name a key that removes nothing: a key the provider never
// carried, and the same key twice in one request. Neither is an error —
// unlike TagOpenIDConnectProvider, which rejects a repeated key outright.
func IAMUntagOpenIDConnectProvider_removal_is_idempotent(s *S3Conf) error {
	testName := "IAMUntagOpenIDConnectProvider_removal_is_idempotent"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn, err := createTestOIDCProvider(client)
		if err != nil {
			return err
		}

		checkErr := func() error {
			if _, err := tagOIDCProvider(client, &iam.TagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: &arn,
				Tags:                     iamTagList(map[string]string{"env": "prod"}),
			}); err != nil {
				return err
			}

			if _, err := untagOIDCProvider(client, &iam.UntagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: &arn,
				TagKeys:                  []string{"never-existed"},
			}); err != nil {
				return fmt.Errorf("removing a key the provider does not carry: %w", err)
			}
			if err := checkIAMOIDCProviderTags(client, arn, map[string]string{"env": "prod"}); err != nil {
				return err
			}

			if _, err := untagOIDCProvider(client, &iam.UntagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: &arn,
				TagKeys:                  []string{"env", "env"},
			}); err != nil {
				return fmt.Errorf("removing the same key twice: %w", err)
			}
			return checkIAMOIDCProviderTags(client, arn, map[string]string{})
		}()

		deleteErr := deleteOIDCProvider(client, arn)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

// IAMUntagOpenIDConnectProvider_case_sensitive_key covers removal by a
// differently-cased key: provider tag keys are compared exactly, so the
// stored tag survives and only its exact key removes it.
func IAMUntagOpenIDConnectProvider_case_sensitive_key(s *S3Conf) error {
	testName := "IAMUntagOpenIDConnectProvider_case_sensitive_key"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn, err := createTestOIDCProvider(client)
		if err != nil {
			return err
		}

		checkErr := func() error {
			if _, err := tagOIDCProvider(client, &iam.TagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: &arn,
				Tags:                     iamTagList(map[string]string{"env": "prod"}),
			}); err != nil {
				return err
			}
			if _, err := untagOIDCProvider(client, &iam.UntagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: &arn,
				TagKeys:                  []string{"EnV"},
			}); err != nil {
				return err
			}
			if err := checkIAMOIDCProviderTags(client, arn, map[string]string{"env": "prod"}); err != nil {
				return err
			}

			if _, err := untagOIDCProvider(client, &iam.UntagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: &arn,
				TagKeys:                  []string{"env"},
			}); err != nil {
				return err
			}
			return checkIAMOIDCProviderTags(client, arn, map[string]string{})
		}()

		deleteErr := deleteOIDCProvider(client, arn)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

// IAMUntagOpenIDConnectProvider_removes_only_named_keys covers a partial
// removal leaving the rest of the set intact, including a key whose name
// only prefixes one of the supplied keys — matching is exact, not by prefix.
func IAMUntagOpenIDConnectProvider_removes_only_named_keys(s *S3Conf) error {
	testName := "IAMUntagOpenIDConnectProvider_removes_only_named_keys"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn, err := createTestOIDCProvider(client)
		if err != nil {
			return err
		}

		checkErr := func() error {
			if _, err := tagOIDCProvider(client, &iam.TagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: &arn,
				Tags:                     iamTagList(map[string]string{"env": "prod", "environment": "prod", "team": "storage"}),
			}); err != nil {
				return err
			}
			if _, err := untagOIDCProvider(client, &iam.UntagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: &arn,
				TagKeys:                  []string{"env"},
			}); err != nil {
				return err
			}
			return checkIAMOIDCProviderTags(client, arn, map[string]string{"environment": "prod", "team": "storage"})
		}()

		deleteErr := deleteOIDCProvider(client, arn)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func untagOIDCProvider(client *iam.Client, input *iam.UntagOpenIDConnectProviderInput) (*iam.UntagOpenIDConnectProviderOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.UntagOpenIDConnectProvider(ctx, input)
}
