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
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/iamapi/storage"
)

func IAMTagOpenIDConnectProvider_missing_arn(s *S3Conf) error {
	testName := "IAMTagOpenIDConnectProvider_missing_arn"
	body := []byte(url.Values{
		"Action":              {"TagOpenIDConnectProvider"},
		"Version":             {"2010-05-08"},
		"Tags.member.1.Key":   {"env"},
		"Tags.member.1.Value": {"prod"},
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

func IAMTagOpenIDConnectProvider_invalid_arn(s *S3Conf) error {
	testName := "IAMTagOpenIDConnectProvider_invalid_arn"
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
			_, err := tagOIDCProvider(client, &iam.TagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: aws.String(tt.arn),
				Tags:                     iamTagList(map[string]string{"env": "prod"}),
			})
			if checkErr := checkIAMApiErr(err, tt.want); checkErr != nil {
				return fmt.Errorf("%s: %w", tt.name, checkErr)
			}
		}
		return nil
	})
}

func IAMTagOpenIDConnectProvider_missing_tags(s *S3Conf) error {
	testName := "IAMTagOpenIDConnectProvider_missing_tags"
	body := []byte(url.Values{
		"Action":                   {"TagOpenIDConnectProvider"},
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
		return checkIAMAuthRequest(s, req, iamerr.MissingValue("tags"))
	})
}

func IAMTagOpenIDConnectProvider_missing_tag_key(s *S3Conf) error {
	testName := "IAMTagOpenIDConnectProvider_missing_tag_key"
	body := []byte(url.Values{
		"Action":                   {"TagOpenIDConnectProvider"},
		"Version":                  {"2010-05-08"},
		"OpenIDConnectProviderArn": {oidcProviderArn("https://validprovider.example.com")},
		"Tags.member.1.Value":      {"prod"},
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
		return checkIAMAuthRequest(s, req, iamerr.MissingTagKey(1))
	})
}

func IAMTagOpenIDConnectProvider_missing_tag_value(s *S3Conf) error {
	testName := "IAMTagOpenIDConnectProvider_missing_tag_value"
	body := []byte(url.Values{
		"Action":                   {"TagOpenIDConnectProvider"},
		"Version":                  {"2010-05-08"},
		"OpenIDConnectProviderArn": {oidcProviderArn("https://validprovider.example.com")},
		"Tags.member.1.Key":        {"env"},
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
		return checkIAMAuthRequest(s, req, iamerr.MissingTagValue(1))
	})
}

func IAMTagOpenIDConnectProvider_invalid_tags(s *S3Conf) error {
	testName := "IAMTagOpenIDConnectProvider_invalid_tags"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn := oidcProviderArn("https://validprovider.example.com")
		tests := []struct {
			name string
			tags []iamtypes.Tag
			want iamerr.Error
		}{
			{"empty_key", []iamtypes.Tag{{Key: aws.String(""), Value: aws.String("prod")}}, iamerr.TagKeyTooShort(1)},
			{"key_too_long", iamTagList(map[string]string{strings.Repeat("k", 129): "prod"}), iamerr.TagKeyTooLong(1)},
			{"invalid_key", iamTagList(map[string]string{"invalid*key": "prod"}), iamerr.InvalidTagKey(1)},
			{"value_too_long", iamTagList(map[string]string{"env": strings.Repeat("v", 257)}), iamerr.TagValueTooLong(1)},
			{"invalid_value", iamTagList(map[string]string{"env": "invalid*value"}), iamerr.InvalidTagValue(1)},
		}
		for _, tt := range tests {
			_, err := tagOIDCProvider(client, &iam.TagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: &arn,
				Tags:                     tt.tags,
			})
			if checkErr := checkIAMApiErr(err, tt.want); checkErr != nil {
				return fmt.Errorf("%s: %w", tt.name, checkErr)
			}
		}
		return nil
	})
}

// IAMTagOpenIDConnectProvider_duplicate_tag_keys covers the provider
// actions' exact tag-key comparison: an identical key twice in one request
// is rejected, where a differently-cased repeat is two separate tags.
func IAMTagOpenIDConnectProvider_duplicate_tag_keys(s *S3Conf) error {
	testName := "IAMTagOpenIDConnectProvider_duplicate_tag_keys"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn, err := createTestOIDCProvider(client)
		if err != nil {
			return err
		}

		checkErr := func() error {
			_, err := tagOIDCProvider(client, &iam.TagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: &arn,
				Tags: []iamtypes.Tag{
					{Key: aws.String("env"), Value: aws.String("prod")},
					{Key: aws.String("env"), Value: aws.String("staging")},
				},
			})
			if err := checkIAMApiErr(err, iamerr.GetAPIError(iamerr.ErrDuplicateExactTagKeys)); err != nil {
				return err
			}

			if _, err := tagOIDCProvider(client, &iam.TagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: &arn,
				Tags: []iamtypes.Tag{
					{Key: aws.String("env"), Value: aws.String("prod")},
					{Key: aws.String("ENV"), Value: aws.String("staging")},
				},
			}); err != nil {
				return fmt.Errorf("differently-cased keys: %w", err)
			}
			return checkIAMOIDCProviderTags(client, arn, map[string]string{"env": "prod", "ENV": "staging"})
		}()

		deleteErr := deleteOIDCProvider(client, arn)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMTagOpenIDConnectProvider_too_many_tags(s *S3Conf) error {
	testName := "IAMTagOpenIDConnectProvider_too_many_tags"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := tagOIDCProvider(client, &iam.TagOpenIDConnectProviderInput{
			OpenIDConnectProviderArn: aws.String(oidcProviderArn("https://validprovider.example.com")),
			Tags:                     numberedIAMTags(1, maxIAMTagMembersPerRequest+1),
		})
		return checkIAMApiErr(err, iamerr.GetAPIError(iamerr.ErrTooManyTags))
	})
}

func IAMTagOpenIDConnectProvider_non_existing_provider(s *S3Conf) error {
	testName := "IAMTagOpenIDConnectProvider_non_existing_provider"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn := oidcProviderArn("https://" + genRandString(16) + ".example.com")
		_, err := tagOIDCProvider(client, &iam.TagOpenIDConnectProviderInput{
			OpenIDConnectProviderArn: &arn,
			Tags:                     iamTagList(map[string]string{"env": "prod"}),
		})
		return checkIAMApiErr(err, iamerr.NoSuchEntityOIDCProviderDelete(arn))
	})
}

// IAMTagOpenIDConnectProvider_invalid_tags_precede_lookup covers a
// malformed tag naming a provider that does not exist: the request is
// validated in full before the provider is looked up, so the tag error
// wins over NoSuchEntity.
func IAMTagOpenIDConnectProvider_invalid_tags_precede_lookup(s *S3Conf) error {
	testName := "IAMTagOpenIDConnectProvider_invalid_tags_precede_lookup"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := tagOIDCProvider(client, &iam.TagOpenIDConnectProviderInput{
			OpenIDConnectProviderArn: aws.String(oidcProviderArn("https://" + genRandString(16) + ".example.com")),
			Tags:                     iamTagList(map[string]string{"invalid*key": "prod"}),
		})
		return checkIAMApiErr(err, iamerr.InvalidTagKey(1))
	})
}

func IAMTagOpenIDConnectProvider_tag_limit_exceeded(s *S3Conf) error {
	testName := "IAMTagOpenIDConnectProvider_tag_limit_exceeded"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn, err := createTestOIDCProvider(client)
		if err != nil {
			return err
		}

		checkErr := func() error {
			if _, err := tagOIDCProvider(client, &iam.TagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: &arn,
				Tags:                     numberedIAMTags(1, storage.MaxTagsPerResource),
			}); err != nil {
				return err
			}

			if _, err := tagOIDCProvider(client, &iam.TagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: &arn,
				Tags:                     iamTagList(map[string]string{"key1": "replaced"}),
			}); err != nil {
				return fmt.Errorf("replacing a tag at the quota: %w", err)
			}

			// A differently-cased key is a new tag, so it overflows.
			_, err := tagOIDCProvider(client, &iam.TagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: &arn,
				Tags:                     iamTagList(map[string]string{"KEY1": "x"}),
			})
			return checkIAMApiErr(err, iamerr.GetAPIError(iamerr.ErrTagLimitExceeded))
		}()

		deleteErr := deleteOIDCProvider(client, arn)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMTagOpenIDConnectProvider_success(s *S3Conf) error {
	testName := "IAMTagOpenIDConnectProvider_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn, err := createTestOIDCProvider(client)
		if err != nil {
			return err
		}

		checkErr := func() error {
			// An empty tag value is legal; only the key has a minimum length.
			want := map[string]string{"env": "prod", "team": "storage", "empty": ""}
			out, err := tagOIDCProvider(client, &iam.TagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: &arn,
				Tags:                     iamTagList(want),
			})
			if err != nil {
				return err
			}
			if requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata); !ok || requestID == "" {
				return fmt.Errorf("expected TagOpenIDConnectProvider response request id")
			}

			if err := checkIAMOIDCProviderTags(client, arn, want); err != nil {
				return err
			}
			// GetOpenIDConnectProvider reports the same tags the tag actions maintain.
			provider, err := getIAMOIDCProvider(client, arn)
			if err != nil {
				return err
			}
			return compareIAMTags(provider.Tags, want)
		}()

		deleteErr := deleteOIDCProvider(client, arn)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

// IAMTagOpenIDConnectProvider_overwrites_existing_tag covers re-tagging a
// key that is already present: the value is replaced rather than added
// alongside, while a differently-cased key is a separate tag that leaves
// the original in place.
func IAMTagOpenIDConnectProvider_overwrites_existing_tag(s *S3Conf) error {
	testName := "IAMTagOpenIDConnectProvider_overwrites_existing_tag"
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
			if _, err := tagOIDCProvider(client, &iam.TagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: &arn,
				Tags:                     iamTagList(map[string]string{"env": "staging"}),
			}); err != nil {
				return err
			}
			if err := checkIAMOIDCProviderTags(client, arn, map[string]string{"env": "staging"}); err != nil {
				return err
			}

			if _, err := tagOIDCProvider(client, &iam.TagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: &arn,
				Tags:                     iamTagList(map[string]string{"ENV": "qa"}),
			}); err != nil {
				return err
			}
			return checkIAMOIDCProviderTags(client, arn, map[string]string{"env": "staging", "ENV": "qa"})
		}()

		deleteErr := deleteOIDCProvider(client, arn)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

// IAMTagOpenIDConnectProvider_isolated_per_provider covers two providers
// carrying the same tag keys: each set is its own, in both directions.
func IAMTagOpenIDConnectProvider_isolated_per_provider(s *S3Conf) error {
	testName := "IAMTagOpenIDConnectProvider_isolated_per_provider"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		first, err := createTestOIDCProvider(client)
		if err != nil {
			return err
		}
		second, err := createTestOIDCProvider(client)
		if err != nil {
			deleteOIDCProvider(client, first)
			return err
		}

		checkErr := func() error {
			if _, err := tagOIDCProvider(client, &iam.TagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: &first,
				Tags:                     iamTagList(map[string]string{"owner": "first"}),
			}); err != nil {
				return err
			}
			if _, err := tagOIDCProvider(client, &iam.TagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: &second,
				Tags:                     iamTagList(map[string]string{"owner": "second"}),
			}); err != nil {
				return err
			}

			if err := checkIAMOIDCProviderTags(client, first, map[string]string{"owner": "first"}); err != nil {
				return err
			}
			if err := checkIAMOIDCProviderTags(client, second, map[string]string{"owner": "second"}); err != nil {
				return err
			}

			// Untagging one must not strip the other's identically-named key.
			if _, err := untagOIDCProvider(client, &iam.UntagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: &first,
				TagKeys:                  []string{"owner"},
			}); err != nil {
				return err
			}
			if err := checkIAMOIDCProviderTags(client, first, map[string]string{}); err != nil {
				return err
			}
			return checkIAMOIDCProviderTags(client, second, map[string]string{"owner": "second"})
		}()

		deleteErr := deleteOIDCProvider(client, first)
		if secondErr := deleteOIDCProvider(client, second); deleteErr == nil {
			deleteErr = secondErr
		}
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func tagOIDCProvider(client *iam.Client, input *iam.TagOpenIDConnectProviderInput) (*iam.TagOpenIDConnectProviderOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.TagOpenIDConnectProvider(ctx, input)
}

// checkIAMOIDCProviderTags asserts ListOpenIDConnectProviderTags reports
// exactly want for arn.
func checkIAMOIDCProviderTags(client *iam.Client, arn string, want map[string]string) error {
	out, err := listIAMOIDCProviderTags(client, &iam.ListOpenIDConnectProviderTagsInput{OpenIDConnectProviderArn: &arn})
	if err != nil {
		return err
	}
	if out.IsTruncated {
		return fmt.Errorf("expected IsTruncated to be false")
	}
	return compareIAMTags(out.Tags, want)
}
