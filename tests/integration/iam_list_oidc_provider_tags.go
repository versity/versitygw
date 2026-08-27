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
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/versity/versitygw/iamapi/iamerr"
)

func IAMListOpenIDConnectProviderTags_missing_arn(s *S3Conf) error {
	testName := "IAMListOpenIDConnectProviderTags_missing_arn"
	body := []byte(url.Values{
		"Action":  {"ListOpenIDConnectProviderTags"},
		"Version": {"2010-05-08"},
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

func IAMListOpenIDConnectProviderTags_invalid_arn(s *S3Conf) error {
	testName := "IAMListOpenIDConnectProviderTags_invalid_arn"
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
			_, err := listIAMOIDCProviderTags(client, &iam.ListOpenIDConnectProviderTagsInput{
				OpenIDConnectProviderArn: aws.String(tt.arn),
			})
			if checkErr := checkIAMApiErr(err, tt.want); checkErr != nil {
				return fmt.Errorf("%s: %w", tt.name, checkErr)
			}
		}
		return nil
	})
}

func IAMListOpenIDConnectProviderTags_invalid_max_items(s *S3Conf) error {
	testName := "IAMListOpenIDConnectProviderTags_invalid_max_items"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn := oidcProviderArn("https://validprovider.example.com")
		for maxItems, expected := range map[int32]iamerr.Error{
			-1:   iamerr.GetAPIError(iamerr.ErrMaxItemsTooLow),
			0:    iamerr.GetAPIError(iamerr.ErrMaxItemsTooLow),
			1001: iamerr.GetAPIError(iamerr.ErrMaxItemsTooHigh),
		} {
			_, err := listIAMOIDCProviderTags(client, &iam.ListOpenIDConnectProviderTagsInput{
				OpenIDConnectProviderArn: &arn,
				MaxItems:                 aws.Int32(maxItems),
			})
			if checkErr := checkIAMApiErr(err, expected); checkErr != nil {
				return fmt.Errorf("MaxItems %d: %w", maxItems, checkErr)
			}
		}
		return nil
	})
}

func IAMListOpenIDConnectProviderTags_invalid_max_items_format(s *S3Conf) error {
	testName := "IAMListOpenIDConnectProviderTags_invalid_max_items_format"
	body := []byte(url.Values{
		"Action":                   {"ListOpenIDConnectProviderTags"},
		"Version":                  {"2010-05-08"},
		"OpenIDConnectProviderArn": {oidcProviderArn("https://validprovider.example.com")},
		"MaxItems":                 {"not-a-number"},
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
		return checkIAMAuthRequest(s, req, iamerr.MalformedInput())
	})
}

func IAMListOpenIDConnectProviderTags_non_existing_provider(s *S3Conf) error {
	testName := "IAMListOpenIDConnectProviderTags_non_existing_provider"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn := oidcProviderArn("https://" + genRandString(16) + ".example.com")
		_, err := listIAMOIDCProviderTags(client, &iam.ListOpenIDConnectProviderTagsInput{OpenIDConnectProviderArn: &arn})
		return checkIAMApiErr(err, iamerr.NoSuchEntityOIDCProviderDelete(arn))
	})
}

func IAMListOpenIDConnectProviderTags_empty_result(s *S3Conf) error {
	testName := "IAMListOpenIDConnectProviderTags_empty_result"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn, err := createTestOIDCProvider(client)
		if err != nil {
			return err
		}

		checkErr := func() error {
			out, err := listIAMOIDCProviderTags(client, &iam.ListOpenIDConnectProviderTagsInput{OpenIDConnectProviderArn: &arn})
			if err != nil {
				return err
			}
			if len(out.Tags) != 0 {
				return fmt.Errorf("expected no tags, instead got %v", iamTagMap(out.Tags))
			}
			if out.IsTruncated {
				return fmt.Errorf("expected IsTruncated to be false")
			}
			return nil
		}()

		deleteErr := deleteOIDCProvider(client, arn)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMListOpenIDConnectProviderTags_success(s *S3Conf) error {
	testName := "IAMListOpenIDConnectProviderTags_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn, err := createOIDCProviderReturningArnWithTags(client, []iamtypes.Tag{
			{Key: aws.String("created"), Value: aws.String("at-create-time")},
		})
		if err != nil {
			return err
		}

		checkErr := func() error {
			if _, err := tagOIDCProvider(client, &iam.TagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: &arn,
				Tags:                     iamTagList(map[string]string{"env": "prod", "team": "storage"}),
			}); err != nil {
				return err
			}

			out, err := listIAMOIDCProviderTags(client, &iam.ListOpenIDConnectProviderTagsInput{OpenIDConnectProviderArn: &arn})
			if err != nil {
				return err
			}
			if requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata); !ok || requestID == "" {
				return fmt.Errorf("expected ListOpenIDConnectProviderTags response request id")
			}
			if out.IsTruncated {
				return fmt.Errorf("expected IsTruncated to be false")
			}
			// Tags supplied at creation and tags added afterwards are the
			// same set: the tag action merges into whatever create stored.
			return compareIAMTags(out.Tags, map[string]string{
				"created": "at-create-time",
				"env":     "prod",
				"team":    "storage",
			})
		}()

		deleteErr := deleteOIDCProvider(client, arn)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMListOpenIDConnectProviderTags_pagination(s *S3Conf) error {
	testName := "IAMListOpenIDConnectProviderTags_pagination"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn, err := createTestOIDCProvider(client)
		if err != nil {
			return err
		}

		checkErr := func() error {
			want := []string{"alpha", "beta", "gamma"}
			tags := map[string]string{}
			for _, key := range want {
				tags[key] = key + "-value"
			}
			if _, err := tagOIDCProvider(client, &iam.TagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: &arn,
				Tags:                     iamTagList(tags),
			}); err != nil {
				return err
			}

			input := iam.ListOpenIDConnectProviderTagsInput{OpenIDConnectProviderArn: &arn, MaxItems: aws.Int32(1)}
			var pages []*iam.ListOpenIDConnectProviderTagsOutput
			for {
				out, err := listIAMOIDCProviderTags(client, &input)
				if err != nil {
					return err
				}
				pages = append(pages, out)
				if !out.IsTruncated {
					break
				}
				input.Marker = out.Marker
			}

			if len(pages) != len(want) {
				return fmt.Errorf("expected %d pages, instead got %d", len(want), len(pages))
			}
			var got []string
			for i, page := range pages {
				if len(page.Tags) != 1 {
					return fmt.Errorf("expected page %d to contain 1 tag, instead got %d", i+1, len(page.Tags))
				}
				if page.IsTruncated != (i < len(pages)-1) {
					return fmt.Errorf("unexpected IsTruncated value on page %d", i+1)
				}
				got = append(got, aws.ToString(page.Tags[0].Key))
			}
			slices.Sort(got)
			if !slices.Equal(got, want) {
				return fmt.Errorf("expected tag keys %v, instead got %v", want, got)
			}
			return nil
		}()

		deleteErr := deleteOIDCProvider(client, arn)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func listIAMOIDCProviderTags(client *iam.Client, input *iam.ListOpenIDConnectProviderTagsInput) (*iam.ListOpenIDConnectProviderTagsOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.ListOpenIDConnectProviderTags(ctx, input)
}
