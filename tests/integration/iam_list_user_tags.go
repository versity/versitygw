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
	"github.com/versity/versitygw/iamapi/iamerr"
)

func IAMListUserTags_missing_user_name(s *S3Conf) error {
	testName := "IAMListUserTags_missing_user_name"
	body := []byte(url.Values{
		"Action":  {"ListUserTags"},
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
		return checkIAMAuthRequest(s, req, iamerr.MissingValue("userName"))
	})
}

func IAMListUserTags_invalid_user_name(s *S3Conf) error {
	testName := "IAMListUserTags_invalid_user_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := listIAMUserTags(client, &iam.ListUserTagsInput{
			UserName: aws.String("invalid user name"),
		})
		return checkIAMApiErr(err, iamerr.InvalidUserName("userName"))
	})
}

func IAMListUserTags_user_name_too_long(s *S3Conf) error {
	testName := "IAMListUserTags_user_name_too_long"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := listIAMUserTags(client, &iam.ListUserTagsInput{
			UserName: aws.String(strings.Repeat("a", 129)),
		})
		return checkIAMApiErr(err, iamerr.UserNameTooLong("userName", 128))
	})
}

func IAMListUserTags_invalid_max_items(s *S3Conf) error {
	testName := "IAMListUserTags_invalid_max_items"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		for maxItems, expected := range map[int32]iamerr.Error{
			-1:   iamerr.GetAPIError(iamerr.ErrMaxItemsTooLow),
			0:    iamerr.GetAPIError(iamerr.ErrMaxItemsTooLow),
			1001: iamerr.GetAPIError(iamerr.ErrMaxItemsTooHigh),
		} {
			_, err := listIAMUserTags(client, &iam.ListUserTagsInput{
				UserName: aws.String("validusername"),
				MaxItems: aws.Int32(maxItems),
			})
			if checkErr := checkIAMApiErr(err, expected); checkErr != nil {
				return fmt.Errorf("MaxItems %d: %w", maxItems, checkErr)
			}
		}
		return nil
	})
}

func IAMListUserTags_invalid_max_items_format(s *S3Conf) error {
	testName := "IAMListUserTags_invalid_max_items_format"
	body := []byte(url.Values{
		"Action":   {"ListUserTags"},
		"Version":  {"2010-05-08"},
		"UserName": {"validusername"},
		"MaxItems": {"not-a-number"},
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

func IAMListUserTags_non_existing_user(s *S3Conf) error {
	testName := "IAMListUserTags_non_existing_user"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := "non-existing-" + genRandString(16)
		_, err := listIAMUserTags(client, &iam.ListUserTagsInput{UserName: &userName})
		return checkIAMApiErr(err, iamerr.NoSuchEntityUser(userName))
	})
}

func IAMListUserTags_empty_result(s *S3Conf) error {
	testName := "IAMListUserTags_empty_result"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := newIAMUserName()
		if _, err := createIAMUser(client, &iam.CreateUserInput{UserName: &userName}); err != nil {
			return err
		}

		checkErr := func() error {
			out, err := listIAMUserTags(client, &iam.ListUserTagsInput{UserName: &userName})
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

		deleteErr := deleteIAMUser(client, userName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMListUserTags_success(s *S3Conf) error {
	testName := "IAMListUserTags_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := newIAMUserName()
		if _, err := createIAMUser(client, &iam.CreateUserInput{
			UserName: &userName,
			Tags:     iamTagList(map[string]string{"created": "at-create-time"}),
		}); err != nil {
			return err
		}

		checkErr := func() error {
			if _, err := tagIAMUser(client, &iam.TagUserInput{
				UserName: &userName,
				Tags:     iamTagList(map[string]string{"env": "prod", "team": "storage"}),
			}); err != nil {
				return err
			}

			out, err := listIAMUserTags(client, &iam.ListUserTagsInput{UserName: &userName})
			if err != nil {
				return err
			}
			if requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata); !ok || requestID == "" {
				return fmt.Errorf("expected ListUserTags response request id")
			}
			if out.IsTruncated {
				return fmt.Errorf("expected IsTruncated to be false")
			}
			// Tags supplied at creation and tags added afterwards are the
			// same set: TagUser merges into whatever CreateUser stored.
			return compareIAMTags(out.Tags, map[string]string{
				"created": "at-create-time",
				"env":     "prod",
				"team":    "storage",
			})
		}()

		deleteErr := deleteIAMUser(client, userName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMListUserTags_pagination(s *S3Conf) error {
	testName := "IAMListUserTags_pagination"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := newIAMUserName()
		if _, err := createIAMUser(client, &iam.CreateUserInput{UserName: &userName}); err != nil {
			return err
		}

		checkErr := func() error {
			want := []string{"alpha", "beta", "gamma"}
			tags := map[string]string{}
			for _, key := range want {
				tags[key] = key + "-value"
			}
			if _, err := tagIAMUser(client, &iam.TagUserInput{UserName: &userName, Tags: iamTagList(tags)}); err != nil {
				return err
			}

			input := iam.ListUserTagsInput{UserName: &userName, MaxItems: aws.Int32(1)}
			var pages []*iam.ListUserTagsOutput
			for {
				out, err := listIAMUserTags(client, &input)
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

		deleteErr := deleteIAMUser(client, userName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func listIAMUserTags(client *iam.Client, input *iam.ListUserTagsInput) (*iam.ListUserTagsOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.ListUserTags(ctx, input)
}
