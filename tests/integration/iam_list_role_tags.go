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

func IAMListRoleTags_missing_role_name(s *S3Conf) error {
	testName := "IAMListRoleTags_missing_role_name"
	body := []byte(url.Values{
		"Action":  {"ListRoleTags"},
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
		return checkIAMAuthRequest(s, req, iamerr.MissingValue("roleName"))
	})
}

func IAMListRoleTags_invalid_role_name(s *S3Conf) error {
	testName := "IAMListRoleTags_invalid_role_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := listIAMRoleTags(client, &iam.ListRoleTagsInput{
			RoleName: aws.String("invalid role name"),
		})
		return checkIAMApiErr(err, iamerr.InvalidUserName("roleName"))
	})
}

func IAMListRoleTags_role_name_too_long(s *S3Conf) error {
	testName := "IAMListRoleTags_role_name_too_long"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := listIAMRoleTags(client, &iam.ListRoleTagsInput{
			RoleName: aws.String(strings.Repeat("a", 65)),
		})
		return checkIAMApiErr(err, iamerr.UserNameTooLong("roleName", 64))
	})
}

func IAMListRoleTags_invalid_max_items(s *S3Conf) error {
	testName := "IAMListRoleTags_invalid_max_items"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		for maxItems, expected := range map[int32]iamerr.Error{
			-1:   iamerr.GetAPIError(iamerr.ErrMaxItemsTooLow),
			0:    iamerr.GetAPIError(iamerr.ErrMaxItemsTooLow),
			1001: iamerr.GetAPIError(iamerr.ErrMaxItemsTooHigh),
		} {
			_, err := listIAMRoleTags(client, &iam.ListRoleTagsInput{
				RoleName: aws.String("validrolename"),
				MaxItems: aws.Int32(maxItems),
			})
			if checkErr := checkIAMApiErr(err, expected); checkErr != nil {
				return fmt.Errorf("MaxItems %d: %w", maxItems, checkErr)
			}
		}
		return nil
	})
}

func IAMListRoleTags_invalid_max_items_format(s *S3Conf) error {
	testName := "IAMListRoleTags_invalid_max_items_format"
	body := []byte(url.Values{
		"Action":   {"ListRoleTags"},
		"Version":  {"2010-05-08"},
		"RoleName": {"validrolename"},
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

func IAMListRoleTags_non_existing_role(s *S3Conf) error {
	testName := "IAMListRoleTags_non_existing_role"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName := "non-existing-" + genRandString(16)
		_, err := listIAMRoleTags(client, &iam.ListRoleTagsInput{RoleName: &roleName})
		return checkIAMApiErr(err, iamerr.NoSuchEntityRole(roleName))
	})
}

func IAMListRoleTags_empty_result(s *S3Conf) error {
	testName := "IAMListRoleTags_empty_result"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName, err := createTaggableIAMRole(client, nil)
		if err != nil {
			return err
		}

		checkErr := func() error {
			out, err := listIAMRoleTags(client, &iam.ListRoleTagsInput{RoleName: &roleName})
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

		deleteErr := deleteIAMRole(client, roleName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMListRoleTags_success(s *S3Conf) error {
	testName := "IAMListRoleTags_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName, err := createTaggableIAMRole(client, iamTagList(map[string]string{"created": "at-create-time"}))
		if err != nil {
			return err
		}

		checkErr := func() error {
			if _, err := tagIAMRole(client, &iam.TagRoleInput{
				RoleName: &roleName,
				Tags:     iamTagList(map[string]string{"env": "prod", "team": "storage"}),
			}); err != nil {
				return err
			}

			out, err := listIAMRoleTags(client, &iam.ListRoleTagsInput{RoleName: &roleName})
			if err != nil {
				return err
			}
			if requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata); !ok || requestID == "" {
				return fmt.Errorf("expected ListRoleTags response request id")
			}
			if out.IsTruncated {
				return fmt.Errorf("expected IsTruncated to be false")
			}
			// Tags supplied at creation and tags added afterwards are the
			// same set: TagRole merges into whatever CreateRole stored.
			return compareIAMTags(out.Tags, map[string]string{
				"created": "at-create-time",
				"env":     "prod",
				"team":    "storage",
			})
		}()

		deleteErr := deleteIAMRole(client, roleName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMListRoleTags_pagination(s *S3Conf) error {
	testName := "IAMListRoleTags_pagination"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName, err := createTaggableIAMRole(client, nil)
		if err != nil {
			return err
		}

		checkErr := func() error {
			want := []string{"alpha", "beta", "gamma"}
			tags := map[string]string{}
			for _, key := range want {
				tags[key] = key + "-value"
			}
			if _, err := tagIAMRole(client, &iam.TagRoleInput{RoleName: &roleName, Tags: iamTagList(tags)}); err != nil {
				return err
			}

			input := iam.ListRoleTagsInput{RoleName: &roleName, MaxItems: aws.Int32(1)}
			var pages []*iam.ListRoleTagsOutput
			for {
				out, err := listIAMRoleTags(client, &input)
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

		deleteErr := deleteIAMRole(client, roleName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func listIAMRoleTags(client *iam.Client, input *iam.ListRoleTagsInput) (*iam.ListRoleTagsOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.ListRoleTags(ctx, input)
}
