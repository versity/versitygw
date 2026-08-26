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

func IAMUntagRole_missing_role_name(s *S3Conf) error {
	testName := "IAMUntagRole_missing_role_name"
	body := []byte(url.Values{
		"Action":           {"UntagRole"},
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
		return checkIAMAuthRequest(s, req, iamerr.MissingValue("roleName"))
	})
}

func IAMUntagRole_invalid_role_name(s *S3Conf) error {
	testName := "IAMUntagRole_invalid_role_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := untagIAMRole(client, &iam.UntagRoleInput{
			RoleName: aws.String("invalid role name"),
			TagKeys:  []string{"env"},
		})
		return checkIAMApiErr(err, iamerr.InvalidUserName("roleName"))
	})
}

func IAMUntagRole_role_name_too_long(s *S3Conf) error {
	testName := "IAMUntagRole_role_name_too_long"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := untagIAMRole(client, &iam.UntagRoleInput{
			RoleName: aws.String(strings.Repeat("a", 65)),
			TagKeys:  []string{"env"},
		})
		return checkIAMApiErr(err, iamerr.UserNameTooLong("roleName", 64))
	})
}

func IAMUntagRole_missing_tag_keys(s *S3Conf) error {
	testName := "IAMUntagRole_missing_tag_keys"
	body := []byte(url.Values{
		"Action":   {"UntagRole"},
		"Version":  {"2010-05-08"},
		"RoleName": {"validrolename"},
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

func IAMUntagRole_invalid_tag_key(s *S3Conf) error {
	testName := "IAMUntagRole_invalid_tag_key"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		for _, tagKey := range []string{"", strings.Repeat("k", 129), "invalid*key"} {
			_, err := untagIAMRole(client, &iam.UntagRoleInput{
				RoleName: aws.String("validrolename"),
				TagKeys:  []string{tagKey},
			})
			if checkErr := checkIAMApiErr(err, iamerr.GetAPIError(iamerr.ErrInvalidTagKeys)); checkErr != nil {
				return fmt.Errorf("tag key %q: %w", tagKey, checkErr)
			}
		}
		return nil
	})
}

func IAMUntagRole_too_many_tag_keys(s *S3Conf) error {
	testName := "IAMUntagRole_too_many_tag_keys"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		tagKeys := make([]string, 0, maxIAMTagMembersPerRequest+1)
		for i := range maxIAMTagMembersPerRequest + 1 {
			tagKeys = append(tagKeys, fmt.Sprintf("key%d", i+1))
		}

		_, err := untagIAMRole(client, &iam.UntagRoleInput{
			RoleName: aws.String("validrolename"),
			TagKeys:  tagKeys,
		})
		return checkIAMApiErr(err, iamerr.GetAPIError(iamerr.ErrTooManyTagKeys))
	})
}

func IAMUntagRole_non_existing_role(s *S3Conf) error {
	testName := "IAMUntagRole_non_existing_role"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName := "non-existing-" + genRandString(16)
		_, err := untagIAMRole(client, &iam.UntagRoleInput{
			RoleName: &roleName,
			TagKeys:  []string{"env"},
		})
		return checkIAMApiErr(err, iamerr.NoSuchEntityRole(roleName))
	})
}

func IAMUntagRole_success(s *S3Conf) error {
	testName := "IAMUntagRole_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName, err := createTaggableIAMRole(client, nil)
		if err != nil {
			return err
		}

		checkErr := func() error {
			if _, err := tagIAMRole(client, &iam.TagRoleInput{
				RoleName: &roleName,
				Tags:     iamTagList(map[string]string{"env": "prod", "team": "storage", "owner": "alice"}),
			}); err != nil {
				return err
			}

			out, err := untagIAMRole(client, &iam.UntagRoleInput{
				RoleName: &roleName,
				TagKeys:  []string{"env", "owner"},
			})
			if err != nil {
				return err
			}
			if requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata); !ok || requestID == "" {
				return fmt.Errorf("expected UntagRole response request id")
			}

			return checkIAMRoleTags(client, roleName, map[string]string{"team": "storage"})
		}()

		deleteErr := deleteIAMRole(client, roleName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

// IAMUntagRole_removal_is_idempotent covers the two ways a request can name
// a key that removes nothing: a key the role never carried, and the same
// key twice in one request. Neither is an error — unlike TagRole, which
// rejects a repeated key outright.
func IAMUntagRole_removal_is_idempotent(s *S3Conf) error {
	testName := "IAMUntagRole_removal_is_idempotent"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName, err := createTaggableIAMRole(client, nil)
		if err != nil {
			return err
		}

		checkErr := func() error {
			if _, err := tagIAMRole(client, &iam.TagRoleInput{
				RoleName: &roleName,
				Tags:     iamTagList(map[string]string{"env": "prod"}),
			}); err != nil {
				return err
			}

			if _, err := untagIAMRole(client, &iam.UntagRoleInput{
				RoleName: &roleName,
				TagKeys:  []string{"never-existed"},
			}); err != nil {
				return fmt.Errorf("removing a key the role does not carry: %w", err)
			}
			if err := checkIAMRoleTags(client, roleName, map[string]string{"env": "prod"}); err != nil {
				return err
			}

			if _, err := untagIAMRole(client, &iam.UntagRoleInput{
				RoleName: &roleName,
				TagKeys:  []string{"env", "env"},
			}); err != nil {
				return fmt.Errorf("removing the same key twice: %w", err)
			}
			return checkIAMRoleTags(client, roleName, map[string]string{})
		}()

		deleteErr := deleteIAMRole(client, roleName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

// IAMUntagRole_case_insensitive_key covers removal by a differently-cased
// key: IAM compares tag keys case-insensitively, so the tag is removed even
// though the supplied key does not match the stored casing.
func IAMUntagRole_case_insensitive_key(s *S3Conf) error {
	testName := "IAMUntagRole_case_insensitive_key"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName, err := createTaggableIAMRole(client, nil)
		if err != nil {
			return err
		}

		checkErr := func() error {
			if _, err := tagIAMRole(client, &iam.TagRoleInput{
				RoleName: &roleName,
				Tags:     iamTagList(map[string]string{"env": "prod"}),
			}); err != nil {
				return err
			}
			if _, err := untagIAMRole(client, &iam.UntagRoleInput{
				RoleName: &roleName,
				TagKeys:  []string{"EnV"},
			}); err != nil {
				return err
			}
			return checkIAMRoleTags(client, roleName, map[string]string{})
		}()

		deleteErr := deleteIAMRole(client, roleName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

// IAMUntagRole_removes_only_named_keys covers a partial removal leaving the
// rest of the set intact, including a key whose name only prefixes one of
// the supplied keys — matching is exact, not by prefix.
func IAMUntagRole_removes_only_named_keys(s *S3Conf) error {
	testName := "IAMUntagRole_removes_only_named_keys"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName, err := createTaggableIAMRole(client, nil)
		if err != nil {
			return err
		}

		checkErr := func() error {
			if _, err := tagIAMRole(client, &iam.TagRoleInput{
				RoleName: &roleName,
				Tags:     iamTagList(map[string]string{"env": "prod", "environment": "prod", "team": "storage"}),
			}); err != nil {
				return err
			}
			if _, err := untagIAMRole(client, &iam.UntagRoleInput{
				RoleName: &roleName,
				TagKeys:  []string{"env"},
			}); err != nil {
				return err
			}
			return checkIAMRoleTags(client, roleName, map[string]string{"environment": "prod", "team": "storage"})
		}()

		deleteErr := deleteIAMRole(client, roleName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func untagIAMRole(client *iam.Client, input *iam.UntagRoleInput) (*iam.UntagRoleOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.UntagRole(ctx, input)
}
