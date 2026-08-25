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

func IAMUntagUser_missing_user_name(s *S3Conf) error {
	testName := "IAMUntagUser_missing_user_name"
	body := []byte(url.Values{
		"Action":           {"UntagUser"},
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
		return checkIAMAuthRequest(s, req, iamerr.MissingValue("userName"))
	})
}

func IAMUntagUser_invalid_user_name(s *S3Conf) error {
	testName := "IAMUntagUser_invalid_user_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := untagIAMUser(client, &iam.UntagUserInput{
			UserName: aws.String("invalid user name"),
			TagKeys:  []string{"env"},
		})
		return checkIAMApiErr(err, iamerr.InvalidUserName("userName"))
	})
}

func IAMUntagUser_user_name_too_long(s *S3Conf) error {
	testName := "IAMUntagUser_user_name_too_long"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := untagIAMUser(client, &iam.UntagUserInput{
			UserName: aws.String(strings.Repeat("a", 129)),
			TagKeys:  []string{"env"},
		})
		return checkIAMApiErr(err, iamerr.UserNameTooLong("userName", 128))
	})
}

func IAMUntagUser_missing_tag_keys(s *S3Conf) error {
	testName := "IAMUntagUser_missing_tag_keys"
	body := []byte(url.Values{
		"Action":   {"UntagUser"},
		"Version":  {"2010-05-08"},
		"UserName": {"validusername"},
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

// IAMUntagUser_invalid_tag_key covers every malformed TagKeys member the
// same way IAM does: whichever constraint fails — empty, over-long, or
// outside the allowed charset — the response is one generic error naming
// the whole constraint set, not the individual constraint that tripped.
func IAMUntagUser_invalid_tag_key(s *S3Conf) error {
	testName := "IAMUntagUser_invalid_tag_key"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		for _, tagKey := range []string{"", strings.Repeat("k", 129), "invalid*key"} {
			_, err := untagIAMUser(client, &iam.UntagUserInput{
				UserName: aws.String("validusername"),
				TagKeys:  []string{tagKey},
			})
			if checkErr := checkIAMApiErr(err, iamerr.GetAPIError(iamerr.ErrInvalidTagKeys)); checkErr != nil {
				return fmt.Errorf("tag key %q: %w", tagKey, checkErr)
			}
		}
		return nil
	})
}

func IAMUntagUser_too_many_tag_keys(s *S3Conf) error {
	testName := "IAMUntagUser_too_many_tag_keys"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		tagKeys := make([]string, 0, maxIAMTagMembersPerRequest+1)
		for i := range maxIAMTagMembersPerRequest + 1 {
			tagKeys = append(tagKeys, fmt.Sprintf("key%d", i+1))
		}

		_, err := untagIAMUser(client, &iam.UntagUserInput{
			UserName: aws.String("validusername"),
			TagKeys:  tagKeys,
		})
		return checkIAMApiErr(err, iamerr.GetAPIError(iamerr.ErrTooManyTagKeys))
	})
}

func IAMUntagUser_non_existing_user(s *S3Conf) error {
	testName := "IAMUntagUser_non_existing_user"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := "non-existing-" + genRandString(16)
		_, err := untagIAMUser(client, &iam.UntagUserInput{
			UserName: &userName,
			TagKeys:  []string{"env"},
		})
		return checkIAMApiErr(err, iamerr.NoSuchEntityUser(userName))
	})
}

func IAMUntagUser_success(s *S3Conf) error {
	testName := "IAMUntagUser_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := newIAMUserName()
		if _, err := createIAMUser(client, &iam.CreateUserInput{UserName: &userName}); err != nil {
			return err
		}

		checkErr := func() error {
			if _, err := tagIAMUser(client, &iam.TagUserInput{
				UserName: &userName,
				Tags:     iamTagList(map[string]string{"env": "prod", "team": "storage", "owner": "alice"}),
			}); err != nil {
				return err
			}

			out, err := untagIAMUser(client, &iam.UntagUserInput{
				UserName: &userName,
				TagKeys:  []string{"env", "owner"},
			})
			if err != nil {
				return err
			}
			if requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata); !ok || requestID == "" {
				return fmt.Errorf("expected UntagUser response request id")
			}

			return checkIAMUserTags(client, userName, map[string]string{"team": "storage"})
		}()

		deleteErr := deleteIAMUser(client, userName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

// IAMUntagUser_removal_is_idempotent covers the two ways a request can name
// a key that removes nothing: a key the user never carried, and the same
// key twice in one request. Neither is an error — unlike TagUser, which
// rejects a repeated key outright.
func IAMUntagUser_removal_is_idempotent(s *S3Conf) error {
	testName := "IAMUntagUser_removal_is_idempotent"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := newIAMUserName()
		if _, err := createIAMUser(client, &iam.CreateUserInput{UserName: &userName}); err != nil {
			return err
		}

		checkErr := func() error {
			if _, err := tagIAMUser(client, &iam.TagUserInput{
				UserName: &userName,
				Tags:     iamTagList(map[string]string{"env": "prod"}),
			}); err != nil {
				return err
			}

			if _, err := untagIAMUser(client, &iam.UntagUserInput{
				UserName: &userName,
				TagKeys:  []string{"never-existed"},
			}); err != nil {
				return fmt.Errorf("removing a key the user does not carry: %w", err)
			}
			if err := checkIAMUserTags(client, userName, map[string]string{"env": "prod"}); err != nil {
				return err
			}

			if _, err := untagIAMUser(client, &iam.UntagUserInput{
				UserName: &userName,
				TagKeys:  []string{"env", "env"},
			}); err != nil {
				return fmt.Errorf("removing the same key twice: %w", err)
			}
			return checkIAMUserTags(client, userName, map[string]string{})
		}()

		deleteErr := deleteIAMUser(client, userName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

// IAMUntagUser_case_insensitive_key covers removal by a differently-cased
// key: IAM compares tag keys case-insensitively, so the tag is removed even
// though the supplied key does not match the stored casing.
func IAMUntagUser_case_insensitive_key(s *S3Conf) error {
	testName := "IAMUntagUser_case_insensitive_key"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := newIAMUserName()
		if _, err := createIAMUser(client, &iam.CreateUserInput{UserName: &userName}); err != nil {
			return err
		}

		checkErr := func() error {
			if _, err := tagIAMUser(client, &iam.TagUserInput{
				UserName: &userName,
				Tags:     iamTagList(map[string]string{"env": "prod"}),
			}); err != nil {
				return err
			}
			if _, err := untagIAMUser(client, &iam.UntagUserInput{
				UserName: &userName,
				TagKeys:  []string{"EnV"},
			}); err != nil {
				return err
			}
			return checkIAMUserTags(client, userName, map[string]string{})
		}()

		deleteErr := deleteIAMUser(client, userName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func untagIAMUser(client *iam.Client, input *iam.UntagUserInput) (*iam.UntagUserOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.UntagUser(ctx, input)
}
