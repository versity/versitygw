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

func IAMTagUser_missing_user_name(s *S3Conf) error {
	testName := "IAMTagUser_missing_user_name"
	body := []byte(url.Values{
		"Action":              {"TagUser"},
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
		return checkIAMAuthRequest(s, req, iamerr.MissingValue("userName"))
	})
}

func IAMTagUser_invalid_user_name(s *S3Conf) error {
	testName := "IAMTagUser_invalid_user_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := tagIAMUser(client, &iam.TagUserInput{
			UserName: aws.String("invalid user name"),
			Tags:     iamTagList(map[string]string{"env": "prod"}),
		})
		return checkIAMApiErr(err, iamerr.InvalidUserName("userName"))
	})
}

func IAMTagUser_user_name_too_long(s *S3Conf) error {
	testName := "IAMTagUser_user_name_too_long"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := tagIAMUser(client, &iam.TagUserInput{
			UserName: aws.String(strings.Repeat("a", 129)),
			Tags:     iamTagList(map[string]string{"env": "prod"}),
		})
		return checkIAMApiErr(err, iamerr.UserNameTooLong("userName", 128))
	})
}

func IAMTagUser_missing_tags(s *S3Conf) error {
	testName := "IAMTagUser_missing_tags"
	body := []byte(url.Values{
		"Action":   {"TagUser"},
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
		return checkIAMAuthRequest(s, req, iamerr.MissingValue("tags"))
	})
}

func IAMTagUser_missing_tag_key(s *S3Conf) error {
	testName := "IAMTagUser_missing_tag_key"
	body := []byte(url.Values{
		"Action":              {"TagUser"},
		"Version":             {"2010-05-08"},
		"UserName":            {"validusername"},
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
		return checkIAMAuthRequest(s, req, iamerr.MissingTagKey(1))
	})
}

func IAMTagUser_missing_tag_value(s *S3Conf) error {
	testName := "IAMTagUser_missing_tag_value"
	body := []byte(url.Values{
		"Action":            {"TagUser"},
		"Version":           {"2010-05-08"},
		"UserName":          {"validusername"},
		"Tags.member.1.Key": {"env"},
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

func IAMTagUser_empty_tag_key(s *S3Conf) error {
	testName := "IAMTagUser_empty_tag_key"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := tagIAMUser(client, &iam.TagUserInput{
			UserName: aws.String("validusername"),
			Tags:     []iamtypes.Tag{{Key: aws.String(""), Value: aws.String("prod")}},
		})
		return checkIAMApiErr(err, iamerr.TagKeyTooShort(1))
	})
}

func IAMTagUser_tag_key_too_long(s *S3Conf) error {
	testName := "IAMTagUser_tag_key_too_long"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := tagIAMUser(client, &iam.TagUserInput{
			UserName: aws.String("validusername"),
			Tags:     iamTagList(map[string]string{strings.Repeat("k", 129): "prod"}),
		})
		return checkIAMApiErr(err, iamerr.TagKeyTooLong(1))
	})
}

func IAMTagUser_invalid_tag_key(s *S3Conf) error {
	testName := "IAMTagUser_invalid_tag_key"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := tagIAMUser(client, &iam.TagUserInput{
			UserName: aws.String("validusername"),
			Tags:     iamTagList(map[string]string{"invalid*key": "prod"}),
		})
		return checkIAMApiErr(err, iamerr.InvalidTagKey(1))
	})
}

func IAMTagUser_tag_value_too_long(s *S3Conf) error {
	testName := "IAMTagUser_tag_value_too_long"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := tagIAMUser(client, &iam.TagUserInput{
			UserName: aws.String("validusername"),
			Tags:     iamTagList(map[string]string{"env": strings.Repeat("v", 257)}),
		})
		return checkIAMApiErr(err, iamerr.TagValueTooLong(1))
	})
}

func IAMTagUser_invalid_tag_value(s *S3Conf) error {
	testName := "IAMTagUser_invalid_tag_value"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := tagIAMUser(client, &iam.TagUserInput{
			UserName: aws.String("validusername"),
			Tags:     iamTagList(map[string]string{"env": "invalid*value"}),
		})
		return checkIAMApiErr(err, iamerr.InvalidTagValue(1))
	})
}

// IAMTagUser_duplicate_tag_keys covers both an exact repeat and a
// differently-cased repeat: IAM compares tag keys case-insensitively, so
// both are the same key twice in one request.
func IAMTagUser_duplicate_tag_keys(s *S3Conf) error {
	testName := "IAMTagUser_duplicate_tag_keys"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		for _, second := range []string{"env", "ENV"} {
			_, err := tagIAMUser(client, &iam.TagUserInput{
				UserName: aws.String("validusername"),
				Tags: []iamtypes.Tag{
					{Key: aws.String("env"), Value: aws.String("prod")},
					{Key: aws.String(second), Value: aws.String("staging")},
				},
			})
			if checkErr := checkIAMApiErr(err, iamerr.GetAPIError(iamerr.ErrDuplicateTagKeys)); checkErr != nil {
				return fmt.Errorf("duplicate key %q: %w", second, checkErr)
			}
		}
		return nil
	})
}

func IAMTagUser_too_many_tags(s *S3Conf) error {
	testName := "IAMTagUser_too_many_tags"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := tagIAMUser(client, &iam.TagUserInput{
			UserName: aws.String("validusername"),
			Tags:     numberedIAMTags(1, maxIAMTagMembersPerRequest+1),
		})
		return checkIAMApiErr(err, iamerr.GetAPIError(iamerr.ErrTooManyTags))
	})
}

func IAMTagUser_non_existing_user(s *S3Conf) error {
	testName := "IAMTagUser_non_existing_user"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := "non-existing-" + genRandString(16)
		_, err := tagIAMUser(client, &iam.TagUserInput{
			UserName: &userName,
			Tags:     iamTagList(map[string]string{"env": "prod"}),
		})
		return checkIAMApiErr(err, iamerr.NoSuchEntityUser(userName))
	})
}

func IAMTagUser_tag_limit_exceeded(s *S3Conf) error {
	testName := "IAMTagUser_tag_limit_exceeded"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := newIAMUserName()
		if _, err := createIAMUser(client, &iam.CreateUserInput{UserName: &userName}); err != nil {
			return err
		}

		checkErr := func() error {
			if _, err := tagIAMUser(client, &iam.TagUserInput{
				UserName: &userName,
				Tags:     numberedIAMTags(1, storage.MaxTagsPerResource),
			}); err != nil {
				return err
			}

			if _, err := tagIAMUser(client, &iam.TagUserInput{
				UserName: &userName,
				Tags:     iamTagList(map[string]string{"key1": "replaced"}),
			}); err != nil {
				return fmt.Errorf("replacing a tag at the quota: %w", err)
			}

			_, err := tagIAMUser(client, &iam.TagUserInput{
				UserName: &userName,
				Tags:     iamTagList(map[string]string{"overflow": "x"}),
			})
			return checkIAMApiErr(err, iamerr.GetAPIError(iamerr.ErrTagLimitExceeded))
		}()

		deleteErr := deleteIAMUser(client, userName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMTagUser_success(s *S3Conf) error {
	testName := "IAMTagUser_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := newIAMUserName()
		if _, err := createIAMUser(client, &iam.CreateUserInput{UserName: &userName}); err != nil {
			return err
		}

		checkErr := func() error {
			// An empty tag value is legal; only the key has a minimum length.
			want := map[string]string{"env": "prod", "team": "storage", "empty": ""}
			out, err := tagIAMUser(client, &iam.TagUserInput{
				UserName: &userName,
				Tags:     iamTagList(want),
			})
			if err != nil {
				return err
			}
			if requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata); !ok || requestID == "" {
				return fmt.Errorf("expected TagUser response request id")
			}

			if err := checkIAMUserTags(client, userName, want); err != nil {
				return err
			}
			// GetUser reports the same tags the tag actions maintain.
			user, err := getIAMUser(client, &iam.GetUserInput{UserName: &userName})
			if err != nil {
				return err
			}
			return compareIAMTags(user.User.Tags, want)
		}()

		deleteErr := deleteIAMUser(client, userName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

// IAMTagUser_overwrites_existing_tag covers re-tagging a key that is
// already present: the value is replaced rather than added alongside, and a
// differently-cased key is the same tag — the newly supplied casing wins.
func IAMTagUser_overwrites_existing_tag(s *S3Conf) error {
	testName := "IAMTagUser_overwrites_existing_tag"
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
			if _, err := tagIAMUser(client, &iam.TagUserInput{
				UserName: &userName,
				Tags:     iamTagList(map[string]string{"env": "staging"}),
			}); err != nil {
				return err
			}
			if err := checkIAMUserTags(client, userName, map[string]string{"env": "staging"}); err != nil {
				return err
			}

			if _, err := tagIAMUser(client, &iam.TagUserInput{
				UserName: &userName,
				Tags:     iamTagList(map[string]string{"ENV": "qa"}),
			}); err != nil {
				return err
			}
			return checkIAMUserTags(client, userName, map[string]string{"ENV": "qa"})
		}()

		deleteErr := deleteIAMUser(client, userName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

// maxIAMTagMembersPerRequest mirrors the per-request Tags/TagKeys member
// cap the service enforces
const maxIAMTagMembersPerRequest = 50

func tagIAMUser(client *iam.Client, input *iam.TagUserInput) (*iam.TagUserOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.TagUser(ctx, input)
}

func iamTagList(tags map[string]string) []iamtypes.Tag {
	list := make([]iamtypes.Tag, 0, len(tags))
	for key, value := range tags {
		list = append(list, iamtypes.Tag{Key: aws.String(key), Value: aws.String(value)})
	}
	return list
}

// numberedIAMTags builds count tags named key<N>/value<N> starting at
// first, for exercising the per-request and per-user tag quotas.
func numberedIAMTags(first, count int) []iamtypes.Tag {
	list := make([]iamtypes.Tag, 0, count)
	for i := first; i < first+count; i++ {
		list = append(list, iamtypes.Tag{
			Key:   aws.String(fmt.Sprintf("key%d", i)),
			Value: aws.String(fmt.Sprintf("value%d", i)),
		})
	}
	return list
}

// checkIAMUserTags asserts ListUserTags reports exactly want for userName.
func checkIAMUserTags(client *iam.Client, userName string, want map[string]string) error {
	out, err := listIAMUserTags(client, &iam.ListUserTagsInput{UserName: &userName})
	if err != nil {
		return err
	}
	if out.IsTruncated {
		return fmt.Errorf("expected IsTruncated to be false")
	}
	return compareIAMTags(out.Tags, want)
}

func compareIAMTags(got []iamtypes.Tag, want map[string]string) error {
	if len(got) != len(want) {
		return fmt.Errorf("expected %d tags, instead got %d: %v", len(want), len(got), iamTagMap(got))
	}
	for key, value := range want {
		found, ok := iamTagMap(got)[key]
		if !ok {
			return fmt.Errorf("expected tag %q to be present, instead got %v", key, iamTagMap(got))
		}
		if found != value {
			return fmt.Errorf("expected tag %q to be %q, instead got %q", key, value, found)
		}
	}
	return nil
}

func iamTagMap(tags []iamtypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		out[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	return out
}
