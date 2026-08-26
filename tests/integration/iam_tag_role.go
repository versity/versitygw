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

func IAMTagRole_missing_role_name(s *S3Conf) error {
	testName := "IAMTagRole_missing_role_name"
	body := []byte(url.Values{
		"Action":              {"TagRole"},
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
		return checkIAMAuthRequest(s, req, iamerr.MissingValue("roleName"))
	})
}

func IAMTagRole_invalid_role_name(s *S3Conf) error {
	testName := "IAMTagRole_invalid_role_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := tagIAMRole(client, &iam.TagRoleInput{
			RoleName: aws.String("invalid role name"),
			Tags:     iamTagList(map[string]string{"env": "prod"}),
		})
		return checkIAMApiErr(err, iamerr.InvalidUserName("roleName"))
	})
}

func IAMTagRole_role_name_too_long(s *S3Conf) error {
	testName := "IAMTagRole_role_name_too_long"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := tagIAMRole(client, &iam.TagRoleInput{
			RoleName: aws.String(strings.Repeat("a", 65)),
			Tags:     iamTagList(map[string]string{"env": "prod"}),
		})
		return checkIAMApiErr(err, iamerr.UserNameTooLong("roleName", 64))
	})
}

func IAMTagRole_missing_tags(s *S3Conf) error {
	testName := "IAMTagRole_missing_tags"
	body := []byte(url.Values{
		"Action":   {"TagRole"},
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
		return checkIAMAuthRequest(s, req, iamerr.MissingValue("tags"))
	})
}

func IAMTagRole_missing_tag_key(s *S3Conf) error {
	testName := "IAMTagRole_missing_tag_key"
	body := []byte(url.Values{
		"Action":              {"TagRole"},
		"Version":             {"2010-05-08"},
		"RoleName":            {"validrolename"},
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

func IAMTagRole_missing_tag_value(s *S3Conf) error {
	testName := "IAMTagRole_missing_tag_value"
	body := []byte(url.Values{
		"Action":            {"TagRole"},
		"Version":           {"2010-05-08"},
		"RoleName":          {"validrolename"},
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

func IAMTagRole_empty_tag_key(s *S3Conf) error {
	testName := "IAMTagRole_empty_tag_key"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := tagIAMRole(client, &iam.TagRoleInput{
			RoleName: aws.String("validrolename"),
			Tags:     []iamtypes.Tag{{Key: aws.String(""), Value: aws.String("prod")}},
		})
		return checkIAMApiErr(err, iamerr.TagKeyTooShort(1))
	})
}

func IAMTagRole_tag_key_too_long(s *S3Conf) error {
	testName := "IAMTagRole_tag_key_too_long"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := tagIAMRole(client, &iam.TagRoleInput{
			RoleName: aws.String("validrolename"),
			Tags:     iamTagList(map[string]string{strings.Repeat("k", 129): "prod"}),
		})
		return checkIAMApiErr(err, iamerr.TagKeyTooLong(1))
	})
}

func IAMTagRole_invalid_tag_key(s *S3Conf) error {
	testName := "IAMTagRole_invalid_tag_key"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := tagIAMRole(client, &iam.TagRoleInput{
			RoleName: aws.String("validrolename"),
			Tags:     iamTagList(map[string]string{"invalid*key": "prod"}),
		})
		return checkIAMApiErr(err, iamerr.InvalidTagKey(1))
	})
}

func IAMTagRole_tag_value_too_long(s *S3Conf) error {
	testName := "IAMTagRole_tag_value_too_long"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := tagIAMRole(client, &iam.TagRoleInput{
			RoleName: aws.String("validrolename"),
			Tags:     iamTagList(map[string]string{"env": strings.Repeat("v", 257)}),
		})
		return checkIAMApiErr(err, iamerr.TagValueTooLong(1))
	})
}

func IAMTagRole_invalid_tag_value(s *S3Conf) error {
	testName := "IAMTagRole_invalid_tag_value"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := tagIAMRole(client, &iam.TagRoleInput{
			RoleName: aws.String("validrolename"),
			Tags:     iamTagList(map[string]string{"env": "invalid*value"}),
		})
		return checkIAMApiErr(err, iamerr.InvalidTagValue(1))
	})
}

// IAMTagRole_duplicate_tag_keys covers both an exact repeat and a
// differently-cased repeat: IAM compares tag keys case-insensitively, so
// both are the same key twice in one request.
func IAMTagRole_duplicate_tag_keys(s *S3Conf) error {
	testName := "IAMTagRole_duplicate_tag_keys"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		for _, second := range []string{"env", "ENV"} {
			_, err := tagIAMRole(client, &iam.TagRoleInput{
				RoleName: aws.String("validrolename"),
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

func IAMTagRole_too_many_tags(s *S3Conf) error {
	testName := "IAMTagRole_too_many_tags"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := tagIAMRole(client, &iam.TagRoleInput{
			RoleName: aws.String("validrolename"),
			Tags:     numberedIAMTags(1, maxIAMTagMembersPerRequest+1),
		})
		return checkIAMApiErr(err, iamerr.GetAPIError(iamerr.ErrTooManyTags))
	})
}

func IAMTagRole_non_existing_role(s *S3Conf) error {
	testName := "IAMTagRole_non_existing_role"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName := "non-existing-" + genRandString(16)
		_, err := tagIAMRole(client, &iam.TagRoleInput{
			RoleName: &roleName,
			Tags:     iamTagList(map[string]string{"env": "prod"}),
		})
		return checkIAMApiErr(err, iamerr.NoSuchEntityRole(roleName))
	})
}

func IAMTagRole_tag_limit_exceeded(s *S3Conf) error {
	testName := "IAMTagRole_tag_limit_exceeded"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName, err := createTaggableIAMRole(client, nil)
		if err != nil {
			return err
		}

		checkErr := func() error {
			if _, err := tagIAMRole(client, &iam.TagRoleInput{
				RoleName: &roleName,
				Tags:     numberedIAMTags(1, storage.MaxTagsPerResource),
			}); err != nil {
				return err
			}

			if _, err := tagIAMRole(client, &iam.TagRoleInput{
				RoleName: &roleName,
				Tags:     iamTagList(map[string]string{"key1": "replaced"}),
			}); err != nil {
				return fmt.Errorf("replacing a tag at the quota: %w", err)
			}

			_, err := tagIAMRole(client, &iam.TagRoleInput{
				RoleName: &roleName,
				Tags:     iamTagList(map[string]string{"overflow": "x"}),
			})
			return checkIAMApiErr(err, iamerr.GetAPIError(iamerr.ErrTagLimitExceeded))
		}()

		deleteErr := deleteIAMRole(client, roleName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMTagRole_success(s *S3Conf) error {
	testName := "IAMTagRole_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName, err := createTaggableIAMRole(client, nil)
		if err != nil {
			return err
		}

		checkErr := func() error {
			// An empty tag value is legal; only the key has a minimum length.
			want := map[string]string{"env": "prod", "team": "storage", "empty": ""}
			out, err := tagIAMRole(client, &iam.TagRoleInput{
				RoleName: &roleName,
				Tags:     iamTagList(want),
			})
			if err != nil {
				return err
			}
			if requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata); !ok || requestID == "" {
				return fmt.Errorf("expected TagRole response request id")
			}

			if err := checkIAMRoleTags(client, roleName, want); err != nil {
				return err
			}
			// GetRole reports the same tags the tag actions maintain.
			role, err := getIAMRole(client, roleName)
			if err != nil {
				return err
			}
			return compareIAMTags(role.Role.Tags, want)
		}()

		deleteErr := deleteIAMRole(client, roleName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

// IAMTagRole_overwrites_existing_tag covers re-tagging a key that is
// already present: the value is replaced rather than added alongside, and a
// differently-cased key is the same tag — the newly supplied casing wins.
func IAMTagRole_overwrites_existing_tag(s *S3Conf) error {
	testName := "IAMTagRole_overwrites_existing_tag"
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
			if _, err := tagIAMRole(client, &iam.TagRoleInput{
				RoleName: &roleName,
				Tags:     iamTagList(map[string]string{"env": "staging"}),
			}); err != nil {
				return err
			}
			if err := checkIAMRoleTags(client, roleName, map[string]string{"env": "staging"}); err != nil {
				return err
			}

			if _, err := tagIAMRole(client, &iam.TagRoleInput{
				RoleName: &roleName,
				Tags:     iamTagList(map[string]string{"ENV": "qa"}),
			}); err != nil {
				return err
			}
			return checkIAMRoleTags(client, roleName, map[string]string{"ENV": "qa"})
		}()

		deleteErr := deleteIAMRole(client, roleName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

// IAMTagRole_isolated_from_same_named_user covers a role and a user sharing
// a name: they are separate entities, so tagging one leaves the other's
// tags untouched in both directions.
func IAMTagRole_isolated_from_same_named_user(s *S3Conf) error {
	testName := "IAMTagRole_isolated_from_same_named_user"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		name := "shared-name-" + genRandString(16)
		if _, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 &name,
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
		}); err != nil {
			return err
		}
		if _, err := createIAMUser(client, &iam.CreateUserInput{UserName: &name}); err != nil {
			deleteIAMRole(client, name)
			return err
		}

		checkErr := func() error {
			if _, err := tagIAMRole(client, &iam.TagRoleInput{
				RoleName: &name,
				Tags:     iamTagList(map[string]string{"owner": "role"}),
			}); err != nil {
				return err
			}
			if _, err := tagIAMUser(client, &iam.TagUserInput{
				UserName: &name,
				Tags:     iamTagList(map[string]string{"owner": "user"}),
			}); err != nil {
				return err
			}

			if err := checkIAMRoleTags(client, name, map[string]string{"owner": "role"}); err != nil {
				return err
			}
			if err := checkIAMUserTags(client, name, map[string]string{"owner": "user"}); err != nil {
				return err
			}

			// Untagging the user must not strip the role's identically-named key.
			if _, err := untagIAMUser(client, &iam.UntagUserInput{UserName: &name, TagKeys: []string{"owner"}}); err != nil {
				return err
			}
			if err := checkIAMUserTags(client, name, map[string]string{}); err != nil {
				return err
			}
			return checkIAMRoleTags(client, name, map[string]string{"owner": "role"})
		}()

		deleteErr := deleteIAMUser(client, name)
		if roleErr := deleteIAMRole(client, name); deleteErr == nil {
			deleteErr = roleErr
		}
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func tagIAMRole(client *iam.Client, input *iam.TagRoleInput) (*iam.TagRoleOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.TagRole(ctx, input)
}

// createTaggableIAMRole creates a role carrying tags, if any, and returns
// its generated name.
func createTaggableIAMRole(client *iam.Client, tags []iamtypes.Tag) (string, error) {
	roleName := newIAMRoleName()
	_, err := createIAMRole(client, &iam.CreateRoleInput{
		RoleName:                 &roleName,
		AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
		Tags:                     tags,
	})
	if err != nil {
		return "", err
	}
	return roleName, nil
}

// checkIAMRoleTags asserts ListRoleTags reports exactly want for roleName.
func checkIAMRoleTags(client *iam.Client, roleName string, want map[string]string) error {
	out, err := listIAMRoleTags(client, &iam.ListRoleTagsInput{RoleName: &roleName})
	if err != nil {
		return err
	}
	if out.IsTruncated {
		return fmt.Errorf("expected IsTruncated to be false")
	}
	return compareIAMTags(out.Tags, want)
}
