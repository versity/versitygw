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
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/versity/versitygw/iamapi/iamerr"
)

var integrationIAMUserIDPattern = regexp.MustCompile(`^AIDA[A-Z2-7]{17}$`)

func IAMCreateUser_user_already_exists(s *S3Conf) error {
	testName := "IAMCreateUser_user_already_exists"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := newIAMUserName()
		_, err := createIAMUser(client, &iam.CreateUserInput{
			UserName: &userName,
		})
		if err != nil {
			return err
		}

		_, err = createIAMUser(client, &iam.CreateUserInput{UserName: &userName})
		return checkIAMApiErr(err, iamerr.EntityAlreadyExistsUser(userName))
	})
}

func IAMCreateUser_invalid_user_name(s *S3Conf) error {
	testName := "IAMCreateUser_invalid_user_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := createIAMUser(client, &iam.CreateUserInput{
			UserName: aws.String("invalid/user"),
		})
		return checkIAMApiErr(err, iamerr.InvalidUserName("userName"))
	})
}

func IAMCreateUser_long_user_name(s *S3Conf) error {
	testName := "IAMCreateUser_long_user_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := createIAMUser(client, &iam.CreateUserInput{
			UserName: aws.String(strings.Repeat("a", 65)),
		})
		return checkIAMApiErr(err, iamerr.UserNameTooLong("userName", 64))
	})
}

func IAMCreateUser_missing_user_name(s *S3Conf) error {
	testName := "IAMCreateUser_missing_user_name"
	body := []byte("Action=CreateUser&Version=2010-05-08")
	return authHandler(s, &authConfig{
		testName: testName,
		method:   http.MethodPost,
		service:  "iam",
		region:   iamAuthRegion,
		body:     body,
		date:     time.Now().UTC(),
		headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
	}, func(req *http.Request) error {
		return checkIAMAuthRequest(s, req, iamerr.ValidationError("1 validation error detected: Value at 'userName' failed to satisfy constraint: Member must not be null"))
	})
}

func IAMCreateUser_invalid_tag_key(s *S3Conf) error {
	testName := "IAMCreateUser_invalid_tag_key"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := createIAMUser(client, &iam.CreateUserInput{
			UserName: aws.String(newIAMUserName()),
			Tags: []iamtypes.Tag{
				{Key: aws.String("invalid*key"), Value: aws.String("value")},
			},
		})
		return checkIAMApiErr(err, iamerr.ValidationError("1 validation error detected: Value at 'tags.1.member.key' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]+"))
	})
}

func IAMCreateUser_invalid_tag_value(s *S3Conf) error {
	testName := "IAMCreateUser_invalid_tag_value"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := createIAMUser(client, &iam.CreateUserInput{
			UserName: aws.String(newIAMUserName()),
			Tags: []iamtypes.Tag{
				{Key: aws.String("key"), Value: aws.String("invalid*value")},
			},
		})
		return checkIAMApiErr(err, iamerr.ValidationError("1 validation error detected: Value at 'tags.1.member.value' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]*"))
	})
}

func IAMCreateUser_long_tag_key(s *S3Conf) error {
	testName := "IAMCreateUser_long_tag_key"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := createIAMUser(client, &iam.CreateUserInput{
			UserName: aws.String(newIAMUserName()),
			Tags: []iamtypes.Tag{
				{Key: aws.String(strings.Repeat("k", 129)), Value: aws.String("value")},
			},
		})
		return checkIAMApiErr(err, iamerr.ValidationError("1 validation error detected: Value at 'tags.1.member.key' failed to satisfy constraint: Member must have length less than or equal to 128"))
	})
}

func IAMCreateUser_long_tag_value(s *S3Conf) error {
	testName := "IAMCreateUser_long_tag_value"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := createIAMUser(client, &iam.CreateUserInput{
			UserName: aws.String(newIAMUserName()),
			Tags: []iamtypes.Tag{
				{Key: aws.String("key"), Value: aws.String(strings.Repeat("v", 257))},
			},
		})
		return checkIAMApiErr(err, iamerr.ValidationError("1 validation error detected: Value at 'tags.1.member.value' failed to satisfy constraint: Member must have length less than or equal to 256"))
	})
}

func IAMCreateUser_duplicate_tag_keys(s *S3Conf) error {
	testName := "IAMCreateUser_duplicate_tag_keys"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := createIAMUser(client, &iam.CreateUserInput{
			UserName: aws.String(newIAMUserName()),
			Tags: []iamtypes.Tag{
				{Key: aws.String("key"), Value: aws.String("one")},
				{Key: aws.String("KEY"), Value: aws.String("two")},
			},
		})
		return checkIAMApiErr(err, iamerr.InvalidInput("Duplicate tag keys found. Please note that Tag keys are case insensitive."))
	})
}

func IAMCreateUser_success(s *S3Conf) error {
	testName := "IAMCreateUser_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := newIAMUserName()
		out, err := createIAMUser(client, &iam.CreateUserInput{
			UserName: &userName,
			Path:     aws.String("/"),
			Tags: []iamtypes.Tag{
				{Key: aws.String("key"), Value: aws.String("value")},
			},
		})
		if err != nil {
			return err
		}

		checkErr := checkCreateUserOutput(out, userName, "/", true)
		deleteErr := deleteIAMUser(client, userName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMCreateUser_default_path(s *S3Conf) error {
	testName := "IAMCreateUser_default_path"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := newIAMUserName()
		out, err := createIAMUser(client, &iam.CreateUserInput{UserName: &userName})
		if err != nil {
			return err
		}

		checkErr := checkCreateUserOutput(out, userName, "/", false)
		deleteErr := deleteIAMUser(client, userName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMCreateUser_invalid_path(s *S3Conf) error {
	testName := "IAMCreateUser_invalid_path"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := createIAMUser(client, &iam.CreateUserInput{
			UserName: aws.String(newIAMUserName()),
			Path:     aws.String("invalid"),
		})
		return checkIAMApiErr(err, iamerr.InvalidPath("path"))
	})
}

func IAMCreateUser_long_path(s *S3Conf) error {
	testName := "IAMCreateUser_long_path"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := createIAMUser(client, &iam.CreateUserInput{
			UserName: aws.String(newIAMUserName()),
			Path:     aws.String("/" + strings.Repeat("a", 511) + "/"),
		})
		return checkIAMApiErr(err, iamerr.PathTooLong("path", 512))
	})
}

func createIAMUser(client *iam.Client, input *iam.CreateUserInput) (*iam.CreateUserOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.CreateUser(ctx, input)
}

func deleteIAMUser(client *iam.Client, userName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	_, err := client.DeleteUser(ctx, &iam.DeleteUserInput{UserName: &userName})
	return err
}

func newIAMUserName() string {
	return "create-user-" + genRandString(16)
}

func checkCreateUserOutput(out *iam.CreateUserOutput, userName, path string, expectTags bool) error {
	if out == nil || out.User == nil {
		return fmt.Errorf("expected CreateUser output user")
	}

	user := out.User
	if aws.ToString(user.Path) != path {
		return fmt.Errorf("expected user path to be %q, instead got %q", path, aws.ToString(user.Path))
	}
	if aws.ToString(user.UserName) != userName {
		return fmt.Errorf("expected user name to be %q, instead got %q", userName, aws.ToString(user.UserName))
	}
	expectedARN := "arn:aws:iam::000000000000:user" + path + userName
	if aws.ToString(user.Arn) != expectedARN {
		return fmt.Errorf("expected user ARN to be %q, instead got %q", expectedARN, aws.ToString(user.Arn))
	}
	if !integrationIAMUserIDPattern.MatchString(aws.ToString(user.UserId)) {
		return fmt.Errorf("expected AWS IAM user id, instead got %q", aws.ToString(user.UserId))
	}
	if user.CreateDate == nil || user.CreateDate.IsZero() {
		return fmt.Errorf("expected user create date")
	}
	if expectTags {
		if len(user.Tags) != 1 || aws.ToString(user.Tags[0].Key) != "key" || aws.ToString(user.Tags[0].Value) != "value" {
			return fmt.Errorf("expected user tag key=value, instead got %#v", user.Tags)
		}
	} else if len(user.Tags) != 0 {
		return fmt.Errorf("expected no user tags, instead got %#v", user.Tags)
	}
	if requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata); !ok || requestID == "" {
		return fmt.Errorf("expected CreateUser response request id")
	}

	return nil
}
