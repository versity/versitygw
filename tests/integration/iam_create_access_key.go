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
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/versity/versitygw/iamapi/iamerr"
)

var integrationIAMAccessKeyIDPattern = regexp.MustCompile(`^AKIA[A-Z2-7]{17}$`)

func IAMCreateAccessKey_missing_user_name(s *S3Conf) error {
	testName := "IAMCreateAccessKey_missing_user_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := createIAMAccessKey(client, &iam.CreateAccessKeyInput{})
		return checkIAMApiErr(err, iamerr.MissingParameter("UserName"))
	})
}

func IAMCreateAccessKey_invalid_user_name(s *S3Conf) error {
	testName := "IAMCreateAccessKey_invalid_user_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := createIAMAccessKey(client, &iam.CreateAccessKeyInput{
			UserName: aws.String("invalid/user"),
		})
		return checkIAMApiErr(err, iamerr.InvalidUserName("userName"))
	})
}

func IAMCreateAccessKey_long_user_name(s *S3Conf) error {
	testName := "IAMCreateAccessKey_long_user_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := createIAMAccessKey(client, &iam.CreateAccessKeyInput{
			UserName: aws.String(strings.Repeat("a", 129)),
		})
		return checkIAMApiErr(err, iamerr.UserNameTooLong("userName", 128))
	})
}

func IAMCreateAccessKey_non_existing_user(s *S3Conf) error {
	testName := "IAMCreateAccessKey_non_existing_user"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := "non-existing-" + genRandString(16)
		_, err := createIAMAccessKey(client, &iam.CreateAccessKeyInput{UserName: &userName})
		return checkIAMApiErr(err, iamerr.NoSuchEntityUser(userName))
	})
}

func IAMCreateAccessKey_limit_exceeded(s *S3Conf) error {
	testName := "IAMCreateAccessKey_limit_exceeded"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := newIAMUserName()
		if _, err := createIAMUser(client, &iam.CreateUserInput{UserName: &userName}); err != nil {
			return err
		}

		checkErr := func() error {
			for range 2 {
				if _, err := createIAMAccessKey(client, &iam.CreateAccessKeyInput{UserName: &userName}); err != nil {
					return err
				}
			}
			_, err := createIAMAccessKey(client, &iam.CreateAccessKeyInput{UserName: &userName})
			return checkIAMApiErr(err, iamerr.AccessKeysLimitExceeded(2))
		}()

		deleteErr := deleteIAMUserAndAccessKeys(client, userName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMCreateAccessKey_success(s *S3Conf) error {
	testName := "IAMCreateAccessKey_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := newIAMUserName()
		if _, err := createIAMUser(client, &iam.CreateUserInput{UserName: &userName}); err != nil {
			return err
		}

		out, err := createIAMAccessKey(client, &iam.CreateAccessKeyInput{UserName: &userName})
		checkErr := func() error {
			if err != nil {
				return err
			}
			return checkCreateAccessKeyOutput(out, userName)
		}()

		deleteErr := deleteIAMUserAndAccessKeys(client, userName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func createIAMAccessKey(client *iam.Client, input *iam.CreateAccessKeyInput) (*iam.CreateAccessKeyOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.CreateAccessKey(ctx, input)
}

func checkCreateAccessKeyOutput(out *iam.CreateAccessKeyOutput, userName string) error {
	if out == nil || out.AccessKey == nil {
		return fmt.Errorf("expected CreateAccessKey output access key")
	}

	key := out.AccessKey
	if aws.ToString(key.UserName) != userName {
		return fmt.Errorf("expected access key user name to be %q, instead got %q", userName, aws.ToString(key.UserName))
	}
	if !integrationIAMAccessKeyIDPattern.MatchString(aws.ToString(key.AccessKeyId)) {
		return fmt.Errorf("expected AWS IAM access key id, instead got %q", aws.ToString(key.AccessKeyId))
	}
	if key.Status != iamtypes.StatusTypeActive {
		return fmt.Errorf("expected access key status to be %q, instead got %q", iamtypes.StatusTypeActive, key.Status)
	}
	if aws.ToString(key.SecretAccessKey) == "" {
		return fmt.Errorf("expected access key secret")
	}
	if key.CreateDate == nil || key.CreateDate.IsZero() {
		return fmt.Errorf("expected access key create date")
	}
	if requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata); !ok || requestID == "" {
		return fmt.Errorf("expected CreateAccessKey response request id")
	}

	return nil
}
