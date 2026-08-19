// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License. You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package integration

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/versity/versitygw/iamapi/iamerr"
)

func IAMDeleteUser_invalid_user_name(s *S3Conf) error {
	testName := "IAMDeleteUser_invalid_user_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		err := deleteIAMUser(client, "invalid/user")
		return checkIAMApiErr(err, iamerr.InvalidUserName("userName"))
	})
}

func IAMDeleteUser_long_user_name(s *S3Conf) error {
	testName := "IAMDeleteUser_long_user_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		err := deleteIAMUser(client, strings.Repeat("a", 129))
		return checkIAMApiErr(err, iamerr.UserNameTooLong("userName", 128))
	})
}

func IAMDeleteUser_non_existing_user(s *S3Conf) error {
	testName := "IAMDeleteUser_non_existing_user"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		const userName = "asdfadsf"
		err := deleteIAMUser(client, userName)
		return checkIAMApiErr(err, iamerr.NoSuchEntityUser(userName))
	})
}

func IAMDeleteUser_has_access_keys(s *S3Conf) error {
	testName := "IAMDeleteUser_has_access_keys"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := newIAMUserName()
		if _, err := createIAMUser(client, &iam.CreateUserInput{UserName: &userName}); err != nil {
			return err
		}

		out, err := createIAMAccessKey(client, &iam.CreateAccessKeyInput{UserName: &userName})
		if err != nil {
			return err
		}
		accessKeyID := aws.ToString(out.AccessKey.AccessKeyId)

		checkErr := checkIAMApiErr(deleteIAMUser(client, userName), iamerr.GetAPIError(iamerr.ErrDeleteConflict))

		deleteKeyErr := deleteIAMAccessKey(client, userName, accessKeyID)
		deleteUserErr := deleteIAMUser(client, userName)

		if checkErr != nil {
			return checkErr
		}
		if deleteKeyErr != nil {
			return deleteKeyErr
		}
		return deleteUserErr
	})
}

func IAMDeleteUser_success(s *S3Conf) error {
	testName := "IAMDeleteUser_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := newIAMUserName()
		if _, err := createIAMUser(client, &iam.CreateUserInput{UserName: &userName}); err != nil {
			return err
		}

		if err := deleteIAMUser(client, userName); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		defer cancel()
		_, err := client.GetUser(ctx, &iam.GetUserInput{UserName: aws.String(userName)})
		return checkIAMApiErr(err, iamerr.NoSuchEntityUser(userName))
	})
}
