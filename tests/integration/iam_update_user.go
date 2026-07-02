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
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/versity/versitygw/iamapi/iamerr"
)

func IAMUpdateUser_invalid_user_name(s *S3Conf) error {
	testName := "IAMUpdateUser_invalid_user_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := updateIAMUser(client, &iam.UpdateUserInput{UserName: aws.String("invalid/user")})
		return checkIAMApiErr(err, iamerr.InvalidUserName("userName"))
	})
}

func IAMUpdateUser_long_user_name(s *S3Conf) error {
	testName := "IAMUpdateUser_long_user_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := updateIAMUser(client, &iam.UpdateUserInput{UserName: aws.String(strings.Repeat("a", 129))})
		return checkIAMApiErr(err, iamerr.UserNameTooLong("userName", 128))
	})
}

func IAMUpdateUser_invalid_new_user_name(s *S3Conf) error {
	testName := "IAMUpdateUser_invalid_new_user_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := updateIAMUser(client, &iam.UpdateUserInput{
			UserName:    aws.String("asdfadsf"),
			NewUserName: aws.String("invalid/user"),
		})
		return checkIAMApiErr(err, iamerr.InvalidUserName("newUserName"))
	})
}

func IAMUpdateUser_long_new_user_name(s *S3Conf) error {
	testName := "IAMUpdateUser_long_new_user_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := updateIAMUser(client, &iam.UpdateUserInput{
			UserName:    aws.String("asdfadsf"),
			NewUserName: aws.String(strings.Repeat("a", 65)),
		})
		return checkIAMApiErr(err, iamerr.UserNameTooLong("newUserName", 64))
	})
}

func IAMUpdateUser_non_existing_user(s *S3Conf) error {
	testName := "IAMUpdateUser_non_existing_user"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		const userName = "asdfadsf"
		_, err := updateIAMUser(client, &iam.UpdateUserInput{UserName: aws.String(userName)})
		return checkIAMApiErr(err, iamerr.NoSuchEntityUser(userName))
	})
}

func IAMUpdateUser_invalid_new_path(s *S3Conf) error {
	testName := "IAMUpdateUser_invalid_new_path"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := updateIAMUser(client, &iam.UpdateUserInput{
			UserName: aws.String("asdfadsf"),
			NewPath:  aws.String("invalid"),
		})
		return checkIAMApiErr(err, iamerr.InvalidPath("newPath"))
	})
}

func IAMUpdateUser_long_new_path(s *S3Conf) error {
	testName := "IAMUpdateUser_long_new_path"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := updateIAMUser(client, &iam.UpdateUserInput{
			UserName: aws.String("asdfadsf"),
			NewPath:  aws.String("/" + strings.Repeat("a", 511) + "/"),
		})
		return checkIAMApiErr(err, iamerr.PathTooLong("newPath", 512))
	})
}

func IAMUpdateUser_new_user_name_already_exists(s *S3Conf) error {
	testName := "IAMUpdateUser_new_user_name_already_exists"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := newIAMUserName()
		existingUserName := newIAMUserName()
		if _, err := createIAMUser(client, &iam.CreateUserInput{UserName: &userName}); err != nil {
			return err
		}
		if _, err := createIAMUser(client, &iam.CreateUserInput{UserName: &existingUserName}); err != nil {
			deleteErr := deleteIAMUser(client, userName)
			if deleteErr != nil {
				return fmt.Errorf("create second user: %v; delete first user: %w", err, deleteErr)
			}
			return err
		}

		_, updateErr := updateIAMUser(client, &iam.UpdateUserInput{
			UserName:    &userName,
			NewUserName: &existingUserName,
		})
		checkErr := checkIAMApiErr(updateErr, iamerr.EntityAlreadyExistsUser(existingUserName))
		firstDeleteErr := deleteIAMUser(client, userName)
		secondDeleteErr := deleteIAMUser(client, existingUserName)
		if checkErr != nil {
			return checkErr
		}
		if firstDeleteErr != nil {
			return firstDeleteErr
		}
		return secondDeleteErr
	})
}

func IAMUpdateUser_success(s *S3Conf) error {
	testName := "IAMUpdateUser_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := newIAMUserName()
		created, err := createIAMUser(client, &iam.CreateUserInput{UserName: &userName})
		if err != nil {
			return err
		}

		newUserName := newIAMUserName()
		newPath := "/updated/"
		out, err := updateIAMUser(client, &iam.UpdateUserInput{
			UserName:    &userName,
			NewUserName: &newUserName,
			NewPath:     &newPath,
		})
		if err != nil {
			deleteErr := deleteIAMUser(client, userName)
			if deleteErr != nil {
				return fmt.Errorf("update user: %v; delete user: %w", err, deleteErr)
			}
			return err
		}

		checkErr := func() error {
			if out == nil {
				return fmt.Errorf("expected UpdateUser output")
			}
			if requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata); !ok || requestID == "" {
				return fmt.Errorf("expected UpdateUser response request id")
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			updated, err := client.GetUser(ctx, &iam.GetUserInput{UserName: &newUserName})
			cancel()
			if err != nil {
				return err
			}
			if updated == nil || updated.User == nil || created == nil || created.User == nil {
				return fmt.Errorf("expected created and updated users")
			}
			if aws.ToString(updated.User.UserName) != newUserName || aws.ToString(updated.User.Path) != newPath {
				return fmt.Errorf("expected updated user name/path %q/%q, instead got %q/%q", newUserName, newPath, aws.ToString(updated.User.UserName), aws.ToString(updated.User.Path))
			}
			expectedARN := "arn:aws:iam::000000000000:user" + newPath + newUserName
			if aws.ToString(updated.User.Arn) != expectedARN {
				return fmt.Errorf("expected updated user ARN %q, instead got %q", expectedARN, aws.ToString(updated.User.Arn))
			}
			if updated.User.CreateDate == nil || created.User.CreateDate == nil {
				return fmt.Errorf("expected created and updated user create dates")
			}
			if aws.ToString(updated.User.UserId) != aws.ToString(created.User.UserId) || !updated.User.CreateDate.Equal(*created.User.CreateDate) {
				return fmt.Errorf("expected UpdateUser to preserve user id and create date")
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			defer cancel()
			_, err = client.GetUser(ctx, &iam.GetUserInput{UserName: &userName})
			return checkIAMApiErr(err, iamerr.NoSuchEntityUser(userName))
		}()
		deleteErr := deleteIAMUser(client, newUserName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func updateIAMUser(client *iam.Client, input *iam.UpdateUserInput) (*iam.UpdateUserOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.UpdateUser(ctx, input)
}
