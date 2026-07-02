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
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/versity/versitygw/iamapi/iamerr"
)

func IAMGetUser_long_user_name(s *S3Conf) error {
	testName := "IAMGetUser_long_user_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		defer cancel()
		_, err := client.GetUser(ctx, &iam.GetUserInput{
			UserName: aws.String(strings.Repeat("a", 129)),
		})
		return checkIAMApiErr(err, iamerr.UserNameTooLong("userName", 128))
	})
}

func IAMGetUser_invalid_user_name(s *S3Conf) error {
	testName := "IAMGetUser_invalid_user_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		defer cancel()
		_, err := client.GetUser(ctx, &iam.GetUserInput{
			UserName: aws.String("invalid/user"),
		})
		return checkIAMApiErr(err, iamerr.InvalidUserName("userName"))
	})
}

func IAMGetUser_non_existing_user(s *S3Conf) error {
	testName := "IAMGetUser_non_existing_user"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		const userName = "asdkjnfkj"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		defer cancel()
		_, err := client.GetUser(ctx, &iam.GetUserInput{UserName: aws.String(userName)})
		return checkIAMApiErr(err, iamerr.NoSuchEntityUser(userName))
	})
}

func IAMGetUser_success(s *S3Conf) error {
	testName := "IAMGetUser_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := newIAMUserName()
		_, err := createIAMUser(client, &iam.CreateUserInput{
			UserName: &userName,
			Tags: []iamtypes.Tag{
				{Key: aws.String("team"), Value: aws.String("integration")},
				{Key: aws.String("purpose"), Value: aws.String("get-user")},
			},
		})
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := client.GetUser(ctx, &iam.GetUserInput{UserName: &userName})
		cancel()
		if err != nil {
			deleteErr := deleteIAMUser(client, userName)
			if deleteErr != nil {
				return fmt.Errorf("get user: %v; delete user: %w", err, deleteErr)
			}
			return err
		}

		checkErr := func() error {
			if out == nil || out.User == nil {
				return fmt.Errorf("expected GetUser output user")
			}

			user := out.User
			if aws.ToString(user.Path) != "/" {
				return fmt.Errorf("expected user path to be %q, instead got %q", "/", aws.ToString(user.Path))
			}
			if aws.ToString(user.UserName) != userName {
				return fmt.Errorf("expected user name to be %q, instead got %q", userName, aws.ToString(user.UserName))
			}
			expectedARN := "arn:aws:iam::000000000000:user/" + userName
			if aws.ToString(user.Arn) != expectedARN {
				return fmt.Errorf("expected user ARN to be %q, instead got %q", expectedARN, aws.ToString(user.Arn))
			}
			if !integrationIAMUserIDPattern.MatchString(aws.ToString(user.UserId)) {
				return fmt.Errorf("expected AWS IAM user id, instead got %q", aws.ToString(user.UserId))
			}
			if user.CreateDate == nil || user.CreateDate.IsZero() {
				return fmt.Errorf("expected user create date")
			}
			if len(user.Tags) != 2 ||
				aws.ToString(user.Tags[0].Key) != "team" || aws.ToString(user.Tags[0].Value) != "integration" ||
				aws.ToString(user.Tags[1].Key) != "purpose" || aws.ToString(user.Tags[1].Value) != "get-user" {
				return fmt.Errorf("expected user tags team=integration and purpose=get-user, instead got %#v", user.Tags)
			}
			if requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata); !ok || requestID == "" {
				return fmt.Errorf("expected GetUser response request id")
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

func IAMGetUser_root_user(s *S3Conf) error {
	testName := "IAMGetUser_root_user"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		defer cancel()
		out, err := client.GetUser(ctx, &iam.GetUserInput{UserName: aws.String("")})
		if err != nil {
			return err
		}
		if out == nil || out.User == nil {
			return fmt.Errorf("expected GetUser output root user")
		}
		if aws.ToString(out.User.Arn) != "arn:aws:iam::000000000000:root" {
			return fmt.Errorf("expected root user ARN, instead got %q", aws.ToString(out.User.Arn))
		}
		if aws.ToString(out.User.UserId) != "000000000000" {
			return fmt.Errorf("expected root user id to be %q, instead got %q", "000000000000", aws.ToString(out.User.UserId))
		}
		if requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata); !ok || requestID == "" {
			return fmt.Errorf("expected GetUser response request id")
		}

		return nil
	})
}
