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
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/versity/versitygw/iamapi/iamerr"
)

func IAMDeleteAccessKey_missing_user_name(s *S3Conf) error {
	testName := "IAMDeleteAccessKey_missing_user_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		err := deleteIAMAccessKey(client, "", genRandString(20))
		return checkIAMApiErr(err, iamerr.MissingParameter("UserName"))
	})
}

func IAMDeleteAccessKey_invalid_user_name(s *S3Conf) error {
	testName := "IAMDeleteAccessKey_invalid_user_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		err := deleteIAMAccessKey(client, "invalid/user", genRandString(20))
		return checkIAMApiErr(err, iamerr.InvalidUserName("userName"))
	})
}

func IAMDeleteAccessKey_long_user_name(s *S3Conf) error {
	testName := "IAMDeleteAccessKey_long_user_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		err := deleteIAMAccessKey(client, strings.Repeat("a", 129), genRandString(20))
		return checkIAMApiErr(err, iamerr.UserNameTooLong("userName", 128))
	})
}

func IAMDeleteAccessKey_missing_access_key_id(s *S3Conf) error {
	testName := "IAMDeleteAccessKey_missing_access_key_id"
	body := []byte(url.Values{
		"Action":   {"DeleteAccessKey"},
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
		headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
	}, func(req *http.Request) error {
		return checkIAMAuthRequest(s, req, iamerr.MissingParameter("AccessKeyId"))
	})
}

func IAMDeleteAccessKey_access_key_id_too_short(s *S3Conf) error {
	testName := "IAMDeleteAccessKey_access_key_id_too_short"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		err := deleteIAMAccessKey(client, "validusername", genRandString(15))
		return checkIAMApiErr(err, iamerr.AccessKeyIDTooShort(16))
	})
}

func IAMDeleteAccessKey_access_key_id_too_long(s *S3Conf) error {
	testName := "IAMDeleteAccessKey_access_key_id_too_long"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		err := deleteIAMAccessKey(client, "validusername", genRandString(129))
		return checkIAMApiErr(err, iamerr.AccessKeyIDTooLong(128))
	})
}

func IAMDeleteAccessKey_invalid_access_key_id_chars(s *S3Conf) error {
	testName := "IAMDeleteAccessKey_invalid_access_key_id_chars"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		err := deleteIAMAccessKey(client, "validusername", "invalid-key-id-1234")
		return checkIAMApiErr(err, iamerr.GetAPIError(iamerr.ErrInvalidAccessKeyIDChars))
	})
}

func IAMDeleteAccessKey_non_existing_user(s *S3Conf) error {
	testName := "IAMDeleteAccessKey_non_existing_user"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := "non-existing-" + genRandString(16)
		err := deleteIAMAccessKey(client, userName, genRandString(20))
		return checkIAMApiErr(err, iamerr.NoSuchEntityUser(userName))
	})
}

func IAMDeleteAccessKey_non_existing_access_key(s *S3Conf) error {
	testName := "IAMDeleteAccessKey_non_existing_access_key"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := newIAMUserName()
		if _, err := createIAMUser(client, &iam.CreateUserInput{UserName: &userName}); err != nil {
			return err
		}

		accessKeyID := genRandString(20)
		deleteErr := deleteIAMAccessKey(client, userName, accessKeyID)
		checkErr := checkIAMApiErr(deleteErr, iamerr.NoSuchEntityAccessKey(accessKeyID))

		userDeleteErr := deleteIAMUser(client, userName)
		if checkErr != nil {
			return checkErr
		}
		return userDeleteErr
	})
}

func IAMDeleteAccessKey_success(s *S3Conf) error {
	testName := "IAMDeleteAccessKey_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := newIAMUserName()
		if _, err := createIAMUser(client, &iam.CreateUserInput{UserName: &userName}); err != nil {
			return err
		}

		checkErr := func() error {
			created, err := createIAMAccessKey(client, &iam.CreateAccessKeyInput{UserName: &userName})
			if err != nil {
				return err
			}
			accessKeyID := aws.ToString(created.AccessKey.AccessKeyId)

			if err := deleteIAMAccessKey(client, userName, accessKeyID); err != nil {
				return err
			}

			_, err = getIAMAccessKeyLastUsed(client, accessKeyID)
			return checkIAMApiErr(err, iamerr.NoSuchEntityAccessKey(accessKeyID))
		}()

		deleteErr := deleteIAMUser(client, userName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func deleteIAMAccessKey(client *iam.Client, userName, accessKeyID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()

	input := &iam.DeleteAccessKeyInput{AccessKeyId: &accessKeyID}
	if userName != "" {
		input.UserName = &userName
	}
	_, err := client.DeleteAccessKey(ctx, input)
	return err
}
