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
)

func IAMUpdateAccessKey_missing_user_name(s *S3Conf) error {
	testName := "IAMUpdateAccessKey_missing_user_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := updateIAMAccessKey(client, &iam.UpdateAccessKeyInput{
			AccessKeyId: aws.String(genRandString(20)),
			Status:      iamtypes.StatusTypeActive,
		})
		return checkIAMApiErr(err, iamerr.MissingParameter("UserName"))
	})
}

func IAMUpdateAccessKey_invalid_user_name(s *S3Conf) error {
	testName := "IAMUpdateAccessKey_invalid_user_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := updateIAMAccessKey(client, &iam.UpdateAccessKeyInput{
			UserName:    aws.String("invalid/user"),
			AccessKeyId: aws.String(genRandString(20)),
			Status:      iamtypes.StatusTypeActive,
		})
		return checkIAMApiErr(err, iamerr.InvalidUserName("userName"))
	})
}

func IAMUpdateAccessKey_long_user_name(s *S3Conf) error {
	testName := "IAMUpdateAccessKey_long_user_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := updateIAMAccessKey(client, &iam.UpdateAccessKeyInput{
			UserName:    aws.String(strings.Repeat("a", 129)),
			AccessKeyId: aws.String(genRandString(20)),
			Status:      iamtypes.StatusTypeActive,
		})
		return checkIAMApiErr(err, iamerr.UserNameTooLong("userName", 128))
	})
}

func IAMUpdateAccessKey_missing_access_key_id(s *S3Conf) error {
	testName := "IAMUpdateAccessKey_missing_access_key_id"
	body := []byte(url.Values{
		"Action":   {"UpdateAccessKey"},
		"Version":  {"2010-05-08"},
		"UserName": {"validusername"},
		"Status":   {"Active"},
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

func IAMUpdateAccessKey_access_key_id_too_short(s *S3Conf) error {
	testName := "IAMUpdateAccessKey_access_key_id_too_short"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := updateIAMAccessKey(client, &iam.UpdateAccessKeyInput{
			UserName:    aws.String("validusername"),
			AccessKeyId: aws.String(genRandString(15)),
			Status:      iamtypes.StatusTypeActive,
		})
		return checkIAMApiErr(err, iamerr.AccessKeyIDTooShort(16))
	})
}

func IAMUpdateAccessKey_access_key_id_too_long(s *S3Conf) error {
	testName := "IAMUpdateAccessKey_access_key_id_too_long"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := updateIAMAccessKey(client, &iam.UpdateAccessKeyInput{
			UserName:    aws.String("validusername"),
			AccessKeyId: aws.String(genRandString(129)),
			Status:      iamtypes.StatusTypeActive,
		})
		return checkIAMApiErr(err, iamerr.AccessKeyIDTooLong(128))
	})
}

func IAMUpdateAccessKey_invalid_access_key_id_chars(s *S3Conf) error {
	testName := "IAMUpdateAccessKey_invalid_access_key_id_chars"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := updateIAMAccessKey(client, &iam.UpdateAccessKeyInput{
			UserName:    aws.String("validusername"),
			AccessKeyId: aws.String("invalid-key-id-1234"),
			Status:      iamtypes.StatusTypeActive,
		})
		return checkIAMApiErr(err, iamerr.GetAPIError(iamerr.ErrInvalidAccessKeyIDChars))
	})
}

func IAMUpdateAccessKey_missing_status(s *S3Conf) error {
	testName := "IAMUpdateAccessKey_missing_status"
	body := []byte(url.Values{
		"Action":      {"UpdateAccessKey"},
		"Version":     {"2010-05-08"},
		"UserName":    {"validusername"},
		"AccessKeyId": {genRandString(20)},
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
		return checkIAMAuthRequest(s, req, iamerr.MissingParameter("Status"))
	})
}

func IAMUpdateAccessKey_invalid_status(s *S3Conf) error {
	testName := "IAMUpdateAccessKey_invalid_status"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := updateIAMAccessKey(client, &iam.UpdateAccessKeyInput{
			UserName:    aws.String("validusername"),
			AccessKeyId: aws.String(genRandString(20)),
			Status:      iamtypes.StatusType("Bogus"),
		})
		return checkIAMApiErr(err, iamerr.InvalidAccessKeyStatus("Bogus"))
	})
}

func IAMUpdateAccessKey_non_existing_user(s *S3Conf) error {
	testName := "IAMUpdateAccessKey_non_existing_user"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := "non-existing-" + genRandString(16)
		_, err := updateIAMAccessKey(client, &iam.UpdateAccessKeyInput{
			UserName:    &userName,
			AccessKeyId: aws.String(genRandString(20)),
			Status:      iamtypes.StatusTypeActive,
		})
		return checkIAMApiErr(err, iamerr.NoSuchEntityUser(userName))
	})
}

func IAMUpdateAccessKey_non_existing_access_key(s *S3Conf) error {
	testName := "IAMUpdateAccessKey_non_existing_access_key"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := newIAMUserName()
		if _, err := createIAMUser(client, &iam.CreateUserInput{UserName: &userName}); err != nil {
			return err
		}

		accessKeyID := genRandString(20)
		_, updateErr := updateIAMAccessKey(client, &iam.UpdateAccessKeyInput{
			UserName:    &userName,
			AccessKeyId: &accessKeyID,
			Status:      iamtypes.StatusTypeActive,
		})
		checkErr := checkIAMApiErr(updateErr, iamerr.NoSuchEntityAccessKey(accessKeyID))

		deleteErr := deleteIAMUser(client, userName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMUpdateAccessKey_success(s *S3Conf) error {
	testName := "IAMUpdateAccessKey_success"
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

			out, err := updateIAMAccessKey(client, &iam.UpdateAccessKeyInput{
				UserName:    &userName,
				AccessKeyId: &accessKeyID,
				Status:      iamtypes.StatusTypeInactive,
			})
			if err != nil {
				return err
			}
			if out == nil {
				return fmt.Errorf("expected UpdateAccessKey output")
			}
			if requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata); !ok || requestID == "" {
				return fmt.Errorf("expected UpdateAccessKey response request id")
			}

			listOut, err := listIAMAccessKeys(client, &iam.ListAccessKeysInput{UserName: &userName})
			if err != nil {
				return err
			}
			if len(listOut.AccessKeyMetadata) != 1 {
				return fmt.Errorf("expected 1 access key, instead got %d", len(listOut.AccessKeyMetadata))
			}
			if listOut.AccessKeyMetadata[0].Status != iamtypes.StatusTypeInactive {
				return fmt.Errorf("expected access key status to be %q, instead got %q", iamtypes.StatusTypeInactive, listOut.AccessKeyMetadata[0].Status)
			}

			return nil
		}()

		deleteErr := deleteIAMUserAndAccessKeys(client, userName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func updateIAMAccessKey(client *iam.Client, input *iam.UpdateAccessKeyInput) (*iam.UpdateAccessKeyOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.UpdateAccessKey(ctx, input)
}
