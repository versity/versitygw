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
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/versity/versitygw/iamapi/iamerr"
)

func IAMGetAccessKeyLastUsed_missing_access_key_id(s *S3Conf) error {
	testName := "IAMGetAccessKeyLastUsed_missing_access_key_id"
	body := []byte(url.Values{
		"Action":  {"GetAccessKeyLastUsed"},
		"Version": {"2010-05-08"},
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

func IAMGetAccessKeyLastUsed_access_key_id_too_short(s *S3Conf) error {
	testName := "IAMGetAccessKeyLastUsed_access_key_id_too_short"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := getIAMAccessKeyLastUsed(client, genRandString(15))
		return checkIAMApiErr(err, iamerr.AccessKeyIDTooShort(16))
	})
}

func IAMGetAccessKeyLastUsed_access_key_id_too_long(s *S3Conf) error {
	testName := "IAMGetAccessKeyLastUsed_access_key_id_too_long"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := getIAMAccessKeyLastUsed(client, genRandString(129))
		return checkIAMApiErr(err, iamerr.AccessKeyIDTooLong(128))
	})
}

func IAMGetAccessKeyLastUsed_invalid_access_key_id_chars(s *S3Conf) error {
	testName := "IAMGetAccessKeyLastUsed_invalid_access_key_id_chars"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := getIAMAccessKeyLastUsed(client, "invalid-key-id-1234")
		return checkIAMApiErr(err, iamerr.GetAPIError(iamerr.ErrInvalidAccessKeyIDChars))
	})
}

func IAMGetAccessKeyLastUsed_non_existing_access_key(s *S3Conf) error {
	testName := "IAMGetAccessKeyLastUsed_non_existing_access_key"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		accessKeyID := genRandString(20)
		_, err := getIAMAccessKeyLastUsed(client, accessKeyID)
		return checkIAMApiErr(err, iamerr.NoSuchEntityAccessKey(accessKeyID))
	})
}

func IAMGetAccessKeyLastUsed_success(s *S3Conf) error {
	testName := "IAMGetAccessKeyLastUsed_success"
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

			out, err := getIAMAccessKeyLastUsed(client, accessKeyID)
			if err != nil {
				return err
			}
			if out == nil || out.AccessKeyLastUsed == nil {
				return fmt.Errorf("expected GetAccessKeyLastUsed output")
			}
			if aws.ToString(out.UserName) != userName {
				return fmt.Errorf("expected access key user name to be %q, instead got %q", userName, aws.ToString(out.UserName))
			}
			if aws.ToString(out.AccessKeyLastUsed.ServiceName) != "N/A" {
				return fmt.Errorf("expected access key last used service name to be %q, instead got %q", "N/A", aws.ToString(out.AccessKeyLastUsed.ServiceName))
			}
			if aws.ToString(out.AccessKeyLastUsed.Region) != "N/A" {
				return fmt.Errorf("expected access key last used region to be %q, instead got %q", "N/A", aws.ToString(out.AccessKeyLastUsed.Region))
			}
			if out.AccessKeyLastUsed.LastUsedDate != nil {
				return fmt.Errorf("expected no access key last used date, instead got %v", out.AccessKeyLastUsed.LastUsedDate)
			}
			if requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata); !ok || requestID == "" {
				return fmt.Errorf("expected GetAccessKeyLastUsed response request id")
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

func getIAMAccessKeyLastUsed(client *iam.Client, accessKeyID string) (*iam.GetAccessKeyLastUsedOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{AccessKeyId: &accessKeyID})
}
