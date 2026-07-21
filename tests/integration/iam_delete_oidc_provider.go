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
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/versity/versitygw/iamapi/iamerr"
)

func IAMDeleteOpenIDConnectProvider_missing_arn(s *S3Conf) error {
	testName := "IAMDeleteOpenIDConnectProvider_missing_arn"
	body := []byte("Action=DeleteOpenIDConnectProvider&Version=2010-05-08")
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
		return checkIAMAuthRequest(s, req, iamerr.MissingValue("openIDConnectProviderArn"))
	})
}

func IAMDeleteOpenIDConnectProvider_non_existing(s *S3Conf) error {
	testName := "IAMDeleteOpenIDConnectProvider_non_existing"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn := oidcProviderArn("https://" + genRandString(16) + ".example.com")
		err := deleteOIDCProvider(client, arn)
		return checkIAMApiErr(err, iamerr.NoSuchEntityOIDCProviderDelete(arn))
	})
}

func IAMDeleteOpenIDConnectProvider_success(s *S3Conf) error {
	testName := "IAMDeleteOpenIDConnectProvider_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn, err := createTestOIDCProvider(client)
		if err != nil {
			return err
		}
		if err := deleteOIDCProvider(client, arn); err != nil {
			return err
		}

		_, err = getIAMOIDCProvider(client, arn)
		return checkIAMApiErr(err, iamerr.NoSuchEntityOIDCProviderGet(arn))
	})
}

// IAMDeleteOpenIDConnectProvider_not_idempotent confirms a second delete
// of the same ARN fails.
func IAMDeleteOpenIDConnectProvider_not_idempotent(s *S3Conf) error {
	testName := "IAMDeleteOpenIDConnectProvider_not_idempotent"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn, err := createTestOIDCProvider(client)
		if err != nil {
			return err
		}
		if err := deleteOIDCProvider(client, arn); err != nil {
			return err
		}

		err = deleteOIDCProvider(client, arn)
		return checkIAMApiErr(err, iamerr.NoSuchEntityOIDCProviderDelete(arn))
	})
}
