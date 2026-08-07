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
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/versity/versitygw/iamapi/iamerr"
)

func IAMRemoveClientIDFromOpenIDConnectProvider_missing_arn(s *S3Conf) error {
	testName := "IAMRemoveClientIDFromOpenIDConnectProvider_missing_arn"
	body := []byte(url.Values{
		"Action":   {"RemoveClientIDFromOpenIDConnectProvider"},
		"Version":  {"2010-05-08"},
		"ClientID": {"sts.amazonaws.com"},
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
		return checkIAMAuthRequest(s, req, iamerr.MissingValue("openIDConnectProviderArn"))
	})
}

func IAMRemoveClientIDFromOpenIDConnectProvider_missing_client_id(s *S3Conf) error {
	testName := "IAMRemoveClientIDFromOpenIDConnectProvider_missing_client_id"
	body := []byte(url.Values{
		"Action":                   {"RemoveClientIDFromOpenIDConnectProvider"},
		"Version":                  {"2010-05-08"},
		"OpenIDConnectProviderArn": {"arn:aws:iam::000000000000:oidc-provider/example.com"},
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
		return checkIAMAuthRequest(s, req, iamerr.MissingValue("clientID"))
	})
}

func IAMRemoveClientIDFromOpenIDConnectProvider_client_id_too_long(s *S3Conf) error {
	testName := "IAMRemoveClientIDFromOpenIDConnectProvider_client_id_too_long"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn, err := createTestOIDCProvider(client)
		if err != nil {
			return err
		}

		checkErr := checkIAMApiErr(removeClientIDFromOIDCProvider(client, arn, strings.Repeat("c", 256)), iamerr.ValueTooLong("clientID", 255))
		deleteErr := deleteOIDCProvider(client, arn)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMRemoveClientIDFromOpenIDConnectProvider_non_existing_provider(s *S3Conf) error {
	testName := "IAMRemoveClientIDFromOpenIDConnectProvider_non_existing_provider"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn := oidcProviderArn("https://" + genRandString(16) + ".example.com")
		err := removeClientIDFromOIDCProvider(client, arn, "sts.amazonaws.com")
		return checkIAMApiErr(err, iamerr.NoSuchEntityOIDCProviderGet(arn))
	})
}

func IAMRemoveClientIDFromOpenIDConnectProvider_success(s *S3Conf) error {
	testName := "IAMRemoveClientIDFromOpenIDConnectProvider_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		out, err := createOIDCProvider(client, &iam.CreateOpenIDConnectProviderInput{
			Url:            aws.String(newIAMOIDCProviderURL()),
			ClientIDList:   []string{"sts.amazonaws.com", "another-client"},
			ThumbprintList: []string{validOIDCThumbprint},
		})
		if err != nil {
			return err
		}
		arn := aws.ToString(out.OpenIDConnectProviderArn)

		checkErr := func() error {
			if err := removeClientIDFromOIDCProvider(client, arn, "sts.amazonaws.com"); err != nil {
				return err
			}
			got, err := getIAMOIDCProvider(client, arn)
			if err != nil {
				return err
			}
			if len(got.ClientIDList) != 1 || got.ClientIDList[0] != "another-client" {
				return fmt.Errorf("expected ClientIDList [another-client], instead got %#v", got.ClientIDList)
			}
			return nil
		}()

		deleteErr := deleteOIDCProvider(client, arn)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

// IAMRemoveClientIDFromOpenIDConnectProvider_idempotent_absent confirms
// removing a client ID that was never added succeeds silently rather than
// erroring.
func IAMRemoveClientIDFromOpenIDConnectProvider_idempotent_absent(s *S3Conf) error {
	testName := "IAMRemoveClientIDFromOpenIDConnectProvider_idempotent_absent"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn, err := createTestOIDCProvider(client)
		if err != nil {
			return err
		}

		checkErr := removeClientIDFromOIDCProvider(client, arn, "never-added")
		deleteErr := deleteOIDCProvider(client, arn)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func removeClientIDFromOIDCProvider(client *iam.Client, arn, clientID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	_, err := client.RemoveClientIDFromOpenIDConnectProvider(ctx, &iam.RemoveClientIDFromOpenIDConnectProviderInput{
		OpenIDConnectProviderArn: &arn,
		ClientID:                 &clientID,
	})
	return err
}
