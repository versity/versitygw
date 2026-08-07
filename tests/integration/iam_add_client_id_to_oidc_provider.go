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
	"github.com/versity/versitygw/iamapi/storage"
)

func IAMAddClientIDToOpenIDConnectProvider_missing_arn(s *S3Conf) error {
	testName := "IAMAddClientIDToOpenIDConnectProvider_missing_arn"
	body := []byte(url.Values{
		"Action":   {"AddClientIDToOpenIDConnectProvider"},
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

func IAMAddClientIDToOpenIDConnectProvider_missing_client_id(s *S3Conf) error {
	testName := "IAMAddClientIDToOpenIDConnectProvider_missing_client_id"
	body := []byte(url.Values{
		"Action":                   {"AddClientIDToOpenIDConnectProvider"},
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

func IAMAddClientIDToOpenIDConnectProvider_client_id_too_long(s *S3Conf) error {
	testName := "IAMAddClientIDToOpenIDConnectProvider_client_id_too_long"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn, err := createTestOIDCProvider(client)
		if err != nil {
			return err
		}

		checkErr := checkIAMApiErr(addClientIDToOIDCProvider(client, arn, strings.Repeat("c", 256)), iamerr.ValueTooLong("clientID", 255))
		deleteErr := deleteOIDCProvider(client, arn)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMAddClientIDToOpenIDConnectProvider_non_existing_provider(s *S3Conf) error {
	testName := "IAMAddClientIDToOpenIDConnectProvider_non_existing_provider"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn := oidcProviderArn("https://" + genRandString(16) + ".example.com")
		err := addClientIDToOIDCProvider(client, arn, "sts.amazonaws.com")
		return checkIAMApiErr(err, iamerr.NoSuchEntityOIDCProviderGet(arn))
	})
}

func IAMAddClientIDToOpenIDConnectProvider_limit_exceeded(s *S3Conf) error {
	testName := "IAMAddClientIDToOpenIDConnectProvider_limit_exceeded"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		clientIDs := make([]string, storage.MaxClientIDsPerOIDCProvider)
		for i := range clientIDs {
			clientIDs[i] = fmt.Sprintf("client-%d", i)
		}
		out, err := createOIDCProvider(client, &iam.CreateOpenIDConnectProviderInput{
			Url:            aws.String(newIAMOIDCProviderURL()),
			ClientIDList:   clientIDs,
			ThumbprintList: []string{validOIDCThumbprint},
		})
		if err != nil {
			return err
		}
		arn := aws.ToString(out.OpenIDConnectProviderArn)

		checkErr := checkIAMApiErr(
			addClientIDToOIDCProvider(client, arn, "one-too-many"),
			iamerr.ClientIdsPerOpenIdConnectProviderLimitExceeded(storage.MaxClientIDsPerOIDCProvider),
		)
		deleteErr := deleteOIDCProvider(client, arn)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMAddClientIDToOpenIDConnectProvider_success(s *S3Conf) error {
	testName := "IAMAddClientIDToOpenIDConnectProvider_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn, err := createTestOIDCProvider(client)
		if err != nil {
			return err
		}

		checkErr := func() error {
			if err := addClientIDToOIDCProvider(client, arn, "sts.amazonaws.com"); err != nil {
				return err
			}
			out, err := getIAMOIDCProvider(client, arn)
			if err != nil {
				return err
			}
			if len(out.ClientIDList) != 1 || out.ClientIDList[0] != "sts.amazonaws.com" {
				return fmt.Errorf("expected ClientIDList [sts.amazonaws.com], instead got %#v", out.ClientIDList)
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

// IAMAddClientIDToOpenIDConnectProvider_idempotent_duplicate confirms
// adding an already-present client ID succeeds silently rather than
// erroring or creating a duplicate entry.
func IAMAddClientIDToOpenIDConnectProvider_idempotent_duplicate(s *S3Conf) error {
	testName := "IAMAddClientIDToOpenIDConnectProvider_idempotent_duplicate"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn, err := createTestOIDCProvider(client)
		if err != nil {
			return err
		}

		checkErr := func() error {
			if err := addClientIDToOIDCProvider(client, arn, "sts.amazonaws.com"); err != nil {
				return err
			}
			if err := addClientIDToOIDCProvider(client, arn, "sts.amazonaws.com"); err != nil {
				return err
			}
			out, err := getIAMOIDCProvider(client, arn)
			if err != nil {
				return err
			}
			if len(out.ClientIDList) != 1 || out.ClientIDList[0] != "sts.amazonaws.com" {
				return fmt.Errorf("expected ClientIDList [sts.amazonaws.com] (no duplicate), instead got %#v", out.ClientIDList)
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

func addClientIDToOIDCProvider(client *iam.Client, arn, clientID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	_, err := client.AddClientIDToOpenIDConnectProvider(ctx, &iam.AddClientIDToOpenIDConnectProviderInput{
		OpenIDConnectProviderArn: &arn,
		ClientID:                 &clientID,
	})
	return err
}
