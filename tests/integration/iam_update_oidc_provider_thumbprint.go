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
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/versity/versitygw/iamapi/iamerr"
)

func IAMUpdateOpenIDConnectProviderThumbprint_missing_arn(s *S3Conf) error {
	testName := "IAMUpdateOpenIDConnectProviderThumbprint_missing_arn"
	body := []byte(url.Values{
		"Action":                  {"UpdateOpenIDConnectProviderThumbprint"},
		"Version":                 {"2010-05-08"},
		"ThumbprintList.member.1": {validOIDCThumbprint},
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

func IAMUpdateOpenIDConnectProviderThumbprint_missing_thumbprint_list(s *S3Conf) error {
	testName := "IAMUpdateOpenIDConnectProviderThumbprint_missing_thumbprint_list"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn, err := createTestOIDCProvider(client)
		if err != nil {
			return err
		}

		checkErr := checkIAMApiErr(updateOIDCProviderThumbprint(client, arn, []string{}), iamerr.ThumbprintListEmpty())
		deleteErr := deleteOIDCProvider(client, arn)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMUpdateOpenIDConnectProviderThumbprint_too_many_thumbprints(s *S3Conf) error {
	testName := "IAMUpdateOpenIDConnectProviderThumbprint_too_many_thumbprints"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn, err := createTestOIDCProvider(client)
		if err != nil {
			return err
		}

		thumbprints := []string{
			strings.Repeat("1", 40), strings.Repeat("2", 40), strings.Repeat("3", 40),
			strings.Repeat("4", 40), strings.Repeat("5", 40), strings.Repeat("6", 40),
		}
		checkErr := checkIAMApiErr(updateOIDCProviderThumbprint(client, arn, thumbprints), iamerr.ThumbprintListTooLong(5))
		deleteErr := deleteOIDCProvider(client, arn)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMUpdateOpenIDConnectProviderThumbprint_wrong_length_thumbprint(s *S3Conf) error {
	testName := "IAMUpdateOpenIDConnectProviderThumbprint_wrong_length_thumbprint"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn, err := createTestOIDCProvider(client)
		if err != nil {
			return err
		}

		checkErr := checkIAMApiErr(
			updateOIDCProviderThumbprint(client, arn, []string{strings.Repeat("a", 39)}),
			iamerr.InvalidInput("Thumbprint must be exactly 40 characters."),
		)
		deleteErr := deleteOIDCProvider(client, arn)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMUpdateOpenIDConnectProviderThumbprint_non_existing_provider(s *S3Conf) error {
	testName := "IAMUpdateOpenIDConnectProviderThumbprint_non_existing_provider"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn := oidcProviderArn("https://" + genRandString(16) + ".example.com")
		err := updateOIDCProviderThumbprint(client, arn, []string{validOIDCThumbprint})
		return checkIAMApiErr(err, iamerr.NoSuchEntityOIDCProviderGet(arn))
	})
}

func IAMUpdateOpenIDConnectProviderThumbprint_success(s *S3Conf) error {
	testName := "IAMUpdateOpenIDConnectProviderThumbprint_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn, err := createTestOIDCProvider(client)
		if err != nil {
			return err
		}

		checkErr := func() error {
			newThumbprints := []string{strings.Repeat("A", 40), strings.Repeat("B", 40)}
			if err := updateOIDCProviderThumbprint(client, arn, newThumbprints); err != nil {
				return err
			}
			out, err := getIAMOIDCProvider(client, arn)
			if err != nil {
				return err
			}
			// Full replace (the original validOIDCThumbprint must be gone),
			// lowercased (submitted uppercase).
			want := []string{strings.Repeat("a", 40), strings.Repeat("b", 40)}
			if !slices.Equal(out.ThumbprintList, want) {
				return fmt.Errorf("expected ThumbprintList %#v, instead got %#v", want, out.ThumbprintList)
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

// IAMUpdateOpenIDConnectProviderThumbprint_boundary_max_thumbprints
// confirms exactly MaxThumbprintsPerOIDCProvider entries succeeds — the
// limit message says "fewer than 5", but 5 itself is accepted.
func IAMUpdateOpenIDConnectProviderThumbprint_boundary_max_thumbprints(s *S3Conf) error {
	testName := "IAMUpdateOpenIDConnectProviderThumbprint_boundary_max_thumbprints"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn, err := createTestOIDCProvider(client)
		if err != nil {
			return err
		}

		thumbprints := []string{
			strings.Repeat("1", 40), strings.Repeat("2", 40), strings.Repeat("3", 40),
			strings.Repeat("4", 40), strings.Repeat("5", 40),
		}
		checkErr := updateOIDCProviderThumbprint(client, arn, thumbprints)
		deleteErr := deleteOIDCProvider(client, arn)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func updateOIDCProviderThumbprint(client *iam.Client, arn string, thumbprints []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	_, err := client.UpdateOpenIDConnectProviderThumbprint(ctx, &iam.UpdateOpenIDConnectProviderThumbprintInput{
		OpenIDConnectProviderArn: &arn,
		ThumbprintList:           thumbprints,
	})
	return err
}
