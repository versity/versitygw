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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/versity/versitygw/iamapi/iamerr"
)

func IAMGetOpenIDConnectProvider_missing_arn(s *S3Conf) error {
	testName := "IAMGetOpenIDConnectProvider_missing_arn"
	body := []byte("Action=GetOpenIDConnectProvider&Version=2010-05-08")
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

func IAMGetOpenIDConnectProvider_invalid_arn(s *S3Conf) error {
	testName := "IAMGetOpenIDConnectProvider_invalid_arn"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		tests := []struct {
			name string
			arn  string
			want iamerr.Error
		}{
			{"too_short", strings.Repeat("a", 19), iamerr.ValueTooShort("openIDConnectProviderArn", 20)},
			{"too_long", strings.Repeat("a", 2049), iamerr.ValueTooLong("openIDConnectProviderArn", 2048)},
			{"wrong_resource_type", "arn:aws:iam::000000000000:role/some-role", iamerr.ValidationError("Invalid resource type in ARN")},
			{"foreign_account_id", "arn:aws:iam::123456789012:oidc-provider/example.com", iamerr.AccessDeniedOIDCProvider("000000000000", "arn:aws:iam::123456789012:oidc-provider/example.com")},
		}
		for _, tt := range tests {
			_, err := getIAMOIDCProvider(client, tt.arn)
			if checkErr := checkIAMApiErr(err, tt.want); checkErr != nil {
				return fmt.Errorf("%s: %w", tt.name, checkErr)
			}
		}
		return nil
	})
}

func IAMGetOpenIDConnectProvider_non_existing(s *S3Conf) error {
	testName := "IAMGetOpenIDConnectProvider_non_existing"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		arn := oidcProviderArn("https://" + genRandString(16) + ".example.com")
		_, err := getIAMOIDCProvider(client, arn)
		return checkIAMApiErr(err, iamerr.NoSuchEntityOIDCProviderGet(arn))
	})
}

func IAMGetOpenIDConnectProvider_success(s *S3Conf) error {
	testName := "IAMGetOpenIDConnectProvider_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		providerURL := newIAMOIDCProviderURL()
		created, err := createOIDCProvider(client, &iam.CreateOpenIDConnectProviderInput{
			Url:            aws.String(providerURL),
			ClientIDList:   []string{"sts.amazonaws.com", "another-client"},
			ThumbprintList: []string{validOIDCThumbprint},
			Tags: []iamtypes.Tag{
				{Key: aws.String("env"), Value: aws.String("test")},
			},
		})
		if err != nil {
			return err
		}
		arn := aws.ToString(created.OpenIDConnectProviderArn)

		checkErr := func() error {
			out, err := getIAMOIDCProvider(client, arn)
			if err != nil {
				return err
			}
			wantURL := strings.TrimPrefix(providerURL, "https://")
			if aws.ToString(out.Url) != wantURL {
				return fmt.Errorf("expected Url %q, instead got %q", wantURL, aws.ToString(out.Url))
			}
			wantClientIDs := []string{"sts.amazonaws.com", "another-client"}
			if len(out.ClientIDList) != len(wantClientIDs) {
				return fmt.Errorf("expected ClientIDList %#v, instead got %#v", wantClientIDs, out.ClientIDList)
			}
			for i, id := range wantClientIDs {
				if out.ClientIDList[i] != id {
					return fmt.Errorf("expected ClientIDList %#v, instead got %#v", wantClientIDs, out.ClientIDList)
				}
			}
			if len(out.ThumbprintList) != 1 || out.ThumbprintList[0] != validOIDCThumbprint {
				return fmt.Errorf("expected ThumbprintList [%s], instead got %#v", validOIDCThumbprint, out.ThumbprintList)
			}
			if out.CreateDate == nil || out.CreateDate.IsZero() {
				return fmt.Errorf("expected CreateDate to be set")
			}
			if len(out.Tags) != 1 || aws.ToString(out.Tags[0].Key) != "env" || aws.ToString(out.Tags[0].Value) != "test" {
				return fmt.Errorf("expected tag env=test, instead got %#v", out.Tags)
			}
			if requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata); !ok || requestID == "" {
				return fmt.Errorf("expected GetOpenIDConnectProvider response request id")
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

func getIAMOIDCProvider(client *iam.Client, arn string) (*iam.GetOpenIDConnectProviderOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.GetOpenIDConnectProvider(ctx, &iam.GetOpenIDConnectProviderInput{OpenIDConnectProviderArn: &arn})
}
