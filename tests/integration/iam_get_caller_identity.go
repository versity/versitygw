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
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/versity/versitygw/iamapi/iamerr"
)

// getCallerIdentity calls GetCallerIdentity through a real STS SDK client
// configured with access/secret.
func getCallerIdentity(cfg S3Conf, access, secret string) (*sts.GetCallerIdentityOutput, error) {
	cfg.awsID = access
	cfg.awsSecret = secret
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return cfg.GetSTSClient().GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
}

func IAMGetCallerIdentity_root_success(s *S3Conf) error {
	testName := "IAMGetCallerIdentity_root_success"
	return iamActionHandler(s, testName, func(_ *iam.Client) error {
		out, err := getCallerIdentity(*s, s.awsID, s.awsSecret)
		if err != nil {
			return err
		}
		wantArn := "arn:aws:iam::000000000000:root"
		if aws.ToString(out.Arn) != wantArn {
			return fmt.Errorf("expected Arn %q, instead got %q", wantArn, aws.ToString(out.Arn))
		}
		if aws.ToString(out.UserId) != "000000000000" {
			return fmt.Errorf("expected UserId %q, instead got %q", "000000000000", aws.ToString(out.UserId))
		}
		if aws.ToString(out.Account) != "000000000000" {
			return fmt.Errorf("expected Account %q, instead got %q", "000000000000", aws.ToString(out.Account))
		}
		return nil
	})
}

func IAMGetCallerIdentity_user_success(s *S3Conf) error {
	testName := "IAMGetCallerIdentity_user_success"
	return iamActionHandler(s, testName, func(client *iam.Client) (err error) {
		userName := newIAMUserName()
		createOut, err := createIAMUser(client, &iam.CreateUserInput{UserName: &userName})
		if err != nil {
			return err
		}
		defer func() {
			if delErr := deleteIAMUserAndAccessKeys(client, userName); delErr != nil {
				err = fmt.Errorf("%w (also: delete user: %v)", err, delErr)
			}
		}()
		userArn := aws.ToString(createOut.User.Arn)
		userID := aws.ToString(createOut.User.UserId)

		keyOut, err := createIAMAccessKey(client, &iam.CreateAccessKeyInput{UserName: &userName})
		if err != nil {
			return err
		}

		out, err := getCallerIdentity(*s, aws.ToString(keyOut.AccessKey.AccessKeyId), aws.ToString(keyOut.AccessKey.SecretAccessKey))
		if err != nil {
			return err
		}
		if aws.ToString(out.Arn) != userArn {
			return fmt.Errorf("expected Arn %q, instead got %q", userArn, aws.ToString(out.Arn))
		}
		if aws.ToString(out.UserId) != userID {
			return fmt.Errorf("expected UserId %q, instead got %q", userID, aws.ToString(out.UserId))
		}
		if aws.ToString(out.Account) != "000000000000" {
			return fmt.Errorf("expected Account %q, instead got %q", "000000000000", aws.ToString(out.Account))
		}
		return nil
	})
}

func IAMGetCallerIdentity_unknown_access_key(s *S3Conf) error {
	testName := "IAMGetCallerIdentity_unknown_access_key"
	return iamActionHandler(s, testName, func(_ *iam.Client) error {
		_, err := getCallerIdentity(*s, "AKIAuNKNOWNACCESSKEYID", "does-not-matter")
		return checkIAMApiErr(err, iamerr.GetAPIError(iamerr.ErrInvalidClientTokenID))
	})
}

func IAMGetCallerIdentity_no_auth(s *S3Conf) error {
	testName := "IAMGetCallerIdentity_no_auth"
	runF(testName)

	body := []byte(url.Values{"Action": {"GetCallerIdentity"}, "Version": {"2011-06-15"}}.Encode())
	req, err := http.NewRequest(http.MethodPost, s.endpoint+"/", bytes.NewReader(body))
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}
	if err := checkSTSApiErr(resp, iamerr.GetAPIError(iamerr.ErrMissingAuthenticationToken)); err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	passF(testName)
	return nil
}

func IAMGetCallerIdentity_wrong_version_is_invalid_action(s *S3Conf) error {
	testName := "IAMGetCallerIdentity_wrong_version_is_invalid_action"
	cfg := &authConfig{
		testName: testName,
		method:   http.MethodPost,
		service:  "sts",
		region:   iamAuthRegion,
		body:     []byte(url.Values{"Action": {"GetCallerIdentity"}, "Version": {"2010-05-08"}}.Encode()),
		date:     time.Now().UTC(),
		headers:  map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	}
	return authHandler(s, cfg, func(req *http.Request) error {
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		return checkSTSApiErr(resp, iamerr.InvalidAction("GetCallerIdentity", "2010-05-08"))
	})
}

// IAMGetCallerIdentity_incorrect_service_scope confirms the shared sigv4
// auth pipeline reports the STS-specific service name ("sts", not "iam")
// when GetCallerIdentity is signed with a Credential scoped to the wrong
// service.
func IAMGetCallerIdentity_incorrect_service_scope(s *S3Conf) error {
	testName := "IAMGetCallerIdentity_incorrect_service_scope"
	cfg := &authConfig{
		testName: testName,
		method:   http.MethodPost,
		service:  "iam", // wrong: GetCallerIdentity expects "sts"
		region:   iamAuthRegion,
		body:     []byte(url.Values{"Action": {"GetCallerIdentity"}, "Version": {"2011-06-15"}}.Encode()),
		date:     time.Now().UTC(),
		headers:  map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	}
	return authHandler(s, cfg, func(req *http.Request) error {
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		return checkSTSApiErr(resp, iamerr.IncorrectServiceScope("sts"))
	})
}
