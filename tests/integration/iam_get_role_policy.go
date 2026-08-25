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

func IAMGetRolePolicy_missing_role_name(s *S3Conf) error {
	testName := "IAMGetRolePolicy_missing_role_name"
	body := []byte(url.Values{
		"Action":     {"GetRolePolicy"},
		"Version":    {"2010-05-08"},
		"PolicyName": {"p"},
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
		return checkIAMAuthRequest(s, req, iamerr.MissingValue("roleName"))
	})
}

func IAMGetRolePolicy_missing_policy_name(s *S3Conf) error {
	testName := "IAMGetRolePolicy_missing_policy_name"
	body := []byte(url.Values{
		"Action":   {"GetRolePolicy"},
		"Version":  {"2010-05-08"},
		"RoleName": {newIAMRoleName()},
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
		return checkIAMAuthRequest(s, req, iamerr.MissingValue("policyName"))
	})
}

func IAMGetRolePolicy_non_existing_role(s *S3Conf) error {
	testName := "IAMGetRolePolicy_non_existing_role"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName := "non-existing-" + genRandString(16)
		_, err := getIAMRolePolicy(client, &iam.GetRolePolicyInput{
			RoleName:   &roleName,
			PolicyName: aws.String("p"),
		})
		return checkIAMApiErr(err, iamerr.NoSuchEntityRole(roleName))
	})
}

func IAMGetRolePolicy_non_existing_policy(s *S3Conf) error {
	testName := "IAMGetRolePolicy_non_existing_policy"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName := newIAMRoleName()
		if _, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 &roleName,
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
		}); err != nil {
			return err
		}

		checkErr := checkIAMApiErr(
			func() error {
				_, err := getIAMRolePolicy(client, &iam.GetRolePolicyInput{RoleName: &roleName, PolicyName: aws.String("missing")})
				return err
			}(),
			iamerr.NoSuchEntityRolePolicy(roleName, "missing"),
		)

		deleteErr := deleteIAMRole(client, roleName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMGetRolePolicy_success(s *S3Conf) error {
	testName := "IAMGetRolePolicy_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName := newIAMRoleName()
		if _, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 &roleName,
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
		}); err != nil {
			return err
		}

		checkErr := func() error {
			if _, err := putIAMRolePolicy(client, &iam.PutRolePolicyInput{
				RoleName:       &roleName,
				PolicyName:     aws.String("ReadOnly"),
				PolicyDocument: aws.String(validIAMPolicyDocument),
			}); err != nil {
				return err
			}

			out, err := getIAMRolePolicy(client, &iam.GetRolePolicyInput{RoleName: &roleName, PolicyName: aws.String("ReadOnly")})
			if err != nil {
				return err
			}
			if out == nil {
				return fmt.Errorf("expected GetRolePolicy output")
			}
			if aws.ToString(out.RoleName) != roleName {
				return fmt.Errorf("expected role name %q, instead got %q", roleName, aws.ToString(out.RoleName))
			}
			if aws.ToString(out.PolicyName) != "ReadOnly" {
				return fmt.Errorf("expected policy name %q, instead got %q", "ReadOnly", aws.ToString(out.PolicyName))
			}
			gotDocument, err := url.QueryUnescape(aws.ToString(out.PolicyDocument))
			if err != nil {
				return fmt.Errorf("failed to url-decode policy document %q: %w", aws.ToString(out.PolicyDocument), err)
			}
			if gotDocument != validIAMPolicyDocument {
				return fmt.Errorf("expected policy document %q, instead got %q", validIAMPolicyDocument, gotDocument)
			}
			if requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata); !ok || requestID == "" {
				return fmt.Errorf("expected GetRolePolicy response request id")
			}
			return nil
		}()

		deleteErr := deleteIAMRoleAndPolicies(client, roleName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func getIAMRolePolicy(client *iam.Client, input *iam.GetRolePolicyInput) (*iam.GetRolePolicyOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.GetRolePolicy(ctx, input)
}
