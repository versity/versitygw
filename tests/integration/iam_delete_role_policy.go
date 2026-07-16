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

func IAMDeleteRolePolicy_missing_role_name(s *S3Conf) error {
	testName := "IAMDeleteRolePolicy_missing_role_name"
	body := []byte(url.Values{
		"Action":     {"DeleteRolePolicy"},
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

func IAMDeleteRolePolicy_missing_policy_name(s *S3Conf) error {
	testName := "IAMDeleteRolePolicy_missing_policy_name"
	body := []byte(url.Values{
		"Action":   {"DeleteRolePolicy"},
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

func IAMDeleteRolePolicy_non_existing_role(s *S3Conf) error {
	testName := "IAMDeleteRolePolicy_non_existing_role"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName := "non-existing-" + genRandString(16)
		_, err := deleteIAMRolePolicyRaw(client, &iam.DeleteRolePolicyInput{
			RoleName:   &roleName,
			PolicyName: aws.String("p"),
		})
		return checkIAMApiErr(err, iamerr.NoSuchEntityRole(roleName))
	})
}

func IAMDeleteRolePolicy_non_existing_policy(s *S3Conf) error {
	testName := "IAMDeleteRolePolicy_non_existing_policy"
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
				_, err := deleteIAMRolePolicyRaw(client, &iam.DeleteRolePolicyInput{RoleName: &roleName, PolicyName: aws.String("missing")})
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

func IAMDeleteRolePolicy_success(s *S3Conf) error {
	testName := "IAMDeleteRolePolicy_success"
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
				PolicyName:     aws.String("p"),
				PolicyDocument: aws.String(validIAMPolicyDocument),
			}); err != nil {
				return err
			}

			out, err := deleteIAMRolePolicyRaw(client, &iam.DeleteRolePolicyInput{RoleName: &roleName, PolicyName: aws.String("p")})
			if err != nil {
				return err
			}
			if requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata); !ok || requestID == "" {
				return fmt.Errorf("expected DeleteRolePolicy response request id")
			}

			_, err = getIAMRolePolicy(client, &iam.GetRolePolicyInput{RoleName: &roleName, PolicyName: aws.String("p")})
			return checkIAMApiErr(err, iamerr.NoSuchEntityRolePolicy(roleName, "p"))
		}()

		deleteErr := deleteIAMRole(client, roleName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMDeleteRolePolicy_blocks_role_deletion(s *S3Conf) error {
	testName := "IAMDeleteRolePolicy_blocks_role_deletion"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName := newIAMRoleName()
		if _, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 &roleName,
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
		}); err != nil {
			return err
		}
		if _, err := putIAMRolePolicy(client, &iam.PutRolePolicyInput{
			RoleName:       &roleName,
			PolicyName:     aws.String("p"),
			PolicyDocument: aws.String(validIAMPolicyDocument),
		}); err != nil {
			return err
		}

		checkErr := checkIAMApiErr(deleteIAMRole(client, roleName), iamerr.GetAPIError(iamerr.ErrDeleteConflictPolicies))

		deletePolicyErr := deleteIAMRolePolicy(client, roleName, "p")
		deleteRoleErr := deleteIAMRole(client, roleName)

		if checkErr != nil {
			return checkErr
		}
		if deletePolicyErr != nil {
			return deletePolicyErr
		}
		return deleteRoleErr
	})
}

func deleteIAMRolePolicyRaw(client *iam.Client, input *iam.DeleteRolePolicyInput) (*iam.DeleteRolePolicyOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.DeleteRolePolicy(ctx, input)
}

func deleteIAMRolePolicy(client *iam.Client, roleName, policyName string) error {
	_, err := deleteIAMRolePolicyRaw(client, &iam.DeleteRolePolicyInput{RoleName: &roleName, PolicyName: &policyName})
	return err
}

// deleteIAMRoleAndPolicies deletes all of the role's inline policies before
// deleting the role, since DeleteRole rejects roles with policies still
// attached. Use this for test cleanup after a test has created inline
// policies.
func deleteIAMRoleAndPolicies(client *iam.Client, roleName string) error {
	out, err := listIAMRolePolicies(client, &iam.ListRolePoliciesInput{RoleName: &roleName})
	if err != nil {
		return err
	}
	for _, policyName := range out.PolicyNames {
		if err := deleteIAMRolePolicy(client, roleName, policyName); err != nil {
			return err
		}
	}
	return deleteIAMRole(client, roleName)
}
