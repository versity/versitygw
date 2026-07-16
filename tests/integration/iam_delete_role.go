// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License. You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package integration

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/versity/versitygw/iamapi/iamerr"
)

func IAMDeleteRole_missing_role_name(s *S3Conf) error {
	testName := "IAMDeleteRole_missing_role_name"
	body := []byte("Action=DeleteRole&Version=2010-05-08")
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
		return checkIAMAuthRequest(s, req, iamerr.MissingParameter("RoleName"))
	})
}

func IAMDeleteRole_invalid_role_name(s *S3Conf) error {
	testName := "IAMDeleteRole_invalid_role_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		err := deleteIAMRole(client, "invalid/role")
		return checkIAMApiErr(err, iamerr.InvalidUserName("roleName"))
	})
}

func IAMDeleteRole_long_role_name(s *S3Conf) error {
	testName := "IAMDeleteRole_long_role_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		err := deleteIAMRole(client, strings.Repeat("a", 129))
		return checkIAMApiErr(err, iamerr.UserNameTooLong("roleName", 128))
	})
}

func IAMDeleteRole_non_existing_role(s *S3Conf) error {
	testName := "IAMDeleteRole_non_existing_role"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		const roleName = "asdfadsf"
		err := deleteIAMRole(client, roleName)
		return checkIAMApiErr(err, iamerr.NoSuchEntityRole(roleName))
	})
}

func IAMDeleteRole_has_policies(s *S3Conf) error {
	testName := "IAMDeleteRole_has_policies"
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

func IAMDeleteRole_success(s *S3Conf) error {
	testName := "IAMDeleteRole_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName := newIAMRoleName()
		if _, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 &roleName,
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
		}); err != nil {
			return err
		}

		if err := deleteIAMRole(client, roleName); err != nil {
			return err
		}

		_, err := getIAMRole(client, roleName)
		return checkIAMApiErr(err, iamerr.NoSuchEntityRole(roleName))
	})
}

func deleteIAMRole(client *iam.Client, roleName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	_, err := client.DeleteRole(ctx, &iam.DeleteRoleInput{RoleName: &roleName})
	return err
}
