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

func IAMDeleteUserPolicy_missing_user_name(s *S3Conf) error {
	testName := "IAMDeleteUserPolicy_missing_user_name"
	body := []byte(url.Values{
		"Action":     {"DeleteUserPolicy"},
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
		return checkIAMAuthRequest(s, req, iamerr.MissingValue("userName"))
	})
}

func IAMDeleteUserPolicy_missing_policy_name(s *S3Conf) error {
	testName := "IAMDeleteUserPolicy_missing_policy_name"
	body := []byte(url.Values{
		"Action":   {"DeleteUserPolicy"},
		"Version":  {"2010-05-08"},
		"UserName": {newIAMUserName()},
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

func IAMDeleteUserPolicy_non_existing_user(s *S3Conf) error {
	testName := "IAMDeleteUserPolicy_non_existing_user"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := "non-existing-" + genRandString(16)
		_, err := deleteIAMUserPolicyRaw(client, &iam.DeleteUserPolicyInput{
			UserName:   &userName,
			PolicyName: aws.String("p"),
		})
		return checkIAMApiErr(err, iamerr.NoSuchEntityUser(userName))
	})
}

func IAMDeleteUserPolicy_non_existing_policy(s *S3Conf) error {
	testName := "IAMDeleteUserPolicy_non_existing_policy"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := newIAMUserName()
		if _, err := createIAMUser(client, &iam.CreateUserInput{UserName: &userName}); err != nil {
			return err
		}

		checkErr := checkIAMApiErr(
			func() error {
				_, err := deleteIAMUserPolicyRaw(client, &iam.DeleteUserPolicyInput{UserName: &userName, PolicyName: aws.String("missing")})
				return err
			}(),
			iamerr.NoSuchEntityUserPolicy(userName, "missing"),
		)

		deleteErr := deleteIAMUser(client, userName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMDeleteUserPolicy_success(s *S3Conf) error {
	testName := "IAMDeleteUserPolicy_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := newIAMUserName()
		if _, err := createIAMUser(client, &iam.CreateUserInput{UserName: &userName}); err != nil {
			return err
		}

		checkErr := func() error {
			if _, err := putIAMUserPolicy(client, &iam.PutUserPolicyInput{
				UserName:       &userName,
				PolicyName:     aws.String("p"),
				PolicyDocument: aws.String(validIAMPolicyDocument),
			}); err != nil {
				return err
			}

			out, err := deleteIAMUserPolicyRaw(client, &iam.DeleteUserPolicyInput{UserName: &userName, PolicyName: aws.String("p")})
			if err != nil {
				return err
			}
			if requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata); !ok || requestID == "" {
				return fmt.Errorf("expected DeleteUserPolicy response request id")
			}

			_, err = getIAMUserPolicy(client, &iam.GetUserPolicyInput{UserName: &userName, PolicyName: aws.String("p")})
			return checkIAMApiErr(err, iamerr.NoSuchEntityUserPolicy(userName, "p"))
		}()

		deleteErr := deleteIAMUser(client, userName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMDeleteUserPolicy_blocks_user_deletion(s *S3Conf) error {
	testName := "IAMDeleteUserPolicy_blocks_user_deletion"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		userName := newIAMUserName()
		if _, err := createIAMUser(client, &iam.CreateUserInput{UserName: &userName}); err != nil {
			return err
		}
		if _, err := putIAMUserPolicy(client, &iam.PutUserPolicyInput{
			UserName:       &userName,
			PolicyName:     aws.String("p"),
			PolicyDocument: aws.String(validIAMPolicyDocument),
		}); err != nil {
			return err
		}

		checkErr := checkIAMApiErr(deleteIAMUser(client, userName), iamerr.GetAPIError(iamerr.ErrDeleteConflictPolicies))

		deletePolicyErr := deleteIAMUserPolicy(client, userName, "p")
		deleteUserErr := deleteIAMUser(client, userName)

		if checkErr != nil {
			return checkErr
		}
		if deletePolicyErr != nil {
			return deletePolicyErr
		}
		return deleteUserErr
	})
}

func deleteIAMUserPolicyRaw(client *iam.Client, input *iam.DeleteUserPolicyInput) (*iam.DeleteUserPolicyOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.DeleteUserPolicy(ctx, input)
}

func deleteIAMUserPolicy(client *iam.Client, userName, policyName string) error {
	_, err := deleteIAMUserPolicyRaw(client, &iam.DeleteUserPolicyInput{UserName: &userName, PolicyName: &policyName})
	return err
}

// deleteIAMUserAndPolicies deletes all of the user's inline policies before
// deleting the user, since DeleteUser rejects users with policies still
// attached. Use this for test cleanup after a test has created inline
// policies.
func deleteIAMUserAndPolicies(client *iam.Client, userName string) error {
	out, err := listIAMUserPolicies(client, &iam.ListUserPoliciesInput{UserName: &userName})
	if err != nil {
		return err
	}
	for _, policyName := range out.PolicyNames {
		if err := deleteIAMUserPolicy(client, userName, policyName); err != nil {
			return err
		}
	}
	return deleteIAMUser(client, userName)
}
