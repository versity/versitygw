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
	"slices"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/versity/versitygw/iamapi/iamerr"
)

func IAMListRolePolicies_missing_role_name(s *S3Conf) error {
	testName := "IAMListRolePolicies_missing_role_name"
	body := []byte("Action=ListRolePolicies&Version=2010-05-08")
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

func IAMListRolePolicies_non_existing_role(s *S3Conf) error {
	testName := "IAMListRolePolicies_non_existing_role"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName := "non-existing-" + genRandString(16)
		_, err := listIAMRolePolicies(client, &iam.ListRolePoliciesInput{RoleName: &roleName})
		return checkIAMApiErr(err, iamerr.NoSuchEntityRole(roleName))
	})
}

func IAMListRolePolicies_invalid_max_items(s *S3Conf) error {
	testName := "IAMListRolePolicies_invalid_max_items"
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
				_, err := listIAMRolePolicies(client, &iam.ListRolePoliciesInput{RoleName: &roleName, MaxItems: aws.Int32(1001)})
				return err
			}(),
			iamerr.InvalidMaxItems("1001"),
		)

		deleteErr := deleteIAMRole(client, roleName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMListRolePolicies_empty_result(s *S3Conf) error {
	testName := "IAMListRolePolicies_empty_result"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName := newIAMRoleName()
		if _, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 &roleName,
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
		}); err != nil {
			return err
		}

		checkErr := func() error {
			out, err := listIAMRolePolicies(client, &iam.ListRolePoliciesInput{RoleName: &roleName})
			if err != nil {
				return err
			}
			if len(out.PolicyNames) != 0 {
				return fmt.Errorf("expected no policies, instead got %v", out.PolicyNames)
			}
			if out.IsTruncated {
				return fmt.Errorf("expected IsTruncated to be false")
			}
			return nil
		}()

		deleteErr := deleteIAMRole(client, roleName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMListRolePolicies_success(s *S3Conf) error {
	testName := "IAMListRolePolicies_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName := newIAMRoleName()
		if _, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 &roleName,
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
		}); err != nil {
			return err
		}

		checkErr := func() error {
			want := []string{"Alpha", "Beta"}
			for _, name := range want {
				if _, err := putIAMRolePolicy(client, &iam.PutRolePolicyInput{
					RoleName:       &roleName,
					PolicyName:     aws.String(name),
					PolicyDocument: aws.String(validIAMPolicyDocument),
				}); err != nil {
					return err
				}
			}

			out, err := listIAMRolePolicies(client, &iam.ListRolePoliciesInput{RoleName: &roleName})
			if err != nil {
				return err
			}
			if requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata); !ok || requestID == "" {
				return fmt.Errorf("expected ListRolePolicies response request id")
			}
			got := slices.Clone(out.PolicyNames)
			slices.Sort(got)
			if !slices.Equal(got, want) {
				return fmt.Errorf("expected policy names %v, instead got %v", want, got)
			}
			if out.IsTruncated {
				return fmt.Errorf("expected IsTruncated to be false")
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

func IAMListRolePolicies_pagination(s *S3Conf) error {
	testName := "IAMListRolePolicies_pagination"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName := newIAMRoleName()
		if _, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 &roleName,
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
		}); err != nil {
			return err
		}

		checkErr := func() error {
			want := []string{"Alpha", "Beta", "Gamma"}
			for _, name := range want {
				if _, err := putIAMRolePolicy(client, &iam.PutRolePolicyInput{
					RoleName:       &roleName,
					PolicyName:     aws.String(name),
					PolicyDocument: aws.String(validIAMPolicyDocument),
				}); err != nil {
					return err
				}
			}

			input := iam.ListRolePoliciesInput{RoleName: &roleName, MaxItems: aws.Int32(1)}
			var pages []*iam.ListRolePoliciesOutput
			for {
				out, err := listIAMRolePolicies(client, &input)
				if err != nil {
					return err
				}
				pages = append(pages, out)
				if !out.IsTruncated {
					break
				}
				input.Marker = out.Marker
			}

			if len(pages) != len(want) {
				return fmt.Errorf("expected %d pages, instead got %d", len(want), len(pages))
			}
			var got []string
			for i, page := range pages {
				if len(page.PolicyNames) != 1 {
					return fmt.Errorf("expected page %d to contain 1 policy, instead got %d", i+1, len(page.PolicyNames))
				}
				if page.IsTruncated != (i < len(pages)-1) {
					return fmt.Errorf("unexpected IsTruncated value on page %d", i+1)
				}
				got = append(got, page.PolicyNames...)
			}
			slices.Sort(got)
			if !slices.Equal(got, want) {
				return fmt.Errorf("expected policy names %v, instead got %v", want, got)
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

func listIAMRolePolicies(client *iam.Client, input *iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.ListRolePolicies(ctx, input)
}
