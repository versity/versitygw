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
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/iamapi/storage"
)

func IAMPutRolePolicy_missing_role_name(s *S3Conf) error {
	testName := "IAMPutRolePolicy_missing_role_name"
	body := []byte(url.Values{
		"Action":         {"PutRolePolicy"},
		"Version":        {"2010-05-08"},
		"PolicyName":     {"p"},
		"PolicyDocument": {validIAMPolicyDocument},
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

func IAMPutRolePolicy_missing_policy_name(s *S3Conf) error {
	testName := "IAMPutRolePolicy_missing_policy_name"
	body := []byte(url.Values{
		"Action":         {"PutRolePolicy"},
		"Version":        {"2010-05-08"},
		"RoleName":       {newIAMRoleName()},
		"PolicyDocument": {validIAMPolicyDocument},
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

func IAMPutRolePolicy_missing_policy_document(s *S3Conf) error {
	testName := "IAMPutRolePolicy_missing_policy_document"
	body := []byte(url.Values{
		"Action":     {"PutRolePolicy"},
		"Version":    {"2010-05-08"},
		"RoleName":   {newIAMRoleName()},
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
		return checkIAMAuthRequest(s, req, iamerr.MissingValue("policyDocument"))
	})
}

func IAMPutRolePolicy_invalid_policy_name(s *S3Conf) error {
	testName := "IAMPutRolePolicy_invalid_policy_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := putIAMRolePolicy(client, &iam.PutRolePolicyInput{
			RoleName:       aws.String(newIAMRoleName()),
			PolicyName:     aws.String("bad/name"),
			PolicyDocument: aws.String(validIAMPolicyDocument),
		})
		return checkIAMApiErr(err, iamerr.InvalidUserName("policyName"))
	})
}

func IAMPutRolePolicy_long_policy_name(s *S3Conf) error {
	testName := "IAMPutRolePolicy_long_policy_name"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := putIAMRolePolicy(client, &iam.PutRolePolicyInput{
			RoleName:       aws.String(newIAMRoleName()),
			PolicyName:     aws.String(strings.Repeat("p", 129)),
			PolicyDocument: aws.String(validIAMPolicyDocument),
		})
		return checkIAMApiErr(err, iamerr.UserNameTooLong("policyName", 128))
	})
}

func IAMPutRolePolicy_non_ascii_policy_document(s *S3Conf) error {
	testName := "IAMPutRolePolicy_non_ascii_policy_document"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := putIAMRolePolicy(client, &iam.PutRolePolicyInput{
			RoleName:       aws.String(newIAMRoleName()),
			PolicyName:     aws.String("p"),
			PolicyDocument: aws.String("emoji\U0001F600test"),
		})
		return checkIAMApiErr(err, iamerr.InvalidCharset("policyDocument"))
	})
}

func IAMPutRolePolicy_non_existing_role(s *S3Conf) error {
	testName := "IAMPutRolePolicy_non_existing_role"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName := "non-existing-" + genRandString(16)
		_, err := putIAMRolePolicy(client, &iam.PutRolePolicyInput{
			RoleName:       &roleName,
			PolicyName:     aws.String("p"),
			PolicyDocument: aws.String(validIAMPolicyDocument),
		})
		return checkIAMApiErr(err, iamerr.NoSuchEntityRole(roleName))
	})
}

func IAMPutRolePolicy_malformed_policy_document(s *S3Conf) error {
	testName := "IAMPutRolePolicy_malformed_policy_document"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		cases := []struct {
			name    string
			doc     string
			wantErr iamerr.APIError
		}{
			{"invalid json syntax", `{not valid json`, iamerr.MalformedPolicyDocument("Syntax errors in policy.")},
			{"empty object", `{}`, iamerr.MalformedPolicyDocument("Syntax errors in policy.")},
			{"invalid version", `{"Version":"2020-01-01","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`, iamerr.MalformedPolicyDocument("Syntax errors in policy.")},
			{"missing statement", `{"Version":"2012-10-17"}`, iamerr.MalformedPolicyDocument("Syntax errors in policy.")},
			{"null statement", `{"Version":"2012-10-17","Statement":null}`, iamerr.MalformedPolicyDocument("Syntax errors in policy.")},
			{"empty statement array", `{"Version":"2012-10-17","Statement":[]}`, iamerr.MalformedPolicyDocument("Syntax errors in policy.")},
			{"statement is a string", `{"Version":"2012-10-17","Statement":"hello"}`, iamerr.MalformedPolicyDocument("Syntax errors in policy.")},
			{"missing effect", `{"Version":"2012-10-17","Statement":[{"Action":"s3:GetObject","Resource":"*"}]}`, iamerr.MalformedPolicyDocument("Syntax errors in policy.")},
			{"invalid effect value", `{"Version":"2012-10-17","Statement":[{"Effect":"Maybe","Action":"s3:GetObject","Resource":"*"}]}`, iamerr.MalformedPolicyDocument("Syntax errors in policy.")},
			{"action and notaction both present", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","NotAction":"s3:PutObject","Resource":"*"}]}`, iamerr.MalformedPolicyDocument("Syntax errors in policy.")},
			{"resource and notresource both present", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","NotResource":"foo"}]}`, iamerr.MalformedPolicyDocument("Syntax errors in policy.")},
			{"numeric action wrong type", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":123,"Resource":"*"}]}`, iamerr.MalformedPolicyDocument("Syntax errors in policy.")},

			{"missing action and notaction", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Resource":"*"}]}`, iamerr.MalformedPolicyDocument("Policy statement must contain actions.")},

			{"missing resource and notresource", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject"}]}`, iamerr.MalformedPolicyDocument("Policy statement must contain resources.")},
			{"empty resource array", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":[]}]}`, iamerr.MalformedPolicyDocument("Policy statement must contain resources.")},

			{"empty string action", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"","Resource":"*"}]}`, iamerr.MalformedPolicyDocument("Actions/Conditions must be prefaced by a vendor, e.g., iam, sdb, ec2, etc.")},
			{"action missing vendor colon", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"GetObject","Resource":"*"}]}`, iamerr.MalformedPolicyDocument("Actions/Conditions must be prefaced by a vendor, e.g., iam, sdb, ec2, etc.")},
			{"notaction missing vendor colon", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":"GetObject","Resource":"*"}]}`, iamerr.MalformedPolicyDocument("Actions/Conditions must be prefaced by a vendor, e.g., iam, sdb, ec2, etc.")},
			{"empty vendor prefix", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":":GetObject","Resource":"*"}]}`, iamerr.MalformedPolicyDocument("Vendor  is not valid")},
			{"vendor with invalid character", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam :Get","Resource":"*"}]}`, iamerr.MalformedPolicyDocument("Vendor iam  is not valid")},

			{"resource with no colon at all", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"invalid"}]}`, iamerr.MalformedPolicyDocument(`Resource invalid must be in ARN format or "*".`)},
			{"notresource with no colon at all", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","NotResource":"invalid"}]}`, iamerr.MalformedPolicyDocument(`Resource invalid must be in ARN format or "*".`)},
			{"resource with colon but no arn prefix", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"s3::example-bucket/*"}]}`, iamerr.MalformedPolicyDocument(`Partition "" is not valid for resource "arn::example-bucket/*:*:*:*".`)},
			{"resource with arn prefix but too few fields", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:awss3::example-bucket/*"}]}`, iamerr.MalformedPolicyDocument("The policy failed legacy parsing")},
			{"resource with invalid partition", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws2:s3:::example-bucket/*"}]}`, iamerr.MalformedPolicyDocument(`Partition "aws2" is not valid for resource "arn:aws2:s3:::example-bucket/*".`)},

			{"duplicate sid across statements", `{"Version":"2012-10-17","Statement":[{"Sid":"Dup","Effect":"Allow","Action":"s3:GetObject","Resource":"*"},{"Sid":"Dup","Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}`, iamerr.MalformedPolicyDocument("Statement IDs (SID) in a single policy must be unique.")},
		}

		for _, c := range cases {
			if err := func() error {
				roleName := newIAMRoleName()
				if _, err := createIAMRole(client, &iam.CreateRoleInput{
					RoleName:                 &roleName,
					AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
				}); err != nil {
					return fmt.Errorf("%s: %w", c.name, err)
				}

				checkErr := func() error {
					_, err := putIAMRolePolicy(client, &iam.PutRolePolicyInput{
						RoleName:       &roleName,
						PolicyName:     aws.String("p"),
						PolicyDocument: aws.String(c.doc),
					})
					if err := checkIAMApiErr(err, c.wantErr); err != nil {
						return fmt.Errorf("%s: %w", c.name, err)
					}
					return nil
				}()

				deleteErr := deleteIAMRole(client, roleName)
				if checkErr != nil {
					return checkErr
				}
				return deleteErr
			}(); err != nil {
				return err
			}
		}

		return nil
	})
}

func IAMPutRolePolicy_principal_not_allowed(s *S3Conf) error {
	testName := "IAMPutRolePolicy_principal_not_allowed"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName := newIAMRoleName()
		if _, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 &roleName,
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
		}); err != nil {
			return err
		}

		checkErr := func() error {
			doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}]}`
			_, err := putIAMRolePolicy(client, &iam.PutRolePolicyInput{
				RoleName:       &roleName,
				PolicyName:     aws.String("p"),
				PolicyDocument: aws.String(doc),
			})
			return checkIAMApiErr(err, iamerr.MalformedPolicyDocument("Policy document should not specify a principal."))
		}()

		deleteErr := deleteIAMRole(client, roleName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMPutRolePolicy_limit_exceeded(s *S3Conf) error {
	testName := "IAMPutRolePolicy_limit_exceeded"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName := newIAMRoleName()
		if _, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 &roleName,
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
		}); err != nil {
			return err
		}

		checkErr := func() error {
			oversized := `{"Version":"2012-10-17","Statement":[{"Sid":"` + strings.Repeat("x", 10500) + `","Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
			_, err := putIAMRolePolicy(client, &iam.PutRolePolicyInput{
				RoleName:       &roleName,
				PolicyName:     aws.String("p"),
				PolicyDocument: aws.String(oversized),
			})
			return checkIAMApiErr(err, iamerr.InlinePolicyQuotaExceeded("role", roleName, storage.MaxInlinePolicyBytesPerRole))
		}()

		deleteErr := deleteIAMRole(client, roleName)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMPutRolePolicy_success(s *S3Conf) error {
	testName := "IAMPutRolePolicy_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleName := newIAMRoleName()
		if _, err := createIAMRole(client, &iam.CreateRoleInput{
			RoleName:                 &roleName,
			AssumeRolePolicyDocument: aws.String(validTrustPolicyDocument),
		}); err != nil {
			return err
		}

		out, err := putIAMRolePolicy(client, &iam.PutRolePolicyInput{
			RoleName:       &roleName,
			PolicyName:     aws.String("ReadOnly"),
			PolicyDocument: aws.String(validIAMPolicyDocument),
		})
		checkErr := func() error {
			if err != nil {
				return err
			}
			if out == nil {
				return fmt.Errorf("expected PutRolePolicy output")
			}
			if requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata); !ok || requestID == "" {
				return fmt.Errorf("expected PutRolePolicy response request id")
			}

			got, err := getIAMRolePolicy(client, &iam.GetRolePolicyInput{RoleName: &roleName, PolicyName: aws.String("ReadOnly")})
			if err != nil {
				return err
			}
			gotDocument, err := url.QueryUnescape(aws.ToString(got.PolicyDocument))
			if err != nil {
				return fmt.Errorf("failed to url-decode policy document %q: %w", aws.ToString(got.PolicyDocument), err)
			}
			if gotDocument != validIAMPolicyDocument {
				return fmt.Errorf("expected policy document %q, instead got %q", validIAMPolicyDocument, gotDocument)
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

func IAMPutRolePolicy_overwrite_updates_existing(s *S3Conf) error {
	testName := "IAMPutRolePolicy_overwrite_updates_existing"
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

			updated := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}`
			if _, err := putIAMRolePolicy(client, &iam.PutRolePolicyInput{
				RoleName:       &roleName,
				PolicyName:     aws.String("p"),
				PolicyDocument: aws.String(updated),
			}); err != nil {
				return err
			}

			got, err := getIAMRolePolicy(client, &iam.GetRolePolicyInput{RoleName: &roleName, PolicyName: aws.String("p")})
			if err != nil {
				return err
			}
			gotDocument, err := url.QueryUnescape(aws.ToString(got.PolicyDocument))
			if err != nil {
				return fmt.Errorf("failed to url-decode policy document %q: %w", aws.ToString(got.PolicyDocument), err)
			}
			if gotDocument != updated {
				return fmt.Errorf("expected overwritten policy document %q, instead got %q", updated, gotDocument)
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

func putIAMRolePolicy(client *iam.Client, input *iam.PutRolePolicyInput) (*iam.PutRolePolicyOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.PutRolePolicy(ctx, input)
}
