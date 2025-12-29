// Copyright 2023 Versity Software
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
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/s3err"
)

func PutBucketPolicy_non_existing_bucket(s *S3Conf) error {
	testName := "PutBucketPolicy_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		doc := genPolicyDoc("Allow", `"*"`, `"s3:*"`, fmt.Sprintf(`"arn:aws:s3:::%v"`, bucket))
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: getPtr("non-existing-bucket"),
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_invalid_json(s *S3Conf) error {
	testName := "PutBucketPolicy_invalid_json"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for _, doc := range []string{
			"{true}",
			"{asdfsdaf",
			`{"Principal": "*" `,
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
				Bucket: &bucket,
				Policy: &doc,
			})
			cancel()
			if err := checkApiErr(err, getMalformedPolicyError("This policy contains invalid Json")); err != nil {
				return err
			}
		}

		for _, doc := range []string{
			"false",
			"invalid_json",
			"bucketPolicy",
			`"Statement": []}`,
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
				Bucket: &bucket,
				Policy: &doc,
			})
			cancel()
			if err := checkApiErr(err, getMalformedPolicyError("Policies must be valid JSON and the first byte must be '{'")); err != nil {
				return err
			}
		}

		return nil
	})
}

func PutBucketPolicy_statement_not_provided(s *S3Conf) error {
	testName := "PutBucketPolicy_statement_not_provided"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		doc := `{}`

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()
		if err := checkApiErr(err, getMalformedPolicyError("Missing required field Statement")); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_empty_statement(s *S3Conf) error {
	testName := "PutBucketPolicy_empty_statement"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		doc := `{"Statement": []}`

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()
		if err := checkApiErr(err, getMalformedPolicyError("Could not parse the policy: Statement is empty!")); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_invalid_effect(s *S3Conf) error {
	testName := "PutBucketPolicy_invalid_effect"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		doc := genPolicyDoc("invalid_effect", `"*"`, `"s3:*"`, `"arn:aws:s3:::*"`)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError("Invalid effect: invalid_effect")); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_invalid_action(s *S3Conf) error {
	testName := "PutBucketPolicy_invalid_action"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		err := createUsers(s, []user{testuser})
		if err != nil {
			return err
		}

		for _, action := range []string{
			// empty actions
			`""`, "[]",
			// completely invalid action
			`"invalid_action"`, `["invalid_action"]`,
			// only prefix
			`"s3"`, `"s3:"`,
			// malformed prefix
			`"s4:GetObject"`, `"ss3:ListBucket"`, `"s3x:PutBucketAcl"`, `":GetObject"`, `"s3GetObject"`,
			// bad separator
			`"s3::GetObject"`, `"s3:Put-Object"`, `"s3:GetObject:"`, `"s3:Put(Object)"`,
			// wildcard abuse
			`"s3:*Obj??ect*"`, `"s3:????"`, `"s3:*:"`, `"*GetObject"`, `"???PutObject"`, `"s3:Abort?"`, `"s3:??Abort*"`,
		} {
			doc := genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser.access), action, fmt.Sprintf(`"arn:aws:s3:::%s"`, bucket))

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
				Bucket: &bucket,
				Policy: &doc,
			})
			cancel()

			if err := checkApiErr(err, getMalformedPolicyError("Policy has invalid action")); err != nil {
				return err
			}
		}

		return nil
	})
}

func PutBucketPolicy_empty_principals_string(s *S3Conf) error {
	testName := "PutBucketPolicy_empty_principals_string"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		doc := genPolicyDoc("Allow", `""`, `"s3:*"`, `"arn:aws:s3:::*"`)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError("Invalid principal in policy")); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_empty_principals_array(s *S3Conf) error {
	testName := "PutBucketPolicy_empty_principals_array"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		doc := genPolicyDoc("Allow", `[]`, `"s3:*"`, `"arn:aws:s3:::*"`)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError("Invalid principal in policy")); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_principals_aws_struct_empty_string(s *S3Conf) error {
	testName := "PutBucketPolicy_principals_aws_struct_empty_string"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		doc := genPolicyDoc("Allow", `{"AWS": ""}`, `"s3:*"`, `"arn:aws:s3:::*"`)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError("Invalid principal in policy")); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_principals_aws_struct_empty_string_slice(s *S3Conf) error {
	testName := "PutBucketPolicy_principals_aws_struct_empty_string_slice"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		doc := genPolicyDoc("Allow", `{"AWS": []}`, `"s3:*"`, `"arn:aws:s3:::*"`)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError("Invalid principal in policy")); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_principals_incorrect_wildcard_usage(s *S3Conf) error {
	testName := "PutBucketPolicy_principals_incorrect_wildcard_usage"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		doc := genPolicyDoc("Allow", `["*", "grt1"]`, `"s3:*"`, `"arn:aws:s3:::*"`)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError("Invalid principal in policy")); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_non_existing_principals(s *S3Conf) error {
	testName := "PutBucketPolicy_non_existing_principals"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		doc := genPolicyDoc("Allow", `["a_rarely_existing_user_account_1", "a_rarely_existing_user_account_2"]`, `"s3:*"`, `"arn:aws:s3:::*"`)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError("Invalid principal in policy")); err != nil {
			return err
		}

		return nil
	})
}

func PutBucketPolicy_empty_resources_string(s *S3Conf) error {
	testName := "PutBucketPolicy_empty_resources_string"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		doc := genPolicyDoc("Allow", `["*"]`, `"s3:*"`, `""`)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError("Policy has invalid resource")); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_empty_resources_array(s *S3Conf) error {
	testName := "PutBucketPolicy_empty_resources_array"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		doc := genPolicyDoc("Allow", `["*"]`, `"s3:*"`, `[]`)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError("Policy has invalid resource")); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_invalid_resource_prefix(s *S3Conf) error {
	testName := "PutBucketPolicy_invalid_resource_prefix"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		resource := fmt.Sprintf(`"arn:aws:iam:::%v"`, bucket)
		doc := genPolicyDoc("Allow", `["*"]`, `"s3:*"`, resource)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError("Policy has invalid resource")); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_invalid_resource_with_starting_slash(s *S3Conf) error {
	testName := "PutBucketPolicy_invalid_resource_with_starting_slash"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		resource := fmt.Sprintf(`"arn:aws:s3:::/%v"`, bucket)
		doc := genPolicyDoc("Allow", `["*"]`, `"s3:*"`, resource)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError("Policy has invalid resource")); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_duplicate_resource(s *S3Conf) error {
	testName := "PutBucketPolicy_duplicate_resource"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		resource := fmt.Sprintf(`"arn:aws:s3:::%v"`, bucket)
		doc := genPolicyDoc("Allow", `["*"]`, `"s3:*"`, fmt.Sprintf("[%v, %v]", resource, resource))

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()
		if err != nil {
			return err
		}

		return nil
	})
}

func PutBucketPolicy_incorrect_bucket_name(s *S3Conf) error {
	testName := "PutBucketPolicy_incorrect_bucket_name"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		resource := fmt.Sprintf(`"arn:aws:s3:::prefix-%v"`, bucket)
		doc := genPolicyDoc("Allow", `["*"]`, `"s3:*"`, resource)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()

		if err := checkApiErr(err, getMalformedPolicyError("Policy has invalid resource")); err != nil {
			return err
		}
		return nil
	})
}

func PutBucketPolicy_action_resource_mismatch(s *S3Conf) error {
	testName := "PutBucketPolicy_action_resource_mismatch"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		bucketResource := fmt.Sprintf(`"arn:aws:s3:::%s"`, bucket)
		objectResource := fmt.Sprintf(`"arn:aws:s3:::%v/*"`, bucket)

		for _, test := range []struct {
			resource string
			action   string
		}{
			// bucket resources
			{bucketResource, `"s3:GetObject"`},
			{bucketResource, `"s3:PutObjectTagging"`},
			{bucketResource, `"s3:GetObjec?"`},
			{bucketResource, `"s3:Abort*"`},
			{bucketResource, `"s3:*Multipart*"`},
			{bucketResource, `"s3:???Object"`},
			// object resources
			{objectResource, `"s3:ListBucket"`},
			{objectResource, `"s3:GetBucketTagging"`},
			{objectResource, `"s3:???BucketVersioning"`},
			{objectResource, `"s3:*Bucket*"`},
			{objectResource, `"s3:GetBucket*"`},
		} {
			doc := genPolicyDoc("Allow", `["*"]`, test.action, test.resource)
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
				Bucket: &bucket,
				Policy: &doc,
			})
			cancel()
			if err := checkApiErr(err, getMalformedPolicyError("Action does not apply to any resource(s) in statement")); err != nil {
				return err
			}
		}

		return nil
	})
}

func PutBucketPolicy_explicit_deny(s *S3Conf) error {
	testName := "PutBucketPolicy_explicit_deny"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser1, testuser2 := getUser("user"), getUser("user")
		err := createUsers(s, []user{testuser1, testuser2})
		if err != nil {
			return err
		}

		resource := fmt.Sprintf("arn:aws:s3:::%v", bucket)
		resourceWildCard := fmt.Sprintf("%v/*", resource)
		resourcePrefix := fmt.Sprintf("%v/someprefix/*", resource)

		policy := fmt.Sprintf(`{
				"Statement": [
					{
						"Action": [
							"s3:*"
						],
						"Effect": "Allow",
						"Principal": [
							"%s"
						],
						"Resource": [
							"%v",
							"%v"
						]
					},
					{
						"Action": [
							"s3:*"
						],
						"Effect": "Allow",
						"Principal": [
							"%s"
						],
						"Resource": [
							"%v",
							"%v"
						]
					},
					{
						"Action": [
							"s3:*"
						],
						"Effect": "Deny",
						"Principal": [
							"%s"
						],
						"Resource": "%v"
					}
				]
			}`, testuser1.access, resourcePrefix, resource, testuser2.access, resourceWildCard, resource, testuser2.access, resourcePrefix)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &policy,
		})
		cancel()
		if err != nil {
			return err
		}

		userClient := s.getUserClient(testuser2)

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    getPtr("someprefix/hello"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		return nil
	})
}

func PutBucketPolicy_multi_wildcard_resource(s *S3Conf) error {
	testName := "PutBucketPolicy_multi_wildcard_resource"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		resource := fmt.Sprintf(`["arn:aws:s3:::%v/*/*", "arn:aws:s3:::%v"]`, bucket, bucket)
		principal := fmt.Sprintf("\"%v\"", testuser.access)
		doc := genPolicyDoc("Allow", principal, `"s3:*"`, resource)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()
		if err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)
		_, err = putObjects(userClient, []string{"foo"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		_, err = putObjects(userClient, []string{"bar/quxx", "foo/bar/baz", "foo/bar/xyz/quxx"}, bucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func PutBucketPolicy_any_char_match(s *S3Conf) error {
	testName := "PutBucketPolicy_any_char_match"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		resource := fmt.Sprintf(`["arn:aws:s3:::%v/m?-obj/*"]`, bucket)
		principal := fmt.Sprintf("\"%v\"", testuser.access)
		doc := genPolicyDoc("Allow", principal, `"s3:*"`, resource)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &doc,
		})
		cancel()
		if err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)
		_, err = putObjects(userClient, []string{"myy-obj/hello", "rand/foo", "my-objj/bar"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		_, err = putObjects(userClient, []string{"my-obj/hello", "mk-obj/foo", "m--obj/bar"}, bucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func PutBucketPolicy_version(s *S3Conf) error {
	testName := "PutBucketPolicy_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		invalidVersionErr := getMalformedPolicyError("The policy must contain a valid version string")
		for i, test := range []struct {
			version string
			err     error
		}{
			{"2008-10-17", nil},
			{"2012-10-17", nil},
			{"", invalidVersionErr},
			{"invalid", invalidVersionErr},
			{"2000-10-17", invalidVersionErr},
			{"2012-10-16", invalidVersionErr},
		} {
			policy := fmt.Sprintf(
				`{
				"Version": "%s",
				"Statement": [
					{
						"Effect":  "Deny",
						"Principal": "%s",
						"Action":  "s3:GetObject",
						"Resource":  "arn:aws:s3:::%s/obj"
					}
				]
			}
			`, test.version, s.awsID, bucket)

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
				Bucket: &bucket,
				Policy: &policy,
			})
			cancel()
			if test.err == nil && err != nil {
				return fmt.Errorf("test %v failed: expected no error but got %v", i+1, err)
			}
			if test.err != nil {
				apiErr, ok := test.err.(s3err.APIError)
				if !ok {
					return fmt.Errorf("test %v failed: expected s3err.APIError", i+1)
				}

				if err := checkApiErr(err, apiErr); err != nil {
					return fmt.Errorf("test %v failed: %v", i+1, err)
				}
			}
		}

		return nil
	})
}

func PutBucketPolicy_success(s *S3Conf) error {
	testName := "PutBucketPolicy_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser1, testuser2 := getUser("user"), getUser("user")
		err := createUsers(s, []user{testuser1, testuser2})
		if err != nil {
			return err
		}

		bucketResource := fmt.Sprintf(`"arn:aws:s3:::%v"`, bucket)
		objectResource := fmt.Sprintf(`"arn:aws:s3:::%v/*"`, bucket)

		for _, doc := range []string{
			genPolicyDoc("Allow", fmt.Sprintf(`["%s", "%s"]`, testuser1.access, testuser2.access), `["s3:DeleteBucket", "s3:GetBucketAcl"]`, bucketResource),
			genPolicyDoc("Allow", fmt.Sprintf(`{"AWS": ["%s", "%s"]}`, testuser1.access, testuser2.access), `["s3:DeleteBucket", "s3:GetBucketAcl"]`, bucketResource),
			genPolicyDoc("Deny", `"*"`, `"s3:DeleteBucket"`, fmt.Sprintf(`"arn:aws:s3:::%v"`, bucket)),
			genPolicyDoc("Deny", `{"AWS": "*"}`, `"s3:DeleteBucket"`, fmt.Sprintf(`"arn:aws:s3:::%v"`, bucket)),
			genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser1.access), `["s3:PutBucketVersioning", "s3:ListMultipartUploadParts", "s3:ListBucket"]`, fmt.Sprintf(`[%v, %v]`, bucketResource, objectResource)),
			genPolicyDoc("Allow", `"*"`, `"s3:*"`, fmt.Sprintf(`[%v, %v]`, bucketResource, objectResource)),
			genPolicyDoc("Allow", `"*"`, `"s3:Get*"`, objectResource),
			genPolicyDoc("Deny", `"*"`, `"s3:Create*"`, fmt.Sprintf(`[%v, %v]`, bucketResource, objectResource)),
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
				Bucket: &bucket,
				Policy: &doc,
			})
			cancel()
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func PutBucketPolicy_status(s *S3Conf) error {
	testname := "PutBucketPolicy_status"
	return actionHandler(s, testname, func(s3client *s3.Client, bucket string) error {
		doc := genPolicyDoc("Allow", `"*"`, `"s3:GetObject"`, fmt.Sprintf(`"arn:aws:s3:::%s/*"`, bucket))
		req, err := createSignedReq(http.MethodPut, s.endpoint, bucket+"?policy", s.awsID, s.awsSecret, "s3", s.awsRegion, []byte(doc), time.Now(), nil)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusNoContent {
			return fmt.Errorf("expected the response status code to be %v, instead got %v", http.StatusNoContent, resp.StatusCode)
		}

		return nil
	})
}
