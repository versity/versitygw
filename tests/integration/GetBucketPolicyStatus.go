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

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/s3err"
)

func GetBucketPolicyStatus_non_existing_bucket(s *S3Conf) error {
	testName := "GetBucketPolicyStatus_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{
			Bucket: getPtr("non-existing-bucket"),
		})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket))
	})
}

func GetBucketPolicyStatus_no_such_bucket_policy(s *S3Conf) error {
	testName := "GetBucketPolicyStatus_no_such_bucket_policy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{
			Bucket: &bucket,
		})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucketPolicy))
	})
}

func GetBucketPolicyStatus_success(s *S3Conf) error {
	testName := "GetBucketPolicyStatus_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser1, testuser2 := getUser("user"), getUser("user")
		err := createUsers(s, []user{testuser1, testuser2})
		if err != nil {
			return err
		}

		for _, test := range []struct {
			policy string
			status bool
		}{
			{
				policy: genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser1.access), `["s3:DeleteBucket", "s3:GetBucketTagging"]`, fmt.Sprintf(`"arn:aws:s3:::%v"`, bucket)),
				status: false,
			},
			{
				policy: genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser2.access), `"s3:GetObject"`, fmt.Sprintf(`"arn:aws:s3:::%v/obj"`, bucket)),
				status: false,
			},
			{
				policy: genPolicyDoc("Allow", `"*"`, `"s3:PutObject"`, fmt.Sprintf(`"arn:aws:s3:::%v/*"`, bucket)),
				status: true,
			},
			{
				policy: genPolicyDoc("Allow", `"*"`, `"s3:ListBucket"`, fmt.Sprintf(`"arn:aws:s3:::%v"`, bucket)),
				status: true,
			},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
				Bucket: &bucket,
				Policy: &test.policy,
			})
			cancel()
			if err != nil {
				return err
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{
				Bucket: &bucket,
			})
			cancel()
			if err != nil {
				return err
			}
			if res.PolicyStatus.IsPublic == nil {
				return fmt.Errorf("expected non nil policy status")
			}

			if *res.PolicyStatus.IsPublic != test.status {
				return fmt.Errorf("expected the policy public status to be %v, instead got %v", test.status, *res.PolicyStatus.IsPublic)
			}
		}

		return nil
	})
}
