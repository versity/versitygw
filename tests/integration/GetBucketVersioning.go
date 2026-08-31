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
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

func GetBucketVersioning_non_existing_bucket(s *S3Conf) error {
	testName := "GetBucketVersioning_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: getPtr(getBucketName()),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func GetBucketVersioning_empty_response(s *S3Conf) error {
	testName := "GetBucketVersioning_empty_response"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.Status != "" {
			return fmt.Errorf("expected empty versioning status, instead got %v",
				res.Status)
		}
		if res.MFADelete != "" {
			return fmt.Errorf("expected empty mfa delete status, instead got %v",
				res.MFADelete)
		}

		return nil
	})
}

func GetBucketVersioning_success(s *S3Conf) error {
	testName := "GetBucketVersioning_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.Status != types.BucketVersioningStatusEnabled {
			return fmt.Errorf("expected bucket versioning status to be %v, instead got %v",
				types.BucketVersioningStatusEnabled, res.Status)
		}
		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func GetBucketVersioning_non_owner_access_denied(s *S3Conf) error {
	testName := "GetBucketVersioning_non_owner_access_denied"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := userClient.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func GetBucketVersioning_with_policy_access(s *S3Conf) error {
	testName := "GetBucketVersioning_with_policy_access"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		bucketResource := fmt.Sprintf(`"arn:aws:s3:::%v"`, bucket)
		principal := fmt.Sprintf(`"%v"`, testuser.access)
		userClient := s.getUserClient(testuser)

		// Error path: the policy grants the user another bucket action,
		// but not s3:GetBucketVersioning.
		policy := genPolicyDoc("Allow", principal, `"s3:GetBucketTagging"`, bucketResource)
		if err := putBucketPolicy(s3client, bucket, policy); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := userClient.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		// Happy path: the policy grants s3:GetBucketVersioning to a user
		// who neither owns the bucket nor is an admin.
		policy = genPolicyDoc("Allow", principal, `"s3:GetBucketVersioning"`, bucketResource)
		if err := putBucketPolicy(s3client, bucket, policy); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := userClient.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.Status != types.BucketVersioningStatusEnabled {
			return fmt.Errorf("expected bucket versioning status to be %v, instead got %v",
				types.BucketVersioningStatusEnabled, res.Status)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func GetBucketVersioning_with_acl_access(s *S3Conf) error {
	testName := "GetBucketVersioning_with_acl_access"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket:    &bucket,
			GrantRead: &testuser.access,
		})
		cancel()
		if err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := userClient.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.Status != types.BucketVersioningStatusEnabled {
			return fmt.Errorf("expected bucket versioning status to be %v, instead got %v",
				types.BucketVersioningStatusEnabled, res.Status)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled),
		withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
}
