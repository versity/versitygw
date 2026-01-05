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

func GetBucketLocation_success(s *S3Conf) error {
	testName := "GetBucketLocation_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		expectedLocConstraint := s.awsRegion
		if s.awsRegion == "us-east-1" {
			expectedLocConstraint = ""
		}

		if string(resp.LocationConstraint) != expectedLocConstraint {
			return fmt.Errorf("expected bucket region to be %v, instead got %v",
				expectedLocConstraint, resp.LocationConstraint)
		}

		return nil
	})
}

func GetBucketLocation_non_exist(s *S3Conf) error {
	testName := "GetBucketLocation_non_exist"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		invalidBucket := "bucket-no-exist"
		resp, err := s3client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
			Bucket: &invalidBucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		if resp != nil && resp.LocationConstraint != "" {
			return fmt.Errorf("expected empty location constraint, instead got %v",
				resp.LocationConstraint)
		}

		return nil
	})
}

func GetBucketLocation_no_access(s *S3Conf) error {
	testName := "GetBucketLocation_no_access"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testUser := getUser("user")
		err := createUsers(s, []user{testUser})
		if err != nil {
			return err
		}

		userClient := s.getUserClient(testUser)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		resp, err := userClient.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		if resp != nil && resp.LocationConstraint != "" {
			return fmt.Errorf("expected empty location constraint, instead got %v",
				resp.LocationConstraint)
		}

		return nil
	})
}
