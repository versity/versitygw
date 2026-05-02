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

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

func DeleteBucketWebsite_non_existing_bucket(s *S3Conf) error {
	testName := "DeleteBucketWebsite_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteBucketWebsite(ctx, &s3.DeleteBucketWebsiteInput{
			Bucket: getPtr("non-existing-bucket"),
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket))
	})
}

func DeleteBucketWebsite_success(s *S3Conf) error {
	testName := "DeleteBucketWebsite_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		deleteWebsite := func() error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.DeleteBucketWebsite(ctx, &s3.DeleteBucketWebsiteInput{
				Bucket: &bucket,
			})
			cancel()
			return err
		}

		// should not return error when deleting unset website config
		err := deleteWebsite()
		if err != nil {
			return err
		}

		// put a website config
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketWebsite(ctx, &s3.PutBucketWebsiteInput{
			Bucket: &bucket,
			WebsiteConfiguration: &types.WebsiteConfiguration{
				IndexDocument: &types.IndexDocument{
					Suffix: getPtr("index.html"),
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		// delete the website config
		err = deleteWebsite()
		if err != nil {
			return err
		}

		// verify it's gone
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetBucketWebsite(ctx, &s3.GetBucketWebsiteInput{
			Bucket: &bucket,
		})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchWebsiteConfiguration))
	})
}
