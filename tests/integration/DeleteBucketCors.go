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
	"net/http"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

func DeleteBucketCors_non_existing_bucket(s *S3Conf) error {
	testName := "DeleteBucketCors_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteBucketCors(ctx, &s3.DeleteBucketCorsInput{
			Bucket: getPtr("non-existing-bucket"),
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket))
	})
}

func DeleteBucketCors_success(s *S3Conf) error {
	testName := "DeleteBucketCors_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		deletebucketcors := func() error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.DeleteBucketCors(ctx, &s3.DeleteBucketCorsInput{
				Bucket: &bucket,
			})
			cancel()
			return err
		}

		// should not return error when deleting unset bucket CORS
		err := deletebucketcors()
		if err != nil {
			return err
		}

		err = putBucketCors(s3client, &s3.PutBucketCorsInput{
			Bucket: &bucket,
			CORSConfiguration: &types.CORSConfiguration{
				CORSRules: []types.CORSRule{
					{
						AllowedOrigins: []string{"http://origin.com"},
						AllowedMethods: []string{http.MethodPost},
						AllowedHeaders: []string{"X-Amz-Meta-Header"},
						ExposeHeaders:  []string{"Content-Disposition"},
						MaxAgeSeconds:  getPtr(int32(5000)),
					},
				},
			},
		})
		if err != nil {
			return err
		}

		err = deletebucketcors()
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetBucketCors(ctx, &s3.GetBucketCorsInput{
			Bucket: &bucket,
		})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchCORSConfiguration))
	})
}
