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

func PutBucketWebsite_non_existing_bucket(s *S3Conf) error {
	testName := "PutBucketWebsite_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketWebsite(ctx, &s3.PutBucketWebsiteInput{
			Bucket: getPtr("non-existing-bucket"),
			WebsiteConfiguration: &types.WebsiteConfiguration{
				IndexDocument: &types.IndexDocument{
					Suffix: getPtr("index.html"),
				},
			},
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket))
	})
}

func PutBucketWebsite_empty_suffix(s *S3Conf) error {
	testName := "PutBucketWebsite_empty_suffix"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketWebsite(ctx, &s3.PutBucketWebsiteInput{
			Bucket: &bucket,
			WebsiteConfiguration: &types.WebsiteConfiguration{
				IndexDocument: &types.IndexDocument{
					Suffix: getPtr(""),
				},
			},
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidWebsiteSuffix))
	})
}

func PutBucketWebsite_suffix_with_slash(s *S3Conf) error {
	testName := "PutBucketWebsite_suffix_with_slash"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketWebsite(ctx, &s3.PutBucketWebsiteInput{
			Bucket: &bucket,
			WebsiteConfiguration: &types.WebsiteConfiguration{
				IndexDocument: &types.IndexDocument{
					Suffix: getPtr("/index.html"),
				},
			},
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidWebsiteSuffix))
	})
}

func PutBucketWebsite_invalid_redirect_protocol(s *S3Conf) error {
	testName := "PutBucketWebsite_invalid_redirect_protocol"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketWebsite(ctx, &s3.PutBucketWebsiteInput{
			Bucket: &bucket,
			WebsiteConfiguration: &types.WebsiteConfiguration{
				RedirectAllRequestsTo: &types.RedirectAllRequestsTo{
					HostName: getPtr("example.com"),
					Protocol: types.Protocol("ftp"),
				},
			},
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidWebsiteConfiguration))
	})
}

func PutBucketWebsite_redirect_and_index(s *S3Conf) error {
	testName := "PutBucketWebsite_redirect_and_index"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketWebsite(ctx, &s3.PutBucketWebsiteInput{
			Bucket: &bucket,
			WebsiteConfiguration: &types.WebsiteConfiguration{
				RedirectAllRequestsTo: &types.RedirectAllRequestsTo{
					HostName: getPtr("example.com"),
				},
				IndexDocument: &types.IndexDocument{
					Suffix: getPtr("index.html"),
				},
			},
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidWebsiteConfiguration))
	})
}

func PutBucketWebsite_success(s *S3Conf) error {
	testName := "PutBucketWebsite_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketWebsite(ctx, &s3.PutBucketWebsiteInput{
			Bucket: &bucket,
			WebsiteConfiguration: &types.WebsiteConfiguration{
				IndexDocument: &types.IndexDocument{
					Suffix: getPtr("index.html"),
				},
				ErrorDocument: &types.ErrorDocument{
					Key: getPtr("error.html"),
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		return nil
	})
}

func PutBucketWebsite_success_redirect_all(s *S3Conf) error {
	testName := "PutBucketWebsite_success_redirect_all"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketWebsite(ctx, &s3.PutBucketWebsiteInput{
			Bucket: &bucket,
			WebsiteConfiguration: &types.WebsiteConfiguration{
				RedirectAllRequestsTo: &types.RedirectAllRequestsTo{
					HostName: getPtr("example.com"),
					Protocol: types.ProtocolHttps,
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		return nil
	})
}
