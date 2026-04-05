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

func GetBucketWebsite_non_existing_bucket(s *S3Conf) error {
	testName := "GetBucketWebsite_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetBucketWebsite(ctx, &s3.GetBucketWebsiteInput{
			Bucket: getPtr("non-existing-bucket"),
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket))
	})
}

func GetBucketWebsite_no_such_website_config(s *S3Conf) error {
	testName := "GetBucketWebsite_no_such_website_config"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetBucketWebsite(ctx, &s3.GetBucketWebsiteInput{
			Bucket: &bucket,
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchWebsiteConfiguration))
	})
}

func GetBucketWebsite_success(s *S3Conf) error {
	testName := "GetBucketWebsite_success"
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

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.GetBucketWebsite(ctx, &s3.GetBucketWebsiteInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.IndexDocument == nil || res.IndexDocument.Suffix == nil || *res.IndexDocument.Suffix != "index.html" {
			return fmt.Errorf("expected IndexDocument.Suffix to be %q, got %v", "index.html", res.IndexDocument)
		}
		if res.ErrorDocument == nil || res.ErrorDocument.Key == nil || *res.ErrorDocument.Key != "error.html" {
			return fmt.Errorf("expected ErrorDocument.Key to be %q, got %v", "error.html", res.ErrorDocument)
		}

		return nil
	})
}

func GetBucketWebsite_success_redirect_all(s *S3Conf) error {
	testName := "GetBucketWebsite_success_redirect_all"
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

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.GetBucketWebsite(ctx, &s3.GetBucketWebsiteInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.RedirectAllRequestsTo == nil || res.RedirectAllRequestsTo.HostName == nil || *res.RedirectAllRequestsTo.HostName != "example.com" {
			return fmt.Errorf("expected RedirectAllRequestsTo.HostName to be %q, got %v", "example.com", res.RedirectAllRequestsTo)
		}
		if res.RedirectAllRequestsTo.Protocol != types.ProtocolHttps {
			return fmt.Errorf("expected RedirectAllRequestsTo.Protocol to be %q, got %q", types.ProtocolHttps, res.RedirectAllRequestsTo.Protocol)
		}

		return nil
	})
}
