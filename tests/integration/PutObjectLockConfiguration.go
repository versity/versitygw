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
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

func PutObjectLockConfiguration_non_existing_bucket(s *S3Conf) error {
	testName := "PutObjectLockConfiguration_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: getPtr(getBucketName()),
			ObjectLockConfiguration: &types.ObjectLockConfiguration{
				ObjectLockEnabled: types.ObjectLockEnabledEnabled,
				Rule: &types.ObjectLockRule{
					DefaultRetention: &types.DefaultRetention{
						Mode: types.ObjectLockRetentionModeCompliance,
						Days: getPtr(int32(10)),
					},
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func PutObjectLockConfiguration_empty_request_body(s *S3Conf) error {
	testName := "PutObjectLockConfiguration_empty_request_body"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMissingRequestBody)); err != nil {
			return err
		}
		return nil
	})
}

func PutObjectLockConfiguration_malformed_body(s *S3Conf) error {
	testName := "PutObjectLockConfiguration_malformed_body"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		body := []byte("malformed_body")
		hasher := md5.New()
		_, err := hasher.Write(body)
		if err != nil {
			return err
		}

		sum := hasher.Sum(nil)
		md5Sum := base64.StdEncoding.EncodeToString(sum)

		req, err := createSignedReq(
			http.MethodPut,
			s.endpoint,
			fmt.Sprintf("%s?object-lock", bucket),
			s.awsID,
			s.awsSecret,
			"s3",
			s.awsRegion,
			body,
			time.Now(),
			map[string]string{"Content-Md5": md5Sum},
		)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("err sending request: %w", err)
		}

		if err := checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrMalformedXML)); err != nil {
			return err
		}

		return nil
	})
}

func PutObjectLockConfiguration_not_enabled_on_bucket_creation(s *S3Conf) error {
	testName := "PutObjectLockConfiguration_not_enabled_on_bucket_creation"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		var days int32 = 12
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
			ObjectLockConfiguration: &types.ObjectLockConfiguration{
				ObjectLockEnabled: types.ObjectLockEnabledEnabled,
				Rule: &types.ObjectLockRule{
					DefaultRetention: &types.DefaultRetention{
						Days: &days,
						Mode: types.ObjectLockRetentionModeCompliance,
					},
				},
			},
		})
		cancel()
		// this test cases address the successful object lock status upload
		// on versioning-disabled gateway mode, where versioning is not supported
		// and object lock may be enabled without bucket versioning status check
		// Note: this is not S3 compatible feature.
		return err
	})
}

func PutObjectLockConfiguration_invalid_status(s *S3Conf) error {
	testName := "PutObjectLockConfiguration_invalid_status"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		var days int32 = 12
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
			ObjectLockConfiguration: &types.ObjectLockConfiguration{
				ObjectLockEnabled: types.ObjectLockEnabled("invalid_status"),
				Rule: &types.ObjectLockRule{
					DefaultRetention: &types.DefaultRetention{
						Days: &days,
					},
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMalformedXML)); err != nil {
			return err
		}
		return nil
	})
}

func PutObjectLockConfiguration_invalid_mode(s *S3Conf) error {
	testName := "PutObjectLockConfiguration_invalid_status"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		var days int32 = 12
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
			ObjectLockConfiguration: &types.ObjectLockConfiguration{
				ObjectLockEnabled: types.ObjectLockEnabledEnabled,
				Rule: &types.ObjectLockRule{
					DefaultRetention: &types.DefaultRetention{
						Days: &days,
						Mode: types.ObjectLockRetentionMode("invalid_mode"),
					},
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMalformedXML)); err != nil {
			return err
		}
		return nil
	})
}

func PutObjectLockConfiguration_both_years_and_days(s *S3Conf) error {
	testName := "PutObjectLockConfiguration_both_years_and_days"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		var days, years int32 = 12, 24
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
			ObjectLockConfiguration: &types.ObjectLockConfiguration{
				ObjectLockEnabled: types.ObjectLockEnabledEnabled,
				Rule: &types.ObjectLockRule{
					DefaultRetention: &types.DefaultRetention{
						Days:  &days,
						Years: &years,
					},
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMalformedXML)); err != nil {
			return err
		}
		return nil
	})
}

func PutObjectLockConfiguration_invalid_years_days(s *S3Conf) error {
	testName := "PutObjectLockConfiguration_invalid_years"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		var days, years int32 = -3, -5
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
			ObjectLockConfiguration: &types.ObjectLockConfiguration{
				ObjectLockEnabled: types.ObjectLockEnabledEnabled,
				Rule: &types.ObjectLockRule{
					DefaultRetention: &types.DefaultRetention{
						Days: &days,
						Mode: types.ObjectLockRetentionModeCompliance,
					},
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLockInvalidRetentionPeriod)); err != nil {
			return err
		}
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
			ObjectLockConfiguration: &types.ObjectLockConfiguration{
				ObjectLockEnabled: types.ObjectLockEnabledEnabled,
				Rule: &types.ObjectLockRule{
					DefaultRetention: &types.DefaultRetention{
						Years: &years,
						Mode:  types.ObjectLockRetentionModeCompliance,
					},
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLockInvalidRetentionPeriod)); err != nil {
			return err
		}

		return nil
	})
}

func PutObjectLockConfiguration_success(s *S3Conf) error {
	testName := "PutObjectLockConfiguration_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
			ObjectLockConfiguration: &types.ObjectLockConfiguration{
				ObjectLockEnabled: types.ObjectLockEnabledEnabled,
			},
		})
		cancel()
		if err != nil {
			return err
		}
		return nil
	}, withLock())
}
