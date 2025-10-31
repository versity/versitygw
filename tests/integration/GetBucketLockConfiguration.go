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

func GetObjectLockConfiguration_non_existing_bucket(s *S3Conf) error {
	testName := "GetObjectLockConfiguration_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
			Bucket: getPtr(getBucketName()),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func GetObjectLockConfiguration_unset_config(s *S3Conf) error {
	testName := "GetObjectLockConfiguration_unset_config"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound)); err != nil {
			return err
		}

		return nil
	})
}

func GetObjectLockConfiguration_success(s *S3Conf) error {
	testName := "GetObjectLockConfiguration_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		var days int32 = 20
		config := types.ObjectLockConfiguration{
			ObjectLockEnabled: types.ObjectLockEnabledEnabled,
			Rule: &types.ObjectLockRule{
				DefaultRetention: &types.DefaultRetention{
					Mode: types.ObjectLockRetentionModeCompliance,
					Days: &days,
				},
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket:                  &bucket,
			ObjectLockConfiguration: &config,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if resp.ObjectLockConfiguration == nil {
			return fmt.Errorf("got nil object lock configuration")
		}

		respConfig := resp.ObjectLockConfiguration
		if respConfig.ObjectLockEnabled != config.ObjectLockEnabled {
			return fmt.Errorf("expected lock status to be %v, instead got %v",
				config.ObjectLockEnabled, respConfig.ObjectLockEnabled)
		}
		if respConfig.Rule == nil {
			return fmt.Errorf("got nil object lock rule")
		}
		if respConfig.Rule.DefaultRetention == nil {
			return fmt.Errorf("got nil object lock default retention")
		}
		if respConfig.Rule.DefaultRetention.Days == nil {
			return fmt.Errorf("expected lock config days to be not nil")
		}
		if *respConfig.Rule.DefaultRetention.Days != *config.Rule.DefaultRetention.Days {
			return fmt.Errorf("expected lock config days to be %v, instead got %v",
				*config.Rule.DefaultRetention.Days, *respConfig.Rule.DefaultRetention.Days)
		}
		if respConfig.Rule.DefaultRetention.Mode != config.Rule.DefaultRetention.Mode {
			return fmt.Errorf("expected lock config mode to be %v, instead got %v",
				config.Rule.DefaultRetention.Mode, respConfig.Rule.DefaultRetention.Mode)
		}

		return nil
	}, withLock())
}
