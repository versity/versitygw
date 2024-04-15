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

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
)

type BucketLockConfig struct {
	Enabled          bool
	DefaultRetention *types.DefaultRetention
	CreatedAt        *time.Time
}

type ObjectLockConfig struct {
	LegalHoldEnabled bool
	Retention        *types.ObjectLockRetention
}

func ParseBucketLockConfigurationOutput(input []byte) (*types.ObjectLockConfiguration, error) {
	var config BucketLockConfig
	if err := json.Unmarshal(input, &config); err != nil {
		return nil, fmt.Errorf("parse object lock config: %w", err)
	}

	result := &types.ObjectLockConfiguration{
		Rule: &types.ObjectLockRule{
			DefaultRetention: config.DefaultRetention,
		},
	}

	if config.Enabled {
		result.ObjectLockEnabled = types.ObjectLockEnabledEnabled
	}

	return result, nil
}

func CheckObjectAccess(ctx context.Context, bucket, userAccess string, objects []string, isAdminOrRoot bool, be backend.Backend) error {
	data, err := be.GetObjectLockConfiguration(ctx, bucket)
	if err != nil {
		if errors.Is(err, s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound)) {
			return nil
		}

		return err
	}

	var bucketLockConfig BucketLockConfig
	if err := json.Unmarshal(data, &bucketLockConfig); err != nil {
		return fmt.Errorf("parse object lock config: %w", err)
	}

	if !bucketLockConfig.Enabled {
		return nil
	}

	for _, obj := range objects {
		retention, err := be.GetObjectRetention(ctx, bucket, obj, "")
		if err != nil {
			if errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchKey)) {
				continue
			}
			if errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchObjectLockConfiguration)) {
				continue
			}

			return err
		}

		if retention.Mode != "" && retention.RetainUntilDate != nil {
			if retention.RetainUntilDate.After(time.Now()) {
				switch retention.Mode {
				case types.ObjectLockRetentionModeGovernance:
					if !isAdminOrRoot {
						policy, err := be.GetBucketPolicy(ctx, bucket)
						if err != nil {
							return err
						}
						err = verifyBucketPolicy(policy, userAccess, bucket, obj, BypassGovernanceRetentionAction)
						if err != nil {
							return s3err.GetAPIError(s3err.ErrObjectLocked)
						}
					}
				case types.ObjectLockRetentionModeCompliance:
					return s3err.GetAPIError(s3err.ErrObjectLocked)
				}
			}
		}

		legalHold, err := be.GetObjectLegalHold(ctx, bucket, obj, "")
		if err != nil {
			return err
		}

		if legalHold.Status == types.ObjectLockLegalHoldStatusOn && !isAdminOrRoot {
			return s3err.GetAPIError(s3err.ErrObjectLocked)
		}
	}

	if bucketLockConfig.DefaultRetention != nil && bucketLockConfig.CreatedAt != nil {
		expirationDate := *bucketLockConfig.CreatedAt
		if bucketLockConfig.DefaultRetention.Days != nil {
			expirationDate = expirationDate.AddDate(0, 0, int(*bucketLockConfig.DefaultRetention.Days))
		}
		if bucketLockConfig.DefaultRetention.Years != nil {
			expirationDate = expirationDate.AddDate(int(*bucketLockConfig.DefaultRetention.Years), 0, 0)
		}

		if expirationDate.After(time.Now()) {
			switch bucketLockConfig.DefaultRetention.Mode {
			case types.ObjectLockRetentionModeGovernance:
				if !isAdminOrRoot {
					policy, err := be.GetBucketPolicy(ctx, bucket)
					if err != nil {
						return err
					}
					err = verifyBucketPolicy(policy, userAccess, bucket, "", BypassGovernanceRetentionAction)
					if err != nil {
						return s3err.GetAPIError(s3err.ErrObjectLocked)
					}
				}
			case types.ObjectLockRetentionModeCompliance:
				return s3err.GetAPIError(s3err.ErrObjectLocked)
			}
		}
	}

	return nil
}
