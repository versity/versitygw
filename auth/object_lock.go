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
	"encoding/xml"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

type BucketLockConfig struct {
	Enabled          bool
	DefaultRetention *types.DefaultRetention
	CreatedAt        *time.Time
}

func ParseBucketLockConfigurationInput(input []byte) ([]byte, error) {
	var lockConfig types.ObjectLockConfiguration
	if err := xml.Unmarshal(input, &lockConfig); err != nil {
		return nil, s3err.GetAPIError(s3err.ErrMalformedXML)
	}

	if lockConfig.ObjectLockEnabled != "" && lockConfig.ObjectLockEnabled != types.ObjectLockEnabledEnabled {
		return nil, s3err.GetAPIError(s3err.ErrMalformedXML)
	}

	config := BucketLockConfig{
		Enabled: lockConfig.ObjectLockEnabled == types.ObjectLockEnabledEnabled,
	}

	if lockConfig.Rule != nil && lockConfig.Rule.DefaultRetention != nil {
		retention := lockConfig.Rule.DefaultRetention

		if retention.Mode != types.ObjectLockRetentionModeCompliance && retention.Mode != types.ObjectLockRetentionModeGovernance {
			return nil, s3err.GetAPIError(s3err.ErrMalformedXML)
		}
		if retention.Years != nil && retention.Days != nil {
			return nil, s3err.GetAPIError(s3err.ErrMalformedXML)
		}

		if retention.Days != nil && *retention.Days <= 0 {
			return nil, s3err.GetAPIError(s3err.ErrObjectLockInvalidRetentionPeriod)
		}
		if retention.Years != nil && *retention.Years <= 0 {
			return nil, s3err.GetAPIError(s3err.ErrObjectLockInvalidRetentionPeriod)
		}

		config.DefaultRetention = retention
		now := time.Now()
		config.CreatedAt = &now
	}

	return json.Marshal(config)
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

func ParseObjectLockRetentionInput(input []byte) ([]byte, error) {
	var retention s3response.PutObjectRetentionInput
	if err := xml.Unmarshal(input, &retention); err != nil {
		return nil, s3err.GetAPIError(s3err.ErrMalformedXML)
	}

	if retention.RetainUntilDate.Before(time.Now()) {
		return nil, s3err.GetAPIError(s3err.ErrPastObjectLockRetainDate)
	}
	switch retention.Mode {
	case types.ObjectLockRetentionModeCompliance:
	case types.ObjectLockRetentionModeGovernance:
	default:
		return nil, s3err.GetAPIError(s3err.ErrMalformedXML)
	}

	return json.Marshal(retention)
}

func ParseObjectLockRetentionOutput(input []byte) (*types.ObjectLockRetention, error) {
	var retention types.ObjectLockRetention
	if err := json.Unmarshal(input, &retention); err != nil {
		return nil, fmt.Errorf("parse object lock retention: %w", err)
	}

	return &retention, nil
}

func ParseObjectLegalHoldOutput(status *bool) *s3response.GetObjectLegalHoldResult {
	if status == nil {
		return nil
	}

	if *status {
		return &s3response.GetObjectLegalHoldResult{
			Status: types.ObjectLockLegalHoldStatusOn,
		}
	}

	return &s3response.GetObjectLegalHoldResult{
		Status: types.ObjectLockLegalHoldStatusOff,
	}
}

func CheckObjectAccess(ctx context.Context, bucket, userAccess string, objects []types.ObjectIdentifier, bypass, isBucketPublic bool, be backend.Backend) error {
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

	checkDefaultRetention := false

	if bucketLockConfig.DefaultRetention != nil && bucketLockConfig.CreatedAt != nil {
		expirationDate := *bucketLockConfig.CreatedAt
		if bucketLockConfig.DefaultRetention.Days != nil {
			expirationDate = expirationDate.AddDate(0, 0, int(*bucketLockConfig.DefaultRetention.Days))
		}
		if bucketLockConfig.DefaultRetention.Years != nil {
			expirationDate = expirationDate.AddDate(int(*bucketLockConfig.DefaultRetention.Years), 0, 0)
		}

		if expirationDate.After(time.Now()) {
			checkDefaultRetention = true
		}
	}

	for _, obj := range objects {
		var key, versionId string
		if obj.Key != nil {
			key = *obj.Key
		}
		if obj.VersionId != nil {
			versionId = *obj.VersionId
		}
		checkRetention := true
		retentionData, err := be.GetObjectRetention(ctx, bucket, key, versionId)
		if errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchKey)) {
			continue
		}
		if errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchObjectLockConfiguration)) {
			checkRetention = false
		}
		if err != nil && checkRetention {
			return err
		}

		if checkRetention {
			retention, err := ParseObjectLockRetentionOutput(retentionData)
			if err != nil {
				return err
			}

			if retention.Mode != "" && retention.RetainUntilDate != nil {
				if retention.RetainUntilDate.After(time.Now()) {
					switch retention.Mode {
					case types.ObjectLockRetentionModeGovernance:
						if !bypass {
							return s3err.GetAPIError(s3err.ErrObjectLocked)
						} else {
							policy, err := be.GetBucketPolicy(ctx, bucket)
							if errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchBucketPolicy)) {
								return s3err.GetAPIError(s3err.ErrObjectLocked)
							}
							if err != nil {
								return err
							}
							if isBucketPublic {
								err = VerifyPublicBucketPolicy(policy, bucket, key, BypassGovernanceRetentionAction)
							} else {
								err = VerifyBucketPolicy(policy, userAccess, bucket, key, BypassGovernanceRetentionAction)
							}
							if err != nil {
								return s3err.GetAPIError(s3err.ErrObjectLocked)
							}
						}
					case types.ObjectLockRetentionModeCompliance:
						return s3err.GetAPIError(s3err.ErrObjectLocked)
					}
				}
			}
		}

		checkLegalHold := true

		status, err := be.GetObjectLegalHold(ctx, bucket, key, versionId)
		if err != nil {
			if errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchKey)) {
				continue
			}
			if errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchObjectLockConfiguration)) {
				checkLegalHold = false
			} else {
				return err
			}
		}

		if checkLegalHold && *status {
			return s3err.GetAPIError(s3err.ErrObjectLocked)
		}

		if checkDefaultRetention {
			switch bucketLockConfig.DefaultRetention.Mode {
			case types.ObjectLockRetentionModeGovernance:
				if !bypass {
					return s3err.GetAPIError(s3err.ErrObjectLocked)
				} else {
					policy, err := be.GetBucketPolicy(ctx, bucket)
					if errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchBucketPolicy)) {
						return s3err.GetAPIError(s3err.ErrObjectLocked)
					}
					if err != nil {
						return err
					}
					if isBucketPublic {
						err = VerifyPublicBucketPolicy(policy, bucket, key, BypassGovernanceRetentionAction)
					} else {
						err = VerifyBucketPolicy(policy, userAccess, bucket, key, BypassGovernanceRetentionAction)
					}
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
