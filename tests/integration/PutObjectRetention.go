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
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

func PutObjectRetention_non_existing_bucket(s *S3Conf) error {
	testName := "PutObjectRetention_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: getPtr(getBucketName()),
			Key:    getPtr("my-obj"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func PutObjectRetention_non_existing_object(s *S3Conf) error {
	testName := "PutObjectRetention_non_existing_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		date := time.Now().Add(time.Hour * 3)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeCompliance,
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchKey)); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func PutObjectRetention_unset_bucket_object_lock_config(s *S3Conf) error {
	testName := "PutObjectRetention_unset_bucket_object_lock_config"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		date := time.Now().Add(time.Hour * 3)
		key := "my-obj"

		_, err := putObjects(s3client, []string{key}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &key,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeCompliance,
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMissingObjectLockConfiguration)); err != nil {
			return err
		}

		return nil
	})
}

func PutObjectRetention_expired_retain_until_date(s *S3Conf) error {
	testName := "PutObjectRetention_expired_retain_until_date"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		date := time.Now().Add(-time.Hour * 3)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeCompliance,
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgPastObjectLockRetainDate, date.Format(time.RFC3339))); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func PutObjectRetention_invalid_mode(s *S3Conf) error {
	testName := "PutObjectRetention_invalid_mode"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		date := time.Now().Add(time.Hour * 3)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionMode("invalid_mode"),
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMalformedXML)); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func PutObjectRetention_overwrite_compliance_mode(s *S3Conf) error {
	testName := "PutObjectRetention_overwrite_compliance_mode"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		date := time.Now().Add(complianceTestRetention)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &obj,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeCompliance,
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		// A fresh date, not the one above: COMPLIANCE denies a mode switch
		// unconditionally regardless of what date is requested, so this only
		// needs to still be in the future by request time, not tied to what
		// was stored a round trip ago.
		attempted := time.Now().Add(complianceTestRetention)
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &obj,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeGovernance,
				RetainUntilDate: &attempted,
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
			return err
		}

		return cleanupLockedObjects(s3client, bucket, []objToDelete{{key: obj, isCompliance: true}})
	}, withLock())
}

func PutObjectRetention_overwrite_compliance_with_compliance(s *S3Conf) error {
	testName := "PutObjectRetention_overwrite_compliance_with_compliance"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		date := time.Now().Add(complianceTestRetention)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &obj,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeCompliance,
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		// Extending stays within complianceTestRetention's budget so the
		// object can still be waited out: a COMPLIANCE retention pushed years
		// into the future could never be cleaned up.
		newDate := date.Add(complianceTestRetention)

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &obj,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeCompliance,
				RetainUntilDate: &newDate,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		return cleanupLockedObjects(s3client, bucket, []objToDelete{{key: obj, isCompliance: true}})
	}, withLock())
}

func PutObjectRetention_overwrite_governance_with_governance(s *S3Conf) error {
	testName := "PutObjectRetention_overwrite_governance_with_governance"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		date := time.Now().Add(time.Hour * 200)
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &obj,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeGovernance,
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		newDate := date.Add(time.Hour)

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &obj,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeGovernance,
				RetainUntilDate: &newDate,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		return cleanupLockedObjects(s3client, bucket, []objToDelete{{key: obj}})
	}, withLock())
}

func PutObjectRetention_overwrite_governance_without_bypass_specified(s *S3Conf) error {
	testName := "PutObjectRetention_overwrite_governance_without_bypass_specified"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		date := time.Now().Add(time.Hour * 3)
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &obj,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeGovernance,
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &obj,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeCompliance,
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
			return err
		}

		return cleanupLockedObjects(s3client, bucket, []objToDelete{{key: obj}})
	}, withLock())
}

func PutObjectRetention_overwrite_governance_with_permission(s *S3Conf) error {
	testName := "PutObjectRetention_overwrite_governance_with_permission"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		date := time.Now().Add(complianceTestRetention)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &obj,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeGovernance,
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		policy := genPolicyDoc("Allow", `"*"`, `["s3:BypassGovernanceRetention"]`, fmt.Sprintf(`"arn:aws:s3:::%v/*"`, bucket))
		bypass := true

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &policy,
		})
		cancel()
		if err != nil {
			return err
		}

		complianceDate := time.Now().Add(complianceTestRetention)
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &obj,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeCompliance,
				RetainUntilDate: &complianceDate,
			},
			BypassGovernanceRetention: &bypass,
		})
		cancel()
		if err != nil {
			return err
		}

		return cleanupLockedObjects(s3client, bucket, []objToDelete{{key: obj, isCompliance: true}})
	}, withLock())
}

func PutObjectRetention_shorten_governance_without_bypass(s *S3Conf) error {
	testName := "PutObjectRetention_shorten_governance_without_bypass"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		date := time.Now().Add(time.Hour)
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &obj,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeGovernance,
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		shorter := time.Now().Add(complianceTestRetention / 2)

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &obj,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeGovernance,
				RetainUntilDate: &shorter,
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
			return err
		}

		return cleanupLockedObjects(s3client, bucket, []objToDelete{{key: obj}})
	}, withLock())
}

func PutObjectRetention_shorten_governance_with_bypass(s *S3Conf) error {
	testName := "PutObjectRetention_shorten_governance_with_bypass"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		date := time.Now().Add(time.Hour)
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &obj,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeGovernance,
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		policy := genPolicyDoc("Allow", fmt.Sprintf(`"%v"`, s.awsID), `["s3:BypassGovernanceRetention"]`, fmt.Sprintf(`"arn:aws:s3:::%v/*"`, bucket))
		bypass := true

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &policy,
		})
		cancel()
		if err != nil {
			return err
		}

		shorter := time.Now().Add(complianceTestRetention / 2)

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &obj,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeGovernance,
				RetainUntilDate: &shorter,
			},
			BypassGovernanceRetention: &bypass,
		})
		cancel()
		if err != nil {
			return err
		}

		return cleanupLockedObjects(s3client, bucket, []objToDelete{{key: obj}})
	}, withLock())
}

func PutObjectRetention_shorten_compliance_denied(s *S3Conf) error {
	testName := "PutObjectRetention_shorten_compliance_denied"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		policy := genPolicyDoc("Allow", fmt.Sprintf(`"%v"`, s.awsID), `["s3:BypassGovernanceRetention"]`, fmt.Sprintf(`"arn:aws:s3:::%v/*"`, bucket))
		bypass := true

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &policy,
		})
		cancel()
		if err != nil {
			return err
		}

		// The COMPLIANCE lock goes on last, after the slow setup above rather
		// than before it, so the whole complianceTestRetention budget is left
		// for the two attempts below. Started any earlier, a slow object upload
		// can consume the entire window and leave an already expired retention
		// with nothing to shorten.
		date := time.Now().Add(complianceTestRetention)

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &obj,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeCompliance,
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		// Recomputed fresh right before each request below, rather than once
		// up front: the server rejects a RetainUntilDate that has already
		// passed (InvalidArgument) before it ever gets to the object-lock
		// comparison this test is exercising (ErrObjectLocked)
		newShorterDate := func() time.Time {
			return time.Now().Add(time.Until(date) / 2)
		}

		// Neither asking to bypass nor holding the permission helps.
		shorter := newShorterDate()
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &obj,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeCompliance,
				RetainUntilDate: &shorter,
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
			return err
		}

		shorter = newShorterDate()
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &obj,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeCompliance,
				RetainUntilDate: &shorter,
			},
			BypassGovernanceRetention: &bypass,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
			return err
		}

		return cleanupLockedObjects(s3client, bucket, []objToDelete{{key: obj, isCompliance: true}})
	}, withLock())
}

func PutObjectRetention_rewrite_same_date(s *S3Conf) error {
	testName := "PutObjectRetention_rewrite_same_date"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		govObj, compObj := "my-obj-governance", "my-obj-compliance"
		_, err := putObjects(s3client, []string{govObj, compObj}, bucket)
		if err != nil {
			return err
		}

		for _, obj := range []struct {
			key  string
			mode types.ObjectLockRetentionMode
		}{
			{key: govObj, mode: types.ObjectLockRetentionModeGovernance},
			{key: compObj, mode: types.ObjectLockRetentionModeCompliance},
		} {
			date := time.Now().Add(complianceTestRetention)
			if obj.mode == types.ObjectLockRetentionModeGovernance {
				date = time.Now().Add(time.Hour)
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
				Bucket: &bucket,
				Key:    &obj.key,
				Retention: &types.ObjectLockRetention{
					Mode:            obj.mode,
					RetainUntilDate: &date,
				},
			})
			cancel()
			if err != nil {
				return err
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
				Bucket: &bucket,
				Key:    &obj.key,
				Retention: &types.ObjectLockRetention{
					Mode:            obj.mode,
					RetainUntilDate: &date,
				},
			})
			cancel()
			if err != nil {
				return fmt.Errorf("%v: rewriting the identical date must be allowed: %w", obj.mode, err)
			}
		}

		return cleanupLockedObjects(s3client, bucket, []objToDelete{
			{key: govObj},
			{key: compObj, isCompliance: true},
		})
	}, withLock())
}

func PutObjectRetention_success(s *S3Conf) error {
	testName := "PutObjectRetention_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key := "my-obj"

		_, err := putObjects(s3client, []string{key}, bucket)
		if err != nil {
			return err
		}

		date := time.Now().Add(complianceTestRetention)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &key,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeCompliance,
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		return cleanupLockedObjects(s3client, bucket, []objToDelete{{key: key, isCompliance: true}})
	}, withLock())
}
