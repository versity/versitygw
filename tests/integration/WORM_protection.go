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
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

func WORMProtection_bucket_object_lock_configuration_governance_mode(s *S3Conf) error {
	testName := "WORMProtection_bucket_object_lock_configuration_governance_mode"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		var days int32 = 10
		object := "my-obj"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
			ObjectLockConfiguration: &types.ObjectLockConfiguration{
				ObjectLockEnabled: types.ObjectLockEnabledEnabled,
				Rule: &types.ObjectLockRule{
					DefaultRetention: &types.DefaultRetention{
						Mode: types.ObjectLockRetentionModeGovernance,
						Days: &days,
					},
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		// a default retention rule gives the upload Object Lock parameters,
		// which need a checksum of its body
		_, err = putObjectWithData(10, &s3.PutObjectInput{
			Bucket:            &bucket,
			Key:               &object,
			ChecksumAlgorithm: types.ChecksumAlgorithmCrc32,
		}, s3client)
		if err != nil {
			return err
		}

		if err := checkWORMProtection(s, s3client, bucket, object); err != nil {
			return err
		}
		return cleanupLockedObjects(s3client, bucket, []objToDelete{{key: object}})
	}, withLock())
}

func WORMProtection_bucket_object_lock_governance_bypass_delete(s *S3Conf) error {
	testName := "WORMProtection_bucket_object_lock_governance_bypass_delete"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		var days int32 = 10
		object := "my-obj"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
			ObjectLockConfiguration: &types.ObjectLockConfiguration{
				ObjectLockEnabled: types.ObjectLockEnabledEnabled,
				Rule: &types.ObjectLockRule{
					DefaultRetention: &types.DefaultRetention{
						Mode: types.ObjectLockRetentionModeGovernance,
						Days: &days,
					},
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		// a default retention rule gives the upload Object Lock parameters,
		// which need a checksum of its body
		_, err = putObjectWithData(10, &s3.PutObjectInput{
			Bucket:            &bucket,
			Key:               &object,
			ChecksumAlgorithm: types.ChecksumAlgorithmCrc32,
		}, s3client)
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

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:                    &bucket,
			Key:                       &object,
			BypassGovernanceRetention: &bypass,
		})
		cancel()
		return err
	}, withLock())
}

func WORMProtection_bucket_object_lock_governance_bypass_delete_multiple(s *S3Conf) error {
	testName := "WORMProtection_bucket_object_lock_governance_bypass_delete_multiple"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		var days int32 = 10
		obj1, obj2, obj3 := "my-obj-1", "my-obj-2", "my-obj-3"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
			ObjectLockConfiguration: &types.ObjectLockConfiguration{
				ObjectLockEnabled: types.ObjectLockEnabledEnabled,
				Rule: &types.ObjectLockRule{
					DefaultRetention: &types.DefaultRetention{
						Mode: types.ObjectLockRetentionModeGovernance,
						Days: &days,
					},
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		// a default retention rule gives each upload Object Lock parameters,
		// which need a checksum of its body
		for _, key := range []string{obj1, obj2, obj3} {
			_, err = putObjectWithData(10, &s3.PutObjectInput{
				Bucket:            &bucket,
				Key:               &key,
				ChecksumAlgorithm: types.ChecksumAlgorithmCrc32,
			}, s3client)
			if err != nil {
				return err
			}
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

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket:                    &bucket,
			BypassGovernanceRetention: &bypass,
			Delete: &types.Delete{
				Objects: []types.ObjectIdentifier{
					{
						Key: &obj1,
					},
					{
						Key: &obj2,
					},
					{
						Key: &obj3,
					},
				},
			},
		})
		cancel()
		return err
	}, withLock())
}

func WORMProtection_delete_objects_locked_object_partial_success(s *S3Conf) error {
	testName := "WORMProtection_delete_objects_locked_object_partial_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		locked, unlocked := "locked-obj", "unlocked-obj"
		if _, err := putObjects(s3client, []string{locked, unlocked}, bucket); err != nil {
			return err
		}

		date := time.Now().Add(time.Hour)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &locked,
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
		out, err := s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: &bucket,
			Delete: &types.Delete{
				Objects: []types.ObjectIdentifier{
					{Key: &locked},
					{Key: &unlocked},
				},
			},
		})
		cancel()
		if err != nil {
			return fmt.Errorf("expected DeleteObjects to succeed with a per-object denial, not fail outright: %w", err)
		}

		if len(out.Errors) != 1 {
			return fmt.Errorf("expected exactly 1 per-object error, got %+v", out.Errors)
		}
		if err := checkDeleteObjectsErr(out.Errors[0], locked, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
			return err
		}
		if err := checkDeletedKeysInOrder(out.Deleted, []string{unlocked}); err != nil {
			return err
		}

		return cleanupLockedObjects(s3client, bucket, []objToDelete{{key: locked, isCompliance: false}})
	}, withLock())
}

func WORMProtection_object_lock_retention_compliance_locked(s *S3Conf) error {
	testName := "WORMProtection_object_lock_retention_compliance_locked"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-obj"

		_, err := putObjects(s3client, []string{object}, bucket)
		if err != nil {
			return err
		}

		date := time.Now().Add(2 * complianceTestRetention)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &object,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeCompliance,
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if err := checkWORMProtection(s, s3client, bucket, object); err != nil {
			return err
		}

		return cleanupLockedObjects(s3client, bucket, []objToDelete{{key: object, isCompliance: true}})
	}, withLock())
}

func WORMProtection_object_lock_retention_governance_locked(s *S3Conf) error {
	testName := "WORMProtection_object_lock_retention_governance_locked"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-obj"

		_, err := putObjects(s3client, []string{object}, bucket)
		if err != nil {
			return err
		}

		date := time.Now().Add(time.Hour * 3)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &object,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeGovernance,
				RetainUntilDate: &date,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if err := checkWORMProtection(s, s3client, bucket, object); err != nil {
			return err
		}
		return cleanupLockedObjects(s3client, bucket, []objToDelete{{key: object}})
	}, withLock())
}

func WORMProtection_object_lock_retention_governance_bypass_overwrite_put(s *S3Conf) error {
	testName := "WORMProtection_object_lock_retention_governance_bypass_overwrite_put"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-obj"

		_, err := putObjects(s3client, []string{object}, bucket)
		if err != nil {
			return err
		}

		err = lockObject(s3client, objectLockModeGovernance, bucket, object, "")
		if err != nil {
			return err
		}

		policy := genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, s.awsID), `["s3:BypassGovernanceRetention"]`, fmt.Sprintf(`"arn:aws:s3:::%v/*"`, bucket))

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &policy,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &object,
		})
		cancel()
		return err
	}, withLock())
}

func WORMProtection_object_lock_retention_governance_bypass_overwrite_mp(s *S3Conf) error {
	testName := "WORMProtection_object_lock_retention_governance_bypass_overwrite_mp"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-obj"

		_, err := putObjects(s3client, []string{object}, bucket)
		if err != nil {
			return err
		}

		err = lockObject(s3client, objectLockModeGovernance, bucket, object, "")
		if err != nil {
			return err
		}

		policy := genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, s.awsID), `["s3:BypassGovernanceRetention"]`, fmt.Sprintf(`"arn:aws:s3:::%v/*"`, bucket))

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &policy,
		})
		cancel()
		if err != nil {
			return err
		}

		// overwrite the locked object with a new object with mp
		mp, err := createMp(s3client, bucket, object)
		if err != nil {
			return err
		}

		dataLen := int64(10)

		parts, _, err := uploadParts(s3client, dataLen, 1, bucket, object, *mp.UploadId)
		if err != nil {
			return err
		}
		part := parts[0]

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket: &bucket,
			Key:    &object,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: []types.CompletedPart{
					{
						ETag:              part.ETag,
						PartNumber:        part.PartNumber,
						ChecksumCRC64NVME: part.ChecksumCRC64NVME,
					},
				},
			},
			UploadId: mp.UploadId,
		})
		cancel()
		return err
	}, withLock())
}

func WORMProtection_object_lock_retention_governance_bypass_overwrite_copy(s *S3Conf) error {
	testName := "WORMProtection_object_lock_retention_governance_bypass_overwrite_copy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-obj"

		_, err := putObjects(s3client, []string{object}, bucket)
		if err != nil {
			return err
		}

		err = lockObject(s3client, objectLockModeGovernance, bucket, object, "")
		if err != nil {
			return err
		}

		policy := genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, s.awsID), `["s3:BypassGovernanceRetention"]`, fmt.Sprintf(`"arn:aws:s3:::%v/*"`, bucket))

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &policy,
		})
		cancel()
		if err != nil {
			return err
		}

		srcObj := "source-object"
		_, err = putObjects(s3client, []string{srcObj}, bucket)
		if err != nil {
			return err
		}

		// overwrite the locked object with a new object with CopyObject
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        &object,
			CopySource: getPtr(fmt.Sprintf("%s/%s", bucket, srcObj)),
		})
		cancel()
		if err != nil {
			return err
		}
		return err
	}, withLock())
}

func WORMProtection_object_lock_retention_governance_bypass_overwrite_post(s *S3Conf) error {
	testName := "WORMProtection_object_lock_retention_governance_bypass_overwrite_post"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-obj"

		_, err := putObjects(s3client, []string{object}, bucket)
		if err != nil {
			return err
		}

		err = lockObject(s3client, objectLockModeGovernance, bucket, object, "")
		if err != nil {
			return err
		}

		policy := genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, s.awsID), `["s3:BypassGovernanceRetention"]`, fmt.Sprintf(`"arn:aws:s3:::%v/*"`, bucket))

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &policy,
		})
		cancel()
		if err != nil {
			return err
		}

		// overwrite the locked object with a new object with POST object
		data := []byte("new object data")
		resp, err := sendPostObject(PostRequestConfig{
			bucket:      bucket,
			key:         object,
			s3Conf:      s,
			fileContent: data,
		})
		if err != nil {
			return err
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusNoContent {
			return fmt.Errorf("expected status 204, instead got %d", resp.StatusCode)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		defer cancel()
		out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &object,
		})
		if err != nil {
			return err
		}
		defer out.Body.Close()

		gotData, err := io.ReadAll(out.Body)
		if err != nil {
			return err
		}

		if getString(out.ETag) != resp.Header.Get("ETag") {
			return fmt.Errorf("expected the object ETag to be %s, instead got %s", resp.Header.Get("ETag"), getString(out.ETag))
		}
		if !bytes.Equal(gotData, data) {
			return fmt.Errorf("expected the object data to be %q, instead got %q", data, gotData)
		}

		return nil
	}, withLock())
}

func WORMProtection_unable_to_overwrite_locked_object_put(s *S3Conf) error {
	testName := "WORMProtection_unable_to_overwrite_locked_object_put"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-obj"
		_, err := putObjects(s3client, []string{object}, bucket)
		if err != nil {
			return err
		}

		err = lockObject(s3client, objectLockModeLegalHold, bucket, object, "")
		if err != nil {
			return err
		}

		_, err = putObjects(s3client, []string{object}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
			return err
		}
		return cleanupLockedObjects(s3client, bucket, []objToDelete{
			{
				key:                object,
				removeOnlyLeglHold: true,
			},
		})
	}, withLock())
}

func WORMProtection_unable_to_overwrite_locked_object_copy(s *S3Conf) error {
	testName := "WORMProtection_unable_to_overwrite_locked_object_copy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-obj"

		_, err := putObjects(s3client, []string{object}, bucket)
		if err != nil {
			return err
		}

		err = lockObject(s3client, objectLockModeLegalHold, bucket, object, "")
		if err != nil {
			return err
		}

		srcObj := "source-object"
		_, err = putObjects(s3client, []string{srcObj}, bucket)
		if err != nil {
			return err
		}

		// overwrite the locked object with a new object with CopyObject
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        &object,
			CopySource: getPtr(fmt.Sprintf("%s/%s", bucket, srcObj)),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
			return err
		}
		return cleanupLockedObjects(s3client, bucket, []objToDelete{
			{
				key:                object,
				removeOnlyLeglHold: true,
			},
		})
	}, withLock())
}

func WORMProtection_unable_to_overwrite_locked_object_mp(s *S3Conf) error {
	testName := "WORMProtection_unable_to_overwrite_locked_object_mp"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-obj"

		_, err := putObjects(s3client, []string{object}, bucket)
		if err != nil {
			return err
		}

		err = lockObject(s3client, objectLockModeLegalHold, bucket, object, "")
		if err != nil {
			return err
		}

		mp, err := createMp(s3client, bucket, object)
		if err != nil {
			return err
		}

		dataLen := int64(10)

		parts, _, err := uploadParts(s3client, dataLen, 1, bucket, object, *mp.UploadId)
		if err != nil {
			return err
		}
		part := parts[0]

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket: &bucket,
			Key:    &object,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: []types.CompletedPart{
					{
						ETag:              part.ETag,
						PartNumber:        part.PartNumber,
						ChecksumCRC64NVME: part.ChecksumCRC64NVME,
					},
				},
			},
			UploadId: mp.UploadId,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
			return err
		}
		return cleanupLockedObjects(s3client, bucket, []objToDelete{
			{
				key:                object,
				removeOnlyLeglHold: true,
			},
		})
	}, withLock())
}

func WORMProtection_unable_to_overwrite_locked_object_post(s *S3Conf) error {
	testName := "WORMProtection_unable_to_overwrite_locked_object_post"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-obj"

		_, err := putObjects(s3client, []string{object}, bucket)
		if err != nil {
			return err
		}

		err = lockObject(s3client, objectLockModeLegalHold, bucket, object, "")
		if err != nil {
			return err
		}

		// overwrite the locked object with a new object with POST object
		resp, err := sendPostObject(PostRequestConfig{
			bucket:      bucket,
			key:         object,
			s3Conf:      s,
			fileContent: []byte("new object data"),
		})
		if err != nil {
			return err
		}
		if err := checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
			return err
		}
		return cleanupLockedObjects(s3client, bucket, []objToDelete{
			{
				key:                object,
				removeOnlyLeglHold: true,
			},
		})
	}, withLock())
}

func WORMProtection_object_lock_retention_governance_bypass_delete(s *S3Conf) error {
	testName := "WORMProtection_object_lock_retention_governance_bypass_delete"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-obj"

		_, err := putObjects(s3client, []string{object}, bucket)
		if err != nil {
			return err
		}

		date := time.Now().Add(time.Hour * 3)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &object,
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

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:                    &bucket,
			Key:                       &object,
			BypassGovernanceRetention: &bypass,
		})
		cancel()
		return err
	}, withLock())
}

func WORMProtection_object_lock_retention_governance_bypass_delete_mul(s *S3Conf) error {
	testName := "WORMProtection_object_lock_retention_governance_bypass_delete_mul"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objs := []string{"my-obj-1", "my-obj2", "my-obj-3"}

		_, err := putObjects(s3client, objs, bucket)
		if err != nil {
			return err
		}

		for _, obj := range objs {
			o := obj
			date := time.Now().Add(time.Hour * 3)
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
				Bucket: &bucket,
				Key:    &o,
				Retention: &types.ObjectLockRetention{
					Mode:            types.ObjectLockRetentionModeGovernance,
					RetainUntilDate: &date,
				},
			})
			cancel()
			if err != nil {
				return err
			}
		}

		policy := genPolicyDoc("Allow", `"*"`, `["s3:BypassGovernanceRetention"]`, fmt.Sprintf(`"arn:aws:s3:::%v/*"`, bucket))
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

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket:                    &bucket,
			BypassGovernanceRetention: &bypass,
			Delete: &types.Delete{
				Objects: []types.ObjectIdentifier{
					{
						Key: &objs[0],
					},
					{
						Key: &objs[1],
					},
					{
						Key: &objs[2],
					},
				},
			},
		})
		cancel()
		return err
	}, withLock())
}

func WORMProtection_object_lock_legal_hold_locked(s *S3Conf) error {
	testName := "WORMProtection_object_lock_legal_hold_locked"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-obj"

		_, err := putObjects(s3client, []string{object}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
			Bucket: &bucket,
			Key:    &object,
			LegalHold: &types.ObjectLockLegalHold{
				Status: types.ObjectLockLegalHoldStatusOn,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		_, err = putObjects(s3client, []string{object}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
			return err
		}

		return cleanupLockedObjects(s3client, bucket, []objToDelete{{key: object, removeOnlyLeglHold: true}})
	}, withLock())
}

func WORMProtection_root_bypass_governance_retention_delete_object(s *S3Conf) error {
	testName := "WORMProtection_root_bypass_governance_retention_delete_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		retDate := time.Now().Add(time.Hour * 48)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket,
			Key:    &obj,
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeGovernance,
				RetainUntilDate: &retDate,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if err := checkWORMProtection(s, s3client, bucket, obj); err != nil {
			return err
		}

		policy := genPolicyDoc("Allow", fmt.Sprintf(`"%v"`, s.awsID), `["s3:BypassGovernanceRetention"]`, fmt.Sprintf(`"arn:aws:s3:::%v/*"`, bucket))

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: &bucket,
			Policy: &policy,
		})
		cancel()
		if err != nil {
			return err
		}

		bypass := true
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:                    &bucket,
			Key:                       &obj,
			BypassGovernanceRetention: &bypass,
		})
		cancel()
		return err
	}, withLock())
}

// WORMProtection_default_retention_applies_to_new_objects covers each way of
// writing an object to a bucket with a default retention rule. The object
// gets a retention of its own: the rule's mode, until the rule's period from
// the write.
func WORMProtection_default_retention_applies_to_new_objects(s *S3Conf) error {
	testName := "WORMProtection_default_retention_applies_to_new_objects"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
			ObjectLockConfiguration: &types.ObjectLockConfiguration{
				ObjectLockEnabled: types.ObjectLockEnabledEnabled,
				Rule: &types.ObjectLockRule{
					DefaultRetention: &types.DefaultRetention{
						Mode: types.ObjectLockRetentionModeGovernance,
						Days: getPtr(int32(1)),
					},
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		// the margin absorbs clock skew between this process and the gateway
		earliest := time.Now().Add(24*time.Hour - time.Minute)

		// a default retention rule gives each upload Object Lock parameters,
		// which need a checksum of its body
		_, err = putObjectWithData(10, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    getPtr("put-obj"),
		}, s3client, withPutObjectChecksumAlgo(types.ChecksumAlgorithmCrc32))
		if err != nil {
			return err
		}
		_, err = putObjectWithData(0, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    getPtr("dir-obj/"),
		}, s3client, withPutObjectChecksumAlgo(types.ChecksumAlgorithmCrc32))
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        getPtr("copy-obj"),
			CopySource: getPtr(bucket + "/put-obj"),
		})
		cancel()
		if err != nil {
			return err
		}

		mp, err := createMp(s3client, bucket, "mp-obj", withChecksum(types.ChecksumAlgorithmCrc32))
		if err != nil {
			return err
		}
		parts, _, err := uploadParts(s3client, 10, 1, bucket, "mp-obj", *mp.UploadId, withChecksum(types.ChecksumAlgorithmCrc32))
		if err != nil {
			return err
		}
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      getPtr("mp-obj"),
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: []types.CompletedPart{
					{
						ETag:          parts[0].ETag,
						PartNumber:    parts[0].PartNumber,
						ChecksumCRC32: parts[0].ChecksumCRC32,
					},
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		latest := time.Now().Add(24*time.Hour + time.Minute)

		for _, key := range []string{"put-obj", "dir-obj/", "copy-obj", "mp-obj"} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			ret, err := s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
				Bucket: &bucket,
				Key:    &key,
			})
			cancel()
			if err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
			if ret.Retention.Mode != types.ObjectLockRetentionModeGovernance {
				return fmt.Errorf("%s: expected retention mode %v, instead got %v",
					key, types.ObjectLockRetentionModeGovernance, ret.Retention.Mode)
			}
			date := ret.Retention.RetainUntilDate
			if date == nil || date.Before(earliest) || date.After(latest) {
				return fmt.Errorf("%s: expected retain until date between %v and %v, instead got %v",
					key, earliest, latest, date)
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			head, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: &bucket,
				Key:    &key,
			})
			cancel()
			if err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
			if head.ObjectLockMode != types.ObjectLockModeGovernance {
				return fmt.Errorf("%s: expected HeadObject lock mode %v, instead got %v",
					key, types.ObjectLockModeGovernance, head.ObjectLockMode)
			}
			date = head.ObjectLockRetainUntilDate
			if date == nil || date.Before(earliest) || date.After(latest) {
				return fmt.Errorf("%s: expected HeadObject retain until date between %v and %v, instead got %v",
					key, earliest, latest, date)
			}
		}

		return nil
	}, withLock())
}

// WORMProtection_default_retention_survives_rule_change covers an object
// written under a default retention rule: changing or removing the rule
// leaves the object's retention, and its protection, as they are. Objects
// written after the removal get none.
func WORMProtection_default_retention_survives_rule_change(s *S3Conf) error {
	testName := "WORMProtection_default_retention_survives_rule_change"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		putLockConfig := func(rule *types.ObjectLockRule) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
				Bucket: &bucket,
				ObjectLockConfiguration: &types.ObjectLockConfiguration{
					ObjectLockEnabled: types.ObjectLockEnabledEnabled,
					Rule:              rule,
				},
			})
			cancel()
			return err
		}
		getRetention := func(key string) (*types.ObjectLockRetention, error) {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
				Bucket: &bucket,
				Key:    &key,
			})
			cancel()
			if err != nil {
				return nil, err
			}
			return out.Retention, nil
		}

		obj := "my-obj"
		if err := putLockConfig(&types.ObjectLockRule{
			DefaultRetention: &types.DefaultRetention{
				Mode: types.ObjectLockRetentionModeGovernance,
				Days: getPtr(int32(1)),
			},
		}); err != nil {
			return err
		}

		_, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client, withPutObjectChecksumAlgo(types.ChecksumAlgorithmCrc32))
		if err != nil {
			return err
		}

		stamped, err := getRetention(obj)
		if err != nil {
			return err
		}

		for _, change := range []struct {
			name string
			rule *types.ObjectLockRule
		}{
			{
				name: "changed",
				rule: &types.ObjectLockRule{
					DefaultRetention: &types.DefaultRetention{
						Mode: types.ObjectLockRetentionModeGovernance,
						Days: getPtr(int32(2)),
					},
				},
			},
			{name: "removed"},
		} {
			if err := putLockConfig(change.rule); err != nil {
				return fmt.Errorf("rule %s: %w", change.name, err)
			}

			ret, err := getRetention(obj)
			if err != nil {
				return fmt.Errorf("rule %s: %w", change.name, err)
			}
			if ret.Mode != stamped.Mode || ret.RetainUntilDate == nil || !ret.RetainUntilDate.Equal(*stamped.RetainUntilDate) {
				return fmt.Errorf("rule %s: expected the object retention to stay %v until %v, instead got %v until %v",
					change.name, stamped.Mode, stamped.RetainUntilDate, ret.Mode, ret.RetainUntilDate)
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
			return err
		}

		after := "after-removal"
		if _, err := putObjects(s3client, []string{after}, bucket); err != nil {
			return err
		}
		_, err = getRetention(after)
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchObjectLockConfiguration))
	}, withLock())
}

// WORMProtection_default_retention_explicit_lock_settings covers writes to
// a bucket with a default retention rule that set Object Lock parameters of
// their own. A requested retention replaces the rule's, and a legal hold, of
// either status, keeps the rule's retention off the object.
func WORMProtection_default_retention_explicit_lock_settings(s *S3Conf) error {
	testName := "WORMProtection_default_retention_explicit_lock_settings"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
			ObjectLockConfiguration: &types.ObjectLockConfiguration{
				ObjectLockEnabled: types.ObjectLockEnabledEnabled,
				Rule: &types.ObjectLockRule{
					DefaultRetention: &types.DefaultRetention{
						Mode: types.ObjectLockRetentionModeGovernance,
						Days: getPtr(int32(1)),
					},
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		retainUntil := time.Now().Add(time.Hour)
		explicit := "explicit-retention"
		_, err = putObjectWithData(10, &s3.PutObjectInput{
			Bucket:                    &bucket,
			Key:                       &explicit,
			ObjectLockMode:            types.ObjectLockModeGovernance,
			ObjectLockRetainUntilDate: &retainUntil,
		}, s3client, withPutObjectChecksumAlgo(types.ChecksumAlgorithmCrc32))
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		ret, err := s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
			Bucket: &bucket,
			Key:    &explicit,
		})
		cancel()
		if err != nil {
			return err
		}
		if ret.Retention.Mode != types.ObjectLockRetentionModeGovernance {
			return fmt.Errorf("expected retention mode %v, instead got %v",
				types.ObjectLockRetentionModeGovernance, ret.Retention.Mode)
		}
		date := ret.Retention.RetainUntilDate
		if date == nil || date.Sub(retainUntil).Abs() > time.Second {
			return fmt.Errorf("expected retain until date %v, instead got %v", retainUntil, date)
		}

		legalHold := "legal-hold-off"
		_, err = putObjectWithData(10, &s3.PutObjectInput{
			Bucket:                    &bucket,
			Key:                       &legalHold,
			ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatusOff,
		}, s3client, withPutObjectChecksumAlgo(types.ChecksumAlgorithmCrc32))
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
			Bucket: &bucket,
			Key:    &legalHold,
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchObjectLockConfiguration))
	}, withLock())
}

// WORMProtection_default_retention_set_at_create_multipart_upload covers
// multipart uploads to a bucket whose default retention rule changes while
// they are in progress. The rule in force when the upload is created, if
// any, gives the object its retention, counted from the creation.
func WORMProtection_default_retention_set_at_create_multipart_upload(s *S3Conf) error {
	testName := "WORMProtection_default_retention_set_at_create_multipart_upload"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		putLockConfig := func(days int32) error {
			cfg := &types.ObjectLockConfiguration{
				ObjectLockEnabled: types.ObjectLockEnabledEnabled,
			}
			if days != 0 {
				cfg.Rule = &types.ObjectLockRule{
					DefaultRetention: &types.DefaultRetention{
						Mode: types.ObjectLockRetentionModeGovernance,
						Days: &days,
					},
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
				Bucket:                  &bucket,
				ObjectLockConfiguration: cfg,
			})
			cancel()
			return err
		}

		underRule, beforeRule := "under-rule", "before-rule"

		if err := putLockConfig(1); err != nil {
			return err
		}
		// the margin absorbs clock skew between this process and the gateway
		earliest := time.Now().Add(24*time.Hour - time.Minute)
		under, err := createMp(s3client, bucket, underRule, withChecksum(types.ChecksumAlgorithmCrc32))
		if err != nil {
			return err
		}
		latest := time.Now().Add(24*time.Hour + time.Minute)

		if err := putLockConfig(0); err != nil {
			return err
		}
		before, err := createMp(s3client, bucket, beforeRule)
		if err != nil {
			return err
		}
		if err := putLockConfig(2); err != nil {
			return err
		}

		for _, mp := range []struct {
			key      string
			uploadId *string
			opts     []mpOpt
		}{
			{key: underRule, uploadId: under.UploadId, opts: []mpOpt{withChecksum(types.ChecksumAlgorithmCrc32)}},
			{key: beforeRule, uploadId: before.UploadId},
		} {
			parts, _, err := uploadParts(s3client, 10, 1, bucket, mp.key, *mp.uploadId, mp.opts...)
			if err != nil {
				return fmt.Errorf("%s: %w", mp.key, err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
				Bucket:   &bucket,
				Key:      &mp.key,
				UploadId: mp.uploadId,
				MultipartUpload: &types.CompletedMultipartUpload{
					Parts: []types.CompletedPart{
						{
							ETag:          parts[0].ETag,
							PartNumber:    parts[0].PartNumber,
							ChecksumCRC32: parts[0].ChecksumCRC32,
						},
					},
				},
			})
			cancel()
			if err != nil {
				return fmt.Errorf("%s: %w", mp.key, err)
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		ret, err := s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
			Bucket: &bucket,
			Key:    &underRule,
		})
		cancel()
		if err != nil {
			return err
		}
		if ret.Retention.Mode != types.ObjectLockRetentionModeGovernance {
			return fmt.Errorf("expected retention mode %v, instead got %v",
				types.ObjectLockRetentionModeGovernance, ret.Retention.Mode)
		}
		date := ret.Retention.RetainUntilDate
		if date == nil || date.Before(earliest) || date.After(latest) {
			return fmt.Errorf("expected retain until date between %v and %v, instead got %v",
				earliest, latest, date)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
			Bucket: &bucket,
			Key:    &beforeRule,
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchObjectLockConfiguration))
	}, withLock())
}

// WORMProtection_legal_hold_outlives_expired_retention covers an object
// with both a retention and a legal hold: once the retention expires, the
// legal hold still blocks its deletion, with the bypass header too.
func WORMProtection_legal_hold_outlives_expired_retention(s *S3Conf) error {
	testName := "WORMProtection_legal_hold_outlives_expired_retention"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		retainUntil := time.Now().Add(lockWaitTime)
		_, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket:                    &bucket,
			Key:                       &obj,
			ObjectLockMode:            types.ObjectLockModeGovernance,
			ObjectLockRetainUntilDate: &retainUntil,
			ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatusOn,
		}, s3client, withPutObjectChecksumAlgo(types.ChecksumAlgorithmCrc32))
		if err != nil {
			return err
		}

		// The extra second absorbs clock skew between this process and the
		// gateway, which compares the retention against its own clock.
		time.Sleep(time.Until(retainUntil) + time.Second)

		for _, bypass := range []bool{false, true} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket:                    &bucket,
				Key:                       &obj,
				BypassGovernanceRetention: &bypass,
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
				return fmt.Errorf("bypass %v: %w", bypass, err)
			}
		}

		return cleanupLockedObjects(s3client, bucket, []objToDelete{{key: obj, removeOnlyLeglHold: true}})
	}, withLock())
}
