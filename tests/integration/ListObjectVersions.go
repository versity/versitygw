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

func ListObjectVersions_VD_success(s *S3Conf) error {
	testName := "ListObjectVersions_VD_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		versions := []types.ObjectVersion{}
		for i := range 5 {
			dLgth := int64(i * 100)
			key := fmt.Sprintf("my-obj-%v", i)
			out, err := putObjectWithData(dLgth, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &key,
			}, s3client)
			if err != nil {
				return err
			}

			versions = append(versions, types.ObjectVersion{
				ETag:         out.res.ETag,
				IsLatest:     getBoolPtr(true),
				Key:          &key,
				Size:         &dLgth,
				VersionId:    getPtr("null"),
				StorageClass: types.ObjectVersionStorageClassStandard,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareVersions(versions, res.Versions) {
			return fmt.Errorf("expected object versions output to be %v, instead got %v",
				versions, res.Versions)
		}
		return nil
	})
}

func ListObjectVersions_non_existing_bucket(s *S3Conf) error {
	testName := "ListObjectVersions_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: getPtr(getBucketName()),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func ListObjectVersions_negative_max_keys(s *S3Conf) error {
	testName := "ListObjectVersions_negative_max_keys"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket:  &bucket,
			MaxKeys: getPtr(int32(-123)),
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNegativeMaxKeys))
	}, withLock())
}

func ListObjectVersions_list_single_object_versions(s *S3Conf) error {
	testName := "ListObjectVersions_list_single_object_versions"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-obj"
		versions, err := createObjVersions(s3client, bucket, object, 5)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareVersions(versions, out.Versions) {
			return fmt.Errorf("expected the resulting versions to be %v, instead got %v",
				versions, out.Versions)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func ListObjectVersions_list_multiple_object_versions(s *S3Conf) error {
	testName := "ListObjectVersions_list_multiple_object_versions"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj1, obj2, obj3 := "foo", "bar", "baz"

		obj1Versions, err := createObjVersions(s3client, bucket, obj1, 4)
		if err != nil {
			return err
		}
		obj2Versions, err := createObjVersions(s3client, bucket, obj2, 3)
		if err != nil {
			return err
		}
		obj3Versions, err := createObjVersions(s3client, bucket, obj3, 5)
		if err != nil {
			return err
		}

		versions := append(append(obj2Versions, obj3Versions...), obj1Versions...)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareVersions(versions, out.Versions) {
			return fmt.Errorf("expected the resulting versions to be %v, instead got %v",
				versions, out.Versions)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func ListObjectVersions_multiple_object_versions_truncated(s *S3Conf) error {
	testName := "ListObjectVersions_multiple_object_versions_truncated"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj1, obj2, obj3 := "foo", "bar", "baz"

		obj1Versions, err := createObjVersions(s3client, bucket, obj1, 4)
		if err != nil {
			return err
		}
		obj2Versions, err := createObjVersions(s3client, bucket, obj2, 3)
		if err != nil {
			return err
		}
		obj3Versions, err := createObjVersions(s3client, bucket, obj3, 5)
		if err != nil {
			return err
		}

		versions := append(append(obj2Versions, obj3Versions...), obj1Versions...)
		maxKeys := int32(5)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket:  &bucket,
			MaxKeys: &maxKeys,
		})
		cancel()
		if err != nil {
			return err
		}

		if out.Name == nil {
			return fmt.Errorf("expected the bucket name to be %v, instead got nil",
				bucket)
		}
		if *out.Name != bucket {
			return fmt.Errorf("expected the bucket name to be %v, instead got %v",
				bucket, *out.Name)
		}
		if out.IsTruncated == nil || !*out.IsTruncated {
			return fmt.Errorf("expected the output to be truncated")
		}
		if out.MaxKeys == nil {
			return fmt.Errorf("expected the max-keys to be %v, instead got nil",
				maxKeys)
		}
		if *out.MaxKeys != maxKeys {
			return fmt.Errorf("expected the max-keys to be %v, instead got %v",
				maxKeys, *out.MaxKeys)
		}
		if getString(out.NextKeyMarker) != getString(versions[maxKeys-1].Key) {
			return fmt.Errorf("expected the NextKeyMarker to be %v, instead got %v",
				getString(versions[maxKeys-1].Key), getString(out.NextKeyMarker))
		}
		if getString(out.NextVersionIdMarker) != getString(versions[maxKeys-1].VersionId) {
			return fmt.Errorf("expected the NextVersionIdMarker to be %v, instead got %v",
				getString(versions[maxKeys-1].VersionId), getString(out.NextVersionIdMarker))
		}

		if !compareVersions(versions[:maxKeys], out.Versions) {
			return fmt.Errorf("expected the resulting object versions to be %v, instead got %v",
				sprintVersions(versions[:maxKeys]), sprintVersions(out.Versions))
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err = s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket:          &bucket,
			KeyMarker:       out.NextKeyMarker,
			VersionIdMarker: out.NextVersionIdMarker,
		})
		cancel()
		if err != nil {
			return err
		}

		if out.Name == nil {
			return fmt.Errorf("expected the bucket name to be %v, instead got nil",
				bucket)
		}
		if *out.Name != bucket {
			return fmt.Errorf("expected the bucket name to be %v, instead got %v",
				bucket, *out.Name)
		}
		if out.IsTruncated != nil && *out.IsTruncated {
			return fmt.Errorf("expected the output not to be truncated")
		}
		if getString(out.KeyMarker) != getString(versions[maxKeys-1].Key) {
			return fmt.Errorf("expected the KeyMarker to be %v, instead got %v",
				getString(versions[maxKeys-1].Key), getString(out.KeyMarker))
		}
		if getString(out.VersionIdMarker) != getString(versions[maxKeys-1].VersionId) {
			return fmt.Errorf("expected the VersionIdMarker to be %v, instead got %v",
				getString(versions[maxKeys-1].VersionId), getString(out.VersionIdMarker))
		}

		if !compareVersions(versions[maxKeys:], out.Versions) {
			return fmt.Errorf("expected the resulting object versions to be %v, instead got %v",
				sprintVersions(versions[:maxKeys]), sprintVersions(out.Versions))
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func ListObjectVersions_with_delete_markers(s *S3Conf) error {
	testName := "ListObjectVersions_with_delete_markers"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		versions, err := createObjVersions(s3client, bucket, obj, 1)
		if err != nil {
			return err
		}

		versions[0].IsLatest = getBoolPtr(false)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		delMarkers := []types.DeleteMarkerEntry{}
		delMarkers = append(delMarkers, types.DeleteMarkerEntry{
			Key:       &obj,
			VersionId: out.VersionId,
			IsLatest:  getBoolPtr(true),
		})

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareVersions(versions, res.Versions) {
			return fmt.Errorf("expected the resulting versions to be %v, instead got %v",
				versions, res.Versions)
		}
		if !compareDelMarkers(res.DeleteMarkers, delMarkers) {
			return fmt.Errorf("expected the resulting delete markers to be %v, instead got %v",
				delMarkers, res.DeleteMarkers)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func ListObjectVersions_containing_null_versionId_obj(s *S3Conf) error {
	testName := "ListObjectVersions_containing_null_versionId_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		versions, err := createObjVersions(s3client, bucket, obj, 3)
		if err != nil {
			return err
		}

		err = putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusSuspended)
		if err != nil {
			return err
		}

		objLgth := int64(543)
		out, err := putObjectWithData(objLgth, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		if getString(out.res.VersionId) != nullVersionId {
			return fmt.Errorf("expected the uploaded object versionId to be %v, instead got %v",
				nullVersionId, getString(out.res.VersionId))
		}

		versions[0].IsLatest = getBoolPtr(false)

		versions = append([]types.ObjectVersion{
			{
				ETag:         out.res.ETag,
				IsLatest:     getBoolPtr(false),
				Key:          &obj,
				Size:         &objLgth,
				VersionId:    &nullVersionId,
				StorageClass: types.ObjectVersionStorageClassStandard,
			},
		}, versions...)

		err = putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusEnabled)
		if err != nil {
			return err
		}

		newVersions, err := createObjVersions(s3client, bucket, obj, 4)
		if err != nil {
			return err
		}

		versions = append(newVersions, versions...)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareVersions(versions, res.Versions) {
			return fmt.Errorf("expected the listed object versions to be %v, instead got %v",
				versions, res.Versions)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func ListObjectVersions_single_null_versionId_object(s *S3Conf) error {
	testName := "ListObjectVersions_single_null_versionId_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, objLgth := "my-obj", int64(890)
		out, err := putObjectWithData(objLgth, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		err = putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusEnabled)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		versions := []types.ObjectVersion{
			{
				ETag:         out.res.ETag,
				Key:          &obj,
				StorageClass: types.ObjectVersionStorageClassStandard,
				IsLatest:     getBoolPtr(false),
				Size:         &objLgth,
				VersionId:    &nullVersionId,
			},
		}
		delMarkers := []types.DeleteMarkerEntry{
			{
				IsLatest:  getBoolPtr(true),
				Key:       &obj,
				VersionId: res.VersionId,
			},
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareDelMarkers(resp.DeleteMarkers, delMarkers) {
			return fmt.Errorf("expected the delete markers list to be %v, instaed got %v",
				delMarkers, resp.DeleteMarkers)
		}
		if !compareVersions(versions, resp.Versions) {
			return fmt.Errorf("expected the object versions list to be %v, instead got %v",
				versions, resp.Versions)
		}

		return nil
	})
}

func ListObjectVersions_checksum(s *S3Conf) error {
	testName := "ListObjectVersions_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		versions := []types.ObjectVersion{}
		for i, algo := range types.ChecksumAlgorithmCrc32.Values() {
			vers, err := createObjVersions(s3client, bucket, fmt.Sprintf("obj-%v", i), 1, withChecksumAlgo(algo))
			if err != nil {
				return err
			}

			versions = append(versions, vers...)
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareVersions(versions, res.Versions) {
			return fmt.Errorf("expected the versions to be %+v, instead got %+v",
				versions, res.Versions)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}
