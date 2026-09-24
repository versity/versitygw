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
		versions, dirVersions := []types.ObjectVersion{}, []types.ObjectVersion{}
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

			dir := fmt.Sprintf("my-dir-%v/", i)
			out, err = putObjectWithData(0, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &dir,
			}, s3client)
			if err != nil {
				return err
			}

			dirVersions = append(dirVersions, types.ObjectVersion{
				ETag:         out.res.ETag,
				IsLatest:     getBoolPtr(true),
				Key:          &dir,
				Size:         getPtr(int64(0)),
				VersionId:    getPtr("null"),
				StorageClass: types.ObjectVersionStorageClassStandard,
			})
		}

		// the directory objects are listed before the regular objects
		versions = append(dirVersions, versions...)

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
		return checkApiErr(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgNegativeMaxKeys, "-123"))
	}, withLock())
}

func ListObjectVersions_list_single_object_versions(s *S3Conf) error {
	testName := "ListObjectVersions_list_single_object_versions"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(object string) error {
			versions, err := createObjVersions(s3client, bucket, object, 5)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
				Bucket: &bucket,
				Prefix: &object,
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
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func ListObjectVersions_list_multiple_object_versions(s *S3Conf) error {
	testName := "ListObjectVersions_list_multiple_object_versions"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj1, obj2, obj3 := "foo", "bar", "baz"
		// "qux-quux" sorts before the directory object "qux/", which
		// sorts before the object under it
		dir, beforeDir, inDir := "qux/", "qux-quux", "qux/quux"

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
		// "qux/" is put over the existing parent directory of "qux/quux"
		inDirVersions, err := createObjVersions(s3client, bucket, inDir, 2)
		if err != nil {
			return err
		}
		dirVersions, err := createObjVersions(s3client, bucket, dir, 3)
		if err != nil {
			return err
		}
		beforeDirVersions, err := createObjVersions(s3client, bucket, beforeDir, 2)
		if err != nil {
			return err
		}

		versions := append(append(obj2Versions, obj3Versions...), obj1Versions...)
		versions = append(append(append(versions, beforeDirVersions...), dirVersions...), inDirVersions...)

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

func ListObjectVersions_dir_object_with_children(s *S3Conf) error {
	testName := "ListObjectVersions_dir_object_with_children"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, dir, child, nestedObj := "my-obj", "my-dir/", "my-dir/child", "my-dir/sub/obj"

		objVersions, err := createObjVersions(s3client, bucket, obj, 2)
		if err != nil {
			return err
		}
		dirVersions, err := createObjVersions(s3client, bucket, dir, 3)
		if err != nil {
			return err
		}
		childVersions, err := createObjVersions(s3client, bucket, child, 2)
		if err != nil {
			return err
		}
		nestedVersions, err := createObjVersions(s3client, bucket, nestedObj, 1)
		if err != nil {
			return err
		}

		// the objects under "my-dir/" stay listed after it's deleted
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &dir,
		})
		cancel()
		if err != nil {
			return err
		}

		dirVersions[0].IsLatest = getBoolPtr(false)
		delMarkers := []types.DeleteMarkerEntry{
			{
				IsLatest:  getBoolPtr(true),
				Key:       &dir,
				VersionId: res.VersionId,
			},
		}

		for i, test := range []struct {
			prefix     *string
			delimiter  *string
			versions   []types.ObjectVersion
			delMarkers []types.DeleteMarkerEntry
			prefixes   []string
		}{
			// "my-dir/" is rolled up into a common prefix
			{
				delimiter: getPtr("/"),
				versions:  objVersions,
				prefixes:  []string{dir},
			},
			// "my-dir/" itself and "my-dir/child" have no delimiter
			// after the prefix
			{
				prefix:     &dir,
				delimiter:  getPtr("/"),
				versions:   append(dirVersions, childVersions...),
				delMarkers: delMarkers,
				prefixes:   []string{"my-dir/sub/"},
			},
			// "my-dir/sub" isn't a directory object
			{
				prefix:     &dir,
				versions:   append(append(dirVersions, childVersions...), nestedVersions...),
				delMarkers: delMarkers,
			},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
				Bucket:    &bucket,
				Prefix:    test.prefix,
				Delimiter: test.delimiter,
			})
			cancel()
			if err != nil {
				return fmt.Errorf("test case %d failed: %w", i, err)
			}

			if !compareVersions(test.versions, out.Versions) {
				return fmt.Errorf("test case %d failed: expected the versions to be %v, instead got %v",
					i, sprintVersions(test.versions), sprintVersions(out.Versions))
			}
			if !compareDelMarkers(test.delMarkers, out.DeleteMarkers) {
				return fmt.Errorf("test case %d failed: expected the delete markers to be %v, instead got %v",
					i, test.delMarkers, out.DeleteMarkers)
			}
			if !comparePrefixes(test.prefixes, out.CommonPrefixes) {
				return fmt.Errorf("test case %d failed: expected the common prefixes to be %v, instead got %v",
					i, test.prefixes, sprintPrefixes(out.CommonPrefixes))
			}
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func ListObjectVersions_multiple_object_versions_truncated(s *S3Conf) error {
	testName := "ListObjectVersions_multiple_object_versions_truncated"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj1, obj2, obj3, dir, child := "foo", "bar", "baz", "dir/", "dir/child"

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
		dirVersions, err := createObjVersions(s3client, bucket, dir, 4)
		if err != nil {
			return err
		}
		childVersions, err := createObjVersions(s3client, bucket, child, 3)
		if err != nil {
			return err
		}

		versions := append(append(obj2Versions, obj3Versions...), dirVersions...)
		versions = append(append(versions, childVersions...), obj1Versions...)
		maxKeys := int32(5)

		// the pages end on noncurrent versions of "baz", "dir/" and "dir/child"
		var keyMarker, versionIdMarker *string
		for page := 0; page*int(maxKeys) < len(versions); page++ {
			start := page * int(maxKeys)
			end := min(start+int(maxKeys), len(versions))
			truncated := end < len(versions)

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
				Bucket:          &bucket,
				MaxKeys:         &maxKeys,
				KeyMarker:       keyMarker,
				VersionIdMarker: versionIdMarker,
			})
			cancel()
			if err != nil {
				return fmt.Errorf("page %v: %w", page, err)
			}

			if out.Name == nil {
				return fmt.Errorf("page %v: expected the bucket name to be %v, instead got nil",
					page, bucket)
			}
			if *out.Name != bucket {
				return fmt.Errorf("page %v: expected the bucket name to be %v, instead got %v",
					page, bucket, *out.Name)
			}
			isTruncated := out.IsTruncated != nil && *out.IsTruncated
			if isTruncated != truncated {
				return fmt.Errorf("page %v: expected the output truncation to be %v, instead got %v",
					page, truncated, isTruncated)
			}
			if out.MaxKeys == nil {
				return fmt.Errorf("page %v: expected the max-keys to be %v, instead got nil",
					page, maxKeys)
			}
			if *out.MaxKeys != maxKeys {
				return fmt.Errorf("page %v: expected the max-keys to be %v, instead got %v",
					page, maxKeys, *out.MaxKeys)
			}
			if getString(out.KeyMarker) != getString(keyMarker) {
				return fmt.Errorf("page %v: expected the KeyMarker to be %v, instead got %v",
					page, getString(keyMarker), getString(out.KeyMarker))
			}
			if getString(out.VersionIdMarker) != getString(versionIdMarker) {
				return fmt.Errorf("page %v: expected the VersionIdMarker to be %v, instead got %v",
					page, getString(versionIdMarker), getString(out.VersionIdMarker))
			}
			if truncated {
				last := versions[end-1]
				if getString(out.NextKeyMarker) != getString(last.Key) {
					return fmt.Errorf("page %v: expected the NextKeyMarker to be %v, instead got %v",
						page, getString(last.Key), getString(out.NextKeyMarker))
				}
				if getString(out.NextVersionIdMarker) != getString(last.VersionId) {
					return fmt.Errorf("page %v: expected the NextVersionIdMarker to be %v, instead got %v",
						page, getString(last.VersionId), getString(out.NextVersionIdMarker))
				}
			}

			if !compareVersions(versions[start:end], out.Versions) {
				return fmt.Errorf("page %v: expected the resulting object versions to be %v, instead got %v",
					page, sprintVersions(versions[start:end]), sprintVersions(out.Versions))
			}

			keyMarker, versionIdMarker = out.NextKeyMarker, out.NextVersionIdMarker
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func ListObjectVersions_with_delete_markers(s *S3Conf) error {
	testName := "ListObjectVersions_with_delete_markers"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
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
				Prefix: &obj,
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
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func ListObjectVersions_containing_null_versionId_obj(s *S3Conf) error {
	testName := "ListObjectVersions_containing_null_versionId_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			versions, err := createObjVersions(s3client, bucket, obj, 3)
			if err != nil {
				return err
			}

			err = putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusSuspended)
			if err != nil {
				return err
			}

			objLgth := objDataLen(obj, 543)
			out, err := putObjectWithData(objLgth, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}

			if out.res.VersionId != nil {
				return fmt.Errorf("expected PutObject response to omit versionId, instead got %v",
					getString(out.res.VersionId))
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
				Prefix: &obj,
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
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func ListObjectVersions_single_null_versionId_object(s *S3Conf) error {
	testName := "ListObjectVersions_single_null_versionId_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		// the objects are put before versioning is enabled and are
		// listed in this order
		objs, objLgth := []string{"my-dir/", "my-obj"}, int64(890)
		versions := []types.ObjectVersion{}
		for _, obj := range objs {
			size := objDataLen(obj, objLgth)
			out, err := putObjectWithData(size, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}

			versions = append(versions, types.ObjectVersion{
				ETag:         out.res.ETag,
				Key:          &obj,
				StorageClass: types.ObjectVersionStorageClassStandard,
				IsLatest:     getBoolPtr(false),
				Size:         &size,
				VersionId:    &nullVersionId,
			})
		}

		err := putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusEnabled)
		if err != nil {
			return err
		}

		delMarkers := []types.DeleteMarkerEntry{}
		for _, obj := range objs {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			delMarkers = append(delMarkers, types.DeleteMarkerEntry{
				IsLatest:  getBoolPtr(true),
				Key:       &obj,
				VersionId: res.VersionId,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
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

func ListObjectVersions_paginate_null_version(s *S3Conf) error {
	testName := "ListObjectVersions_paginate_null_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		// the null version sits in the middle of the version history:
		// it's an object for "a-obj" and "c-dir/" and a delete marker
		// for "b-obj"
		objs := []string{"a-obj", "b-obj", "c-dir/"}
		oldVersions := map[string][]types.ObjectVersion{}
		for _, obj := range objs {
			versions, err := createObjVersions(s3client, bucket, obj, 2)
			if err != nil {
				return err
			}
			versions[0].IsLatest = getBoolPtr(false)
			oldVersions[obj] = versions
		}

		err := putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusSuspended)
		if err != nil {
			return err
		}

		nullVersions := map[string][]types.ObjectVersion{}
		for _, obj := range []string{"a-obj", "c-dir/"} {
			size := objDataLen(obj, 100)
			out, err := putObjectWithData(size, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}
			nullVersions[obj] = []types.ObjectVersion{
				{
					ETag:         out.res.ETag,
					IsLatest:     getBoolPtr(false),
					Key:          &obj,
					Size:         &size,
					VersionId:    &nullVersionId,
					StorageClass: types.ObjectVersionStorageClassStandard,
				},
			}
		}

		delMarkerObj := "b-obj"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &delMarkerObj,
		})
		cancel()
		if err != nil {
			return err
		}
		delMarkers := []types.DeleteMarkerEntry{
			{
				Key:       &delMarkerObj,
				VersionId: &nullVersionId,
				IsLatest:  getBoolPtr(false),
			},
		}

		err = putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusEnabled)
		if err != nil {
			return err
		}

		versions := []types.ObjectVersion{}
		for _, obj := range objs {
			newVersions, err := createObjVersions(s3client, bucket, obj, 2)
			if err != nil {
				return err
			}
			versions = append(versions, newVersions...)
			versions = append(versions, nullVersions[obj]...)
			versions = append(versions, oldVersions[obj]...)
		}

		// the pages end on each of the versions, the null ones included,
		// and each version is listed once
		total := len(versions) + len(delMarkers)
		for _, maxKeys := range []int32{1, 2, 3, 4, 1000} {
			var gotVersions []types.ObjectVersion
			var gotDelMarkers []types.DeleteMarkerEntry
			var keyMarker, versionIdMarker *string
			for page := 0; ; page++ {
				if page > total {
					return fmt.Errorf("max-keys %v: expected the listing to end within %v pages",
						maxKeys, total)
				}

				ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
				out, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
					Bucket:          &bucket,
					MaxKeys:         &maxKeys,
					KeyMarker:       keyMarker,
					VersionIdMarker: versionIdMarker,
				})
				cancel()
				if err != nil {
					return fmt.Errorf("max-keys %v, page %v: %w", maxKeys, page, err)
				}

				if count := len(out.Versions) + len(out.DeleteMarkers); count > int(maxKeys) {
					return fmt.Errorf("max-keys %v, page %v: expected at most %v entries, instead got %v",
						maxKeys, page, maxKeys, count)
				}
				gotVersions = append(gotVersions, out.Versions...)
				gotDelMarkers = append(gotDelMarkers, out.DeleteMarkers...)

				if out.IsTruncated == nil || !*out.IsTruncated {
					break
				}
				keyMarker, versionIdMarker = out.NextKeyMarker, out.NextVersionIdMarker
			}

			if !compareVersions(versions, gotVersions) {
				return fmt.Errorf("max-keys %v: expected the listed object versions to be %v, instead got %v",
					maxKeys, sprintVersions(versions), sprintVersions(gotVersions))
			}
			if !compareDelMarkers(delMarkers, gotDelMarkers) {
				return fmt.Errorf("max-keys %v: expected the listed delete markers to be %v, instead got %v",
					maxKeys, delMarkers, gotDelMarkers)
			}
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func ListObjectVersions_checksum(s *S3Conf) error {
	testName := "ListObjectVersions_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		versions, dirVersions := []types.ObjectVersion{}, []types.ObjectVersion{}
		for i, algo := range types.ChecksumAlgorithmCrc32.Values() {
			vers, err := createObjVersions(s3client, bucket, fmt.Sprintf("obj-%v", i), 1, withChecksumAlgo(algo))
			if err != nil {
				return err
			}

			versions = append(versions, vers...)

			vers, err = createObjVersions(s3client, bucket, fmt.Sprintf("dir-%v/", i), 1, withChecksumAlgo(algo))
			if err != nil {
				return err
			}

			dirVersions = append(dirVersions, vers...)
		}

		// the directory objects are listed before the regular objects
		versions = append(dirVersions, versions...)

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
