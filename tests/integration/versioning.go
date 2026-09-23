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
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

func Versioning_DeleteBucket_not_empty(s *S3Conf) error {
	testName := "Versioning_DeleteBucket_not_empty"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			versions, err := createObjVersions(s3client, bucket, obj, 2)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.DeleteBucket(ctx, &s3.DeleteBucketInput{
				Bucket: &bucket,
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrVersionedBucketNotEmpty)); err != nil {
				return err
			}

			// delete the key versions, so that the next key
			// is the only one in the bucket
			for _, version := range versions {
				ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
				_, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
					Bucket:    &bucket,
					Key:       &obj,
					VersionId: version.VersionId,
				})
				cancel()
				if err != nil {
					return err
				}
			}

			return nil
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_PutObject_suspended_null_versionId_obj(s *S3Conf) error {
	testName := "Versioning_PutObject_suspended_null_versionId_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			out, err := putObjectWithData(objDataLen(obj, 1222), &s3.PutObjectInput{
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

			return nil
		})
	}, withVersioning(types.BucketVersioningStatusSuspended))
}

func Versioning_PutObject_null_versionId_obj(s *S3Conf) error {
	testName := "Versioning_PutObject_null_versionId_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		keys := []string{"my-obj", "my-dir/"}
		nullVersions := map[string]types.ObjectVersion{}
		err := forEachKey(keys, func(obj string) error {
			lgth := objDataLen(obj, 1234)
			out, err := putObjectWithData(lgth, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}

			nullVersions[obj] = types.ObjectVersion{
				ETag:         out.res.ETag,
				IsLatest:     getBoolPtr(false),
				Key:          &obj,
				Size:         &lgth,
				VersionId:    &nullVersionId,
				StorageClass: types.ObjectVersionStorageClassStandard,
			}
			return nil
		})
		if err != nil {
			return err
		}

		// Enable bucket versioning
		err = putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusEnabled)
		if err != nil {
			return err
		}

		return forEachKey(keys, func(obj string) error {
			versions, err := createObjVersions(s3client, bucket, obj, 4)
			if err != nil {
				return err
			}

			versions = append(versions, nullVersions[obj])

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
				return fmt.Errorf("expected the listed versions to be %v, instead got %v",
					versions, res.Versions)
			}

			return nil
		})
	})
}

func Versioning_PutObject_overwrite_null_versionId_obj(s *S3Conf) error {
	testName := "Versioning_PutObject_overwrite_null_versionId_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		keys := []string{"my-obj", "my-dir/"}
		err := forEachKey(keys, func(obj string) error {
			_, err := putObjectWithData(objDataLen(obj, 1233), &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			return err
		})
		if err != nil {
			return err
		}

		// Enable bucket versioning
		err = putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusEnabled)
		if err != nil {
			return err
		}

		objVersions := map[string][]types.ObjectVersion{}
		err = forEachKey(keys, func(obj string) error {
			versions, err := createObjVersions(s3client, bucket, obj, 4)
			if err != nil {
				return err
			}

			objVersions[obj] = versions
			return nil
		})
		if err != nil {
			return err
		}

		// Set bucket versioning status to Suspended
		err = putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusSuspended)
		if err != nil {
			return err
		}

		return forEachKey(keys, func(obj string) error {
			lgth := objDataLen(obj, 3200)
			out, err := putObjectWithData(lgth, &s3.PutObjectInput{
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

			versions := objVersions[obj]
			versions[0].IsLatest = getBoolPtr(false)

			versions = append([]types.ObjectVersion{
				{
					ETag:         out.res.ETag,
					IsLatest:     getBoolPtr(true),
					Key:          &obj,
					Size:         &lgth,
					VersionId:    &nullVersionId,
					StorageClass: types.ObjectVersionStorageClassStandard,
					ChecksumType: out.res.ChecksumType,
				},
			}, versions...)

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
				return fmt.Errorf("expected the listed versions to be %v, instead got %v",
					versions, res.Versions)
			}

			return nil
		})
	})
}

func Versioning_PutObject_success(s *S3Conf) error {
	testName := "Versioning_PutObject_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.PutObject(ctx, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			if res.VersionId == nil || *res.VersionId == "" {
				return fmt.Errorf("expected the versionId to be returned")
			}

			return nil
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_PutObject_dir_object_new_version_resets_attributes(s *S3Conf) error {
	testName := "Versioning_PutObject_dir_object_new_version_resets_attributes"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-dir/"
		tags := []types.Tag{
			{Key: getPtr("key1"), Value: getPtr("val1")},
			{Key: getPtr("key2"), Value: getPtr("val2")},
		}
		meta := map[string]string{
			"foo": "bar",
			"baz": "quxx",
		}
		redirect := "/some/redirect"

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		first, err := s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:                  &bucket,
			Key:                     &obj,
			Tagging:                 getPtr("key1=val1&key2=val2"),
			Metadata:                meta,
			WebsiteRedirectLocation: &redirect,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		second, err := s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		if getString(first.VersionId) == "" || getString(second.VersionId) == "" {
			return fmt.Errorf("expected non empty versionIds, instead got %q and %q",
				getString(first.VersionId), getString(second.VersionId))
		}
		if *first.VersionId == *second.VersionId {
			return fmt.Errorf("expected a new versionId, instead got %v twice", *first.VersionId)
		}

		// the current version holds none of the first version attributes
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		cur, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		if getString(cur.VersionId) != *second.VersionId {
			return fmt.Errorf("expected the current versionId to be %v, instead got %v",
				*second.VersionId, getString(cur.VersionId))
		}
		if len(cur.Metadata) != 0 {
			return fmt.Errorf("expected empty metadata, instead got %v", cur.Metadata)
		}
		if cur.WebsiteRedirectLocation != nil {
			return fmt.Errorf("expected nil website-redirect-location, instead got %v",
				*cur.WebsiteRedirectLocation)
		}
		if cur.TagCount != nil {
			return fmt.Errorf("expected nil tag count, instead got %v", *cur.TagCount)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		curTags, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		if len(curTags.TagSet) != 0 {
			return fmt.Errorf("expected empty tag set, instead got %v", curTags.TagSet)
		}

		// the first version keeps its attributes
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		old, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: first.VersionId,
		})
		cancel()
		if err != nil {
			return err
		}

		if getString(old.VersionId) != *first.VersionId {
			return fmt.Errorf("expected the versionId to be %v, instead got %v",
				*first.VersionId, getString(old.VersionId))
		}
		if old.ContentLength == nil {
			return fmt.Errorf("expected non nil ContentLength")
		}
		if *old.ContentLength != 0 {
			return fmt.Errorf("expected zero content-length, instead got %v",
				*old.ContentLength)
		}
		if getString(old.ContentType) != directoryContentType {
			return fmt.Errorf("expected the content-type to be %v, instead got %v",
				directoryContentType, getString(old.ContentType))
		}
		if !areMapsSame(meta, old.Metadata) {
			return fmt.Errorf("expected the metadata to be %v, instead got %v",
				meta, old.Metadata)
		}
		if getString(old.WebsiteRedirectLocation) != redirect {
			return fmt.Errorf("expected the website-redirect-location to be %v, instead got %v",
				redirect, getString(old.WebsiteRedirectLocation))
		}
		if old.TagCount == nil {
			return fmt.Errorf("expected non nil TagCount")
		}
		if *old.TagCount != int32(len(tags)) {
			return fmt.Errorf("expected the tag count to be %v, instead got %v",
				len(tags), *old.TagCount)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		oldTags, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: first.VersionId,
		})
		cancel()
		if err != nil {
			return err
		}

		if !areTagsSame(tags, oldTags.TagSet) {
			return fmt.Errorf("expected the tag set to be %v, instead got %v",
				tags, oldTags.TagSet)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_CopyObject_invalid_versionId(s *S3Conf) error {
	testName := "Versioning_CopyObject_invalid_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dstObj, srcObj := "dst-obj", "src-obj"

		srcObjLen := int64(2345)
		_, err := putObjectWithData(srcObjLen, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        &dstObj,
			CopySource: getPtr(fmt.Sprintf("%v/%v?versionId=invalid_versionId", bucket, srcObj)),
		})
		cancel()
		return checkApiErr(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgVersionId, "invalid_versionId"))
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_CopyObject_encoded_versionid_separator_invalid_versionId(s *S3Conf) error {
	testName := "Versioning_CopyObject_encoded_versionid_separator_invalid_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dstObj, srcObj := "dst-obj", "src-obj"

		srcObjLen := int64(2345)
		_, err := putObjectWithData(srcObjLen, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        &dstObj,
			CopySource: getPtr(fmt.Sprintf("%v/%v%%3FversionId%%3D..%%2f..%%2fsecret.txt", bucket, srcObj)),
		})
		cancel()
		return checkApiErr(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgVersionId, "../../secret.txt"))
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_CopyObject_success(s *S3Conf) error {
	testName := "Versioning_CopyObject_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcBucket := getBucketName()
		if err := setup(s, srcBucket); err != nil {
			return err
		}

		srcObjLens := map[string]int64{
			"src-obj":  2345,
			"src-dir/": 0,
		}
		for srcObj, srcObjLen := range srcObjLens {
			_, err := putObjectWithData(srcObjLen, &s3.PutObjectInput{
				Bucket: &srcBucket,
				Key:    &srcObj,
			}, s3client)
			if err != nil {
				return err
			}
		}

		// destination object -> source object
		srcObjs := map[string]string{
			"dst-obj":  "src-obj",
			"dst-dir/": "src-dir/",
			"dst-file": "src-dir/",
		}
		err := forEachKey([]string{"dst-obj", "dst-dir/", "dst-file"}, func(dstObj string) error {
			srcObj := srcObjs[dstObj]
			dstObjVersions, err := createObjVersions(s3client, bucket, dstObj, 1)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
				Bucket:     &bucket,
				Key:        &dstObj,
				CopySource: getPtr(fmt.Sprintf("%v/%v", srcBucket, srcObj)),
			})
			cancel()
			if err != nil {
				return err
			}

			if out.VersionId == nil || *out.VersionId == "" {
				return fmt.Errorf("expected non empty versionId in the result")
			}

			srcObjLen := srcObjLens[srcObj]
			dstObjVersions[0].IsLatest = getBoolPtr(false)
			versions := append([]types.ObjectVersion{
				{
					ETag:         out.CopyObjectResult.ETag,
					IsLatest:     getBoolPtr(true),
					Key:          &dstObj,
					Size:         &srcObjLen,
					VersionId:    out.VersionId,
					StorageClass: types.ObjectVersionStorageClassStandard,
					ChecksumType: out.CopyObjectResult.ChecksumType,
				},
			}, dstObjVersions...)

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
				Bucket: &bucket,
				Prefix: &dstObj,
			})
			cancel()
			if err != nil {
				return err
			}

			if !compareVersions(versions, res.Versions) {
				return fmt.Errorf("expected the resulting versions to be %v, instead got %v",
					versions, res.Versions)
			}

			return nil
		})
		if err != nil {
			return err
		}

		return teardown(s, srcBucket)
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_CopyObject_non_existing_version_id(s *S3Conf) error {
	testName := "Versioning_CopyObject_non_existing_version_id"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dstBucket := getBucketName()
		if err := setup(s, dstBucket); err != nil {
			return err
		}

		err := forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			_, err := createObjVersions(s3client, bucket, obj, 1)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
				Bucket: &dstBucket,
				Key:    &obj,
				CopySource: getPtr(fmt.Sprintf("%v/%v?versionId=01BX5ZZKBKACTAV9WEVGEMMVRZ",
					bucket, obj)),
			})
			cancel()
			return checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchVersion))
		})
		if err != nil {
			return err
		}

		if err := teardown(s, dstBucket); err != nil {
			return err
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_CopyObject_from_an_object_version(s *S3Conf) error {
	testName := "Versioning_CopyObject_from_an_object_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcBucket := getBucketName()
		if err := setup(s, srcBucket, withVersioning(types.BucketVersioningStatusEnabled)); err != nil {
			return err
		}

		// copy the noncurrent and then the current source object version
		dstObjs := map[string]string{
			"my-obj":  "my-dst-obj",
			"my-dir/": "my-dst-dir/",
		}
		err := forEachKey([]string{"my-obj", "my-dir/"}, func(srcObj string) error {
			dstObj := dstObjs[srcObj]
			srcObjVersions, err := createObjVersions(s3client, srcBucket, srcObj, 2)
			if err != nil {
				return err
			}

			for _, srcObjVersion := range reverseSlice(srcObjVersions) {
				ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
				out, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
					Bucket:     &bucket,
					Key:        &dstObj,
					CopySource: getPtr(fmt.Sprintf("%v/%v?versionId=%v", srcBucket, srcObj, *srcObjVersion.VersionId)),
				})
				cancel()
				if err != nil {
					return err
				}

				if out.VersionId == nil || *out.VersionId == "" {
					return fmt.Errorf("expected non empty versionId")
				}
				if out.CopySourceVersionId == nil {
					return fmt.Errorf("expected non nil CopySourceVersionId")
				}
				if *out.CopySourceVersionId != *srcObjVersion.VersionId {
					return fmt.Errorf("expected the SourceVersionId to be %v, instead got %v",
						*srcObjVersion.VersionId, *out.CopySourceVersionId)
				}

				ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
				res, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
					Bucket:    &bucket,
					Key:       &dstObj,
					VersionId: out.VersionId,
				})
				cancel()
				if err != nil {
					return err
				}

				if res.ContentLength == nil {
					return fmt.Errorf("expected non nil ContentLength")
				}
				if res.VersionId == nil {
					return fmt.Errorf("expected non nil VersionId")
				}
				if *res.ContentLength != *srcObjVersion.Size {
					return fmt.Errorf("expected the copied object size to be %v, instead got %v",
						*srcObjVersion.Size, *res.ContentLength)
				}
				if *res.VersionId != *out.VersionId {
					return fmt.Errorf("expected the copied object versionId to be %v, instead got %v",
						*out.VersionId, *res.VersionId)
				}
			}

			return nil
		})
		if err != nil {
			return err
		}

		return teardown(s, srcBucket)
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

// A copy source that resolves to a delete marker is rejected: the key has no
// current version when the marker is the latest, and naming the marker by
// version id is an invalid request. Versions the marker hides stay copyable.
func Versioning_CopyObject_from_a_delete_marker(s *S3Conf) error {
	testName := "Versioning_CopyObject_from_a_delete_marker"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dstBucket, dstObj := getBucketName(), "dst-obj"
		if err := setup(s, dstBucket); err != nil {
			return err
		}

		err := forEachKey([]string{"my-obj", "my-dir/"}, func(srcObj string) error {
			srcObjVersions, err := createObjVersions(s3client, bucket, srcObj, 1)
			if err != nil {
				return err
			}

			delMarker, err := createDeleteMarker(s3client, bucket, srcObj)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
				Bucket:     &dstBucket,
				Key:        &dstObj,
				CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchKey)); err != nil {
				return err
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
				Bucket: &dstBucket,
				Key:    &dstObj,
				CopySource: getPtr(fmt.Sprintf("%v/%v?versionId=%v",
					bucket, srcObj, delMarker)),
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrCopySourceDeleteMarker)); err != nil {
				return err
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
				Bucket: &dstBucket,
				Key:    &dstObj,
				CopySource: getPtr(fmt.Sprintf("%v/%v?versionId=%v",
					bucket, srcObj, getString(srcObjVersions[0].VersionId))),
			})
			cancel()
			if err != nil {
				return err
			}

			if getString(out.CopySourceVersionId) != getString(srcObjVersions[0].VersionId) {
				return fmt.Errorf("expected the copy-source-version-id to be %v, instead got %v",
					getString(srcObjVersions[0].VersionId), getString(out.CopySourceVersionId))
			}

			return nil
		})
		if err != nil {
			return err
		}

		return teardown(s, dstBucket)
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

// A copy of an object onto itself in a versioned bucket is an ordinary
// write: it creates a new version and leaves the one it replaces untouched.
// Without a metadata directive there is nothing to replace, so it's rejected.
func Versioning_CopyObject_to_itself(s *S3Conf) error {
	testName := "Versioning_CopyObject_to_itself"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			// directory objects always carry the directory content-type
			srcContentType, dstContentType := "text/plain", "application/json"
			if strings.HasSuffix(obj, "/") {
				srcContentType, dstContentType = directoryContentType, directoryContentType
			}

			srcMeta := map[string]string{"key": "value"}
			r, err := putObjectWithData(objDataLen(obj, 1234), &s3.PutObjectInput{
				Bucket:      &bucket,
				Key:         &obj,
				ContentType: getPtr("text/plain"),
				Metadata:    srcMeta,
			}, s3client)
			if err != nil {
				return err
			}

			srcVersionId := getString(r.res.VersionId)

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
				Bucket:     &bucket,
				Key:        &obj,
				CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, obj)),
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidCopyDest)); err != nil {
				return err
			}

			dstMeta := map[string]string{"new-key": "new-value"}
			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
				Bucket:            &bucket,
				Key:               &obj,
				CopySource:        getPtr(fmt.Sprintf("%v/%v", bucket, obj)),
				MetadataDirective: types.MetadataDirectiveReplace,
				ContentType:       getPtr("application/json"),
				Metadata:          dstMeta,
			})
			cancel()
			if err != nil {
				return err
			}

			dstVersionId := getString(out.VersionId)
			if dstVersionId == "" {
				return fmt.Errorf("expected non empty versionId")
			}
			if dstVersionId == srcVersionId {
				return fmt.Errorf("expected a new versionId, instead got %v", dstVersionId)
			}

			// the replaced version keeps its own metadata
			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: &srcVersionId,
			})
			cancel()
			if err != nil {
				return err
			}

			if getString(res.ContentType) != srcContentType {
				return fmt.Errorf("expected the source version content-type to be %v, instead got %v",
					srcContentType, getString(res.ContentType))
			}
			if !areMapsSame(res.Metadata, srcMeta) {
				return fmt.Errorf("expected the source version metadata to be %v, instead got %v",
					srcMeta, res.Metadata)
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			res, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			if getString(res.VersionId) != dstVersionId {
				return fmt.Errorf("expected the current versionId to be %v, instead got %v",
					dstVersionId, getString(res.VersionId))
			}
			if getString(res.ContentType) != dstContentType {
				return fmt.Errorf("expected the new version content-type to be %v, instead got %v",
					dstContentType, getString(res.ContentType))
			}
			if !areMapsSame(res.Metadata, dstMeta) {
				return fmt.Errorf("expected the new version metadata to be %v, instead got %v",
					dstMeta, res.Metadata)
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			vRes, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
				Bucket: &bucket,
				Prefix: &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			if len(vRes.Versions) != 2 {
				return fmt.Errorf("expected 2 object versions, instead got %v", len(vRes.Versions))
			}

			return nil
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

// Naming the current version in the copy source makes a copy onto the same
// key a regular copy, so it is accepted even without a metadata directive.
func Versioning_CopyObject_to_itself_from_the_current_version(s *S3Conf) error {
	testName := "Versioning_CopyObject_to_itself_from_the_current_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			versions, err := createObjVersions(s3client, bucket, obj, 1)
			if err != nil {
				return err
			}

			srcVersionId := getString(versions[0].VersionId)

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
				Bucket:     &bucket,
				Key:        &obj,
				CopySource: getPtr(fmt.Sprintf("%v/%v?versionId=%v", bucket, obj, srcVersionId)),
			})
			cancel()
			if err != nil {
				return err
			}

			if getString(out.CopySourceVersionId) != srcVersionId {
				return fmt.Errorf("expected the copy-source-version-id to be %v, instead got %v",
					srcVersionId, getString(out.CopySourceVersionId))
			}
			if getString(out.VersionId) == srcVersionId {
				return fmt.Errorf("expected a new versionId, instead got %v", getString(out.VersionId))
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: &srcVersionId,
			})
			cancel()
			if err != nil {
				return err
			}

			if getString(res.VersionId) != srcVersionId {
				return fmt.Errorf("expected the source version to remain, instead got %v",
					getString(res.VersionId))
			}

			return nil
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_CopyObject_special_chars(s *S3Conf) error {
	testName := "Versioning_CopyObject_special_chars"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dstBucket := getBucketName()
		err := setup(s, dstBucket)
		if err != nil {
			return err
		}

		// source object -> destination object
		dstObjs := map[string]string{
			"foo?bar":  "bar&foo",
			"baz?dir/": "dir&baz/",
		}
		err = forEachKey([]string{"foo?bar", "baz?dir/"}, func(srcObj string) error {
			dstObj := dstObjs[srcObj]
			srcObjVersions, err := createObjVersions(s3client, bucket, srcObj, 1)
			if err != nil {
				return err
			}

			srcObjVersionId := *srcObjVersions[0].VersionId
			copySource := fmt.Sprintf("%v/%v?versionId=%v",
				bucket,
				url.PathEscape(srcObj),
				url.QueryEscape(srcObjVersionId),
			)

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
				Bucket:     &bucket,
				Key:        &dstObj,
				CopySource: getPtr(copySource),
			})
			cancel()
			if err != nil {
				return err
			}

			if res.VersionId == nil || *res.VersionId == "" {
				return fmt.Errorf("expected non empty versionId")
			}
			if res.CopySourceVersionId == nil {
				return fmt.Errorf("expected non nil CopySourceVersionId")
			}
			if *res.CopySourceVersionId != srcObjVersionId {
				return fmt.Errorf("expected the SourceVersionId to be %v, instead got %v",
					srcObjVersionId, *res.CopySourceVersionId)
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket:    &bucket,
				Key:       &dstObj,
				VersionId: res.VersionId,
			})
			cancel()
			if err != nil {
				return err
			}

			if out.VersionId == nil {
				return fmt.Errorf("expected non nil VersionId")
			}
			if *out.VersionId != *res.VersionId {
				return fmt.Errorf("expected the copied object versionId to be %v, instead got %v",
					*res.VersionId, *out.VersionId)
			}

			return nil
		})
		if err != nil {
			return err
		}

		err = teardown(s, dstBucket)
		if err != nil {
			return err
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_HeadObject_invalid_versionId(s *S3Conf) error {
	testName := "Versioning_HeadObject_invalid_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: getPtr("invalid_versionId"),
		})
		cancel()
		if err := checkSdkApiErr(err, "BadRequest"); err != nil {
			return err
		}
		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_HeadObject_non_existing_object_version(s *S3Conf) error {
	testName := "Versioning_HeadObject_non_existing_object_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			dLen := objDataLen(obj, 2000)
			_, err := putObjectWithData(dLen, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: getPtr("01G65Z755AFWAKHE12NY0CQ9FH"),
			})
			cancel()
			if err := checkSdkApiErr(err, "NotFound"); err != nil {
				return err
			}
			return nil
		})
	})
}

func Versioning_HeadObject_invalid_parent(s *S3Conf) error {
	testName := "Versioning_HeadObject_invalid_parent"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dLen := int64(2000)
		obj := "not-a-dir"
		r, err := putObjectWithData(dLen, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		return forEachKey([]string{"not-a-dir/bad-obj", "not-a-dir/bad-dir/"}, func(obj string) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: r.res.VersionId,
			})
			cancel()
			if err := checkSdkApiErr(err, "NotFound"); err != nil {
				return err
			}
			return nil
		})
	})
}

func Versioning_HeadObject_success(s *S3Conf) error {
	testName := "Versioning_HeadObject_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			dLen := objDataLen(obj, 2000)
			r, err := putObjectWithData(dLen, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: r.res.VersionId,
			})
			cancel()
			if err != nil {
				return err
			}

			if out.ContentLength == nil {
				return fmt.Errorf("expected non nil ContentLength")
			}
			if out.VersionId == nil {
				return fmt.Errorf("expected non nil VersionId")
			}
			if *out.ContentLength != dLen {
				return fmt.Errorf("expected the object content-length to be %v, instead got %v",
					dLen, *out.ContentLength)
			}
			if *out.VersionId != *r.res.VersionId {
				return fmt.Errorf("expected the versionId to be %v, instead got %v",
					*r.res.VersionId, *out.VersionId)
			}
			if strings.HasSuffix(obj, "/") && getString(out.ContentType) != directoryContentType {
				return fmt.Errorf("expected the content type to be %v, instead got %v",
					directoryContentType, getString(out.ContentType))
			}

			return nil
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_HeadObject_dir_object_versions(s *S3Conf) error {
	testName := "Versioning_HeadObject_dir_object_versions"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-dir/"

		type dirVersion struct {
			versionId *string
			metadata  map[string]string
		}

		// each version gets its own metadata key
		versions := []dirVersion{}
		for i := range 3 {
			metadata := map[string]string{
				fmt.Sprintf("key%v", i): fmt.Sprintf("value%v", i),
			}
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.PutObject(ctx, &s3.PutObjectInput{
				Bucket:   &bucket,
				Key:      &obj,
				Metadata: metadata,
			})
			cancel()
			if err != nil {
				return err
			}
			if getString(res.VersionId) == "" {
				return fmt.Errorf("expected non empty versionId")
			}

			versions = append(versions, dirVersion{
				versionId: res.VersionId,
				metadata:  metadata,
			})
		}

		checkVersion := func(v dirVersion, contentLength *int64, contentType, versionId *string, metadata map[string]string) error {
			if contentLength == nil {
				return fmt.Errorf("expected non nil ContentLength")
			}
			if *contentLength != 0 {
				return fmt.Errorf("expected the object content-length to be 0, instead got %v",
					*contentLength)
			}
			if getString(contentType) != directoryContentType {
				return fmt.Errorf("expected the content type to be %v, instead got %v",
					directoryContentType, getString(contentType))
			}
			if getString(versionId) != *v.versionId {
				return fmt.Errorf("expected the versionId to be %v, instead got %v",
					*v.versionId, getString(versionId))
			}
			if !areMapsSame(metadata, v.metadata) {
				return fmt.Errorf("expected the object metadata to be %v, instead got %v",
					v.metadata, metadata)
			}
			return nil
		}

		for _, v := range versions {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			head, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: v.versionId,
			})
			cancel()
			if err != nil {
				return fmt.Errorf("head version %v: %w", *v.versionId, err)
			}
			err = checkVersion(v, head.ContentLength, head.ContentType, head.VersionId, head.Metadata)
			if err != nil {
				return fmt.Errorf("head version %v: %w", *v.versionId, err)
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			get, err := s3client.GetObject(ctx, &s3.GetObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: v.versionId,
			})
			if err != nil {
				cancel()
				return fmt.Errorf("get version %v: %w", *v.versionId, err)
			}
			bdy, err := io.ReadAll(get.Body)
			get.Body.Close()
			cancel()
			if err != nil {
				return fmt.Errorf("get version %v: %w", *v.versionId, err)
			}
			if len(bdy) != 0 {
				return fmt.Errorf("get version %v: expected empty body, instead got %v bytes",
					*v.versionId, len(bdy))
			}
			err = checkVersion(v, get.ContentLength, get.ContentType, get.VersionId, get.Metadata)
			if err != nil {
				return fmt.Errorf("get version %v: %w", *v.versionId, err)
			}
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_HeadObject_without_versionId(s *S3Conf) error {
	testName := "Versioning_HeadObject_without_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			versions, err := createObjVersions(s3client, bucket, obj, 3)
			if err != nil {
				return err
			}

			lastVersion := versions[0]

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			if getString(res.VersionId) != *lastVersion.VersionId {
				return fmt.Errorf("expected versionId to be %v, instead got %v",
					*lastVersion.VersionId, getString(res.VersionId))
			}

			return nil
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

// Versioning_HeadObject_null_version_without_versionId heads an object put
// into a versioning-suspended bucket, without naming a version id.
func Versioning_HeadObject_null_versionId_obj(s *S3Conf) error {
	testName := "Versioning_HeadObject_null_versionId_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		keys, dataLen := []string{"my-obj", "my-dir/"}, int64(321)
		// the objects are put before versioning is enabled
		etags := make(map[string]string, len(keys))
		err := forEachKey(keys, func(obj string) error {
			out, err := putObjectWithData(objDataLen(obj, dataLen), &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}
			etags[obj] = getString(out.res.ETag)
			return nil
		})
		if err != nil {
			return err
		}

		err = putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusEnabled)
		if err != nil {
			return err
		}

		return forEachKey(keys, func(obj string) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: &nullVersionId,
			})
			cancel()
			if err != nil {
				return err
			}

			if getString(res.VersionId) != nullVersionId {
				return fmt.Errorf("expected the versionId to be %v, instead got %v",
					nullVersionId, getString(res.VersionId))
			}
			if res.ContentLength == nil || *res.ContentLength != objDataLen(obj, dataLen) {
				return fmt.Errorf("expected the Content-Length to be %v, instead got %v",
					objDataLen(obj, dataLen), res.ContentLength)
			}
			if getString(res.ETag) != etags[obj] {
				return fmt.Errorf("expected the ETag to be %v, instead got %v",
					etags[obj], getString(res.ETag))
			}

			return nil
		})
	})
}

func Versioning_HeadObject_null_version_without_versionId(s *S3Conf) error {
	testName := "Versioning_HeadObject_null_version_without_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			dataLen := objDataLen(obj, 765)
			out, err := putObjectWithData(dataLen, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			if getString(res.VersionId) != nullVersionId {
				return fmt.Errorf("expected the versionId to be %v, instead got %v",
					nullVersionId, getString(res.VersionId))
			}
			if res.ContentLength == nil || *res.ContentLength != dataLen {
				return fmt.Errorf("expected the Content-Length to be %v, instead got %v",
					dataLen, res.ContentLength)
			}
			if getString(res.ETag) != getString(out.res.ETag) {
				return fmt.Errorf("expected the ETag to be %v, instead got %v",
					getString(out.res.ETag), getString(res.ETag))
			}

			return nil
		})
	}, withVersioning(types.BucketVersioningStatusSuspended))
}

func Versioning_HeadObject_delete_marker(s *S3Conf) error {
	testName := "Versioning_HeadObject_delete_marker"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			dLen := objDataLen(obj, 2000)
			_, err := putObjectWithData(dLen, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			if out.VersionId == nil || *out.VersionId == "" {
				return fmt.Errorf("expected non empty versionId")
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: out.VersionId,
			})
			cancel()
			if err := checkSdkApiErr(err, "MethodNotAllowed"); err != nil {
				return err
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err := checkSdkApiErr(err, "NotFound"); err != nil {
				return err
			}

			return nil
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_GetObject_invalid_versionId(s *S3Conf) error {
	testName := "Versioning_GetObject_invalid_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		_, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: getPtr("invalid_version_id"),
		})
		cancel()
		return checkApiErr(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgVersionId, "invalid_version_id"))
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_GetObject_non_existing_object_version(s *S3Conf) error {
	testName := "Versioning_GetObject_non_existing_object_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			dLen := objDataLen(obj, 2000)
			_, err := putObjectWithData(dLen, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.GetObject(ctx, &s3.GetObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: getPtr("01G65Z755AFWAKHE12NY0CQ9FH"),
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchVersion)); err != nil {
				return err
			}

			return nil
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_GetObject_success(s *S3Conf) error {
	testName := "Versioning_GetObject_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			dLen := objDataLen(obj, 2000)
			r, err := putObjectWithData(dLen, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}

			// getObject checks that the object read with versionId is
			// the uploaded version
			getObject := func(versionId *string) error {
				ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
				out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
					Bucket:    &bucket,
					Key:       &obj,
					VersionId: versionId,
				})
				defer cancel()
				if err != nil {
					return err
				}

				if out.ContentLength == nil {
					return fmt.Errorf("expected non nil ContentLength")
				}
				if out.VersionId == nil {
					return fmt.Errorf("expected non nil VersionId")
				}
				if *out.ContentLength != dLen {
					return fmt.Errorf("expected the object content-length to be %v, instead got %v",
						dLen, *out.ContentLength)
				}
				if *out.VersionId != *r.res.VersionId {
					return fmt.Errorf("expected the versionId to be %v, instead got %v",
						*r.res.VersionId, *out.VersionId)
				}

				bdy, err := io.ReadAll(out.Body)
				if err != nil {
					return err
				}
				out.Body.Close()

				outCsum := sha256.Sum256(bdy)
				if outCsum != r.csum {
					return fmt.Errorf("incorrect output content")
				}

				return nil
			}

			// Get the object by versionId
			if err := getObject(r.res.VersionId); err != nil {
				return err
			}

			// Get the object without versionId
			if err := getObject(nil); err != nil {
				return err
			}

			// Get the noncurrent object version by versionId
			_, err = putObjectWithData(objDataLen(obj, 1000), &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}

			return getObject(r.res.VersionId)
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_GetObject_delete_marker_without_versionId(s *S3Conf) error {
	testName := "Versioning_GetObject_delete_marker_without_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		keys := []string{"my-obj", "my-dir/"}
		// the objects are put before versioning is enabled
		err := forEachKey(keys, func(obj string) error {
			_, err := putObjectWithData(objDataLen(obj, 1234), &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			return err
		})
		if err != nil {
			return err
		}

		err = putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusEnabled)
		if err != nil {
			return err
		}

		return forEachKey(keys, func(obj string) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.GetObject(ctx, &s3.GetObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err := checkSdkApiErr(err, "NoSuchKey"); err != nil {
				return err
			}

			return nil
		})
	})
}

func Versioning_GetObject_delete_marker(s *S3Conf) error {
	testName := "Versioning_GetObject_delete_marker"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			dLen := objDataLen(obj, 2000)
			_, err := putObjectWithData(dLen, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			if out.VersionId == nil || *out.VersionId == "" {
				return fmt.Errorf("expected non empty versionId")
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.GetObject(ctx, &s3.GetObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: out.VersionId,
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMethodNotAllowed)); err != nil {
				return err
			}

			return nil
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_GetObject_null_versionId_obj(s *S3Conf) error {
	testName := "Versioning_GetObject_null_versionId_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		keys, dataLen := []string{"my-obj", "my-dir/"}, int64(234)
		// the objects are put before versioning is enabled
		etags := make(map[string]string, len(keys))
		err := forEachKey(keys, func(obj string) error {
			out, err := putObjectWithData(objDataLen(obj, dataLen), &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}
			etags[obj] = getString(out.res.ETag)
			return nil
		})
		if err != nil {
			return err
		}

		err = putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusEnabled)
		if err != nil {
			return err
		}

		return forEachKey(keys, func(obj string) error {
			lgth, etag := objDataLen(obj, dataLen), etags[obj]
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.GetObject(ctx, &s3.GetObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: &nullVersionId,
			})
			cancel()
			if err != nil {
				return err
			}

			if res.ContentLength == nil {
				return fmt.Errorf("expected non nil ContentLength")
			}
			if res.VersionId == nil {
				return fmt.Errorf("expected non nil VersionId")
			}
			if res.ETag == nil {
				return fmt.Errorf("expected non nil ETag")
			}
			if *res.ContentLength != lgth {
				return fmt.Errorf("expected the Content-Length to be %v, instead got %v",
					lgth, *res.ContentLength)
			}
			if *res.VersionId != nullVersionId {
				return fmt.Errorf("expected the versionId to be %v, insted got %v",
					nullVersionId, *res.VersionId)
			}
			if *res.ETag != etag {
				return fmt.Errorf("expecte the ETag to be %v, instead got %v",
					etag, *res.ETag)
			}

			return nil
		})
	})
}

// Versioning_GetObject_null_version_without_versionId reads an object put
// into a versioning-suspended bucket, without naming a version id. The object
// is the null version and the response has to report it as null rather than
// leave the version id out.
func Versioning_GetObject_null_version_without_versionId(s *S3Conf) error {
	testName := "Versioning_GetObject_null_version_without_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			dataLen := objDataLen(obj, 543)
			out, err := putObjectWithData(dataLen, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}
			// a put into a versioning-suspended bucket creates the null
			// version and reports no version id
			if out.res.VersionId != nil {
				return fmt.Errorf("expected PutObject response to omit versionId, instead got %v",
					getString(out.res.VersionId))
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.GetObject(ctx, &s3.GetObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			if getString(res.VersionId) != nullVersionId {
				return fmt.Errorf("expected the versionId to be %v, instead got %v",
					nullVersionId, getString(res.VersionId))
			}
			if res.ContentLength == nil || *res.ContentLength != dataLen {
				return fmt.Errorf("expected the Content-Length to be %v, instead got %v",
					dataLen, res.ContentLength)
			}
			if getString(res.ETag) != getString(out.res.ETag) {
				return fmt.Errorf("expected the ETag to be %v, instead got %v",
					getString(out.res.ETag), getString(res.ETag))
			}

			return nil
		})
	}, withVersioning(types.BucketVersioningStatusSuspended))
}

// Versioning_unversioned_bucket_omits_versionId reads an object in a bucket
// that never had versioning configured. Such a bucket has no versions at all,
// so neither GetObject nor HeadObject reports a version id, not even the null
// one, even though the gateway itself runs with versioning enabled.
func Versioning_unversioned_bucket_omits_versionId(s *S3Conf) error {
	testName := "Versioning_unversioned_bucket_omits_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		vRes, err := s3client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}
		// guard the premise of the test
		if vRes.Status != "" {
			return fmt.Errorf("expected the bucket versioning to be unconfigured, instead got %v",
				vRes.Status)
		}

		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			_, err := putObjectWithData(objDataLen(obj, 432), &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			gRes, err := s3client.GetObject(ctx, &s3.GetObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}
			if gRes.VersionId != nil {
				return fmt.Errorf("expected GetObject to omit the versionId, instead got %v",
					*gRes.VersionId)
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			hRes, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}
			if hRes.VersionId != nil {
				return fmt.Errorf("expected HeadObject to omit the versionId, instead got %v",
					*hRes.VersionId)
			}

			return nil
		})
	})
}

func Versioning_GetObjectAttributes_invalid_versionId(s *S3Conf) error {
	testName := "Versioning_GetObjectAttributes_invalid_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := createObjVersions(s3client, bucket, obj, 1)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: getPtr("invalid_versionId"),
			ObjectAttributes: []types.ObjectAttributes{
				types.ObjectAttributesEtag,
			},
		})
		cancel()
		return checkApiErr(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgVersionId, "invalid_versionId"))
	})
}

func Versioning_GetObjectAttributes_object_version(s *S3Conf) error {
	testName := "Versioning_GetObjectAttributes_object_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			versions, err := createObjVersions(s3client, bucket, obj, 1)
			if err != nil {
				return err
			}
			version := versions[0]

			getObjAttrs := func(versionId *string) (*s3.GetObjectAttributesOutput, error) {
				ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
				res, err := s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
					Bucket:    &bucket,
					Key:       &obj,
					VersionId: versionId,
					ObjectAttributes: []types.ObjectAttributes{
						types.ObjectAttributesEtag,
					},
				})
				cancel()
				return res, err
			}

			// By specifying the versionId
			res, err := getObjAttrs(version.VersionId)
			if err != nil {
				return err
			}

			if getString(res.ETag) != strings.Trim(*version.ETag, "\"") {
				return fmt.Errorf("expected the uploaded object ETag to be %v, instead got %v",
					strings.Trim(*version.ETag, "\""), getString(res.ETag))
			}
			if getString(res.VersionId) != *version.VersionId {
				return fmt.Errorf("expected the uploaded versionId to be %v, instead got %v",
					*version.VersionId, getString(res.VersionId))
			}

			// Without versionId
			res, err = getObjAttrs(nil)
			if err != nil {
				return err
			}

			if getString(res.ETag) != strings.Trim(*version.ETag, "\"") {
				return fmt.Errorf("expected the uploaded object ETag to be %v, instead got %v",
					strings.Trim(*version.ETag, "\""), getString(res.ETag))
			}
			if getString(res.VersionId) != *version.VersionId {
				return fmt.Errorf("expected the uploaded object versionId to be %v, instead got %v",
					*version.VersionId, getString(res.VersionId))
			}

			return nil
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_GetObjectAttributes_delete_marker(s *S3Conf) error {
	testName := "Versioning_GetObjectAttributes_delete_marker"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			_, err := createObjVersions(s3client, bucket, obj, 1)
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

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: res.VersionId,
				ObjectAttributes: []types.ObjectAttributes{
					types.ObjectAttributesEtag,
				},
			})
			cancel()
			if err := checkSdkApiErr(err, "NoSuchKey"); err != nil {
				return err
			}

			return nil
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_DeleteObject_invalid_versionId(s *S3Conf) error {
	testName := "Versioning_DeleteObject_invalid_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjectWithData(3, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: getPtr("invalid_versionId"),
		})
		cancel()
		return checkApiErr(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgVersionId, "invalid_versionId"))
	})
}

func Versioning_DeleteObject_delete_object_version(s *S3Conf) error {
	testName := "Versioning_DeleteObject_delete_object_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			oLen := objDataLen(obj, 1000)
			r, err := putObjectWithData(oLen, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}

			versionId := r.res.VersionId
			if versionId == nil || *versionId == "" {
				return fmt.Errorf("expected non empty versionId")
			}

			_, err = putObjects(s3client, []string{obj}, bucket)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: versionId,
			})
			cancel()
			if err != nil {
				return err
			}

			if out.VersionId == nil {
				return fmt.Errorf("expected non nil versionId")
			}
			if *out.VersionId != *versionId {
				return fmt.Errorf("expected deleted object versionId to be %v, instead got %v",
					*versionId, *out.VersionId)
			}

			return nil
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_DeleteObject_dir_object_latest_version(s *S3Conf) error {
	testName := "Versioning_DeleteObject_dir_object_latest_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-dir/"
		versionIds := []string{}
		for i := range 3 {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.PutObject(ctx, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
				Metadata: map[string]string{
					"version": fmt.Sprint(i),
				},
			})
			cancel()
			if err != nil {
				return err
			}
			if getString(out.VersionId) == "" {
				return fmt.Errorf("expected non empty versionId")
			}

			versionIds = append(versionIds, *out.VersionId)
		}

		// deleting the latest version makes the previous one the current
		for i := 2; i > 0; i-- {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: &versionIds[i],
			})
			cancel()
			if err != nil {
				return err
			}
			if getString(out.VersionId) != versionIds[i] {
				return fmt.Errorf("expected the deleted versionId to be %v, instead got %v",
					versionIds[i], getString(out.VersionId))
			}
			if out.DeleteMarker != nil && *out.DeleteMarker {
				return fmt.Errorf("expected the response DeleteMarker to be false")
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			if getString(res.VersionId) != versionIds[i-1] {
				return fmt.Errorf("expected the versionId to be %v, instead got %v",
					versionIds[i-1], getString(res.VersionId))
			}
			expectedMeta := map[string]string{
				"version": fmt.Sprint(i - 1),
			}
			if !areMapsSame(res.Metadata, expectedMeta) {
				return fmt.Errorf("expected the object metadata to be %v, instead got %v",
					expectedMeta, res.Metadata)
			}
			if getString(res.ContentType) != directoryContentType {
				return fmt.Errorf("expected the content type to be %v, instead got %v",
					directoryContentType, getString(res.ContentType))
			}
			if res.ContentLength == nil || *res.ContentLength != 0 {
				return fmt.Errorf("expected zero content length, instead got %v",
					res.ContentLength)
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: &versionIds[0],
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err == nil {
			return fmt.Errorf("expected NotFound, instead got nil")
		}
		if err := checkSdkApiErr(err, "NotFound"); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if len(res.Versions) != 0 {
			return fmt.Errorf("expected empty object versions, instead got %v", res.Versions)
		}
		if len(res.DeleteMarkers) != 0 {
			return fmt.Errorf("expected empty delete markers list, instead got %v", res.DeleteMarkers)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}
		if getString(out.VersionId) == "" {
			return fmt.Errorf("expected non empty versionId")
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err = s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if len(res.Versions) != 1 {
			return fmt.Errorf("expected 1 object version, instead got %v", len(res.Versions))
		}
		if getString(res.Versions[0].Key) != obj {
			return fmt.Errorf("expected the version key to be %v, instead got %v",
				obj, getString(res.Versions[0].Key))
		}
		if getString(res.Versions[0].VersionId) != *out.VersionId {
			return fmt.Errorf("expected the versionId to be %v, instead got %v",
				*out.VersionId, getString(res.Versions[0].VersionId))
		}
		if res.Versions[0].IsLatest == nil || !*res.Versions[0].IsLatest {
			return fmt.Errorf("expected the version to be the latest")
		}
		if len(res.DeleteMarkers) != 0 {
			return fmt.Errorf("expected empty delete markers list, instead got %v", res.DeleteMarkers)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

// Versioning_DeleteObject_latest_version_with_null_version deletes the current
// version of an object whose history also holds a null version, created while
// versioning was suspended. The version that becomes current has to be the one
// created right before the deleted version, not the older null version.
func Versioning_DeleteObject_latest_version_with_null_version(s *S3Conf) error {
	testName := "Versioning_DeleteObject_latest_version_with_null_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			// the versions are told apart by a metadata entry, as a
			// directory object carries no data
			put := func(marker string) (*s3.PutObjectOutput, error) {
				ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
				defer cancel()
				return s3client.PutObject(ctx, &s3.PutObjectInput{
					Bucket:   &bucket,
					Key:      &obj,
					Metadata: map[string]string{"marker": marker},
				})
			}

			if _, err := put("v1"); err != nil {
				return err
			}
			if _, err := put("v2"); err != nil {
				return err
			}

			err := putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusSuspended)
			if err != nil {
				return err
			}

			// the null version sits in the middle of the version history
			if _, err := put("null"); err != nil {
				return err
			}

			err = putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusEnabled)
			if err != nil {
				return err
			}

			third, err := put("v3")
			if err != nil {
				return err
			}
			latest, err := put("v4")
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: latest.VersionId,
			})
			cancel()
			if err != nil {
				return err
			}
			if getString(out.VersionId) != getString(latest.VersionId) {
				return fmt.Errorf("expected the deleted versionId to be %v, instead got %v",
					getString(latest.VersionId), getString(out.VersionId))
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			expectedMeta := map[string]string{"marker": "v3"}
			if !areMapsSame(res.Metadata, expectedMeta) {
				return fmt.Errorf("expected the object metadata to be %v, instead got %v",
					expectedMeta, res.Metadata)
			}
			if getString(res.VersionId) != getString(third.VersionId) {
				return fmt.Errorf("expected the current versionId to be %v, instead got %v",
					getString(third.VersionId), getString(res.VersionId))
			}

			// the null version has to be left untouched by the delete
			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			versions, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
				Bucket: &bucket,
				Prefix: &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			nullFound := false
			for _, v := range versions.Versions {
				if getString(v.VersionId) == nullVersionId {
					nullFound = true
					if v.IsLatest != nil && *v.IsLatest {
						return fmt.Errorf("expected the null version not to be the latest")
					}
				}
			}
			if !nullFound {
				return fmt.Errorf("expected the null version to be kept in %v",
					versions.Versions)
			}

			return nil
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_DeleteObject_non_existing_object(s *S3Conf) error {
	testName := "Versioning_DeleteObject_non_existing_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			ctx, canel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			canel()
			if err != nil {
				return err
			}

			ctx, canel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: getPtr("non_existing_version_id"),
			})
			canel()
			if err := checkApiErr(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgVersionId, "non_existing_version_id")); err != nil {
				return err
			}

			return nil
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_DeleteObject_implicit_dir(s *S3Conf) error {
	testName := "Versioning_DeleteObject_implicit_dir"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dir, obj := "my-dir/", "my-dir/obj"
		versions, err := createObjVersions(s3client, bucket, obj, 1)
		if err != nil {
			return err
		}

		// "my-dir/" is only the parent directory of "my-dir/obj", not an object
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &dir,
		})
		cancel()
		if err != nil {
			return err
		}

		if out.DeleteMarker != nil && *out.DeleteMarker {
			return fmt.Errorf("expected the response DeleteMarker to be false")
		}
		if getString(out.VersionId) != "" {
			return fmt.Errorf("expected empty versionId, instead got %v",
				getString(out.VersionId))
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareVersions(versions, res.Versions) {
			return fmt.Errorf("expected the versions to be %v, instead got %v",
				versions, res.Versions)
		}
		if len(res.DeleteMarkers) != 0 {
			return fmt.Errorf("expected empty delete markers list, instead got %v",
				res.DeleteMarkers)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_DeleteObject_delete_a_delete_marker(s *S3Conf) error {
	testName := "Versioning_DeleteObject_delete_a_delete_marker"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			oLen := objDataLen(obj, 1000)
			_, err := putObjectWithData(oLen, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			if out.DeleteMarker == nil || !*out.DeleteMarker {
				return fmt.Errorf("expected the response DeleteMarker to be true")
			}
			if out.VersionId == nil || *out.VersionId == "" {
				return fmt.Errorf("expected non empty versionId")
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: out.VersionId,
			})
			cancel()
			if err != nil {
				return err
			}

			if res.DeleteMarker == nil || !*res.DeleteMarker {
				return fmt.Errorf("expected the response DeleteMarker to be true")
			}
			if res.VersionId == nil {
				return fmt.Errorf("expected non empty versionId")
			}
			if *res.VersionId != *out.VersionId {
				return fmt.Errorf("expected the versionId to be %v, instead got %v",
					*out.VersionId, *res.VersionId)
			}

			return nil
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_DeleteObject_dir_object_with_children(s *S3Conf) error {
	testName := "Versioning_DeleteObject_dir_object_with_children"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dir, child := "my-dir/", "my-dir/child"
		dirVersions, err := createObjVersions(s3client, bucket, dir, 1)
		if err != nil {
			return err
		}
		childData, err := putObjectWithData(100, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &child,
		}, s3client)
		if err != nil {
			return err
		}

		// checkObjects checks that the child object is readable and that
		// the bucket lists exactly keys
		checkObjects := func(keys ...string) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
				Bucket: &bucket,
				Key:    &child,
			})
			cancel()
			if err != nil {
				return err
			}
			body, err := io.ReadAll(out.Body)
			out.Body.Close()
			if err != nil {
				return err
			}
			if sha256.Sum256(body) != childData.csum {
				return fmt.Errorf("expected the %v data checksum to match", child)
			}

			objs, _, err := listObjects(s3client, bucket, "", "", 1000)
			if err != nil {
				return err
			}
			if !hasObjNames(objs, keys) {
				return fmt.Errorf("expected the listed objects to be %v, instead got %v",
					keys, objs)
			}

			return nil
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &dir,
		})
		cancel()
		if err != nil {
			return err
		}

		if out.DeleteMarker == nil || !*out.DeleteMarker {
			return fmt.Errorf("expected the response DeleteMarker to be true")
		}
		if getString(out.VersionId) == "" {
			return fmt.Errorf("expected non empty versionId")
		}

		err = checkObjects(child)
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:    &bucket,
			Key:       &dir,
			VersionId: out.VersionId,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.DeleteMarker == nil || !*res.DeleteMarker {
			return fmt.Errorf("expected the response DeleteMarker to be true")
		}
		if getString(res.VersionId) != *out.VersionId {
			return fmt.Errorf("expected the versionId to be %v, instead got %v",
				*out.VersionId, getString(res.VersionId))
		}

		// removing the delete marker restores the directory object
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		head, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &dir,
		})
		cancel()
		if err != nil {
			return err
		}
		if getString(head.VersionId) != *dirVersions[0].VersionId {
			return fmt.Errorf("expected the versionId to be %v, instead got %v",
				*dirVersions[0].VersionId, getString(head.VersionId))
		}

		err = checkObjects(dir, child)
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:    &bucket,
			Key:       &dir,
			VersionId: dirVersions[0].VersionId,
		})
		cancel()
		if err != nil {
			return err
		}
		if getString(res.VersionId) != *dirVersions[0].VersionId {
			return fmt.Errorf("expected the versionId to be %v, instead got %v",
				*dirVersions[0].VersionId, getString(res.VersionId))
		}

		// with no versions left the directory is only the parent of the child
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &dir,
		})
		cancel()
		if err == nil {
			return fmt.Errorf("expected NotFound, instead got nil")
		}
		if err := checkSdkApiErr(err, "NotFound"); err != nil {
			return err
		}

		err = checkObjects(child)
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		versions, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if len(versions.Versions) != 1 || getString(versions.Versions[0].Key) != child {
			return fmt.Errorf("expected only %v versions, instead got %v",
				child, versions.Versions)
		}
		if len(versions.DeleteMarkers) != 0 {
			return fmt.Errorf("expected empty delete markers list, instead got %v",
				versions.DeleteMarkers)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_DeleteObject_trailing_slash_counterpart(s *S3Conf) error {
	testName := "Versioning_DeleteObject_trailing_slash_counterpart"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		expected := []types.ObjectVersion{}
		// deleting the key with or without a trailing slash doesn't delete
		// the object or any of its versions
		for _, keys := range [][2]string{{"my-dir/", "my-dir"}, {"my-obj", "my-obj/"}} {
			obj, other := keys[0], keys[1]
			versions, err := createObjVersions(s3client, bucket, obj, 2)
			if err != nil {
				return err
			}
			expected = append(expected, versions...)

			for _, versionId := range []*string{versions[0].VersionId, versions[1].VersionId} {
				ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
				out, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
					Bucket:    &bucket,
					Key:       &other,
					VersionId: versionId,
				})
				cancel()
				if err != nil {
					return fmt.Errorf("%v: %w", other, err)
				}
				if getString(out.VersionId) != *versionId {
					return fmt.Errorf("%v: expected the versionId to be %v, instead got %v",
						other, *versionId, getString(out.VersionId))
				}
				if out.DeleteMarker != nil && *out.DeleteMarker {
					return fmt.Errorf("%v: expected the response DeleteMarker to be false", other)
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: &bucket,
				Key:    &other,
			})
			cancel()
			if err != nil {
				return fmt.Errorf("%v: %w", other, err)
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return fmt.Errorf("%v: %w", obj, err)
			}
			if getString(res.VersionId) != getString(versions[0].VersionId) {
				return fmt.Errorf("%v: expected the versionId to be %v, instead got %v",
					obj, getString(versions[0].VersionId), getString(res.VersionId))
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareVersions(expected, res.Versions) {
			return fmt.Errorf("expected the versions to be %v, instead got %v",
				expected, res.Versions)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_Delete_null_versionId_object(s *S3Conf) error {
	testName := "Versioning_Delete_null_versionId_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objs, nObjLgth := []string{"my-obj", "my-dir/"}, int64(3211)
		// the null versions are created before versioning is enabled
		for _, obj := range objs {
			_, err := putObjectWithData(objDataLen(obj, nObjLgth), &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}
		}

		err := putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusEnabled)
		if err != nil {
			return err
		}

		return forEachKey(objs, func(obj string) error {
			_, err := createObjVersions(s3client, bucket, obj, 3)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: getPtr(nullVersionId),
			})
			cancel()
			if err != nil {
				return err
			}
			if getString(res.VersionId) != nullVersionId {
				return fmt.Errorf("expected the versionId to be %v, instead got %v",
					nullVersionId, getString(res.VersionId))
			}

			return nil
		})
	})
}

func Versioning_DeleteObject_nested_dir_object(s *S3Conf) error {
	testName := "Versioning_DeleteObject_nested_dir_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"foo/bar/baz", "foo/bar/baz/"}, func(obj string) error {
			out, err := putObjectWithData(objDataLen(obj, 1000), &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: out.res.VersionId,
			})
			cancel()
			if err != nil {
				return err
			}

			if getString(res.VersionId) != getString(out.res.VersionId) {
				return fmt.Errorf("expected the versionId to be %v, instead got %v",
					getString(out.res.VersionId), getString(res.VersionId))
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.DeleteBucket(ctx, &s3.DeleteBucketInput{
				Bucket: &bucket,
			})
			cancel()
			if err != nil {
				return err
			}

			// Then create the bucket back to not get error on teardown
			if err := setup(s, bucket, withLock()); err != nil {
				return err
			}

			return nil
		})
	}, withLock())
}

func Versioning_DeleteObject_non_existing_objects(s *S3Conf) error {
	testName := "Versioning_DeleteObject_non_existing_objects"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		out, err := putObjectWithData(2, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    getPtr("foo"),
		}, s3client)
		if err != nil {
			return err
		}
		versionId := getString(out.res.VersionId)

		out, err = putObjectWithData(0, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    getPtr("my-dir/"),
		}, s3client)
		if err != nil {
			return err
		}
		dirVersionId := getString(out.res.VersionId)

		for _, test := range []struct {
			key       string
			versionId string
		}{
			{"foo/bar", "01KF2YVN948NAZ4JJR4X1AAVRA"},
			{"foo/bar/baz", "01KF2YVN948NAZ4JJR4X1AAVRA"},
			{"hello", "01KF2YVN948NAZ4JJR4X1AAVRA"},
			{"hello/world", "01KF2YVN948NAZ4JJR4X1AAVRA"},
			{"foo/bar/", "01KF2YVN948NAZ4JJR4X1AAVRA"},
			{"hello/", "01KF2YVN948NAZ4JJR4X1AAVRA"},
			{"hello/world/", "01KF2YVN948NAZ4JJR4X1AAVRA"},
			{"foo/bar/baz/quxx", versionId},
			{"foo/bar/baz/quxx/", versionId},
			{"my-dir/hello/", dirVersionId},
			{"foo", versionId},
			{"my-dir/", dirVersionId},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket:    &bucket,
				Key:       &test.key,
				VersionId: &test.versionId,
			})
			cancel()
			if err != nil {
				return err
			}

			if getString(res.VersionId) != test.versionId {
				return fmt.Errorf("expected the versionId to be %s, instead got %s", test.versionId, getString(res.VersionId))
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if len(resp.Versions) != 0 {
			return fmt.Errorf("expected empty object versions, instead got %v", resp.Versions)
		}
		if len(resp.DeleteMarkers) != 0 {
			return fmt.Errorf("expected empty delete markers list, insead got %v", resp.DeleteMarkers)
		}

		return nil
	}, withLock())
}

func Versioning_DeleteObject_suspended(s *S3Conf) error {
	testName := "Versioning_DeleteObject_suspended"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			// the object version is created while versioning is enabled
			err := putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusEnabled)
			if err != nil {
				return err
			}

			versions, err := createObjVersions(s3client, bucket, obj, 1)
			if err != nil {
				return err
			}
			versions[0].IsLatest = getBoolPtr(false)

			err = putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusSuspended)
			if err != nil {
				return err
			}

			for range 5 {
				ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
				res, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
					Bucket: &bucket,
					Key:    &obj,
				})
				cancel()
				if err != nil {
					return err
				}

				if res.DeleteMarker == nil {
					return fmt.Errorf("expected the delete marker to be true")
				}
				if !*res.DeleteMarker {
					return fmt.Errorf("expected the delete marker to be true, instead got %v",
						*res.DeleteMarker)
				}
				if res.VersionId == nil {
					return fmt.Errorf("expected non nil versionId")
				}
				if *res.VersionId != nullVersionId {
					return fmt.Errorf("expected the versionId to be %v, instead got %v",
						nullVersionId, *res.VersionId)
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
				Bucket: &bucket,
				Prefix: &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			delMarkers := []types.DeleteMarkerEntry{
				{
					IsLatest:  getBoolPtr(true),
					Key:       &obj,
					VersionId: &nullVersionId,
				},
			}

			if !compareVersions(versions, res.Versions) {
				return fmt.Errorf("expected the versions to be %v, instead got %v",
					versions, res.Versions)
			}
			if !compareDelMarkers(res.DeleteMarkers, delMarkers) {
				return fmt.Errorf("expected the delete markers to be %v, instead got %v",
					delMarkers, res.DeleteMarkers)
			}

			return nil
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_DeleteObject_never_versioned_bucket(s *S3Conf) error {
	testName := "Versioning_DeleteObject_never_versioned_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		versionId := "01KF2YVN948NAZ4JJR4X1AAVRA"
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			out, err := putObjectWithData(objDataLen(obj, 10), &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}

			// the object only has a null version, so deleting any other
			// version succeeds without deleting the object
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: &versionId,
			})
			cancel()
			if err != nil {
				return err
			}
			if getString(res.VersionId) != versionId {
				return fmt.Errorf("expected the versionId to be %v, instead got %v",
					versionId, getString(res.VersionId))
			}
			if res.DeleteMarker != nil && *res.DeleteMarker {
				return fmt.Errorf("expected the response DeleteMarker to be false")
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			head, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}
			if getString(head.ETag) != getString(out.res.ETag) {
				return fmt.Errorf("expected the ETag to be %v, instead got %v",
					getString(out.res.ETag), getString(head.ETag))
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: &nullVersionId,
			})
			cancel()
			if err != nil {
				return err
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err == nil {
				return fmt.Errorf("expected NotFound, instead got nil")
			}
			return checkSdkApiErr(err, "NotFound")
		})
	})
}

func Versioning_DeleteObjects_success(s *S3Conf) error {
	testName := "Versioning_DeleteObjects_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj1, obj2, obj3 := "foo", "bar", "baz"
		dir1, dir2 := "foo-dir/", "baz-dir/"

		obj1Version, err := createObjVersions(s3client, bucket, obj1, 1)
		if err != nil {
			return err
		}
		obj2Version, err := createObjVersions(s3client, bucket, obj2, 1)
		if err != nil {
			return err
		}
		obj3Version, err := createObjVersions(s3client, bucket, obj3, 1)
		if err != nil {
			return err
		}
		dir1Version, err := createObjVersions(s3client, bucket, dir1, 1)
		if err != nil {
			return err
		}
		dir2Version, err := createObjVersions(s3client, bucket, dir2, 1)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: &bucket,
			Delete: &types.Delete{
				Objects: []types.ObjectIdentifier{
					{
						Key:       obj1Version[0].Key,
						VersionId: obj1Version[0].VersionId,
					},
					{
						Key: obj2Version[0].Key,
					},
					{
						Key: obj3Version[0].Key,
					},
					{
						Key:       dir1Version[0].Key,
						VersionId: dir1Version[0].VersionId,
					},
					{
						Key: dir2Version[0].Key,
					},
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		delResult := []types.DeletedObject{
			{
				Key:          obj1Version[0].Key,
				VersionId:    obj1Version[0].VersionId,
				DeleteMarker: getBoolPtr(false),
			},
			{
				Key:          obj2Version[0].Key,
				DeleteMarker: getBoolPtr(true),
			},
			{
				Key:          obj3Version[0].Key,
				DeleteMarker: getBoolPtr(true),
			},
			{
				Key:          dir1Version[0].Key,
				VersionId:    dir1Version[0].VersionId,
				DeleteMarker: getBoolPtr(false),
			},
			{
				Key:          dir2Version[0].Key,
				DeleteMarker: getBoolPtr(true),
			},
		}

		if len(out.Errors) != 0 {
			return fmt.Errorf("errors occurred during the deletion: %v",
				out.Errors)
		}
		if !compareDelObjects(delResult, out.Deleted) {
			return fmt.Errorf("expected the deleted objects to be %v, instead got %v",
				delResult, out.Deleted)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		obj2Version[0].IsLatest = getBoolPtr(false)
		obj3Version[0].IsLatest = getBoolPtr(false)
		dir2Version[0].IsLatest = getBoolPtr(false)
		versions := append(obj2Version, obj3Version...)
		versions = append(versions, dir2Version...)

		delMarkers := []types.DeleteMarkerEntry{
			{
				IsLatest:  getBoolPtr(true),
				Key:       out.Deleted[1].Key,
				VersionId: out.Deleted[1].DeleteMarkerVersionId,
			},
			{
				IsLatest:  getBoolPtr(true),
				Key:       out.Deleted[2].Key,
				VersionId: out.Deleted[2].DeleteMarkerVersionId,
			},
			{
				IsLatest:  getBoolPtr(true),
				Key:       out.Deleted[4].Key,
				VersionId: out.Deleted[4].DeleteMarkerVersionId,
			},
		}
		if !compareVersions(versions, res.Versions) {
			return fmt.Errorf("expected the resulting versions to be %v, instead got %v",
				versions, res.Versions)
		}
		if !compareDelMarkers(delMarkers, res.DeleteMarkers) {
			return fmt.Errorf("expected the resulting delete markers to be %v, instead got %v",
				delMarkers, res.DeleteMarkers)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_DeleteObjects_delete_deleteMarkers(s *S3Conf) error {
	testName := "Versioning_DeleteObjects_delete_deleteMarkers"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj1, obj2 := "foo", "bar"
		dir1, dir2 := "foo-dir/", "bar-dir/"

		obj1Version, err := createObjVersions(s3client, bucket, obj1, 1)
		if err != nil {
			return err
		}
		obj2Version, err := createObjVersions(s3client, bucket, obj2, 1)
		if err != nil {
			return err
		}
		dir1Version, err := createObjVersions(s3client, bucket, dir1, 1)
		if err != nil {
			return err
		}
		dir2Version, err := createObjVersions(s3client, bucket, dir2, 1)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: &bucket,
			Delete: &types.Delete{
				Objects: []types.ObjectIdentifier{
					{
						Key: obj1Version[0].Key,
					},
					{
						Key: obj2Version[0].Key,
					},
					{
						Key: dir1Version[0].Key,
					},
					{
						Key: dir2Version[0].Key,
					},
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		delResult := []types.DeletedObject{
			{
				Key:          obj1Version[0].Key,
				DeleteMarker: getBoolPtr(true),
			},
			{
				Key:          obj2Version[0].Key,
				DeleteMarker: getBoolPtr(true),
			},
			{
				Key:          dir1Version[0].Key,
				DeleteMarker: getBoolPtr(true),
			},
			{
				Key:          dir2Version[0].Key,
				DeleteMarker: getBoolPtr(true),
			},
		}

		if len(out.Errors) != 0 {
			return fmt.Errorf("errors occurred during the deletion: %v",
				out.Errors)
		}
		if !compareDelObjects(delResult, out.Deleted) {
			return fmt.Errorf("expected the deleted objects to be %v, instead got %v",
				delResult, out.Deleted)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: &bucket,
			Delete: &types.Delete{
				Objects: []types.ObjectIdentifier{
					{
						Key:       out.Deleted[0].Key,
						VersionId: out.Deleted[0].VersionId,
					},
					{
						Key:       out.Deleted[1].Key,
						VersionId: out.Deleted[1].VersionId,
					},
					{
						Key:       out.Deleted[2].Key,
						VersionId: out.Deleted[2].VersionId,
					},
					{
						Key:       out.Deleted[3].Key,
						VersionId: out.Deleted[3].VersionId,
					},
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}
		if len(out.Errors) != 0 {
			return fmt.Errorf("errors occurred during the deletion: %v",
				out.Errors)
		}

		delResult = []types.DeletedObject{
			{
				Key:                   out.Deleted[0].Key,
				DeleteMarker:          getBoolPtr(true),
				DeleteMarkerVersionId: out.Deleted[0].VersionId,
				VersionId:             out.Deleted[0].VersionId,
			},
			{
				Key:                   out.Deleted[1].Key,
				DeleteMarker:          getBoolPtr(true),
				DeleteMarkerVersionId: out.Deleted[1].VersionId,
				VersionId:             out.Deleted[1].VersionId,
			},
			{
				Key:                   out.Deleted[2].Key,
				DeleteMarker:          getBoolPtr(true),
				DeleteMarkerVersionId: out.Deleted[2].VersionId,
				VersionId:             out.Deleted[2].VersionId,
			},
			{
				Key:                   out.Deleted[3].Key,
				DeleteMarker:          getBoolPtr(true),
				DeleteMarkerVersionId: out.Deleted[3].VersionId,
				VersionId:             out.Deleted[3].VersionId,
			},
		}

		if !compareDelObjects(delResult, res.Deleted) {
			return fmt.Errorf("expected the deleted objects to be %v, instead got %v",
				delResult, res.Deleted)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_DeleteObjects_never_versioned_bucket(s *S3Conf) error {
	testName := "Versioning_DeleteObjects_never_versioned_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		versionId := "01KF2YVN948NAZ4JJR4X1AAVRA"
		objs := []string{"my-obj", "my-dir/"}
		etags := map[string]string{}
		objIds := []types.ObjectIdentifier{}
		for _, obj := range objs {
			out, err := putObjectWithData(objDataLen(obj, 10), &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}
			etags[obj] = getString(out.res.ETag)
			objIds = append(objIds, types.ObjectIdentifier{
				Key:       &obj,
				VersionId: &versionId,
			})
		}

		// the objects only have a null version, so deleting any other
		// version succeeds without deleting the objects
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: &bucket,
			Delete: &types.Delete{
				Objects: objIds,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if len(res.Errors) != 0 {
			return fmt.Errorf("expected no errors, instead got %v", res.Errors)
		}
		delResult := []types.DeletedObject{}
		for _, objId := range objIds {
			delResult = append(delResult, types.DeletedObject{
				Key:       objId.Key,
				VersionId: objId.VersionId,
			})
		}
		if !compareDelObjects(delResult, res.Deleted) {
			return fmt.Errorf("expected the deleted objects to be %v, instead got %v",
				delResult, res.Deleted)
		}

		return forEachKey(objs, func(obj string) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			head, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}
			if getString(head.ETag) != etags[obj] {
				return fmt.Errorf("expected the ETag to be %v, instead got %v",
					etags[obj], getString(head.ETag))
			}
			return nil
		})
	})
}

func Versioning_Multipart_Upload_success(s *S3Conf) error {
	testName := "Versioning_Multipart_Upload_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		objSize := int64(25 * 1024 * 1024)
		parts, _, err := uploadParts(s3client, objSize, 5, bucket, obj, *out.UploadId)
		if err != nil {
			return err
		}

		compParts := []types.CompletedPart{}
		for _, el := range parts {
			compParts = append(compParts, types.CompletedPart{
				ETag:       el.ETag,
				PartNumber: el.PartNumber,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: compParts,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if res.Key == nil {
			return fmt.Errorf("expected the object key to be %v, instead got nil",
				obj)
		}
		if *res.Key != obj {
			return fmt.Errorf("expected object key to be %v, instead got %v",
				obj, *res.Key)
		}
		if res.Bucket == nil {
			return fmt.Errorf("expected the bucket name to be %v, instead got nil",
				bucket)
		}
		if *res.Bucket != bucket {
			return fmt.Errorf("expected the bucket name to be %v, instead got %v",
				bucket, *res.Bucket)
		}
		if res.ETag == nil || *res.ETag == "" {
			return fmt.Errorf("expected non-empty ETag")
		}
		if res.VersionId == nil || *res.VersionId == "" {
			return fmt.Errorf("expected non-empty versionId")
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: res.VersionId,
		})
		cancel()
		if err != nil {
			return err
		}

		if resp.ETag == nil || *resp.ETag == "" {
			return fmt.Errorf("expected (head object) non-empty ETag")
		}
		if *resp.ETag != *res.ETag {
			return fmt.Errorf("expected the uploaded object etag to be %v, instead got %v",
				*res.ETag, *resp.ETag)
		}
		if resp.ContentLength == nil {
			return fmt.Errorf("expected (head object) non nil content length")
		}
		if *resp.ContentLength != int64(objSize) {
			return fmt.Errorf("expected the uploaded object size to be %v, instead got %v",
				objSize, resp.ContentLength)
		}
		if resp.VersionId == nil {
			return fmt.Errorf("expected (head object) non nil versionId")
		}
		if *resp.VersionId != *res.VersionId {
			return fmt.Errorf("expected the versionId to be %v, instead got %v",
				*res.VersionId, *resp.VersionId)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_Multipart_Upload_overwrite_an_object(s *S3Conf) error {
	testName := "Versioning_Multipart_Upload_overwrite_an_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		objVersions, err := createObjVersions(s3client, bucket, obj, 2)
		if err != nil {
			return err
		}
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		objSize := int64(25 * 1024 * 1024)
		parts, _, err := uploadParts(s3client, objSize, 5, bucket, obj, *out.UploadId)
		if err != nil {
			return err
		}

		compParts := []types.CompletedPart{}
		for _, el := range parts {
			compParts = append(compParts, types.CompletedPart{
				ETag:       el.ETag,
				PartNumber: el.PartNumber,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: compParts,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if res.Key == nil {
			return fmt.Errorf("expected the object key to be %v, instead got nil",
				obj)
		}
		if *res.Key != obj {
			return fmt.Errorf("expected object key to be %v, instead got %v",
				obj, *res.Key)
		}
		if res.Bucket == nil {
			return fmt.Errorf("expected the bucket name to be %v, instead got nil",
				bucket)
		}
		if *res.Bucket != bucket {
			return fmt.Errorf("expected the bucket name to be %v, instead got %v",
				bucket, *res.Bucket)
		}
		if res.ETag == nil || *res.ETag == "" {
			return fmt.Errorf("expected non-empty ETag")
		}
		if res.VersionId == nil || *res.VersionId == "" {
			return fmt.Errorf("expected non-empty versionId")
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		size := int64(objSize)

		objVersions[0].IsLatest = getBoolPtr(false)
		versions := append([]types.ObjectVersion{
			{
				Key:          &obj,
				VersionId:    res.VersionId,
				ETag:         res.ETag,
				IsLatest:     getBoolPtr(true),
				Size:         &size,
				StorageClass: types.ObjectVersionStorageClassStandard,
			},
		}, objVersions...)

		if !compareVersions(versions, resp.Versions) {
			return fmt.Errorf("expected the resulting versions to be %v, instead got %v",
				versions, resp.Versions)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_UploadPartCopy_invalid_versionId(s *S3Conf) error {
	testName := "Versioning_UploadPartCopy_invalid_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dstObj, srcObj := "dst-obj", "src-obj"
		_, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		mp, err := createMp(s3client, bucket, dstObj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			Key:        &dstObj,
			UploadId:   mp.UploadId,
			PartNumber: getPtr(int32(1)),
			CopySource: getPtr(fmt.Sprintf("%v/%v?versionId=invalid_versionId",
				bucket, srcObj)),
		})
		cancel()
		return checkApiErr(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgVersionId, "invalid_versionId"))
	})
}

func Versioning_UploadPartCopy_encoded_versionid_separator_invalid_versionId(s *S3Conf) error {
	testName := "Versioning_UploadPartCopy_encoded_versionid_separator_invalid_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dstObj, srcObj := "dst-obj", "src-obj"
		_, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		mp, err := createMp(s3client, bucket, dstObj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			Key:        &dstObj,
			UploadId:   mp.UploadId,
			PartNumber: getPtr(int32(1)),
			CopySource: getPtr(fmt.Sprintf("%v/%v%%3FversionId%%3D..%%2f..%%2fsecret.txt", bucket, srcObj)),
		})
		cancel()
		return checkApiErr(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgVersionId, "../../secret.txt"))
	})
}

func Versioning_UploadPartCopy_non_existing_versionId(s *S3Conf) error {
	testName := "Versioning_UploadPartCopy_non_existing_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"src-obj", "src-dir/"}, func(srcObj string) error {
			dstBucket, dstObj := getBucketName(), "dst-obj"

			lgth := objDataLen(srcObj, 100)
			_, err := putObjectWithData(lgth, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &srcObj,
			}, s3client)
			if err != nil {
				return err
			}

			if err := setup(s, dstBucket); err != nil {
				return err
			}

			mp, err := createMp(s3client, dstBucket, dstObj)
			if err != nil {
				return err
			}

			pNumber := int32(1)
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
				Bucket:     &dstBucket,
				Key:        &dstObj,
				UploadId:   mp.UploadId,
				PartNumber: &pNumber,
				CopySource: getPtr(fmt.Sprintf("%v/%v?versionId=01BX5ZZKBKACTAV9WEVGEMMVS0",
					bucket, srcObj)),
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchVersion)); err != nil {
				return err
			}

			if err := teardown(s, dstBucket); err != nil {
				return err
			}

			return nil
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_UploadPartCopy_from_an_object_version(s *S3Conf) error {
	testName := "Versioning_UploadPartCopy_from_an_object_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(srcObj string) error {
			dstBucket, obj := getBucketName(), "dst-obj"
			err := setup(s, dstBucket)
			if err != nil {
				return err
			}

			// the latest version and a noncurrent one
			srcObjVersions, err := createObjVersions(s3client, bucket, srcObj, 2)
			if err != nil {
				return err
			}

			for _, srcObjVersion := range srcObjVersions {
				out, err := createMp(s3client, dstBucket, obj)
				if err != nil {
					return err
				}

				partNumber := int32(1)
				ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
				copyOut, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
					Bucket:     &dstBucket,
					CopySource: getPtr(fmt.Sprintf("%v/%v?versionId=%v", bucket, srcObj, *srcObjVersion.VersionId)),
					UploadId:   out.UploadId,
					Key:        &obj,
					PartNumber: &partNumber,
				})
				cancel()
				if err != nil {
					return err
				}

				if getString(copyOut.CopySourceVersionId) != getString(srcObjVersion.VersionId) {
					return fmt.Errorf("expected the copy-source-version-id to be %v, instead got %v",
						getString(srcObjVersion.VersionId), getString(copyOut.CopySourceVersionId))
				}

				ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
				res, err := s3client.ListParts(ctx, &s3.ListPartsInput{
					Bucket:   &dstBucket,
					Key:      &obj,
					UploadId: out.UploadId,
				})
				cancel()
				if err != nil {
					return err
				}

				if len(res.Parts) != 1 {
					return fmt.Errorf("expected parts to be 1, instead got %v",
						len(res.Parts))
				}
				if res.Parts[0].PartNumber == nil {
					return fmt.Errorf("expected part-number to be non nil")
				}
				if *res.Parts[0].PartNumber != partNumber {
					return fmt.Errorf("expected part-number to be %v, instead got %v",
						partNumber, res.Parts[0].PartNumber)
				}
				if res.Parts[0].Size == nil {
					return fmt.Errorf("expected part size to be non nil")
				}
				if *res.Parts[0].Size != *srcObjVersion.Size {
					return fmt.Errorf("expected part size to be %v, instead got %v",
						*srcObjVersion.Size, res.Parts[0].Size)
				}
				if getString(res.Parts[0].ETag) != getString(copyOut.CopyPartResult.ETag) {
					return fmt.Errorf("expected part etag to be %v, instead got %v",
						getString(copyOut.CopyPartResult.ETag), getString(res.Parts[0].ETag))
				}
			}

			if err := teardown(s, dstBucket); err != nil {
				return err
			}

			return nil
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

// A copy source that resolves to a delete marker is rejected: the key has no
// current version when the marker is the latest, and naming the marker by
// version id is an invalid request. Versions the marker hides stay copyable.
func Versioning_UploadPartCopy_from_a_delete_marker(s *S3Conf) error {
	testName := "Versioning_UploadPartCopy_from_a_delete_marker"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(srcObj string) error {
			dstBucket, dstObj := getBucketName(), "dst-obj"
			if err := setup(s, dstBucket); err != nil {
				return err
			}

			srcObjVersions, err := createObjVersions(s3client, bucket, srcObj, 1)
			if err != nil {
				return err
			}

			delMarker, err := createDeleteMarker(s3client, bucket, srcObj)
			if err != nil {
				return err
			}

			mp, err := createMp(s3client, dstBucket, dstObj)
			if err != nil {
				return err
			}

			partNumber := int32(1)
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
				Bucket:     &dstBucket,
				Key:        &dstObj,
				UploadId:   mp.UploadId,
				PartNumber: &partNumber,
				CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchKey)); err != nil {
				return err
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
				Bucket:     &dstBucket,
				Key:        &dstObj,
				UploadId:   mp.UploadId,
				PartNumber: &partNumber,
				CopySource: getPtr(fmt.Sprintf("%v/%v?versionId=%v",
					bucket, srcObj, delMarker)),
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrCopySourceDeleteMarker)); err != nil {
				return err
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
				Bucket:     &dstBucket,
				Key:        &dstObj,
				UploadId:   mp.UploadId,
				PartNumber: &partNumber,
				CopySource: getPtr(fmt.Sprintf("%v/%v?versionId=%v",
					bucket, srcObj, getString(srcObjVersions[0].VersionId))),
			})
			cancel()
			if err != nil {
				return err
			}

			if getString(out.CopySourceVersionId) != getString(srcObjVersions[0].VersionId) {
				return fmt.Errorf("expected the copy-source-version-id to be %v, instead got %v",
					getString(srcObjVersions[0].VersionId), getString(out.CopySourceVersionId))
			}

			return teardown(s, dstBucket)
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_Enable_object_lock(s *S3Conf) error {
	testName := "Versioning_Enable_object_lock"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.Status != types.BucketVersioningStatusEnabled {
			return fmt.Errorf("expected the bucket versioning status to be %v, instead got %v",
				types.BucketVersioningStatusEnabled, res.Status)
		}

		return nil
	}, withLock())
}

func Versioning_object_lock_not_enabled_on_bucket_creation(s *S3Conf) error {
	testName := "Versioning_not_enabled_on_bucket_creation"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
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
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotAllowed))
	})
}

func Versioning_status_switch_to_suspended_with_object_lock(s *S3Conf) error {
	testName := "Versioning_status_switch_to_suspended_with_object_lock"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusSuspended)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrSuspendedVersioningNotAllowed)); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func Versioning_PutObjectRetention_invalid_versionId(s *S3Conf) error {
	testName := "Versioning_PutObjectRetention_invalid_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := createObjVersions(s3client, bucket, obj, 1)
		if err != nil {
			return err
		}

		rDate := time.Now().Add(time.Hour * 48)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: getPtr("invalid_version_id"),
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeGovernance,
				RetainUntilDate: &rDate,
			},
		})
		cancel()
		return checkApiErr(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgVersionId, "invalid_version_id"))
	}, withLock())
}

func Versioning_PutObjectRetention_non_existing_object_version(s *S3Conf) error {
	testName := "Versioning_PutObjectRetention_non_existing_object_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			_, err := createObjVersions(s3client, bucket, obj, 3)
			if err != nil {
				return err
			}

			rDate := time.Now().Add(time.Hour * 48)
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: getPtr("01G65Z755AFWAKHE12NY0CQ9FH"),
				Retention: &types.ObjectLockRetention{
					Mode:            types.ObjectLockRetentionModeGovernance,
					RetainUntilDate: &rDate,
				},
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchVersion)); err != nil {
				return err
			}

			return nil
		})
	}, withLock(), withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_GetObjectRetention_invalid_versionId(s *S3Conf) error {
	testName := "Versioning_GetObjectRetention_invalid_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := createObjVersions(s3client, bucket, obj, 1)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: getPtr("invalid_versionId"),
		})
		cancel()
		return checkApiErr(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgVersionId, "invalid_versionId"))
	}, withLock())
}

func Versioning_GetObjectRetention_non_existing_object_version(s *S3Conf) error {
	testName := "Versioning_GetObjectRetention_non_existing_object_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			_, err := createObjVersions(s3client, bucket, obj, 3)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: getPtr("01G65Z755AFWAKHE12NY0CQ9FH"),
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchVersion)); err != nil {
				return err
			}

			return nil
		})
	}, withLock(), withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_Put_GetObjectRetention_delete_marker(s *S3Conf) error {
	testName := "Versioning_Put_GetObjectRetention_delete_marker"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-object", "my-dir/"}, func(obj string) error {
			_, err := putObjectWithData(objDataLen(obj, 10), &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			// PutObjectRetention
			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: out.VersionId,
				Retention: &types.ObjectLockRetention{
					Mode:            types.ObjectLockRetentionModeCompliance,
					RetainUntilDate: getPtr(time.Now().AddDate(1, 0, 0)),
				},
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMethodNotAllowed)); err != nil {
				return err
			}

			// GetObjectRetention
			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: out.VersionId,
			})
			cancel()

			return checkApiErr(err, s3err.GetAPIError(s3err.ErrMethodNotAllowed))
		})
	}, withLock())
}

func Versioning_Put_GetObjectRetention_success(s *S3Conf) error {
	testName := "Versioning_Put_GetObjectRetention_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			objVersions, err := createObjVersions(s3client, bucket, obj, 3)
			if err != nil {
				return err
			}
			objVersion := objVersions[1]

			rDate := time.Now().Add(time.Hour * 48)
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: objVersion.VersionId,
				Retention: &types.ObjectLockRetention{
					Mode:            types.ObjectLockRetentionModeGovernance,
					RetainUntilDate: &rDate,
				},
			})
			cancel()
			if err != nil {
				return err
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: objVersion.VersionId,
			})
			cancel()
			if err != nil {
				return err
			}

			if res.Retention.Mode != types.ObjectLockRetentionModeGovernance {
				return fmt.Errorf("expected the object retention mode to be %v, instead got %v",
					types.ObjectLockRetentionModeGovernance, res.Retention.Mode)
			}

			return cleanupLockedObjects(s3client, bucket, []objToDelete{{key: getString(objVersion.Key), versionId: getString(objVersion.VersionId)}})
		})
	}, withLock(), withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_PutObjectLegalHold_invalid_versionId(s *S3Conf) error {
	testName := "Versioning_PutObjectLegalHold_invalid_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := createObjVersions(s3client, bucket, obj, 1)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: getPtr("invalid_version_id"),
			LegalHold: &types.ObjectLockLegalHold{
				Status: types.ObjectLockLegalHoldStatusOn,
			},
		})
		cancel()
		return checkApiErr(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgVersionId, "invalid_version_id"))
	}, withLock())
}

func Versioning_PutObjectLegalHold_non_existing_object_version(s *S3Conf) error {
	testName := "Versioning_PutObjectLegalHold_non_existing_object_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			_, err := createObjVersions(s3client, bucket, obj, 3)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: getPtr("01G65Z755AFWAKHE12NY0CQ9FH"),
				LegalHold: &types.ObjectLockLegalHold{
					Status: types.ObjectLockLegalHoldStatusOn,
				},
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchVersion)); err != nil {
				return err
			}

			return nil
		})
	}, withLock(), withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_GetObjectLegalHold_invalid_versionId(s *S3Conf) error {
	testName := "Versioning_GetObjectLegalHold_invalid_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := createObjVersions(s3client, bucket, obj, 3)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: getPtr("invalid_version_id"),
		})
		cancel()
		return checkApiErr(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgVersionId, "invalid_version_id"))
	}, withLock())
}

func Versioning_GetObjectLegalHold_non_existing_object_version(s *S3Conf) error {
	testName := "Versioning_GetObjectLegalHold_non_existing_object_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			_, err := createObjVersions(s3client, bucket, obj, 3)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: getPtr("01G65Z755AFWAKHE12NY0CQ9FH"),
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchVersion)); err != nil {
				return err
			}

			return nil
		})
	}, withLock(), withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_PutGetObjectLegalHold_delete_marker(s *S3Conf) error {
	testName := "Versioning_PutGetObjectLegalHold_delete_marker"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-object", "my-dir/"}, func(obj string) error {
			_, err := putObjectWithData(objDataLen(obj, 10), &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			// PutObjectLegalHold
			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: out.VersionId,
				LegalHold: &types.ObjectLockLegalHold{
					Status: types.ObjectLockLegalHoldStatusOn,
				},
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMethodNotAllowed)); err != nil {
				return err
			}

			// GetObjectLegalHold
			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: out.VersionId,
			})
			cancel()

			return checkApiErr(err, s3err.GetAPIError(s3err.ErrMethodNotAllowed))
		})
	}, withLock())
}

func Versioning_Put_GetObjectLegalHold_success(s *S3Conf) error {
	testName := "Versioning_Put_GetObjectLegalHold_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			objVersions, err := createObjVersions(s3client, bucket, obj, 3)
			if err != nil {
				return err
			}
			objVersion := objVersions[1]

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: objVersion.VersionId,
				LegalHold: &types.ObjectLockLegalHold{
					Status: types.ObjectLockLegalHoldStatusOn,
				},
			})
			cancel()
			if err != nil {
				return err
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: objVersion.VersionId,
			})
			cancel()
			if err != nil {
				return err
			}

			if res.LegalHold.Status != types.ObjectLockLegalHoldStatusOn {
				return fmt.Errorf("expected the object version legal hold status to be %v, instead got %v",
					types.ObjectLockLegalHoldStatusOn, res.LegalHold.Status)
			}

			return cleanupLockedObjects(s3client, bucket, []objToDelete{
				{
					key:                getString(objVersion.Key),
					versionId:          getString(objVersion.VersionId),
					removeOnlyLeglHold: true,
				},
			})
		})
	}, withLock(), withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_WORM_obj_version_locked_with_legal_hold(s *S3Conf) error {
	testName := "Versioning_WORM_obj_version_locked_with_legal_hold"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			objVersions, err := createObjVersions(s3client, bucket, obj, 2)
			if err != nil {
				return err
			}
			version := objVersions[1]

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: version.VersionId,
				LegalHold: &types.ObjectLockLegalHold{
					Status: types.ObjectLockLegalHoldStatusOn,
				},
			})
			cancel()
			if err != nil {
				return err
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: version.VersionId,
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
				return err
			}

			return cleanupLockedObjects(s3client, bucket, []objToDelete{
				{
					key:                obj,
					versionId:          getString(version.VersionId),
					removeOnlyLeglHold: true,
				},
			})
		})
	}, withLock(), withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_WORM_dir_object_lock_headers(s *S3Conf) error {
	testName := "Versioning_WORM_dir_object_lock_headers"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-dir/"
		rDate := time.Now().Add(time.Hour * 48)
		lockedObjs := []objToDelete{}

		for i, test := range []struct {
			legalHold       types.ObjectLockLegalHoldStatus
			mode            types.ObjectLockMode
			retainUntilDate *time.Time
		}{
			{legalHold: types.ObjectLockLegalHoldStatusOn},
			{mode: types.ObjectLockModeGovernance, retainUntilDate: &rDate},
		} {
			res, err := putObjectWithData(0, &s3.PutObjectInput{
				Bucket:                    &bucket,
				Key:                       &obj,
				ObjectLockLegalHoldStatus: test.legalHold,
				ObjectLockMode:            test.mode,
				ObjectLockRetainUntilDate: test.retainUntilDate,
			}, s3client)
			if err != nil {
				return fmt.Errorf("test %v: %w", i+1, err)
			}

			lockedObjs = append(lockedObjs, objToDelete{
				key:                obj,
				versionId:          getString(res.res.VersionId),
				removeOnlyLeglHold: test.legalHold == types.ObjectLockLegalHoldStatusOn,
			})

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return fmt.Errorf("test %v: %w", i+1, err)
			}

			if out.ObjectLockLegalHoldStatus != test.legalHold {
				return fmt.Errorf("test %v: expected the object legal hold status to be %q, instead got %q",
					i+1, test.legalHold, out.ObjectLockLegalHoldStatus)
			}
			if out.ObjectLockMode != test.mode {
				return fmt.Errorf("test %v: expected the object lock mode to be %q, instead got %q",
					i+1, test.mode, out.ObjectLockMode)
			}
			if test.retainUntilDate == nil {
				if out.ObjectLockRetainUntilDate != nil {
					return fmt.Errorf("test %v: expected nil object lock retain until date, instead got %v",
						i+1, *out.ObjectLockRetainUntilDate)
				}
			} else if out.ObjectLockRetainUntilDate == nil ||
				out.ObjectLockRetainUntilDate.Unix() != test.retainUntilDate.Unix() {
				return fmt.Errorf("test %v: expected the object lock retain until date to be %v, instead got %v",
					i+1, test.retainUntilDate.Format(time.RFC3339), out.ObjectLockRetainUntilDate)
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: res.res.VersionId,
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
				return fmt.Errorf("test %v: %w", i+1, err)
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		if out.DeleteMarker == nil || !*out.DeleteMarker {
			return fmt.Errorf("expected the delete marker to be true, instead got %v", out.DeleteMarker)
		}
		if getString(out.VersionId) == "" {
			return fmt.Errorf("expected non empty delete marker versionId")
		}

		// the noncurrent versions keep their lock settings
		for _, lockedObj := range lockedObjs {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: &lockedObj.versionId,
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
				return fmt.Errorf("version %v: %w", lockedObj.versionId, err)
			}
		}

		return cleanupLockedObjects(s3client, bucket, lockedObjs)
	}, withLock())
}

func Versioning_WORM_obj_version_locked_with_governance_retention(s *S3Conf) error {
	testName := "Versioning_WORM_obj_version_locked_with_governance_retention"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			objVersions, err := createObjVersions(s3client, bucket, obj, 2)
			if err != nil {
				return err
			}
			version := objVersions[0]

			rDate := time.Now().Add(time.Hour * 48)
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: version.VersionId,
				Retention: &types.ObjectLockRetention{
					Mode:            types.ObjectLockRetentionModeGovernance,
					RetainUntilDate: &rDate,
				},
			})
			cancel()
			if err != nil {
				return err
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: version.VersionId,
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
				return err
			}

			return cleanupLockedObjects(s3client, bucket, []objToDelete{
				{
					key:       obj,
					versionId: getString(version.VersionId),
				},
			})
		})
	}, withLock(), withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_WORM_obj_version_locked_with_compliance_retention(s *S3Conf) error {
	testName := "Versioning_WORM_obj_version_locked_with_compliance_retention"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		// COMPLIANCE retentions can only be waited out, so the locked
		// versions of all the keys are cleaned up together
		lockedObjs := []objToDelete{}
		err := forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			objVersions, err := createObjVersions(s3client, bucket, obj, 2)
			if err != nil {
				return err
			}
			version := objVersions[0]

			rDate := time.Now().Add(2 * complianceTestRetention)
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: version.VersionId,
				Retention: &types.ObjectLockRetention{
					Mode:            types.ObjectLockRetentionModeCompliance,
					RetainUntilDate: &rDate,
				},
			})
			cancel()
			if err != nil {
				return err
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: version.VersionId,
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
				return err
			}

			lockedObjs = append(lockedObjs, objToDelete{
				key:          obj,
				versionId:    getString(version.VersionId),
				isCompliance: true,
			})
			return nil
		})
		if err != nil {
			return err
		}

		return cleanupLockedObjects(s3client, bucket, lockedObjs)
	}, withLock(), withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_WORM_delete_marker_locked_object_legal_hold(s *S3Conf) error {
	testName := "Versioning_WORM_delete_marker_locked_object_legal_hold"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			objVersions, err := createObjVersions(s3client, bucket, obj, 1)
			if err != nil {
				return err
			}
			version := objVersions[0]
			objVersions[0].IsLatest = getPtr(false)

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
				Bucket: &bucket,
				Key:    &obj,
				LegalHold: &types.ObjectLockLegalHold{
					Status: types.ObjectLockLegalHoldStatusOn,
				},
			})
			cancel()
			if err != nil {
				return err
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			delMarkers := []types.DeleteMarkerEntry{
				{
					IsLatest:  getPtr(true),
					Key:       &obj,
					VersionId: out.VersionId,
				},
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			resp, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
				Bucket: &bucket,
				Prefix: &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			if !compareVersions(objVersions, resp.Versions) {
				return fmt.Errorf("expected the object versions to be %v, instead got %v", objVersions, resp.Versions)
			}
			if !compareDelMarkers(delMarkers, resp.DeleteMarkers) {
				return fmt.Errorf("expected the object delete markers to be %v, instead got %v", delMarkers, resp.DeleteMarkers)
			}

			return cleanupLockedObjects(s3client, bucket, []objToDelete{
				{
					key:                obj,
					versionId:          getString(version.VersionId),
					removeOnlyLeglHold: true,
				},
			})
		})
	}, withLock())
}

func Versioning_WORM_delete_marker_locked_object_governance_retention(s *S3Conf) error {
	testName := "Versioning_WORM_delete_marker_locked_object_governance_retention"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			objVersions, err := createObjVersions(s3client, bucket, obj, 1)
			if err != nil {
				return err
			}
			version := objVersions[0]
			objVersions[0].IsLatest = getPtr(false)

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
				Bucket: &bucket,
				Key:    &obj,
				Retention: &types.ObjectLockRetention{
					Mode:            types.ObjectLockRetentionModeGovernance,
					RetainUntilDate: getPtr(time.Now().AddDate(1, 0, 0)),
				},
			})
			cancel()
			if err != nil {
				return err
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			delMarkers := []types.DeleteMarkerEntry{
				{
					IsLatest:  getPtr(true),
					Key:       &obj,
					VersionId: out.VersionId,
				},
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			resp, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
				Bucket: &bucket,
				Prefix: &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			if !compareVersions(objVersions, resp.Versions) {
				return fmt.Errorf("expected the object versions to be %v, instead got %v", objVersions, resp.Versions)
			}
			if !compareDelMarkers(delMarkers, resp.DeleteMarkers) {
				return fmt.Errorf("expected the object delete markers to be %v, instead got %v", delMarkers, resp.DeleteMarkers)
			}

			return cleanupLockedObjects(s3client, bucket, []objToDelete{
				{
					key:          obj,
					versionId:    getString(version.VersionId),
					isCompliance: false,
				},
			})
		})
	}, withLock())
}

func Versioning_WORM_delete_marker_locked_object_compliance_retention(s *S3Conf) error {
	testName := "Versioning_WORM_delete_marker_locked_object_compliance_retention"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		// COMPLIANCE retentions can only be waited out, so the locked
		// versions of all the keys are cleaned up together
		lockedObjs := []objToDelete{}
		err := forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			objVersions, err := createObjVersions(s3client, bucket, obj, 1)
			if err != nil {
				return err
			}
			version := objVersions[0]
			objVersions[0].IsLatest = getPtr(false)

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
				Bucket: &bucket,
				Key:    &obj,
				Retention: &types.ObjectLockRetention{
					Mode:            types.ObjectLockRetentionModeCompliance,
					RetainUntilDate: getPtr(time.Now().Add(complianceTestRetention)),
				},
			})
			cancel()
			if err != nil {
				return err
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			delMarkers := []types.DeleteMarkerEntry{
				{
					IsLatest:  getPtr(true),
					Key:       &obj,
					VersionId: out.VersionId,
				},
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			resp, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
				Bucket: &bucket,
				Prefix: &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			if !compareVersions(objVersions, resp.Versions) {
				return fmt.Errorf("expected the object versions to be %v, instead got %v", objVersions, resp.Versions)
			}
			if !compareDelMarkers(delMarkers, resp.DeleteMarkers) {
				return fmt.Errorf("expected the object delete markers to be %v, instead got %v", delMarkers, resp.DeleteMarkers)
			}

			lockedObjs = append(lockedObjs, objToDelete{
				key:          obj,
				versionId:    getString(version.VersionId),
				isCompliance: true,
			})
			return nil
		})
		if err != nil {
			return err
		}

		return cleanupLockedObjects(s3client, bucket, lockedObjs)
	}, withLock())
}

func Versioning_WORM_PutObject_overwrite_locked_object(s *S3Conf) error {
	testName := "Versioning_WORM_PutObject_overwrite_locked_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			versions, err := createObjVersions(s3client, bucket, obj, 1)
			if err != nil {
				return err
			}

			v := versions[0]
			v.IsLatest = getPtr(false)

			// lock the object with legal hold
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
				Bucket: &bucket,
				Key:    &obj,
				LegalHold: &types.ObjectLockLegalHold{
					Status: types.ObjectLockLegalHoldStatusOn,
				},
			})
			cancel()
			if err != nil {
				return err
			}

			dataLen := objDataLen(obj, 10)

			// overwrite the locked object with a new version
			r, err := putObjectWithData(dataLen, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}

			version := types.ObjectVersion{
				ETag:         r.res.ETag,
				IsLatest:     getPtr(true),
				Key:          &obj,
				Size:         &dataLen,
				VersionId:    r.res.VersionId,
				StorageClass: types.ObjectVersionStorageClassStandard,
				ChecksumType: r.res.ChecksumType,
			}

			result := []types.ObjectVersion{version, v}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
				Bucket: &bucket,
				Prefix: &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			if !compareVersions(result, out.Versions) {
				return fmt.Errorf("expected the object versions to be %v, instead got %v", result, out.Versions)
			}

			return cleanupLockedObjects(s3client, bucket, []objToDelete{
				{
					key:                obj,
					versionId:          getString(v.VersionId),
					removeOnlyLeglHold: true,
				},
			})
		})
	}, withLock())
}

func Versioning_WORM_CopyObject_overwrite_locked_object(s *S3Conf) error {
	testName := "Versioning_WORM_CopyObject_overwrite_locked_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			versions, err := createObjVersions(s3client, bucket, obj, 1)
			if err != nil {
				return err
			}

			v := versions[0]
			v.IsLatest = getPtr(false)

			// lock the object with legal hold
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
				Bucket: &bucket,
				Key:    &obj,
				LegalHold: &types.ObjectLockLegalHold{
					Status: types.ObjectLockLegalHoldStatusOn,
				},
			})
			cancel()
			if err != nil {
				return err
			}

			// create a source object version, a directory object for a
			// directory object destination
			srcObj := "source-object"
			if strings.HasSuffix(obj, "/") {
				srcObj = "source-dir/"
			}
			srcVersions, err := createObjVersions(s3client, bucket, srcObj, 1)
			if err != nil {
				return err
			}

			srcVersion := srcVersions[0]

			// overwrite the locked object with a new version with CopyObject
			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			copyResult, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
				Bucket:     &bucket,
				Key:        &obj,
				CopySource: getPtr(fmt.Sprintf("%s/%s", bucket, srcObj)),
			})
			cancel()
			if err != nil {
				return err
			}

			version := types.ObjectVersion{
				ETag:         copyResult.CopyObjectResult.ETag,
				IsLatest:     getPtr(true),
				Key:          &obj,
				Size:         srcVersion.Size,
				VersionId:    copyResult.VersionId,
				StorageClass: types.ObjectVersionStorageClassStandard,
				ChecksumType: copyResult.CopyObjectResult.ChecksumType,
			}

			// the destination and the source versions are listed separately,
			// as the bucket also holds the versions of the other keys
			for _, result := range [][]types.ObjectVersion{{version, v}, {srcVersion}} {
				ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
				out, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
					Bucket: &bucket,
					Prefix: result[0].Key,
				})
				cancel()
				if err != nil {
					return err
				}

				if !compareVersions(result, out.Versions) {
					return fmt.Errorf("expected the object versions to be %v, instead got %v", result, out.Versions)
				}
			}

			return cleanupLockedObjects(s3client, bucket, []objToDelete{
				{
					key:                obj,
					versionId:          getString(v.VersionId),
					removeOnlyLeglHold: true,
				},
			})
		})
	}, withLock())
}

// A copy of a locked object onto itself creates a new version, leaving the
// locked one and its legal hold in place.
func Versioning_WORM_CopyObject_to_itself_locked_object(s *S3Conf) error {
	testName := "Versioning_WORM_CopyObject_to_itself_locked_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			versions, err := createObjVersions(s3client, bucket, obj, 1)
			if err != nil {
				return err
			}

			v := versions[0]
			v.IsLatest = getPtr(false)
			lockedVersionId := getString(v.VersionId)

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
				Bucket: &bucket,
				Key:    &obj,
				LegalHold: &types.ObjectLockLegalHold{
					Status: types.ObjectLockLegalHoldStatusOn,
				},
			})
			cancel()
			if err != nil {
				return err
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			copyResult, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
				Bucket:            &bucket,
				Key:               &obj,
				CopySource:        getPtr(fmt.Sprintf("%v/%v", bucket, obj)),
				MetadataDirective: types.MetadataDirectiveReplace,
				ContentType:       getPtr("application/json"),
			})
			cancel()
			if err != nil {
				return err
			}

			if getString(copyResult.VersionId) == lockedVersionId {
				return fmt.Errorf("expected a new versionId, instead got %v",
					getString(copyResult.VersionId))
			}

			version := types.ObjectVersion{
				ETag:         copyResult.CopyObjectResult.ETag,
				IsLatest:     getPtr(true),
				Key:          &obj,
				Size:         v.Size,
				VersionId:    copyResult.VersionId,
				StorageClass: types.ObjectVersionStorageClassStandard,
				ChecksumType: copyResult.CopyObjectResult.ChecksumType,
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
				Bucket: &bucket,
				Prefix: &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			if !compareVersions([]types.ObjectVersion{version, v}, out.Versions) {
				return fmt.Errorf("expected the object versions to be %v, instead got %v",
					[]types.ObjectVersion{version, v}, out.Versions)
			}

			// the legal hold stays on the version it was set on
			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			lhRes, err := s3client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: &lockedVersionId,
			})
			cancel()
			if err != nil {
				return err
			}

			if lhRes.LegalHold.Status != types.ObjectLockLegalHoldStatusOn {
				return fmt.Errorf("expected the legal hold status to be %v, instead got %v",
					types.ObjectLockLegalHoldStatusOn, lhRes.LegalHold.Status)
			}

			return cleanupLockedObjects(s3client, bucket, []objToDelete{
				{
					key:                obj,
					versionId:          lockedVersionId,
					removeOnlyLeglHold: true,
				},
			})
		})
	}, withLock())
}

func Versioning_WORM_CompleteMultipartUpload_overwrite_locked_object(s *S3Conf) error {
	testName := "Versioning_WORM_CompleteMultipartUpload_overwrite_locked_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		versions, err := createObjVersions(s3client, bucket, obj, 1)
		if err != nil {
			return err
		}

		v := versions[0]
		v.IsLatest = getPtr(false)

		// lock the object with legal hold
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
			Bucket: &bucket,
			Key:    &obj,
			LegalHold: &types.ObjectLockLegalHold{
				Status: types.ObjectLockLegalHoldStatusOn,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		dataLen := int64(5 * 1024 * 1024)

		// overwrite the locked object with a new version
		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, dataLen, 1, bucket, obj, *mp.UploadId)
		if err != nil {
			return err
		}
		part := parts[0]

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket: &bucket,
			Key:    &obj,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: []types.CompletedPart{
					{
						ETag:       part.ETag,
						PartNumber: part.PartNumber,
					},
				},
			},
			UploadId: mp.UploadId,
		})
		cancel()
		if err != nil {
			return err
		}

		version := types.ObjectVersion{
			ETag:         res.ETag,
			IsLatest:     getPtr(true),
			Key:          &obj,
			Size:         &dataLen,
			VersionId:    res.VersionId,
			StorageClass: types.ObjectVersionStorageClassStandard,
		}

		result := []types.ObjectVersion{version, v}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareVersions(result, out.Versions) {
			return fmt.Errorf("expected the object versions to be %v, instead got %v", result, out.Versions)
		}

		return cleanupLockedObjects(s3client, bucket, []objToDelete{
			{
				key:                obj,
				versionId:          getString(v.VersionId),
				removeOnlyLeglHold: true,
			},
		})
	}, withLock())
}

func Versioning_WORM_remove_delete_marker_under_bucket_default_retention(s *S3Conf) error {
	testName := "Versioning_WORM_remove_delete_marker_under_bucket_default_retention"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
			ObjectLockConfiguration: &types.ObjectLockConfiguration{
				ObjectLockEnabled: types.ObjectLockEnabledEnabled,
				Rule: &types.ObjectLockRule{
					DefaultRetention: &types.DefaultRetention{
						Mode: types.ObjectLockRetentionModeGovernance,
						Days: getPtr(int32(5)),
					},
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		return forEachKey([]string{"my-object", "my-dir/"}, func(obj string) error {
			versions, err := createObjVersions(s3client, bucket, obj, 3)
			if err != nil {
				return err
			}

			// Create a delete marker
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			// Delete the delete marker
			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: out.VersionId,
			})
			cancel()
			if err != nil {
				return err
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			resp, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
				Bucket: &bucket,
				Prefix: &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			if !compareVersions(versions, resp.Versions) {
				return fmt.Errorf("expected the object vresions to be %v, instead got %v", versions, resp.Versions)
			}
			if len(resp.DeleteMarkers) != 0 {
				return fmt.Errorf("expected empty delete markers list, instead got %v", resp.DeleteMarkers)
			}

			//
			lockedVersions := make([]objToDelete, 0, len(versions))
			for _, v := range versions {
				lockedVersions = append(lockedVersions, objToDelete{
					key:          obj,
					versionId:    getString(v.VersionId),
					isCompliance: false,
				})
			}
			return cleanupLockedObjects(s3client, bucket, lockedVersions)
		})
	}, withLock())
}

func Versioning_WORM_trailing_slash_counterpart(s *S3Conf) error {
	testName := "Versioning_WORM_trailing_slash_counterpart"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		rDate := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
		lockedObjs := []objToDelete{}

		for _, keys := range [][2]string{{"my-dir/", "my-dir"}, {"my-obj", "my-obj/"}} {
			obj, other := keys[0], keys[1]
			res, err := putObjectWithData(objDataLen(obj, 10), &s3.PutObjectInput{
				Bucket:                    &bucket,
				Key:                       &obj,
				ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatusOn,
				ObjectLockMode:            types.ObjectLockModeGovernance,
				ObjectLockRetainUntilDate: &rDate,
			}, s3client)
			if err != nil {
				return err
			}
			versionId := getString(res.res.VersionId)
			lockedObjs = append(lockedObjs, objToDelete{
				key:                obj,
				versionId:          versionId,
				removeOnlyLeglHold: true,
			})

			// the version belongs to the object, not to the other key
			err = checkObjectLockErr(s3client, bucket, other, versionId, s3err.GetAPIError(s3err.ErrNoSuchVersion))
			if err != nil {
				return fmt.Errorf("%v: %w", other, err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket:    &bucket,
				Key:       &other,
				VersionId: &versionId,
			})
			cancel()
			if err != nil {
				return fmt.Errorf("%v: %w", other, err)
			}

			err = checkObjectLock(s3client, bucket, obj, versionId, rDate)
			if err != nil {
				return fmt.Errorf("%v: %w", obj, err)
			}
		}

		return cleanupLockedObjects(s3client, bucket, lockedObjs)
	}, withLock())
}

func Versioning_WORM_null_version_locked_with_legal_hold(s *S3Conf) error {
	testName := "Versioning_WORM_null_version_locked_with_legal_hold"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objs := []string{"my-obj", "my-dir/"}
		// the objects are put before versioning is enabled: their
		// current versions are the null versions
		_, err := putObjects(s3client, objs, bucket)
		if err != nil {
			return err
		}

		err = putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusEnabled)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
			ObjectLockConfiguration: &types.ObjectLockConfiguration{
				ObjectLockEnabled: types.ObjectLockEnabledEnabled,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		lockedObjs := []objToDelete{}
		err = forEachKey(objs, func(obj string) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: getPtr(nullVersionId),
				LegalHold: &types.ObjectLockLegalHold{
					Status: types.ObjectLockLegalHoldStatusOn,
				},
			})
			cancel()
			if err != nil {
				return err
			}
			lockedObjs = append(lockedObjs, objToDelete{
				key:                obj,
				versionId:          nullVersionId,
				removeOnlyLeglHold: true,
			})

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: getPtr(nullVersionId),
			})
			cancel()
			if err != nil {
				return err
			}
			if res.LegalHold == nil || res.LegalHold.Status != types.ObjectLockLegalHoldStatusOn {
				return fmt.Errorf("expected the legal hold status to be %q, instead got %v",
					types.ObjectLockLegalHoldStatusOn, res.LegalHold)
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: getPtr(nullVersionId),
			})
			cancel()
			return checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked))
		})
		if err != nil {
			return err
		}

		return cleanupLockedObjects(s3client, bucket, lockedObjs)
	})
}

func Versioning_AccessControl_GetObjectVersion(s *S3Conf) error {
	testName := "Versioning_AccessControl_GetObjectVersion"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		err := createUsers(s, []user{testuser})
		if err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)

		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			objData, err := putObjectWithData(objDataLen(obj, 10), &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}

			doc := genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser.access), `"s3:GetObject"`, fmt.Sprintf(`"arn:aws:s3:::%s/*"`, bucket))
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
				Bucket: &bucket,
				Policy: &doc,
			})
			cancel()
			if err != nil {
				return err
			}

			// querying with versionId should return access denied
			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = userClient.GetObject(ctx, &s3.GetObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: objData.res.VersionId,
			})
			defer cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
				return err
			}

			// grant the user s3:GetObjectVersion
			doc = genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser.access), `"s3:GetObjectVersion"`, fmt.Sprintf(`"arn:aws:s3:::%s/*"`, bucket))
			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
				Bucket: &bucket,
				Policy: &doc,
			})
			cancel()
			if err != nil {
				return err
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = userClient.GetObject(ctx, &s3.GetObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: objData.res.VersionId,
			})
			defer cancel()
			if err != nil {
				return err
			}

			return nil
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_AccessControl_HeadObjectVersion(s *S3Conf) error {
	testName := "Versioning_AccessControl_HeadObjectVersion"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		err := createUsers(s, []user{testuser})
		if err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)

		return forEachKey([]string{"my-obj", "my-dir/"}, func(obj string) error {
			objData, err := putObjectWithData(objDataLen(obj, 10), &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}

			doc := genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser.access), `"s3:GetObject"`, fmt.Sprintf(`"arn:aws:s3:::%s/*"`, bucket))
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
				Bucket: &bucket,
				Policy: &doc,
			})
			cancel()
			if err != nil {
				return err
			}

			// querying with versionId should return access denied
			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = userClient.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: objData.res.VersionId,
			})
			cancel()
			if err := checkSdkApiErr(err, http.StatusText(http.StatusForbidden)); err != nil {
				return err
			}

			// grant the user s3:GetObjectVersion
			doc = genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser.access), `"s3:GetObjectVersion"`, fmt.Sprintf(`"arn:aws:s3:::%s/*"`, bucket))
			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
				Bucket: &bucket,
				Policy: &doc,
			})
			cancel()
			if err != nil {
				return err
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = userClient.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: objData.res.VersionId,
			})
			cancel()
			if err != nil {
				return err
			}

			return nil
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_AccessControl_object_tagging_policy(s *S3Conf) error {
	testName := "Versioning_AccessControl_PutObjectTagging_policy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		err := createUsers(s, []user{testuser})
		if err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)

		return forEachKey([]string{"my-object", "my-dir/"}, func(object string) error {
			res, err := putObjectWithData(objDataLen(object, 10), &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &object,
			}, s3client)
			if err != nil {
				return err
			}

			putGetDeleteObjectTagging := func(versionId *string, denyAccess bool) error {
				ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
				_, err := userClient.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
					Bucket:    &bucket,
					Key:       &object,
					VersionId: versionId,
					Tagging: &types.Tagging{
						TagSet: []types.Tag{
							{Key: getPtr("key"), Value: getPtr("value")},
						},
					},
				})
				cancel()
				if denyAccess {
					if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
						return err
					}
				} else {
					if err != nil {
						return err
					}
				}

				ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
				_, err = userClient.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
					Bucket:    &bucket,
					Key:       &object,
					VersionId: versionId,
				})
				cancel()
				if denyAccess {
					if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
						return err
					}
				} else {
					if err != nil {
						return err
					}
				}

				ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
				_, err = userClient.DeleteObjectTagging(ctx, &s3.DeleteObjectTaggingInput{
					Bucket:    &bucket,
					Key:       &object,
					VersionId: versionId,
				})
				cancel()
				if denyAccess {
					if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
						return err
					}
				} else {
					if err != nil {
						return err
					}
				}

				return nil
			}

			policy := genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser.access), `["s3:PutObjectVersionTagging", "s3:GetObjectVersionTagging", "s3:DeleteObjectVersionTagging"]`, fmt.Sprintf(`"arn:aws:s3:::%s/*"`, bucket))
			err = putBucketPolicy(s3client, bucket, policy)
			if err != nil {
				return err
			}

			// deny without versionId
			err = putGetDeleteObjectTagging(nil, true)
			if err != nil {
				return err
			}

			// allow with versionId
			err = putGetDeleteObjectTagging(res.res.VersionId, false)
			if err != nil {
				return err
			}

			policy = genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser.access), `["s3:PutObjectTagging", "s3:GetObjectTagging", "s3:DeleteObjectTagging"]`, fmt.Sprintf(`"arn:aws:s3:::%s/*"`, bucket))
			err = putBucketPolicy(s3client, bucket, policy)
			if err != nil {
				return err
			}

			// allow without versionId
			err = putGetDeleteObjectTagging(nil, false)
			if err != nil {
				return err
			}

			// deny with versionId
			err = putGetDeleteObjectTagging(res.res.VersionId, true)
			if err != nil {
				return err
			}

			return nil
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_AccessControl_DeleteObject_policy(s *S3Conf) error {
	testName := "Versioning_AccessControl_DeleteObject_policy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		err := createUsers(s, []user{testuser})
		if err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)

		return forEachKey([]string{"my-object", "my-dir/"}, func(obj string) error {
			delObject := func(versionId *string, denyAccess bool) error {
				ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
				_, err := userClient.DeleteObject(ctx, &s3.DeleteObjectInput{
					Bucket:    &bucket,
					Key:       &obj,
					VersionId: versionId,
				})
				cancel()
				if denyAccess {
					return checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied))
				}

				return err
			}

			res, err := putObjectWithData(objDataLen(obj, 10), &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}

			policy := genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser.access), `"s3:DeleteObject"`, fmt.Sprintf(`"arn:aws:s3:::%s/*"`, bucket))
			err = putBucketPolicy(s3client, bucket, policy)
			if err != nil {
				return err
			}

			// deny with versionId
			err = delObject(res.res.VersionId, true)
			if err != nil {
				return err
			}

			// allow without versionId
			err = delObject(nil, false)
			if err != nil {
				return err
			}

			policy = genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser.access), `"s3:DeleteObjectVersion"`, fmt.Sprintf(`"arn:aws:s3:::%s/*"`, bucket))
			err = putBucketPolicy(s3client, bucket, policy)
			if err != nil {
				return err
			}

			// recreate the object
			res, err = putObjectWithData(objDataLen(obj, 10), &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}

			// deny without versionId
			err = delObject(nil, true)
			if err != nil {
				return err
			}

			// allow with versionId
			err = delObject(res.res.VersionId, false)
			if err != nil {
				return err
			}

			return nil
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_AccessControl_GetObjectAttributes_policy(s *S3Conf) error {
	testName := "Versioning_AccessControl_GetObjectAttributes_policy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		err := createUsers(s, []user{testuser})
		if err != nil {
			return err
		}
		userClient := s.getUserClient(testuser)

		return forEachKey([]string{"my-object", "my-dir/"}, func(obj string) error {
			res, err := putObjectWithData(objDataLen(obj, 10), &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}

			getObjectAttr := func(versionId *string, denyAccess bool) error {
				ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
				_, err := userClient.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
					Bucket:           &bucket,
					Key:              &obj,
					VersionId:        versionId,
					ObjectAttributes: types.ObjectAttributesChecksum.Values(),
				})
				cancel()
				if denyAccess {
					return checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied))
				}

				return nil
			}

			policy := genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser.access), `"s3:GetObjectAttributes"`, fmt.Sprintf(`"arn:aws:s3:::%s/*"`, bucket))
			err = putBucketPolicy(s3client, bucket, policy)
			if err != nil {
				return err
			}

			// deny with versionId
			err = getObjectAttr(res.res.VersionId, true)
			if err != nil {
				return err
			}

			// allow without versionId
			err = getObjectAttr(nil, false)
			if err != nil {
				return err
			}

			policy = genPolicyDoc("Allow", fmt.Sprintf(`"%s"`, testuser.access), `"s3:GetObjectVersionAttributes"`, fmt.Sprintf(`"arn:aws:s3:::%s/*"`, bucket))
			err = putBucketPolicy(s3client, bucket, policy)
			if err != nil {
				return err
			}

			// deny without versionId
			err = getObjectAttr(nil, true)
			if err != nil {
				return err
			}

			// allow with versionId
			err = getObjectAttr(res.res.VersionId, false)
			if err != nil {
				return err
			}

			return nil
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func VersioningDisabled_GetBucketVersioning_not_configured(s *S3Conf) error {
	testName := "VersioningDisabled_GetBucketVersioning_not_configured"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}
		if res.Status != "" {
			return fmt.Errorf("expected empty versioning status when versioning is not configured, instead got %v",
				res.Status)
		}

		return nil
	})
}

func VersioningDisabled_GetBucketVersioning_no_such_bucket(s *S3Conf) error {
	testName := "VersioningDisabled_GetBucketVersioning_no_such_bucket"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func VersioningDisabled_PutBucketVersioning_not_configured(s *S3Conf) error {
	testName := "VersioningDisabled_PutBucketVersioning_not_configured"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusEnabled)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrVersioningNotConfigured)); err != nil {
			return err
		}

		return nil
	})
}

func Versioning_concurrent_upload_object(s *S3Conf) error {
	testName := "Versioninig_concurrent_upload_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		versionCount := 5
		// Channel to collect errors
		errCh := make(chan error, versionCount)

		uploadVersion := func(wg *sync.WaitGroup) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.PutObject(ctx, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				// Send error to the channel
				errCh <- err
				return
			}

			fmt.Printf("uploaded object successfully: versionId: %v\n", *res.VersionId)
		}

		wg := &sync.WaitGroup{}
		wg.Add(versionCount)

		for range versionCount {
			go uploadVersion(wg)
		}

		wg.Wait()
		close(errCh)

		// Check if there were any errors
		for err := range errCh {
			if err != nil {
				fmt.Printf("error uploading an object: %v\n", err.Error())
				return err
			}
		}

		// List object versions after all uploads
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if len(res.Versions) != versionCount {
			return fmt.Errorf("expected %v object versions, instead got %v",
				versionCount, len(res.Versions))
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_GetObjectTagging_invalid_versionId(s *S3Conf) error {
	testName := "Versioning_GetObjectTagging_invalid_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-object"
		_, err := putObjectWithData(4, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: getPtr("invalid_versionId"),
		})
		cancel()
		return checkApiErr(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgVersionId, "invalid_versionId"))
	})
}

func Versioning_PutObjectTagging_non_existing_object_version(s *S3Conf) error {
	testName := "Versioning_PutObjectTagging_non_existing_object_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-object", "my-dir/"}, func(obj string) error {
			_, err := putObjectWithData(objDataLen(obj, 4), &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
				Bucket: &bucket,
				Key:    &obj,
				Tagging: &types.Tagging{
					TagSet: []types.Tag{{Key: getPtr("key"), Value: getPtr("value")}},
				},
				VersionId: getPtr("01K97XE6PJQ1A4X5TJFDHK4EMC"),
			})
			cancel()
			return checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchVersion))
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_PutGetDeleteObjectTagging_delete_marker(s *S3Conf) error {
	testName := "Versioning_PutGetDeleteObjectTagging_delete_marker"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-object", "my-dir/"}, func(obj string) error {
			_, err := putObjectWithData(objDataLen(obj, 10), &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}

			// PutObjectTagging
			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: out.VersionId,
				Tagging: &types.Tagging{
					TagSet: []types.Tag{{Key: getPtr("key"), Value: getPtr("value")}},
				},
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMethodNotAllowed)); err != nil {
				return err
			}

			// GetObjectTagging
			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: out.VersionId,
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMethodNotAllowed)); err != nil {
				return err
			}

			// DeleteObjectTagging
			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.DeleteObjectTagging(ctx, &s3.DeleteObjectTaggingInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: out.VersionId,
			})
			cancel()

			return checkApiErr(err, s3err.GetAPIError(s3err.ErrMethodNotAllowed))
		})
	}, withLock())
}

func Versioning_PutObjectTagging_invalid_versionId(s *S3Conf) error {
	testName := "Versioning_PutObjectTagging_invalid_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-object"
		_, err := putObjectWithData(4, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
			Bucket: &bucket,
			Key:    &obj,
			Tagging: &types.Tagging{
				TagSet: []types.Tag{{Key: getPtr("key"), Value: getPtr("value")}},
			},
			VersionId: getPtr("invalid_versionId"),
		})
		cancel()
		return checkApiErr(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgVersionId, "invalid_versionId"))
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_GetObjectTagging_non_existing_object_version(s *S3Conf) error {
	testName := "Versioning_GetObjectTagging_non_existing_object_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-object", "my-dir/"}, func(obj string) error {
			_, err := putObjectWithData(objDataLen(obj, 4), &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: getPtr("01K97XE6PJQ1A4X5TJFDHK4EMC"),
			})
			cancel()
			return checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchVersion))
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_DeleteObjectTagging_invalid_versionId(s *S3Conf) error {
	testName := "Versioning_DeleteObjectTagging_invalid_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-object"
		_, err := putObjectWithData(4, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObjectTagging(ctx, &s3.DeleteObjectTaggingInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: getPtr("invalid_versionId"),
		})
		cancel()
		return checkApiErr(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgVersionId, "invalid_versionId"))
	})
}

func Versioning_DeleteObjectTagging_non_existing_object_version(s *S3Conf) error {
	testName := "Versioning_DeleteObjectTagging_non_existing_object_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-object", "my-dir/"}, func(obj string) error {
			_, err := putObjectWithData(objDataLen(obj, 4), &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			}, s3client)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.DeleteObjectTagging(ctx, &s3.DeleteObjectTaggingInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: getPtr("01K97XE6PJQ1A4X5TJFDHK4EMC"),
			})
			cancel()
			return checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchVersion))
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_PutGetDeleteObjectTagging_success(s *S3Conf) error {
	testName := "Versioning_PutGetDeleteObjectTagging_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return forEachKey([]string{"my-object", "my-dir/"}, func(obj string) error {
			versions, err := createObjVersions(s3client, bucket, obj, 5)
			if err != nil {
				return err
			}
			versionId := versions[2].VersionId

			tagging := types.Tagging{
				TagSet: []types.Tag{
					{Key: getPtr("key"), Value: getPtr("value")},
				},
			}

			compareVersionId := func(expected, input *string) error {
				if getString(expected) != getString(input) {
					return fmt.Errorf("expected the response versionId to be %s, instead got %s", getString(expected), getString(input))
				}

				return nil
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
				Bucket:    &bucket,
				Key:       &obj,
				Tagging:   &tagging,
				VersionId: versionId,
			})
			cancel()
			if err != nil {
				return err
			}

			if err := compareVersionId(versionId, res.VersionId); err != nil {
				return err
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: versionId,
			})
			cancel()
			if err != nil {
				return err
			}
			if !areTagsSame(tagging.TagSet, out.TagSet) {
				return fmt.Errorf("expected the object version tags to be %v, instead got %v", tagging.TagSet, out.TagSet)
			}
			if err := compareVersionId(versionId, out.VersionId); err != nil {
				return err
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			resp, err := s3client.DeleteObjectTagging(ctx, &s3.DeleteObjectTaggingInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: versionId,
			})
			cancel()
			if err != nil {
				return err
			}

			if err := compareVersionId(versionId, resp.VersionId); err != nil {
				return err
			}

			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			r, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: versionId,
			})
			cancel()
			if err != nil {
				return err
			}

			if len(r.TagSet) != 0 {
				return fmt.Errorf("expected empty tag set, instead got %v", r.TagSet)
			}

			return nil
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_ObjectTagging_trailing_slash_counterpart(s *S3Conf) error {
	testName := "Versioning_ObjectTagging_trailing_slash_counterpart"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		tagSet := []types.Tag{{Key: getPtr("key"), Value: getPtr("value")}}

		for _, keys := range [][2]string{{"my-dir/", "my-dir"}, {"my-obj", "my-obj/"}} {
			obj, other := keys[0], keys[1]
			res, err := putObjectWithData(objDataLen(obj, 10), &s3.PutObjectInput{
				Bucket:  &bucket,
				Key:     &obj,
				Tagging: getPtr("key=value"),
			}, s3client)
			if err != nil {
				return err
			}
			versionId := getString(res.res.VersionId)

			// the version belongs to the object, not to the other key
			err = checkObjectTaggingErr(s3client, bucket, other, versionId, s3err.GetAPIError(s3err.ErrNoSuchVersion))
			if err != nil {
				return fmt.Errorf("%v: %w", other, err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
				Bucket:    &bucket,
				Key:       &obj,
				VersionId: &versionId,
			})
			cancel()
			if err != nil {
				return fmt.Errorf("%v: %w", obj, err)
			}
			if !areTagsSame(out.TagSet, tagSet) {
				return fmt.Errorf("%v: expected the tag set to be %v, instead got %v",
					obj, tagSet, out.TagSet)
			}
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}
