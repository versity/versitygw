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
		obj := "my-obj"
		_, err := createObjVersions(s3client, bucket, obj, 2)
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

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_PutObject_suspended_null_versionId_obj(s *S3Conf) error {
	testName := "Versioning_PutObject_suspended_null_versionId_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := putObjectWithData(1222, &s3.PutObjectInput{
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

		return nil
	}, withVersioning(types.BucketVersioningStatusSuspended))
}

func Versioning_PutObject_null_versionId_obj(s *S3Conf) error {
	testName := "Versioning_PutObject_null_versionId_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, lgth := "my-obj", int64(1234)
		out, err := putObjectWithData(lgth, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		// Enable bucket versioning
		err = putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusEnabled)
		if err != nil {
			return err
		}

		versions, err := createObjVersions(s3client, bucket, obj, 4)
		if err != nil {
			return err
		}

		versions = append(versions, types.ObjectVersion{
			ETag:         out.res.ETag,
			IsLatest:     getBoolPtr(false),
			Key:          &obj,
			Size:         &lgth,
			VersionId:    &nullVersionId,
			StorageClass: types.ObjectVersionStorageClassStandard,
		})

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket: &bucket,
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
}

func Versioning_PutObject_overwrite_null_versionId_obj(s *S3Conf) error {
	testName := "Versioning_PutObject_overwrite_null_versionId_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjectWithData(int64(1233), &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		// Enable bucket versioning
		err = putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusEnabled)
		if err != nil {
			return err
		}

		versions, err := createObjVersions(s3client, bucket, obj, 4)
		if err != nil {
			return err
		}

		// Set bucket versioning status to Suspended
		err = putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusSuspended)
		if err != nil {
			return err
		}

		lgth := int64(3200)
		out, err := putObjectWithData(lgth, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		if getString(out.res.VersionId) != nullVersionId {
			return fmt.Errorf("expected the uploaded object versionId to be %v, insted got %v",
				nullVersionId, getString(out.res.VersionId))
		}

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
}

func Versioning_PutObject_success(s *S3Conf) error {
	testName := "Versioning_PutObject_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
		})
		cancel()
		if err != nil {
			return err
		}

		if res.VersionId == nil || *res.VersionId == "" {
			return fmt.Errorf("expected the versionId to be returned")
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
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidVersionId))
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_CopyObject_success(s *S3Conf) error {
	testName := "Versioning_CopyObject_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dstObj := "dst-obj"
		srcBucket, srcObj := getBucketName(), "src-obj"

		if err := setup(s, srcBucket); err != nil {
			return err
		}

		dstObjVersions, err := createObjVersions(s3client, bucket, dstObj, 1)
		if err != nil {
			return err
		}

		srcObjLen := int64(2345)
		_, err = putObjectWithData(srcObjLen, &s3.PutObjectInput{
			Bucket: &srcBucket,
			Key:    &srcObj,
		}, s3client)
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

		if err := teardown(s, srcBucket); err != nil {
			return err
		}

		if out.VersionId == nil || *out.VersionId == "" {
			return fmt.Errorf("expected non empty versionId in the result")
		}

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
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_CopyObject_non_existing_version_id(s *S3Conf) error {
	testName := "Versioning_CopyObject_non_existing_version_id"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dstBucket, dstObj := getBucketName(), "my-obj"
		srcObj := "my-obj"

		if err := setup(s, dstBucket); err != nil {
			return err
		}

		_, err := createObjVersions(s3client, bucket, srcObj, 1)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket: &dstBucket,
			Key:    &dstObj,
			CopySource: getPtr(fmt.Sprintf("%v/%v?versionId=01BX5ZZKBKACTAV9WEVGEMMVRZ",
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
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_CopyObject_from_an_object_version(s *S3Conf) error {
	testName := "Versioning_CopyObject_from_an_object_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcBucket, srcObj, dstObj := getBucketName(), "my-obj", "my-dst-obj"
		if err := setup(s, srcBucket, withVersioning(types.BucketVersioningStatusEnabled)); err != nil {
			return err
		}

		srcObjVersions, err := createObjVersions(s3client, srcBucket, srcObj, 1)
		if err != nil {
			return err
		}
		srcObjVersion := srcObjVersions[0]

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

		if err := teardown(s, srcBucket); err != nil {
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

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_CopyObject_special_chars(s *S3Conf) error {
	testName := "Versioning_CopyObject_special_chars"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj, dstBucket, dstObj := "foo?bar", getBucketName(), "bar&foo"
		err := setup(s, dstBucket)
		if err != nil {
			return err
		}

		srcObjVersions, err := createObjVersions(s3client, bucket, srcObj, 1)
		if err != nil {
			return err
		}

		srcObjVersionId := *srcObjVersions[0].VersionId

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        &dstObj,
			CopySource: getPtr(fmt.Sprintf("%v/%v?versionId=%v", bucket, srcObj, srcObjVersionId)),
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
		dLen := int64(2000)
		obj := "my-obj"
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

		obj = "not-a-dir/bad-obj"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
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
}

func Versioning_HeadObject_success(s *S3Conf) error {
	testName := "Versioning_HeadObject_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dLen := int64(2000)
		obj := "my-obj"
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

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_HeadObject_without_versionId(s *S3Conf) error {
	testName := "Versioning_HeadObject_without_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
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
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_HeadObject_delete_marker(s *S3Conf) error {
	testName := "Versioning_HeadObject_delete_marker"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dLen := int64(2000)
		obj := "my-obj"
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
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidVersionId))
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_GetObject_non_existing_object_version(s *S3Conf) error {
	testName := "Versioning_GetObject_non_existing_object_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dLen := int64(2000)
		obj := "my-obj"
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
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_GetObject_success(s *S3Conf) error {
	testName := "Versioning_GetObject_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dLen := int64(2000)
		obj := "my-obj"
		r, err := putObjectWithData(dLen, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		// Get the object by versionId
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket:    &bucket,
			Key:       &obj,
			VersionId: r.res.VersionId,
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

		// Get the object without versionId
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
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

		bdy, err = io.ReadAll(out.Body)
		if err != nil {
			return err
		}
		out.Body.Close()

		outCsum = sha256.Sum256(bdy)
		if outCsum != r.csum {
			return fmt.Errorf("incorrect output content")
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_GetObject_delete_marker_without_versionId(s *S3Conf) error {
	testName := "Versioning_GetObject_delete_marker_without_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjectWithData(1234, &s3.PutObjectInput{
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
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
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
}

func Versioning_GetObject_delete_marker(s *S3Conf) error {
	testName := "Versioning_GetObject_delete_marker"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dLen := int64(2000)
		obj := "my-obj"
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
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_GetObject_null_versionId_obj(s *S3Conf) error {
	testName := "Versioning_GetObject_null_versionId_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, lgth := "my-obj", int64(234)
		out, err := putObjectWithData(lgth, &s3.PutObjectInput{
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
		if *res.ETag != *out.res.ETag {
			return fmt.Errorf("expecte the ETag to be %v, instead got %v",
				*out.res.ETag, *res.ETag)
		}

		return nil
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
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidVersionId))
	})
}

func Versioning_GetObjectAttributes_object_version(s *S3Conf) error {
	testName := "Versioning_GetObjectAttributes_object_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
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
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_GetObjectAttributes_delete_marker(s *S3Conf) error {
	testName := "Versioning_GetObjectAttributes_delete_marker"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
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
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidVersionId))
	})
}

func Versioning_DeleteObject_delete_object_version(s *S3Conf) error {
	testName := "Versioning_DeleteObject_delete_object_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		oLen := int64(1000)
		obj := "my-obj"
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
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_DeleteObject_non_existing_object(s *S3Conf) error {
	testName := "Versioning_DeleteObject_non_existing_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

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
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidVersionId)); err != nil {
			return err
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_DeleteObject_delete_a_delete_marker(s *S3Conf) error {
	testName := "Versioning_DeleteObject_delete_a_delete_marker"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		oLen := int64(1000)
		obj := "my-obj"
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
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_Delete_null_versionId_object(s *S3Conf) error {
	testName := "Versioning_Delete_null_versionId_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, nObjLgth := "my-obj", int64(3211)
		_, err := putObjectWithData(nObjLgth, &s3.PutObjectInput{
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

		_, err = createObjVersions(s3client, bucket, obj, 3)
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
}

func Versioning_DeleteObject_nested_dir_object(s *S3Conf) error {
	testName := "Versioning_DeleteObject_nested_dir_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "foo/bar/baz"
		out, err := putObjectWithData(1000, &s3.PutObjectInput{
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
		if err := setup(s, bucket); err != nil {
			return err
		}

		return nil
	}, withLock())
}

func Versioning_DeleteObject_suspended(s *S3Conf) error {
	testName := "Versioning_DeleteObject_suspended"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
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
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_DeleteObjects_success(s *S3Conf) error {
	testName := "Versioning_DeleteObjects_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj1, obj2, obj3 := "foo", "bar", "baz"

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
		versions := append(obj2Version, obj3Version...)

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

		obj1Version, err := createObjVersions(s3client, bucket, obj1, 1)
		if err != nil {
			return err
		}
		obj2Version, err := createObjVersions(s3client, bucket, obj2, 1)
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
		}

		if !compareDelObjects(delResult, res.Deleted) {
			return fmt.Errorf("expected the deleted objects to be %v, instead got %v",
				delResult, res.Deleted)
		}

		return nil
	}, withVersioning(types.BucketVersioningStatusEnabled))
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
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidVersionId))
	})
}

func Versioning_UploadPartCopy_non_existing_versionId(s *S3Conf) error {
	testName := "Versioning_UploadPartCopy_non_existing_versionId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dstBucket, dstObj, srcObj := getBucketName(), "dst-obj", "src-obj"

		lgth := int64(100)
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
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_UploadPartCopy_from_an_object_version(s *S3Conf) error {
	testName := "Versioning_UploadPartCopy_from_an_object_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcObj, dstBucket, obj := "my-obj", getBucketName(), "dst-obj"
		err := setup(s, dstBucket)
		if err != nil {
			return err
		}

		srcObjVersions, err := createObjVersions(s3client, bucket, srcObj, 1)
		if err != nil {
			return err
		}
		srcObjVersion := srcObjVersions[0]

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

		if err := teardown(s, dstBucket); err != nil {
			return err
		}

		return nil
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
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidVersionId))
	})
}

func Versioning_PutObjectRetention_non_existing_object_version(s *S3Conf) error {
	testName := "Versioning_PutObjectRetention_non_existing_object_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
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
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidVersionId))
	})
}

func Versioning_GetObjectRetention_non_existing_object_version(s *S3Conf) error {
	testName := "Versioning_GetObjectRetention_non_existing_object_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
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
	}, withLock(), withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_Put_GetObjectRetention_success(s *S3Conf) error {
	testName := "Versioning_Put_GetObjectRetention_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
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
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidVersionId))
	})
}

func Versioning_PutObjectLegalHold_non_existing_object_version(s *S3Conf) error {
	testName := "Versioning_PutObjectLegalHold_non_existing_object_version"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
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
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidVersionId))
	})
}

func Versioning_GetObjectLegalHold_non_existing_object_version(s *S3Conf) error {
	testName := "Versioning_GetObjectLegalHold_non_existing_object_version"
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
			VersionId: getPtr("01G65Z755AFWAKHE12NY0CQ9FH"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchVersion)); err != nil {
			return err
		}

		return nil
	}, withLock(), withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_Put_GetObjectLegalHold_success(s *S3Conf) error {
	testName := "Versioning_Put_GetObjectLegalHold_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
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
	}, withLock(), withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_WORM_obj_version_locked_with_legal_hold(s *S3Conf) error {
	testName := "Versioning_WORM_obj_version_locked_with_legal_hold"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
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
	}, withLock(), withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_WORM_obj_version_locked_with_governance_retention(s *S3Conf) error {
	testName := "Versioning_WORM_obj_version_locked_with_governance_retention"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
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
	}, withLock(), withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_WORM_obj_version_locked_with_compliance_retention(s *S3Conf) error {
	testName := "Versioning_WORM_obj_version_locked_with_compliance_retention"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
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

		return cleanupLockedObjects(s3client, bucket, []objToDelete{
			{
				key:          obj,
				versionId:    getString(version.VersionId),
				isCompliance: true,
			},
		})
	}, withLock(), withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_WORM_PutObject_overwrite_locked_object(s *S3Conf) error {
	testName := "Versioning_WORM_PutObject_overwrite_locked_object"
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

		dataLen := int64(10)

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

func Versioning_WORM_CopyObject_overwrite_locked_object(s *S3Conf) error {
	testName := "Versioning_WORM_CopyObject_overwrite_locked_object"
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

		// create a source object version
		srcObj := "source-object"
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

		result := []types.ObjectVersion{version, v, srcVersion}

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

func Versioning_AccessControl_GetObjectVersion(s *S3Conf) error {
	testName := "Versioning_AccessControl_GetObjectVersion"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		objData, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		testuser := getUser("user")
		err = createUsers(s, []user{testuser})
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

		userClient := s.getUserClient(testuser)

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
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_AccessControl_HeadObjectVersion(s *S3Conf) error {
	testName := "Versioning_AccessControl_HeadObjectVersion"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		objData, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		testuser := getUser("user")
		err = createUsers(s, []user{testuser})
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

		userClient := s.getUserClient(testuser)

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
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_AccessControl_object_tagging_policy(s *S3Conf) error {
	testName := "Versioning_AccessControl_PutObjectTagging_policy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		object := "my-object"
		res, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &object,
		}, s3client)
		if err != nil {
			return err
		}

		testuser := getUser("user")
		err = createUsers(s, []user{testuser})
		if err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)

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
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_AccessControl_DeleteObject_policy(s *S3Conf) error {
	testName := "Versioning_AccessControl_DeleteObject_policy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-object"
		testuser := getUser("user")
		err := createUsers(s, []user{testuser})
		if err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)

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

		res, err := putObjectWithData(10, &s3.PutObjectInput{
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
		res, err = putObjectWithData(10, &s3.PutObjectInput{
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
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_AccessControl_GetObjectAttributes_policy(s *S3Conf) error {
	testName := "Versioning_AccessControl_GetObjectAttributes_policy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-object"
		res, err := putObjectWithData(10, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		testuser := getUser("user")
		err = createUsers(s, []user{testuser})
		if err != nil {
			return err
		}
		userClient := s.getUserClient(testuser)

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
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func VersioningDisabled_GetBucketVersioning_not_configured(s *S3Conf) error {
	testName := "VersioningDisabled_GetBucketVersioning_not_configured"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putBucketVersioningStatus(s3client, bucket, types.BucketVersioningStatusEnabled)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrVersioningNotConfigured)); err != nil {
			return err
		}

		return nil
	})
}

func VersioningDisabled_PutBucketVersioning_not_configured(s *S3Conf) error {
	testName := "VersioningDisabled_PutBucketVersioning_not_configured"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: &bucket,
		})
		cancel()
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
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidVersionId))
	})
}

func Versioning_PutObjectTagging_non_existing_object_version(s *S3Conf) error {
	testName := "Versioning_PutObjectTagging_non_existing_object_version"
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
			VersionId: getPtr("01K97XE6PJQ1A4X5TJFDHK4EMC"),
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchVersion))
	}, withVersioning(types.BucketVersioningStatusEnabled))
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
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidVersionId))
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_GetObjectTagging_non_existing_object_version(s *S3Conf) error {
	testName := "Versioning_GetObjectTagging_non_existing_object_version"
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
			VersionId: getPtr("01K97XE6PJQ1A4X5TJFDHK4EMC"),
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchVersion))
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
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidVersionId))
	})
}

func Versioning_DeleteObjectTagging_non_existing_object_version(s *S3Conf) error {
	testName := "Versioning_DeleteObjectTagging_non_existing_object_version"
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
			VersionId: getPtr("01K97XE6PJQ1A4X5TJFDHK4EMC"),
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchVersion))
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func Versioning_PutGetDeleteObjectTagging_success(s *S3Conf) error {
	testName := "Versioning_PutGetDeleteObjectTagging_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-object"
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
	}, withVersioning(types.BucketVersioningStatusEnabled))
}
