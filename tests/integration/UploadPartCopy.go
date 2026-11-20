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
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

func UploadPartCopy_non_existing_bucket(s *S3Conf) error {
	testName := "UploadPartCopy_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		bucketName := getBucketName()
		partNumber := int32(1)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucketName,
			CopySource: getPtr("Copy-Source"),
			UploadId:   getPtr("uploadId"),
			Key:        getPtr("my-obj"),
			PartNumber: &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}
		return nil
	})
}

func UploadPartCopy_incorrect_uploadId(s *S3Conf) error {
	testName := "UploadPartCopy_incorrect_uploadId"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket, srcObj := "my-obj", getBucketName(), "src-obj"
		err := setup(s, srcBucket)
		if err != nil {
			return err
		}
		_, err = putObjects(s3client, []string{srcObj}, srcBucket)
		if err != nil {
			return err
		}

		_, err = createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(1)
		_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			CopySource: getPtr(srcBucket + "/" + srcObj),
			UploadId:   getPtr("incorrect-upload-id"),
			Key:        &obj,
			PartNumber: &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchUpload)); err != nil {
			return err
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_upload_id_path_traversal(s *S3Conf) error {
	testName := "UploadPartCopy_upload_id_path_traversal"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objs, err := putObjects(s3client, []string{"victim-dir/1"}, bucket)
		if err != nil {
			return err
		}
		srcObj := "src-obj"
		_, err = putObjectWithData(100, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		// A posix upload directory is three levels below its bucket, so
		// part 1 of the upload ID would be copied over "victim-dir/1".
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			Key:        getPtr("my-obj"),
			UploadId:   getPtr("../../../victim-dir"),
			PartNumber: getPtr(int32(1)),
			CopySource: getPtr(bucket + "/" + srcObj),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchUpload)); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    objs[0].Key,
		})
		cancel()
		if err != nil {
			return err
		}
		if getString(out.ETag) != getString(objs[0].ETag) {
			return fmt.Errorf("expected the object etag to be %v, instead got %v",
				getString(objs[0].ETag), getString(out.ETag))
		}

		return nil
	})
}

func UploadPartCopy_malformed_upload_id(s *S3Conf) error {
	testName := "UploadPartCopy_malformed_upload_id"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objs, err := putObjects(s3client, []string{"src-obj"}, bucket)
		if err != nil {
			return err
		}

		// A malformed upload ID is reported ahead of an invalid part
		// number and of any copy source error.
		for i, test := range []struct {
			copySource string
			partNumber int32
		}{
			{bucket + "/" + *objs[0].Key, -10},
			{bucket, 1},
			{bucket + "/%ZZ", 1},
			{"non-existing-bucket/src-obj", 1},
			{bucket + "/non-existing-obj", 1},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
				Bucket:     &bucket,
				Key:        getPtr("my-obj"),
				UploadId:   getPtr("../invalid-upload"),
				PartNumber: &test.partNumber,
				CopySource: &test.copySource,
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchUpload)); err != nil {
				return fmt.Errorf("test case %d: %w", i+1, err)
			}
		}

		return nil
	})
}

func UploadPartCopy_incorrect_object_key(s *S3Conf) error {
	testName := "UploadPartCopy_incorrect_object_key"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket, srcObj := "my-obj", getBucketName(), "src-obj"
		err := setup(s, srcBucket)
		if err != nil {
			return err
		}
		_, err = putObjects(s3client, []string{srcObj}, srcBucket)
		if err != nil {
			return err
		}

		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(1)
		_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			CopySource: getPtr(srcBucket + "/" + srcObj),
			UploadId:   out.UploadId,
			Key:        getPtr("non-existing-object-key"),
			PartNumber: &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchUpload)); err != nil {
			return err
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_invalid_part_number(s *S3Conf) error {
	testName := "UploadPartCopy_invalid_part_number"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(-10)
		_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			CopySource: getPtr("bucket/key"),
			UploadId:   out.UploadId,
			Key:        &obj,
			PartNumber: &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgPartNumber, fmt.Sprint(partNumber))); err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_invalid_copy_source(s *S3Conf) error {
	testName := "UploadPartCopy_invalid_copy_source"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "obj"
		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		partNumber := int32(1)
		for _, test := range []struct {
			copySource  string
			expectedErr s3err.S3Error
		}{
			// invalid encoding
			{
				// Invalid hex digits
				copySource:  "bucket/%ZZ",
				expectedErr: s3err.GetInvalidArgumentErr(s3err.InvalidArgCopySourceEncoding, "bucket/%ZZ"),
			},
			{
				// Ends with incomplete escape
				copySource:  "100%/foo/bar/baz",
				expectedErr: s3err.GetInvalidArgumentErr(s3err.InvalidArgCopySourceEncoding, "100%/foo/bar/baz"),
			},
			{
				// Only one digit after %
				copySource:  "bucket/%A/bar",
				expectedErr: s3err.GetInvalidArgumentErr(s3err.InvalidArgCopySourceEncoding, "bucket/%A/bar"),
			},
			{
				// 'G' is not a hex digit
				copySource:  "bucket/%G1/",
				expectedErr: s3err.GetInvalidArgumentErr(s3err.InvalidArgCopySourceEncoding, "bucket/%G1/"),
			},
			{
				// Just a single percent sign
				copySource:  "%",
				expectedErr: s3err.GetInvalidArgumentErr(s3err.InvalidArgCopySourceEncoding, "%"),
			},
			{
				// Only one hex digit
				copySource:  "bucket/%1",
				expectedErr: s3err.GetInvalidArgumentErr(s3err.InvalidArgCopySourceEncoding, "bucket/%1"),
			},
			{
				// Incomplete multibyte UTF-8
				copySource:  "bucket/%C3%",
				expectedErr: s3err.GetInvalidArgumentErr(s3err.InvalidArgCopySourceEncoding, "bucket/%C3%"),
			},
			// invalid bucket name
			{
				// ip v4 address
				copySource:  "192.168.1.1/foo",
				expectedErr: s3err.GetInvalidArgumentErr(s3err.InvalidArgCopySourceBucket, "192.168.1.1/foo"),
			},
			{
				// ip v6 address
				copySource:  "2001:0db8:85a3:0000:0000:8a2e:0370:7334/something",
				expectedErr: s3err.GetInvalidArgumentErr(s3err.InvalidArgCopySourceBucket, "2001:0db8:85a3:0000:0000:8a2e:0370:7334/something"),
			},
			{
				// some special chars
				copySource:  "my-buc@k&()t/obj",
				expectedErr: s3err.GetInvalidArgumentErr(s3err.InvalidArgCopySourceBucket, "my-buc@k&()t/obj"),
			},
			// invalid object key
			{
				// object is missing
				copySource:  "bucket",
				expectedErr: s3err.GetInvalidArgumentErr(s3err.InvalidArgCopySourceObject, ""),
			},
			{
				// object is missing
				copySource:  "bucket/",
				expectedErr: s3err.GetInvalidArgumentErr(s3err.InvalidArgCopySourceObject, ""),
			},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
				Bucket:     &bucket,
				Key:        &obj,
				UploadId:   out.UploadId,
				CopySource: &test.copySource,
				PartNumber: &partNumber,
			})
			cancel()
			if err := checkApiErr(err, test.expectedErr); err != nil {
				return err
			}
		}

		return nil
	})
}

func UploadPartCopy_non_existing_source_bucket(s *S3Conf) error {
	testName := "UploadPartCopy_non_existing_source_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(1)
		_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			CopySource: getPtr("src/bucket/src/obj"),
			UploadId:   out.UploadId,
			Key:        &obj,
			PartNumber: &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_non_existing_source_object_key(s *S3Conf) error {
	testName := "UploadPartCopy_non_existing_source_object_key"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket := "my-obj", getBucketName()

		err := setup(s, srcBucket)
		if err != nil {
			return nil
		}

		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(1)
		_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			CopySource: getPtr(srcBucket + "/non/existing/obj/key"),
			UploadId:   out.UploadId,
			Key:        &obj,
			PartNumber: &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchKey)); err != nil {
			return err
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_success(s *S3Conf) error {
	testName := "UploadPartCopy_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket, srcObj := "my-obj", getBucketName(), "src-obj"
		err := setup(s, srcBucket)
		if err != nil {
			return err
		}
		objSize := 5 * 1024 * 1024
		_, err = putObjectWithData(int64(objSize), &s3.PutObjectInput{
			Bucket: &srcBucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(1)
		copyOut, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			CopySource: getPtr(srcBucket + "/" + srcObj),
			UploadId:   out.UploadId,
			Key:        &obj,
			PartNumber: &partNumber,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
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
		if res.Parts[0].PartNumber == nil || *res.Parts[0].PartNumber != 1 {
			return fmt.Errorf("expected part-number to be 1, instead got %v",
				res.Parts[0].PartNumber)
		}
		if res.Parts[0].Size == nil || *res.Parts[0].Size != int64(objSize) {
			return fmt.Errorf("expected part size to be %v, instead got %v",
				objSize, res.Parts[0].Size)
		}
		if getString(res.Parts[0].ETag) != getString(copyOut.CopyPartResult.ETag) {
			return fmt.Errorf("expected part etag to be %v, instead got %v",
				getString(copyOut.CopyPartResult.ETag), getString(res.Parts[0].ETag))
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_by_range_invalid_ranges(s *S3Conf) error {
	testName := "UploadPartCopy_by_range_invalid_ranges"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket, srcObj := "my-obj", getBucketName(), "src-obj"
		err := setup(s, srcBucket)
		if err != nil {
			return err
		}
		objSize := int64(5 * 1024 * 1024)
		_, err = putObjectWithData(objSize, &s3.PutObjectInput{
			Bucket: &srcBucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		uploadPartCopy := func(csRange string, ptNumber int32) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
				Bucket:          &bucket,
				CopySource:      getPtr(srcBucket + "/" + srcObj),
				UploadId:        out.UploadId,
				Key:             &obj,
				PartNumber:      &ptNumber,
				CopySourceRange: &csRange,
			})
			cancel()
			if err := checkApiErr(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgCopySourceRange, csRange)); err != nil {
				return err
			}

			return nil
		}

		for i, rg := range []string{
			"byte=100-200",
			"bytes=invalid-range",
			"bytes=200-100",
			"bytes=-2-300",
			"bytes=aa-12",
			"bytes=12-aa",
			"bytes=bb-",
		} {
			err := uploadPartCopy(rg, int32(i+1))
			if err != nil {
				return err
			}
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_exceeding_copy_source_range(s *S3Conf) error {
	testName := "UploadPartCopy_exceeding_copy_source_range"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket, srcObj := "my-obj", getBucketName(), "src-obj"
		err := setup(s, srcBucket)
		if err != nil {
			return err
		}
		objSize := int64(1000)
		_, err = putObjectWithData(objSize, &s3.PutObjectInput{
			Bucket: &srcBucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		uploadPartCopy := func(csRange string, ptNumber int32) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
				Bucket:          &bucket,
				CopySource:      getPtr(srcBucket + "/" + srcObj),
				UploadId:        out.UploadId,
				Key:             &obj,
				PartNumber:      &ptNumber,
				CopySourceRange: &csRange,
			})
			cancel()
			return checkApiErr(err, s3err.GetInvalidArgExceedingRange(objSize))
		}

		for i, rg := range []string{
			"bytes=100-1005",
			"bytes=1250-3000",
			"bytes=100-1000",
		} {
			err := uploadPartCopy(rg, int32(i+1))
			if err != nil {
				return err
			}
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_greater_range_than_obj_size(s *S3Conf) error {
	testName := "UploadPartCopy_greater_range_than_obj_size"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket, srcObj := "my-obj", getBucketName(), "src-obj"
		err := setup(s, srcBucket)
		if err != nil {
			return err
		}
		srcObjSize := 5 * 1024 * 1024
		_, err = putObjectWithData(int64(srcObjSize), &s3.PutObjectInput{
			Bucket: &srcBucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(1)
		_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:          &bucket,
			CopySource:      getPtr(srcBucket + "/" + srcObj),
			UploadId:        out.UploadId,
			Key:             &obj,
			CopySourceRange: getPtr(fmt.Sprintf("bytes=0-%v", srcObjSize+50)), // The specified range is greater than the actual object size
			PartNumber:      &partNumber,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetInvalidArgExceedingRange(int64(srcObjSize))); err != nil {
			return err
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_by_range_success(s *S3Conf) error {
	testName := "UploadPartCopy_by_range_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket, srcObj := "my-obj", getBucketName(), "src-obj"
		err := setup(s, srcBucket)
		if err != nil {
			return err
		}
		objSize := 5 * 1024 * 1024
		_, err = putObjectWithData(int64(objSize), &s3.PutObjectInput{
			Bucket: &srcBucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		out, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		partNumber := int32(1)
		copyOut, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:          &bucket,
			CopySource:      getPtr(srcBucket + "/" + srcObj),
			CopySourceRange: getPtr("bytes=100-200"),
			UploadId:        out.UploadId,
			Key:             &obj,
			PartNumber:      &partNumber,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
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
			return fmt.Errorf("expected part-number to be 1, instead got nil")
		}
		if *res.Parts[0].PartNumber != 1 {
			return fmt.Errorf("expected part-number to be 1, instead got %v",
				res.Parts[0].PartNumber)
		}
		if res.Parts[0].Size == nil {
			return fmt.Errorf("expected part size to be non nil, instead got nil")
		}
		if *res.Parts[0].Size != 101 {
			return fmt.Errorf("expected part size to be %v, instead got %v",
				101, res.Parts[0].Size)
		}
		if getString(res.Parts[0].ETag) != getString(copyOut.CopyPartResult.ETag) {
			return fmt.Errorf("expected part etag to be %v, instead got %v",
				getString(copyOut.CopyPartResult.ETag), getString(res.Parts[0].ETag))
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_conditional_reads(s *S3Conf) error {
	testName := "UploadPartCopy_conditional_reads"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		mpKey := "mp-key"
		mp, err := createMp(s3client, bucket, mpKey)
		if err != nil {
			return err
		}

		return testCopySourcePreconditions(s, s3client, bucket,
			fmt.Sprintf("%s/%s?partNumber=1&uploadId=%s", bucket, mpKey, *mp.UploadId))
	})
}

func UploadPartCopy_should_copy_the_checksum(s *S3Conf) error {
	testName := "UploadPartCopy_should_copy_the_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for i, algo := range types.ChecksumAlgorithmCrc32.Values() {
			obj := fmt.Sprintf("my-obj-%v", i+1)
			srcObj := fmt.Sprintf("source-object-%v", i+1)

			mp, err := createMp(s3client, bucket, obj, withChecksum(algo))
			if err != nil {
				return err
			}

			out, err := putObjectWithData(300, &s3.PutObjectInput{
				Bucket:            &bucket,
				Key:               &srcObj,
				ChecksumAlgorithm: algo,
			}, s3client, withPutObjectChecksumAlgo(algo))
			if err != nil {
				return err
			}

			partNumber := int32(1)

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
				Bucket:     &bucket,
				Key:        &obj,
				UploadId:   mp.UploadId,
				PartNumber: &partNumber,
				CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
			})
			cancel()
			if err != nil {
				return err
			}

			if got, expected := getString(getUploadPartCopyChecksum(res.CopyPartResult, algo)), getString(getPutObjectChecksum(out.res, algo)); got != expected {
				return fmt.Errorf("expected %s checksum to be %v, instead got %v", algo, expected, got)
			}
			for _, otherAlgo := range types.ChecksumAlgorithmCrc32.Values() {
				if otherAlgo == algo {
					continue
				}
				if checksum := getUploadPartCopyChecksum(res.CopyPartResult, otherAlgo); checksum != nil {
					return fmt.Errorf("expected nil %s checksum, instead got %v", otherAlgo, *checksum)
				}
			}
		}

		return nil
	})
}

func UploadPartCopy_should_not_copy_the_checksum(s *S3Conf) error {
	testName := "UploadPartCopy_should_not_copy_the_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		srcObj := "source-object"

		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		_, err = putObjectWithData(300, &s3.PutObjectInput{
			Bucket:            &bucket,
			Key:               &srcObj,
			ChecksumAlgorithm: types.ChecksumAlgorithmSha1,
		}, s3client)
		if err != nil {
			return err
		}

		partNumber := int32(1)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			Key:        &obj,
			UploadId:   mp.UploadId,
			PartNumber: &partNumber,
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
		})
		cancel()
		if err != nil {
			return err
		}

		for _, algo := range types.ChecksumAlgorithmCrc32.Values() {
			if checksum := getUploadPartCopyChecksum(res.CopyPartResult, algo); checksum != nil {
				return fmt.Errorf("expected nil %s checksum, instead got %v", algo, *checksum)
			}
		}

		return nil
	})
}

func UploadPartCopy_should_calculate_the_checksum(s *S3Conf) error {
	testName := "UploadPartCopy_should_calculate_the_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for i, algo := range types.ChecksumAlgorithmCrc32.Values() {
			obj := fmt.Sprintf("my-obj-%v", i+1)
			srcObj := fmt.Sprintf("source-object-%v", i+1)

			mp, err := createMp(s3client, bucket, obj, withChecksum(algo))
			if err != nil {
				return err
			}

			_, err = putObjectWithData(300, &s3.PutObjectInput{
				Bucket:            &bucket,
				Key:               &srcObj,
				ChecksumAlgorithm: types.ChecksumAlgorithmSha1,
			}, s3client)
			if err != nil {
				return err
			}

			partNumber := int32(1)

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
				Bucket:     &bucket,
				Key:        &obj,
				UploadId:   mp.UploadId,
				PartNumber: &partNumber,
				CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
			})
			cancel()
			if err != nil {
				return err
			}

			for _, otherAlgo := range types.ChecksumAlgorithmCrc32.Values() {
				checksum := getUploadPartCopyChecksum(res.CopyPartResult, otherAlgo)
				if otherAlgo == algo {
					if getString(checksum) == "" {
						return fmt.Errorf("expected non empty %s checksum", algo)
					}
					continue
				}
				if checksum != nil {
					return fmt.Errorf("expected nil %s checksum, instead got %v", otherAlgo, *checksum)
				}
			}
		}

		return nil
	})
}

func UploadPartCopy_data_integrity_etag(s *S3Conf) error {
	testName := "UploadPartCopy_data_integrity_etag"
	return actionHandler(s, testName, func(_ *s3.Client, bucket string) error {
		customClient := s3.NewFromConfig(s.Config(), func(o *s3.Options) {
			o.RequestChecksumCalculation = aws.RequestChecksumCalculationUnset
		})

		obj := "my-obj"
		srcObj := "source-object"

		mp, err := createMp(customClient, bucket, obj)
		if err != nil {
			return err
		}

		if _, err := putObjectWithData(300, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &srcObj,
		}, customClient); err != nil {
			return err
		}

		partNumber := int32(1)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := customClient.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			Key:        &obj,
			UploadId:   mp.UploadId,
			PartNumber: &partNumber,
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, srcObj)),
		})
		cancel()
		if err != nil {
			return err
		}

		if !isQuotedEtag(getString(res.CopyPartResult.ETag)) {
			return fmt.Errorf("expected UploadPartCopy ETag to be quoted, instead got %s", getString(res.CopyPartResult.ETag))
		}
		if !strings.HasPrefix(getString(res.CopyPartResult.ETag), "\"CRC64NVME-") {
			return fmt.Errorf("expected UploadPartCopy ETag to be CRC64NVME-based, instead got %s", getString(res.CopyPartResult.ETag))
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		parts, err := customClient.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
		})
		cancel()
		if err != nil {
			return err
		}

		if len(parts.Parts) != 1 {
			return fmt.Errorf("expected one uploaded part, instead got %d", len(parts.Parts))
		}
		if got := getString(parts.Parts[0].ETag); got != getString(res.CopyPartResult.ETag) {
			return fmt.Errorf("expected ListParts ETag to be %s, instead got %s", getString(res.CopyPartResult.ETag), got)
		}

		return nil
	})
}

func UploadPartCopy_incorrect_source_bucket_expected_owner(s *S3Conf) error {
	testName := "UploadPartCopy_incorrect_source_bucket_expected_owner"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		srcBucket := getBucketName()
		err := setup(s, srcBucket)
		if err != nil {
			return err
		}
		defer func() {
			_ = teardown(s, srcBucket)
		}()

		srcObj := "src-obj"
		_, err = putObjects(s3client, []string{srcObj}, srcBucket)
		if err != nil {
			return err
		}

		obj := "my-obj"
		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:                    &bucket,
			Key:                       &obj,
			CopySource:                getPtr(fmt.Sprintf("%v/%v", srcBucket, srcObj)),
			UploadId:                  mp.UploadId,
			PartNumber:                getPtr(int32(1)),
			ExpectedSourceBucketOwner: getPtr("incorrect-owner"),
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied))
	})
}
