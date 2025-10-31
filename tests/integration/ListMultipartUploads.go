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

func ListMultipartUploads_non_existing_bucket(s *S3Conf) error {
	testName := "ListMultipartUploads_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		bucketName := getBucketName()
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket: &bucketName,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func ListMultipartUploads_empty_result(s *S3Conf) error {
	testName := "ListMultipartUploads_empty_result"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}
		if len(out.Uploads) != 0 {
			return fmt.Errorf("expected empty uploads, instead got %+v",
				out.Uploads)
		}

		return nil
	})
}

func ListMultipartUploads_invalid_max_uploads(s *S3Conf) error {
	testName := "ListMultipartUploads_invalid_max_uploads"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		maxUploads := int32(-3)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:     &bucket,
			MaxUploads: &maxUploads,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidMaxUploads)); err != nil {
			return err
		}

		return nil
	})
}

func ListMultipartUploads_max_uploads(s *S3Conf) error {
	testName := "ListMultipartUploads_max_uploads"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		uploads := []types.MultipartUpload{}
		for i := 1; i < 6; i++ {
			out, err := createMp(s3client, bucket, fmt.Sprintf("obj%v", i))
			if err != nil {
				return err
			}
			uploads = append(uploads, types.MultipartUpload{
				UploadId:     out.UploadId,
				Key:          out.Key,
				StorageClass: types.StorageClassStandard,
			})
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		maxUploads := int32(2)
		out, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:     &bucket,
			MaxUploads: &maxUploads,
		})
		cancel()
		if err != nil {
			return err
		}

		if out.IsTruncated == nil {
			return fmt.Errorf("unexpected nil is-truncated")
		}
		if out.MaxUploads == nil {
			return fmt.Errorf("unexpected nil max-uploads")
		}
		if !*out.IsTruncated {
			return fmt.Errorf("expected the output to be truncated")
		}
		if *out.MaxUploads != 2 {
			return fmt.Errorf("expected max-uploads to be 2, instead got %v",
				out.MaxUploads)
		}
		if ok := compareMultipartUploads(out.Uploads, uploads[:2]); !ok {
			return fmt.Errorf("expected multipart uploads to be %v, instead got %v",
				uploads[:2], out.Uploads)
		}
		if getString(out.NextKeyMarker) != getString(uploads[1].Key) {
			return fmt.Errorf("expected next-key-marker to be %v, instead got %v",
				getString(uploads[1].Key), getString(out.NextKeyMarker))
		}
		if getString(out.NextUploadIdMarker) != getString(uploads[1].UploadId) {
			return fmt.Errorf("expected next-upload-id-marker to be %v, instead got %v",
				getString(uploads[1].UploadId), getString(out.NextUploadIdMarker))
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err = s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:    &bucket,
			KeyMarker: out.NextKeyMarker,
		})
		cancel()
		if err != nil {
			return err
		}
		if ok := compareMultipartUploads(out.Uploads, uploads[2:]); !ok {
			return fmt.Errorf("expected multipart uploads to be %v, instead got %v",
				uploads[2:], out.Uploads)
		}

		return nil
	})
}

func ListMultipartUploads_exceeding_max_uploads(s *S3Conf) error {
	testName := "ListMultipartUploads_exceeding_max_uploads"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		maxUploads := int32(1343235)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:     &bucket,
			MaxUploads: &maxUploads,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.MaxUploads == nil {
			return fmt.Errorf("unexpected nil max-uploads")
		}
		if *res.MaxUploads != 1000 {
			return fmt.Errorf("expected max-uploads to be %v, instaed got %v",
				1000, *res.MaxUploads)
		}

		return nil
	})
}

func ListMultipartUploads_incorrect_next_key_marker(s *S3Conf) error {
	testName := "ListMultipartUploads_incorrect_next_key_marker"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for i := 1; i < 6; i++ {
			_, err := createMp(s3client, bucket, fmt.Sprintf("obj%v", i))
			if err != nil {
				return err
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:    &bucket,
			KeyMarker: getPtr("wrong_object_key"),
		})
		cancel()
		if err != nil {
			return err
		}

		if len(out.Uploads) != 0 {
			return fmt.Errorf("expected empty list of multipart uploads, instead got %v",
				out.Uploads)
		}

		return nil
	})
}

func ListMultipartUploads_ignore_upload_id_marker(s *S3Conf) error {
	testName := "ListMultipartUploads_ignore_upload_id_marker"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		uploads := []types.MultipartUpload{}
		for i := 1; i < 6; i++ {
			out, err := createMp(s3client, bucket, fmt.Sprintf("obj%v", i))
			if err != nil {
				return err
			}
			uploads = append(uploads, types.MultipartUpload{
				UploadId:     out.UploadId,
				Key:          out.Key,
				StorageClass: types.StorageClassStandard,
			})
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:         &bucket,
			UploadIdMarker: uploads[2].UploadId,
		})
		cancel()
		if err != nil {
			return err
		}
		if ok := compareMultipartUploads(out.Uploads, uploads); !ok {
			return fmt.Errorf("expected multipart uploads to be %v, instead got %v",
				uploads, out.Uploads)
		}

		return nil
	})
}

func ListMultipartUploads_with_checksums(s *S3Conf) error {
	testName := "ListMultipartUploads_with_checksums"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		uploads := []types.MultipartUpload{}
		for _, el := range []struct {
			obj  string
			algo types.ChecksumAlgorithm
			t    types.ChecksumType
		}{
			{
				obj:  "obj-1",
				algo: types.ChecksumAlgorithmCrc32,
				t:    types.ChecksumTypeComposite,
			},
			{
				obj:  "obj-2",
				algo: types.ChecksumAlgorithmCrc32c,
				t:    types.ChecksumTypeFullObject,
			},
			{
				obj:  "obj-3",
				algo: types.ChecksumAlgorithmSha1,
				t:    types.ChecksumTypeComposite,
			},
			{
				obj:  "obj-4",
				algo: types.ChecksumAlgorithmSha256,
				t:    types.ChecksumTypeComposite,
			},
			{
				obj:  "obj-5",
				algo: types.ChecksumAlgorithmCrc64nvme,
				t:    types.ChecksumTypeFullObject,
			},
		} {
			key := el.obj
			mp, err := createMp(s3client, bucket, key, withChecksum(el.algo), withChecksumType(el.t))
			if err != nil {
				return err
			}

			uploads = append(uploads, types.MultipartUpload{
				Key:               &key,
				UploadId:          mp.UploadId,
				StorageClass:      types.StorageClassStandard,
				ChecksumAlgorithm: el.algo,
				ChecksumType:      el.t,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareMultipartUploads(res.Uploads, uploads) {
			return fmt.Errorf("expected the final multipart uploads to be %v, instead got %v",
				uploads, res.Uploads)
		}

		return nil
	})
}

func ListMultipartUploads_success(s *S3Conf) error {
	testName := "ListMultipartUploads_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj1, obj2 := "my-obj-1", "my-obj-2"
		out1, err := createMp(s3client, bucket, obj1)
		if err != nil {
			return err
		}

		out2, err := createMp(s3client, bucket, obj2)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		expected := []types.MultipartUpload{
			{
				Key:          &obj1,
				UploadId:     out1.UploadId,
				StorageClass: types.StorageClassStandard,
			},
			{
				Key:          &obj2,
				UploadId:     out2.UploadId,
				StorageClass: types.StorageClassStandard,
			},
		}

		if len(out.Uploads) != 2 {
			return fmt.Errorf("expected 2 upload, instead got %v",
				len(out.Uploads))
		}
		if ok := compareMultipartUploads(out.Uploads, expected); !ok {
			return fmt.Errorf("expected uploads %v, instead got %v",
				expected, out.Uploads)
		}

		return nil
	})
}
