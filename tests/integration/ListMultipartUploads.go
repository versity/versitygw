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
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
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
		if err := checkApiErr(err, s3err.GetNegativeMaxLimiterErr("max-uploads")); err != nil {
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
		if !compareMultipartUploads(out.Uploads, uploads) {
			return fmt.Errorf("expected multipart uploads to be %v, instead got %v",
				uploads, out.Uploads)
		}

		// should ignore invalid uploaId marker
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err = s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:         &bucket,
			UploadIdMarker: getPtr("invalid_uploadId_marker"),
		})
		cancel()
		if err != nil {
			return err
		}
		if !compareMultipartUploads(out.Uploads, uploads) {
			return fmt.Errorf("expected multipart uploads to be %v, instead got %v",
				uploads, out.Uploads)
		}

		return nil
	})
}

func ListMultipartUploads_invalid_uploadId_marker(s *S3Conf) error {
	testName := "ListMultipartUploads_invalid_uploadId_marker"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		uploads := make([]types.MultipartUpload, 0, 5)
		for i := range 5 {
			out, err := createMp(s3client, bucket, fmt.Sprintf("obj-%v", i))
			if err != nil {
				return err
			}

			uploads = append(uploads, types.MultipartUpload{
				UploadId:     out.UploadId,
				Key:          out.Key,
				StorageClass: types.StorageClassStandard,
			})
		}

		// invalid UUID
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:         &bucket,
			KeyMarker:      getPtr("obj-2"),
			UploadIdMarker: getPtr("invalid_uploadId_marker"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidUploadIdMarker)); err != nil {
			return err
		}

		// valid UUID, but not from the list
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:         &bucket,
			KeyMarker:      getPtr("obj-2"),
			UploadIdMarker: getPtr(uuid.New().String()),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidUploadIdMarker)); err != nil {
			return err
		}

		// uploadId marker and key marker mismatch
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:         &bucket,
			KeyMarker:      getPtr("obj-2"),
			UploadIdMarker: uploads[4].UploadId,
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidUploadIdMarker))
	})
}

func ListMultipartUploads_keyMarker_not_from_list(s *S3Conf) error {
	testName := "ListMultipartUploads_keyMarker_not_from_list"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		uploads := make([]types.MultipartUpload, 0, 9)
		for _, mp := range []struct {
			key   string
			count int
		}{
			{"bar", 3},
			{"baz", 4},
			{"foo", 2},
		} {
			for range mp.count {
				out, err := createMp(s3client, bucket, mp.key)
				if err != nil {
					return err
				}
				uploads = append(uploads, types.MultipartUpload{
					Key:          out.Key,
					UploadId:     out.UploadId,
					StorageClass: types.StorageClassStandard,
				})
				if s.azureTests {
					// add an artificial delay for azure tests
					// as azure uploads all these mps with the same
					// identical creation time
					time.Sleep(time.Second)
				}
			}
		}

		// without uploadId marker
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:    &bucket,
			KeyMarker: getPtr("bat"),
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareMultipartUploads(uploads[3:], out.Uploads) {
			return fmt.Errorf("expected the mp list to be %v, instead got %v", uploads[:3], out.Uploads)
		}

		// should start the listing after the specified uploadId marker
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err = s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:         &bucket,
			KeyMarker:      getPtr("bat"),
			UploadIdMarker: uploads[4].UploadId,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareMultipartUploads(uploads[5:], out.Uploads) {
			return fmt.Errorf("expected the mp list to be %v, instead got %v", uploads[5:], out.Uploads)
		}

		return nil
	})
}

func ListMultipartUploads_delimiter_truncated(s *S3Conf) error {
	testName := "ListMultipartUploads_delimiter_truncated"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		uploads := make([]types.MultipartUpload, 0, 6)
		for _, key := range []string{
			"abc/something",
			"foo/bar/baz",
			"foo/quxx",
			"xyz/hello",
			"zzz/bca",
			"some/very/nested/mp/object",
		} {
			out, err := createMp(s3client, bucket, key)
			if err != nil {
				return err
			}
			uploads = append(uploads, types.MultipartUpload{
				Key:          out.Key,
				UploadId:     out.UploadId,
				StorageClass: types.StorageClassStandard,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:     &bucket,
			Delimiter:  getPtr("/"),
			MaxUploads: getPtr(int32(2)),
		})
		cancel()
		if err != nil {
			return err
		}

		if len(out.Uploads) != 0 {
			return fmt.Errorf("expected empty uplodas list, instead got %v", out.Uploads)
		}
		expectedCps := []string{"abc/", "foo/"}
		if !comparePrefixes(expectedCps, out.CommonPrefixes) {
			return fmt.Errorf("expected the common prefixes to be %v, instead got %v", expectedCps, out.CommonPrefixes)
		}
		if getString(out.NextKeyMarker) != "foo/" {
			return fmt.Errorf("expected the next key marker to be 'foo/', instead got %s", getString(out.NextKeyMarker))
		}
		if getString(out.NextUploadIdMarker) != getString(uploads[1].UploadId) {
			return fmt.Errorf("expected the next upload id marker to be %s, instead got %s", getString(uploads[1].UploadId), getString(out.NextUploadIdMarker))
		}
		if !*out.IsTruncated {
			return fmt.Errorf("expected a truncated response")
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out2, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:         &bucket,
			Delimiter:      getPtr("/"),
			UploadIdMarker: out.NextUploadIdMarker,
			KeyMarker:      out.NextKeyMarker,
		})
		cancel()
		if err != nil {
			return err
		}

		if len(out2.Uploads) != 0 {
			return fmt.Errorf("expected empty uplodas list, instead got %v", out2.Uploads)
		}
		expectedCps = []string{"foo/", "some/", "xyz/", "zzz/"}
		if !comparePrefixes(expectedCps, out2.CommonPrefixes) {
			return fmt.Errorf("expected the common prefixes to be %v, instead got %v", expectedCps, out2.CommonPrefixes)
		}
		if getString(out2.KeyMarker) != "foo/" {
			return fmt.Errorf("expected key marker to be 'foo/', instead got %s", getString(out2.KeyMarker))
		}
		if getString(out2.UploadIdMarker) != getString(uploads[1].UploadId) {
			return fmt.Errorf("expected the upload id marker to be %s, instead got %s", getString(uploads[1].UploadId), getString(out2.UploadIdMarker))
		}
		if getString(out2.NextKeyMarker) != "" {
			return fmt.Errorf("expected empty next key marker, instead got %s", getString(out2.NextKeyMarker))
		}
		if getString(out2.NextUploadIdMarker) != "" {
			return fmt.Errorf("expected empty next upload id marker, instead got %s", getString(out2.NextUploadIdMarker))
		}
		if *out2.IsTruncated {
			return fmt.Errorf("expected a non-truncated response")
		}

		return nil
	})
}

func ListMultipartUploads_prefix(s *S3Conf) error {
	testName := "ListMultipartUploads_prefix"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		prefix := "foo"
		uploads := make([]types.MultipartUpload, 0, 8)
		for _, key := range []string{
			"abc/something",
			"foo/bar/baz",
			"foo/quxx",
			"hello/world",
			"xyz/hello",
			"zzz/bca",
			"some/very/nested/mp/object",
			"foo/xyz",
		} {
			out, err := createMp(s3client, bucket, key)
			if err != nil {
				return err
			}

			if strings.HasPrefix(key, prefix) {
				uploads = append(uploads, types.MultipartUpload{
					Key:          out.Key,
					UploadId:     out.UploadId,
					StorageClass: types.StorageClassStandard,
				})
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket: &bucket,
			Prefix: &prefix,
		})
		cancel()
		if err != nil {
			return err
		}

		if getString(out.Prefix) != prefix {
			return fmt.Errorf("expected the prefix to be %s, instead got %s", prefix, getString(out.Prefix))
		}
		if !compareMultipartUploads(out.Uploads, uploads) {
			return fmt.Errorf("expected the uploads list to be %v, instead got %v", uploads, out.Uploads)
		}

		return nil
	})
}

func ListMultipartUploads_both_delimiter_and_prefix(s *S3Conf) error {
	testName := "ListMultipartUploads_both_delimiter_and_prefix"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for _, key := range []string{
			"foo/abc/bbb/aaa/c",
			"abc/something",
			"foo/bar/baz",
			"foo/quxx",
			"hello/world",
			"foo/random/object",
			"foo/random/another/object",
			"xyz/hello",
			"zzz/bca",
			"some/very/nested/mp/object",
			"foo/xyz",
		} {
			_, err := createMp(s3client, bucket, key)
			if err != nil {
				return err
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:    &bucket,
			Delimiter: getPtr("/"),
			Prefix:    getPtr("foo/"),
		})
		cancel()
		if err != nil {
			return err
		}

		expectedCps := []string{"foo/abc/", "foo/bar/", "foo/random/"}
		if !comparePrefixes(expectedCps, out.CommonPrefixes) {
			return fmt.Errorf("expected the common prefixes to be %v, instead got %v", expectedCps, out.CommonPrefixes)
		}

		return nil
	})
}

func ListMultipartUploads_delimiter_no_matches(s *S3Conf) error {
	testName := "ListMultipartUploads_delimiter_no_matches"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		uploads := make([]types.MultipartUpload, 0, 8)
		for _, key := range []string{
			"abc/something",
			"foo/bar/baz",
			"foo/quxx",
			"hello/world",
			"xyz/hello",
			"zzz/bca",
			"some/very/nested/mp/object",
			"foo/xyz",
		} {
			out, err := createMp(s3client, bucket, key)
			if err != nil {
				return err
			}

			uploads = append(uploads, types.MultipartUpload{
				Key:          out.Key,
				UploadId:     out.UploadId,
				StorageClass: types.StorageClassStandard,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:    &bucket,
			Delimiter: getPtr("delim"),
		})
		cancel()
		if err != nil {
			return err
		}

		sort.SliceStable(uploads, func(i, j int) bool {
			return *uploads[i].Key < *uploads[j].Key
		})

		if !compareMultipartUploads(uploads, out.Uploads) {
			return fmt.Errorf("expected the uploads to be %v, instead got %v", uploads, out.Uploads)
		}
		if len(out.CommonPrefixes) != 0 {
			return fmt.Errorf("expected empty common prefixes, instead got %v", out.CommonPrefixes)
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
