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

func ListObjects_non_existing_bucket(s *S3Conf) error {
	testName := "ListObjects_non_existing_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		bckt := getBucketName()
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bckt,
		})
		cancel()
		if err := checkSdkApiErr(err, "NoSuchBucket"); err != nil {
			return err
		}
		return nil
	})
}

func ListObjects_with_prefix(s *S3Conf) error {
	testName := "ListObjects_with_prefix"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		prefix := "obj"
		objWithPrefix := []string{prefix + "/bar", prefix + "/baz/bla", prefix + "/foo"}
		contents, err := putObjects(s3client, append(objWithPrefix, []string{"azy/csf", "hell"}...), bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
			Prefix: &prefix,
		})
		cancel()
		if err != nil {
			return err
		}

		if getString(out.Prefix) != prefix {
			return fmt.Errorf("expected prefix %v, instead got %v",
				prefix, getString(out.Prefix))
		}
		if !compareObjects(contents[2:], out.Contents) {
			return fmt.Errorf("expected the output to be %v, instead got %v",
				contents[2:], out.Contents)
		}

		return nil
	})
}

func ListObjects_paginated(s *S3Conf) error {
	testName := "ListObjects_paginated"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"dir1/subdir/file.txt", "dir1/subdir.ext", "dir1/subdir1.ext", "dir1/subdir2.ext"}, bucket)
		if err != nil {
			return err
		}

		objs, prefixes, err := listObjects(s3client, bucket, "dir1/", "/", 2)
		if err != nil {
			return err
		}

		expected := []string{"dir1/subdir.ext", "dir1/subdir1.ext", "dir1/subdir2.ext"}
		if !hasObjNames(objs, expected) {
			return fmt.Errorf("expected objects %v, instead got %v",
				expected, objStrings(objs))
		}

		expectedPrefix := []string{"dir1/subdir/"}
		if !hasPrefixName(prefixes, expectedPrefix) {
			return fmt.Errorf("expected prefixes %v, instead got %v",
				expectedPrefix, pfxStrings(prefixes))
		}

		return nil
	})
}

func ListObjects_truncated(s *S3Conf) error {
	testName := "ListObjects_truncated"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		maxKeys := int32(2)
		contents, err := putObjects(s3client, []string{"foo", "bar", "baz"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out1, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket:  &bucket,
			MaxKeys: &maxKeys,
		})
		cancel()
		if err != nil {
			return err
		}

		if out1.IsTruncated == nil || !*out1.IsTruncated {
			return fmt.Errorf("expected output to be truncated")
		}

		if out1.MaxKeys == nil {
			return fmt.Errorf("expected non nil max-keys")
		}
		if *out1.MaxKeys != maxKeys {
			return fmt.Errorf("expected max-keys to be %v, instead got %v",
				maxKeys, out1.MaxKeys)
		}

		if out1.NextMarker == nil {
			return fmt.Errorf("expected non nil next marker")
		}
		if *out1.NextMarker != "baz" {
			return fmt.Errorf("expected next-marker to be baz, instead got %v",
				*out1.NextMarker)
		}

		if !compareObjects(contents[:2], out1.Contents) {
			return fmt.Errorf("expected the output to be %v, instead got %v",
				contents[:2], out1.Contents)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out2, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
			Marker: out1.NextMarker,
		})
		cancel()
		if err != nil {
			return err
		}

		if out2.IsTruncated == nil {
			return fmt.Errorf("expected non nil is-truncated")
		}
		if *out2.IsTruncated {
			return fmt.Errorf("expected output not to be truncated")
		}

		if getString(out2.Marker) != getString(out1.NextMarker) {
			return fmt.Errorf("expected marker to be %v, instead got %v",
				getString(out1.NextMarker), getString(out2.Marker))
		}

		if !compareObjects(contents[2:], out2.Contents) {
			return fmt.Errorf("expected the output to be %v, instead got %v",
				contents[2:], out2.Contents)
		}
		return nil
	})
}

func ListObjects_invalid_max_keys(s *S3Conf) error {
	testName := "ListObjects_invalid_max_keys"
	maxKeys := int32(-5)
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket:  &bucket,
			MaxKeys: &maxKeys,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetNegativeMaxLimiterErr("max-keys")); err != nil {
			return err
		}

		return nil
	})
}

func ListObjects_max_keys_0(s *S3Conf) error {
	testName := "ListObjects_max_keys_0"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objects := []string{"foo", "bar", "baz"}
		_, err := putObjects(s3client, objects, bucket)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		maxKeys := int32(0)
		out, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket:  &bucket,
			MaxKeys: &maxKeys,
		})
		cancel()
		if err != nil {
			return nil
		}

		if len(out.Contents) > 0 {
			return fmt.Errorf("unexpected output for list objects with max-keys 0")
		}

		return nil
	})
}

func ListObjects_exceeding_max_keys(s *S3Conf) error {
	testName := "ListObjects_exceeding_max_keys"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		maxKeys := int32(233333333)
		out, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket:  &bucket,
			MaxKeys: &maxKeys,
		})
		cancel()
		if err != nil {
			return nil
		}

		if out.MaxKeys == nil {
			return fmt.Errorf("unexpected nil max-keys")
		}
		if *out.MaxKeys != 1000 {
			return fmt.Errorf("expected the max-keys to be %v, instaed got %v",
				1000, *out.MaxKeys)
		}

		return nil
	})
}

func ListObjects_delimiter(s *S3Conf) error {
	testName := "ListObjects_delimiter"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"foo/bar/baz", "foo/bar/xyzzy", "quux/thud", "asdf"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket:    &bucket,
			Delimiter: getPtr("/"),
		})
		cancel()
		if err != nil {
			return err
		}

		if getString(out.Delimiter) != "/" {
			return fmt.Errorf("expected delimiter to be /, instead got %v",
				getString(out.Delimiter))
		}
		if len(out.Contents) != 1 || getString(out.Contents[0].Key) != "asdf" {
			return fmt.Errorf("expected result [\"asdf\"], instead got %v",
				out.Contents)
		}

		if !comparePrefixes([]string{"foo/", "quux/"}, out.CommonPrefixes) {
			return fmt.Errorf("expected common prefixes to be %v, instead got %v",
				[]string{"foo/", "quux/"}, out.CommonPrefixes)
		}

		return nil
	})
}

func ListObjects_max_keys_none(s *S3Conf) error {
	testName := "ListObjects_max_keys_none"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"foo", "bar", "baz"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if out.MaxKeys == nil {
			return fmt.Errorf("expected non nil max-keys")
		}
		if *out.MaxKeys != 1000 {
			return fmt.Errorf("expected max-keys to be 1000, instead got %v",
				out.MaxKeys)
		}

		return nil
	})
}

func ListObjects_marker_not_from_obj_list(s *S3Conf) error {
	testName := "ListObjects_marker_not_from_obj_list"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		contents, err := putObjects(s3client, []string{"foo", "bar", "baz", "qux", "hello", "xyz"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
			Marker: getPtr("ceil"),
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareObjects(contents[2:], out.Contents) {
			return fmt.Errorf("expected output to be %v, instead got %v",
				contents, out.Contents)
		}

		return nil
	})
}

func ListObjects_with_checksum(s *S3Conf) error {
	testName := "ListObjects_with_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		contents := []types.Object{}
		for i, el := range types.ChecksumAlgorithmCrc32.Values() {
			key := fmt.Sprintf("obj-%v", i)
			size := int64(i * 30)
			out, err := putObjectWithData(size, &s3.PutObjectInput{
				Bucket:            &bucket,
				Key:               &key,
				ChecksumAlgorithm: el,
			}, s3client)
			if err != nil {
				return err
			}

			contents = append(contents, types.Object{
				Key:          &key,
				ETag:         out.res.ETag,
				Size:         &size,
				StorageClass: types.ObjectStorageClassStandard,
				ChecksumAlgorithm: []types.ChecksumAlgorithm{
					el,
				},
				ChecksumType: out.res.ChecksumType,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareObjects(contents, res.Contents) {
			return fmt.Errorf("expected the objects list to be %v, instead got %v",
				contents, res.Contents)
		}

		return nil
	})
}

func ListObjects_list_all_objs(s *S3Conf) error {
	testName := "ListObjects_list_all_objs"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		contents, err := putObjects(s3client, []string{"foo", "bar", "baz", "quxx/ceil", "ceil", "hello/world"}, bucket)
		if err != nil {
			return err
		}

		// Test 1: List all objects without pagination
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if out.Marker != nil {
			return fmt.Errorf("expected the Marker to be nil, instead got %v",
				*out.Marker)
		}
		if out.NextMarker != nil {
			return fmt.Errorf("expected the NextMarker to be nil, instead got %v",
				*out.NextMarker)
		}
		if out.Delimiter != nil {
			return fmt.Errorf("expected the Delimiter to be nil, instead got %v",
				*out.Delimiter)
		}
		if out.Prefix != nil {
			return fmt.Errorf("expected the Prefix to be nil, instead got %v",
				*out.Prefix)
		}

		if !compareObjects(contents, out.Contents) {
			return fmt.Errorf("expected the contents to be %v, instead got %v",
				contents, out.Contents)
		}

		// Test 2: List all objects with pagination using ListObjectsV2
		var marker *string
		var allObjects []types.Object
		maxKeys := int32(2)

		for {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
				Bucket:  &bucket,
				MaxKeys: &maxKeys,
				Marker:  marker,
			})
			cancel()
			if err != nil {
				return err
			}

			allObjects = append(allObjects, out.Contents...)

			if out.NextMarker == nil || !*out.IsTruncated {
				break
			}
			marker = out.NextMarker
		}

		if !compareObjects(contents, allObjects) {
			return fmt.Errorf("expected the contents to be %v, instead got %v",
				contents, allObjects)
		}

		return nil
	})
}

func ListObjects_nested_dir_file_objs(s *S3Conf) error {
	testName := "ListObjects_nested_dir_file_objs"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		contents, err := putObjects(s3client, []string{"foo/bar/", "foo/bar/baz", "foo/bar/quxx"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareObjects(contents, res.Contents) {
			return fmt.Errorf("expected the objects list to be %+v, instead got %+v", contents, res.Contents)
		}

		// Clean up the nested objects to avoid `ErrDirectoryNotEmpty` error on teardown
		for _, obj := range []string{"foo/bar/baz", "foo/bar/quxx"} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func ListObjects_check_owner(s *S3Conf) error {
	testName := "ListObjects_check_owner"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objs, err := putObjects(s3client, []string{"foo", "bar/baz", "quxx/xyz/eee", "abc/", "bcc"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		for i := range res.Contents {
			res.Contents[i].Owner = &types.Owner{
				ID: &s.awsID,
			}
		}

		if !compareObjects(objs, res.Contents) {
			return fmt.Errorf("expected the contents to be %v, instead got %v",
				objs, res.Contents)
		}

		return nil

	})
}

func ListObjects_non_truncated_common_prefixes(s *S3Conf) error {
	testName := "ListObjects_non_truncated_common_prefixes"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"asdf", "boo/bar", "boo/baz/xyzzy", "cquux/thud", "cquux/bla"}, bucket)
		if err != nil {
			return err
		}

		delim, marker, maxKeys := "/", "boo/", int32(1)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket:    &bucket,
			Marker:    &marker,
			Delimiter: &delim,
			MaxKeys:   &maxKeys,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.IsTruncated == nil {
			return fmt.Errorf("expected non-nil istruncated")
		}
		if *res.IsTruncated {
			return fmt.Errorf("expected non-truncated result")
		}
		if res.MaxKeys == nil {
			return fmt.Errorf("expected non nil max-keys")
		}
		if *res.MaxKeys != maxKeys {
			return fmt.Errorf("expected max-keys to be %v, instead got %v",
				maxKeys, *res.MaxKeys)
		}
		if getString(res.Delimiter) != delim {
			return fmt.Errorf("expected delimiter to be %v, instead got %v",
				delim, getString(res.Delimiter))
		}
		if getString(res.Marker) != marker {
			return fmt.Errorf("expected marker to be %v, instead got %v",
				getString(res.Marker), marker)
		}
		if len(res.Contents) != 0 {
			return fmt.Errorf("expected empty contents, instead got %+v",
				res.Contents)
		}
		cPrefs := []string{"cquux/"}
		if !comparePrefixes(cPrefs, res.CommonPrefixes) {
			return fmt.Errorf("expected common prefixes to be %v, instead got %+v",
				cPrefs, sprintPrefixes(res.CommonPrefixes))
		}

		return nil
	})
}

// ListObjects should not list any pending multipart uploads
// and no pending mp should block the bucket from deletion
func ListObjects_should_not_list_pending_mps(s *S3Conf) error {
	testName := "ListObjects_should_not_list_pending_mps"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for i := range 5 {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
				Bucket: &bucket,
				Key:    getPtr(fmt.Sprintf("obj-%d", i)),
			})
			cancel()
			if err != nil {
				return err
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if len(res.Contents) != 0 {
			return fmt.Errorf("expected empty object list result, instead got %v", res.Contents)
		}
		if len(res.CommonPrefixes) != 0 {
			return fmt.Errorf("expected empty object common prefixes result, instead got %v", res.CommonPrefixes)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteBucket(ctx, &s3.DeleteBucketInput{
			Bucket: &bucket,
		})
		cancel()
		return err
	}, withSkipTearDown())
}

// ListObjects with a marker should not surface pending multipart uploads
// even when real objects are interleaved with the marker boundary.
func ListObjects_mp_masking_with_marker(s *S3Conf) error {
	testName := "ListObjects_mp_masking_with_marker"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		// Create pending multipart uploads with keys that sort after all real objects
		for i := range 3 {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
				Bucket: &bucket,
				Key:    getPtr(fmt.Sprintf("zzz-mp-%d", i+1)),
			})
			cancel()
			if err != nil {
				return err
			}
		}

		contents, err := putObjects(s3client, []string{"aaa", "bbb", "ccc"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
			Marker: getPtr("aaa"),
		})
		cancel()
		if err != nil {
			return err
		}

		// Expect only bbb and ccc (after marker "aaa"), no multipart upload objects
		if !compareObjects(contents[1:], out.Contents) {
			return fmt.Errorf("expected objects %v, instead got %v",
				contents[1:], out.Contents)
		}
		if out.IsTruncated == nil || *out.IsTruncated {
			return fmt.Errorf("expected non-truncated result")
		}

		return nil
	})
}

// ListObjects truncation should count only real objects, not pending multipart uploads.
func ListObjects_mp_masking_truncation(s *S3Conf) error {
	testName := "ListObjects_mp_masking_truncation"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		// Create pending multipart uploads with keys that sort after real objects
		for i := range 2 {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
				Bucket: &bucket,
				Key:    getPtr(fmt.Sprintf("zzz-mp-%d", i+1)),
			})
			cancel()
			if err != nil {
				return err
			}
		}

		contents, err := putObjects(s3client, []string{"obj-a", "obj-b", "obj-c", "obj-d"}, bucket)
		if err != nil {
			return err
		}

		maxKeys := int32(2)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out1, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket:  &bucket,
			MaxKeys: &maxKeys,
		})
		cancel()
		if err != nil {
			return err
		}

		if out1.IsTruncated == nil || !*out1.IsTruncated {
			return fmt.Errorf("expected first page to be truncated")
		}
		if !compareObjects(contents[:2], out1.Contents) {
			return fmt.Errorf("expected first page objects %v, instead got %v",
				contents[:2], out1.Contents)
		}
		if out1.NextMarker == nil || *out1.NextMarker == "" {
			return fmt.Errorf("expected non-empty NextMarker")
		}
		if *out1.NextMarker != "obj-b" {
			return fmt.Errorf("expected NextMarker to be obj-b, instead got %v", *out1.NextMarker)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out2, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
			Marker: out1.NextMarker,
		})
		cancel()
		if err != nil {
			return err
		}

		if out2.IsTruncated == nil || *out2.IsTruncated {
			return fmt.Errorf("expected second page to not be truncated")
		}
		if !compareObjects(contents[2:], out2.Contents) {
			return fmt.Errorf("expected second page objects %v, instead got %v",
				contents[2:], out2.Contents)
		}

		return nil
	})
}

// ListObjects with a delimiter should not include the .sgwtmp/ multipart prefix
// in common prefixes, even when pending multipart uploads exist.
func ListObjects_mp_masking_delimiter(s *S3Conf) error {
	testName := "ListObjects_mp_masking_delimiter"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		// Create pending multipart uploads
		for i := range 2 {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
				Bucket: &bucket,
				Key:    getPtr(fmt.Sprintf("zzz-mp-%d", i+1)),
			})
			cancel()
			if err != nil {
				return err
			}
		}

		_, err := putObjects(s3client, []string{"dir1/file1", "dir2/file2"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket:    &bucket,
			Delimiter: getPtr("/"),
		})
		cancel()
		if err != nil {
			return err
		}

		if len(out.Contents) != 0 {
			return fmt.Errorf("expected empty Contents, instead got %v", out.Contents)
		}
		if !comparePrefixes([]string{"dir1/", "dir2/"}, out.CommonPrefixes) {
			return fmt.Errorf("expected common prefixes [dir1/ dir2/], instead got %v",
				sprintPrefixes(out.CommonPrefixes))
		}

		return nil
	})
}
