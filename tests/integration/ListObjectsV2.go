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
)

func ListObjectsV2_start_after(s *S3Conf) error {
	testName := "ListObjectsV2_start_after"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		contents, err := putObjects(s3client, []string{"foo", "bar", "baz"}, bucket)
		if err != nil {
			return err
		}

		startAfter := "bar"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:     &bucket,
			StartAfter: &startAfter,
		})
		cancel()
		if err != nil {
			return err
		}

		if getString(out.StartAfter) != startAfter {
			return fmt.Errorf("expected StartAfter to be %v, insted got %v",
				startAfter, getString(out.StartAfter))
		}
		if !compareObjects(contents[1:], out.Contents) {
			return fmt.Errorf("expected the output to be %v, instead got %v",
				contents, out.Contents)
		}

		return nil
	})
}

func ListObjectsV2_both_start_after_and_continuation_token(s *S3Conf) error {
	testName := "ListObjectsV2_both_start_after_and_continuation_token"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		contents, err := putObjects(s3client, []string{"foo", "bar", "baz", "quxx"}, bucket)
		if err != nil {
			return err
		}
		var maxKeys int32 = 1

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:  &bucket,
			MaxKeys: &maxKeys,
		})
		cancel()
		if err != nil {
			return err
		}

		if out.IsTruncated == nil || !*out.IsTruncated {
			return fmt.Errorf("expected output to be truncated")
		}

		if out.MaxKeys == nil {
			return fmt.Errorf("expected non nil max-keys")
		}

		if *out.MaxKeys != maxKeys {
			return fmt.Errorf("expected max-keys to be %v, instead got %v",
				maxKeys, out.MaxKeys)
		}

		if getString(out.NextContinuationToken) != "bar" {
			return fmt.Errorf("expected next-marker to be baz, instead got %v",
				getString(out.NextContinuationToken))
		}

		if !compareObjects(contents[:1], out.Contents) {
			return fmt.Errorf("expected the output to be %v, instead got %v",
				contents[:1], out.Contents)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            &bucket,
			ContinuationToken: out.NextContinuationToken,
			StartAfter:        getPtr("baz"),
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareObjects(contents[2:], resp.Contents) {
			return fmt.Errorf("expected the output to be %v, instead got %v",
				contents[2:], resp.Contents)
		}

		return nil
	})
}

func ListObjectsV2_start_after_not_in_list(s *S3Conf) error {
	testName := "ListObjectsV2_start_after_not_in_list"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		contents, err := putObjects(s3client, []string{"foo", "bar", "baz", "quxx"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:     &bucket,
			StartAfter: getPtr("blah"),
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareObjects(contents[2:], out.Contents) {
			return fmt.Errorf("expected the output to be %v, instead got %v",
				contents[2:], out.Contents)
		}

		return nil
	})
}

func ListObjectsV2_start_after_empty_result(s *S3Conf) error {
	testName := "ListObjectsV2_start_after_empty_result"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"foo", "bar", "baz", "quxx"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:     &bucket,
			StartAfter: getPtr("zzz"),
		})
		cancel()
		if err != nil {
			return err
		}

		if len(out.Contents) != 0 {
			return fmt.Errorf("expected empty output instead got %v", out.Contents)
		}

		return nil
	})
}

func ListObjectsV2_both_delimiter_and_prefix(s *S3Conf) error {
	testName := "ListObjectsV2_both_delimiter_and_prefix"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{
			"sample.jpg",
			"photos/2006/January/sample.jpg",
			"photos/2006/February/sample2.jpg",
			"photos/2006/February/sample3.jpg",
			"photos/2006/February/sample4.jpg",
		}, bucket)
		if err != nil {
			return err
		}
		delim, prefix := "/", "photos/2006/"

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:    &bucket,
			Delimiter: &delim,
			Prefix:    &prefix,
		})
		cancel()
		if err != nil {
			return err
		}

		if res.Delimiter == nil || *res.Delimiter != delim {
			return fmt.Errorf("expected the delimiter to be %v", delim)
		}
		if res.Prefix == nil || *res.Prefix != prefix {
			return fmt.Errorf("expected the prefix to be %v", prefix)
		}
		if !comparePrefixes([]string{"photos/2006/February/", "photos/2006/January/"},
			res.CommonPrefixes) {
			return fmt.Errorf("expected the common prefixes to be %v, instead got %v",
				[]string{"photos/2006/February/", "photos/2006/January/"}, res.CommonPrefixes)
		}
		if len(res.Contents) != 0 {
			return fmt.Errorf("expected empty objects list, instead got %v", res.Contents)
		}

		return nil
	})
}

func ListObjectsV2_single_dir_object_with_delim_and_prefix(s *S3Conf) error {
	testName := "ListObjectsV2_single_dir_object_with_delim_and_prefix"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		contents, err := putObjects(s3client, []string{"a/"}, bucket)
		if err != nil {
			return err
		}

		delim, prefix := "/", "a"

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:    &bucket,
			Delimiter: &delim,
			Prefix:    &prefix,
		})
		cancel()
		if err != nil {
			return err
		}

		if !comparePrefixes([]string{"a/"}, res.CommonPrefixes) {
			return fmt.Errorf("expected the common prefixes to be %v, instead got %v",
				[]string{"a/"}, res.CommonPrefixes)
		}
		if len(res.Contents) != 0 {
			return fmt.Errorf("expected empty objects list, instead got %v",
				res.Contents)
		}

		prefix = "a/"

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err = s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:    &bucket,
			Delimiter: &delim,
			Prefix:    &prefix,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareObjects(contents, res.Contents) {
			return fmt.Errorf("expected the object list to be %v, instead got %v",
				[]string{"a/"}, res.Contents)
		}
		if len(res.CommonPrefixes) != 0 {
			return fmt.Errorf("expected empty common prefixes, instead got %v",
				res.CommonPrefixes)
		}

		return nil
	})
}

func ListObjectsV2_truncated_common_prefixes(s *S3Conf) error {
	testName := "ListObjectsV2_truncated_common_prefixes"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"d1/f1", "d2/f2", "d3/f3", "d4/f4"}, bucket)
		if err != nil {
			return err
		}

		delim, maxKeys := "/", int32(3)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:    &bucket,
			Delimiter: &delim,
			MaxKeys:   &maxKeys,
		})
		cancel()
		if err != nil {
			return err
		}

		if !comparePrefixes([]string{"d1/", "d2/", "d3/"}, out.CommonPrefixes) {
			return fmt.Errorf("expected the common prefixes to be %v, instead got %v",
				[]string{"d1/", "d2/", "d3/"}, sprintPrefixes(out.CommonPrefixes))
		}

		if out.MaxKeys == nil {
			return fmt.Errorf("expected non nil max-keys")
		}
		if *out.MaxKeys != maxKeys {
			return fmt.Errorf("expected the max-keys to be %v, instead got %v",
				maxKeys, *out.MaxKeys)
		}
		if getString(out.Delimiter) != delim {
			return fmt.Errorf("expected the delimiter to be %v, instead got %v",
				delim, getString(out.Delimiter))
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err = s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            &bucket,
			Delimiter:         &delim,
			ContinuationToken: out.NextContinuationToken,
		})
		cancel()
		if err != nil {
			return err
		}

		if !comparePrefixes([]string{"d4/"}, out.CommonPrefixes) {
			return fmt.Errorf("expected the common prefixes to be %v, instead got %v",
				[]string{"d4/"}, sprintPrefixes(out.CommonPrefixes))
		}
		if getString(out.Delimiter) != delim {
			return fmt.Errorf("expected the delimiter to be %v, instead got %v",
				delim, getString(out.Delimiter))
		}

		return nil
	})
}

func ListObjectsV2_non_truncated_common_prefixes(s *S3Conf) error {
	testName := "ListObjectsV2_non_truncated_common_prefixes"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"asdf", "boo/bar", "boo/baz/xyzzy", "cquux/thud", "cquux/bla"}, bucket)
		if err != nil {
			return err
		}

		delim, marker, maxKeys := "/", "boo/", int32(1)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:     &bucket,
			StartAfter: &marker,
			Delimiter:  &delim,
			MaxKeys:    &maxKeys,
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

func ListObjectsV2_all_objs_max_keys(s *S3Conf) error {
	testName := "ListObjectsV2_all_objs_max_keys"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		contents, err := putObjects(s3client, []string{"bar", "baz", "foo"}, bucket)
		if err != nil {
			return err
		}

		maxKeys := int32(3)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:  &bucket,
			MaxKeys: &maxKeys,
		})
		cancel()
		if err != nil {
			return err
		}

		if out.IsTruncated == nil || *out.IsTruncated {
			return fmt.Errorf("expected the output not to be truncated")
		}
		if getString(out.NextContinuationToken) != "" {
			return fmt.Errorf("expected empty NextContinuationToken, instead got %v",
				getString(out.NextContinuationToken))
		}
		if out.MaxKeys == nil {
			return fmt.Errorf("expected non nil max-keys")
		}
		if *out.MaxKeys != maxKeys {
			return fmt.Errorf("expected the max-keys to be %v, instead got %v",
				maxKeys, *out.MaxKeys)
		}

		if !compareObjects(contents, out.Contents) {
			return fmt.Errorf("expected the objects list to be %v, instead got %v",
				contents, out.Contents)
		}

		return nil
	})
}

func ListObjectsV2_exceeding_max_keys(s *S3Conf) error {
	testName := "ListObjectsV2_exceeding_max_keys"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		maxKeys := int32(233453333)
		out, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
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

func ListObjectsV2_list_all_objs(s *S3Conf) error {
	testName := "ListObjectsV2_list_all_objs"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		contents, err := putObjects(s3client, []string{"a", "aa", "aaa", "aaaa", "bar", "baz", "foo", "obj1", "hello/world", "xyzz/quxx"}, bucket)
		if err != nil {
			return err
		}

		// Test 1: List all objects without pagination
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if out.StartAfter != nil {
			return fmt.Errorf("expected the StartAfter to be nil, instead got %v",
				*out.StartAfter)
		}
		if out.ContinuationToken != nil {
			return fmt.Errorf("expected the ContinuationToken to be nil, instead got %v",
				*out.ContinuationToken)
		}
		if out.NextContinuationToken != nil {
			return fmt.Errorf("expected the NextContinuationToken to be nil, instead got %v",
				*out.NextContinuationToken)
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
		var continuationToken *string
		var allObjects []types.Object
		maxKeys := int32(2)

		for {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
				Bucket:            &bucket,
				MaxKeys:           &maxKeys,
				ContinuationToken: continuationToken,
			})
			cancel()
			if err != nil {
				return err
			}

			allObjects = append(allObjects, out.Contents...)

			if out.NextContinuationToken == nil || !*out.IsTruncated {
				break
			}
			continuationToken = out.NextContinuationToken
		}

		if !compareObjects(contents, allObjects) {
			return fmt.Errorf("expected the paginated contents to be %v, instead got %v",
				contents, allObjects)
		}

		return nil
	})
}

func ListObjectsV2_with_owner(s *S3Conf) error {
	testName := "ListObjectsV2_with_owner"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objs, err := putObjects(s3client, []string{"foo", "bar/baz", "quxx/xyz/eee", "abc/", "bcc"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:     &bucket,
			FetchOwner: getBoolPtr(true),
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

func ListObjectsV2_with_checksum(s *S3Conf) error {
	testName := "ListObjectsV2_with_checksum"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		contents := []types.Object{}

		for i, el := range types.ChecksumAlgorithmCrc32.Values() {
			key := fmt.Sprintf("obj-%v", i)
			size := int64(i * 100)
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
		res, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareObjects(res.Contents, contents) {
			return fmt.Errorf("expected the objects list to be %v, instead got %v",
				contents, res.Contents)
		}

		return nil
	})
}

func ListObjectsV2_invalid_parent_prefix(s *S3Conf) error {
	testName := "ListObjectsV2_invalid_parent_prefix"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"file"}, bucket)
		if err != nil {
			return err
		}

		delim, maxKeys := "/", int32(100)
		prefix := "file/file/file"

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:    &bucket,
			Delimiter: &delim,
			MaxKeys:   &maxKeys,
			Prefix:    &prefix,
		})
		cancel()
		if err != nil {
			return err
		}

		if len(out.CommonPrefixes) > 0 {
			return fmt.Errorf("expected the common prefixes to be %v, instead got %v",
				[]string{""}, out.CommonPrefixes)
		}
		if out.MaxKeys == nil {
			return fmt.Errorf("expected non nil max-keys")
		}
		if *out.MaxKeys != maxKeys {
			return fmt.Errorf("expected the max-keys to be %v, instead got %v",
				maxKeys, *out.MaxKeys)
		}
		if getString(out.Delimiter) != delim {
			return fmt.Errorf("expected the delimiter to be %v, instead got %v",
				delim, getString(out.Delimiter))
		}
		if len(out.Contents) > 0 {
			return fmt.Errorf("expected the objects to be %v, instead got %v",
				[]types.Object{}, out.Contents)
		}
		return nil
	})
}
