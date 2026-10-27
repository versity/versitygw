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
	"crypto/sha256"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
	"golang.org/x/sync/errgroup"
)

func PutObject_overwrite_dir_obj(s *S3Conf) error {
	testName := "PutObject_overwrite_dir_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"foo/", "foo"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrExistingObjectIsDirectory)); err != nil {
			return err
		}
		return nil
	})
}

func PutObject_overwrite_file_obj(s *S3Conf) error {
	testName := "PutObject_overwrite_file_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"foo", "foo/"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectParentIsFile)); err != nil {
			return err
		}
		return nil
	})
}

func PutObject_overwrite_file_obj_with_nested_obj(s *S3Conf) error {
	testName := "PutObject_overwrite_file_obj_with_nested_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"foo", "foo/bar"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectParentIsFile)); err != nil {
			return err
		}
		return nil
	})
}

func PutObject_dir_obj_with_data(s *S3Conf) error {
	testName := "PutObject_dir_obj_with_data"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjectWithData(int64(20), &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    getPtr("obj/"),
		}, s3client)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrDirectoryObjectContainsData)); err != nil {
			return err
		}
		return nil
	})
}

func PutObject_with_slashes(s *S3Conf) error {
	testName := "PutObject_with_slashes"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objs, err := putObjects(s3client, []string{
			"/obj", "foo//bar", "/foo/baz/bar", "////////bar", "foo//////quxx",
		}, bucket)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		// it's en expected bahvior in posix to normalize the object pahts,
		// by removing multiple slashes
		normalizedObjs := []string{
			"bar",
			"foo/bar",
			"foo/baz/bar",
			"foo/quxx",
			"obj",
		}

		for i := range objs {
			objs[i].Key = &normalizedObjs[i]
		}

		if !compareObjects(objs, res.Contents) {
			return fmt.Errorf("expected the objects to be %vß, instead got %v",
				objStrings(objs), objStrings(res.Contents))
		}

		return nil
	})
}

func PutObject_windows_reserved_names(s *S3Conf) error {
	testName := "PutObject_windows_reserved_names"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		// Windows can't name a file after these keys: each one is next to
		// the key Windows would store it as
		keys := []string{
			"question?", "question", "asterisk*", `quote"`, "colon:name", "C:drive",
			"lt<gt>", "pipe|", "tab\tchar",
			`back\slash`, "back/slash", `dir\..\..\escape`,
			"trailingdot.", "trailingdot", "trailingspace ", "trailingspace",
			"dotdir./file", "dotdir/file", "spacedir /file", "spacedir/file",
			"CON", "nul.txt", "aux/obj", "com1", "LPT9.log", "CONIN$",
			"pua\uf03f", "pua?",
		}
		for _, key := range keys {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &key,
				Body:   strings.NewReader(key),
			})
			cancel()
			if err != nil {
				return fmt.Errorf("put %q: %w", key, err)
			}
		}

		for _, key := range keys {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
				Bucket: &bucket,
				Key:    &key,
			})
			if err != nil {
				cancel()
				return fmt.Errorf("get %q: %w", key, err)
			}
			body, err := io.ReadAll(out.Body)
			out.Body.Close()
			cancel()
			if err != nil {
				return fmt.Errorf("read %q: %w", key, err)
			}
			if string(body) != key {
				return fmt.Errorf("expected the body of %q to be the key, instead got %q", key, body)
			}
		}

		sort.Strings(keys)
		var wantContents []string
		var wantPrefixes []string
		for _, key := range keys {
			prefix, _, found := strings.Cut(key, "/")
			if !found {
				wantContents = append(wantContents, key)
			} else if !slices.Contains(wantPrefixes, prefix+"/") {
				wantPrefixes = append(wantPrefixes, prefix+"/")
			}
		}

		for _, delimiter := range []string{"", "/"} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
				Bucket:    &bucket,
				Delimiter: &delimiter,
			})
			cancel()
			if err != nil {
				return err
			}
			var contents, prefixes []string
			for _, obj := range res.Contents {
				contents = append(contents, *obj.Key)
			}
			for _, cp := range res.CommonPrefixes {
				prefixes = append(prefixes, *cp.Prefix)
			}

			want, wantCps := keys, []string(nil)
			if delimiter != "" {
				want, wantCps = wantContents, wantPrefixes
			}
			if !slices.Equal(contents, want) {
				return fmt.Errorf("expected the objects listed with delimiter %q to be %q, instead got %q",
					delimiter, want, contents)
			}
			if !slices.Equal(prefixes, wantCps) {
				return fmt.Errorf("expected the common prefixes listed with delimiter %q to be %q, instead got %q",
					delimiter, wantCps, prefixes)
			}
		}

		return nil
	})
}

func CreateMultipartUpload_dir_obj(s *S3Conf) error {
	testName := "CreateMultipartUpload_dir_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := createMp(s3client, bucket, "obj/")
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrDirectoryObjectContainsData)); err != nil {
			return err
		}
		return nil
	})
}

func PutObject_name_too_long(s *S3Conf) error {
	testName := "PutObject_name_too_long"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key := genRandString(300)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &key,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrKeyTooLong)); err != nil {
			return err
		}

		return nil
	})
}

func HeadObject_name_too_long(s *S3Conf) error {
	testName := "HeadObject_name_too_long"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    getPtr(genRandString(300)),
		})
		cancel()
		if err := checkSdkApiErr(err, "BadRequest"); err != nil {
			return err
		}

		return nil
	})
}

func DeleteObject_name_too_long(s *S3Conf) error {
	testName := "DeleteObject_name_too_long"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    getPtr(genRandString(300)),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrKeyTooLong)); err != nil {
			return err
		}
		return nil
	})
}

func CopyObject_overwrite_same_dir_object(s *S3Conf) error {
	testName := "CopyObject_overwrite_same_dir_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"foo/"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        getPtr("foo"),
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, "foo/")),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrExistingObjectIsDirectory)); err != nil {
			return err
		}

		return nil
	})
}

func CopyObject_overwrite_same_file_object(s *S3Conf) error {
	testName := "CopyObject_overwrite_same_file_object"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := putObjects(s3client, []string{"foo"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        getPtr("foo/"),
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, "foo")),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectParentIsFile)); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_overwrite_dir_obj(s *S3Conf) error {
	testName := "CompleteMultipartUpload_overwrite_dir_obj"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dir, obj := "foo/", "foo"
		_, err := putObjects(s3client, []string{dir}, bucket)
		if err != nil {
			return err
		}

		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 100, 1, bucket, obj, *mp.UploadId)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: []types.CompletedPart{
					{ETag: parts[0].ETag, PartNumber: parts[0].PartNumber},
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrExistingObjectIsDirectory)); err != nil {
			return err
		}

		// the directory object isn't taken for the object of a completed upload
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: getPtr("non-existing-upload-id"),
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: []types.CompletedPart{
					{ETag: parts[0].ETag, PartNumber: parts[0].PartNumber},
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchUpload)); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &dir,
		})
		cancel()
		if err != nil {
			return err
		}

		// the failed upload can still be completed or aborted
		return checkAndAbortUpload(s3client, bucket, obj, *mp.UploadId)
	})
}

func CompleteMultipartUpload_overwrite_dir_obj_delete_marker(s *S3Conf) error {
	testName := "CompleteMultipartUpload_overwrite_dir_obj_delete_marker"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dir, obj := "foo/", "foo"
		versions, err := createObjVersions(s3client, bucket, dir, 1)
		if err != nil {
			return err
		}
		versions[0].IsLatest = getPtr(false)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &dir,
		})
		cancel()
		if err != nil {
			return err
		}
		delMarkers := []types.DeleteMarkerEntry{
			{Key: &dir, VersionId: out.VersionId, IsLatest: getPtr(true)},
		}

		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		parts, _, err := uploadParts(s3client, 100, 1, bucket, obj, *mp.UploadId)
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: []types.CompletedPart{
					{ETag: parts[0].ETag, PartNumber: parts[0].PartNumber},
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrExistingObjectIsDirectory)); err != nil {
			return err
		}

		// the delete marker of the directory object is left in place
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
		if !compareDelMarkers(delMarkers, res.DeleteMarkers) {
			return fmt.Errorf("expected the delete markers to be %v, instead got %v",
				delMarkers, res.DeleteMarkers)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &dir,
		})
		cancel()
		if err := checkSdkApiErr(err, "NotFound"); err != nil {
			return err
		}

		return checkAndAbortUpload(s3client, bucket, obj, *mp.UploadId)
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

func ObjectTagging_trailing_slash_counterpart(s *S3Conf) error {
	testName := "ObjectTagging_trailing_slash_counterpart"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		tagSet := []types.Tag{{Key: getPtr("key"), Value: getPtr("value")}}

		// a key and the same key with a trailing slash have one path: the
		// object of one of them isn't an object of the other
		for _, keys := range [][2]string{{"my-dir/", "my-dir"}, {"my-obj", "my-obj/"}} {
			obj, other := keys[0], keys[1]
			_, err := putObjectWithData(objDataLen(obj, 10), &s3.PutObjectInput{
				Bucket:  &bucket,
				Key:     &obj,
				Tagging: getPtr("key=value"),
			}, s3client)
			if err != nil {
				return err
			}

			err = checkObjectTaggingErr(s3client, bucket, other, "", s3err.GetAPIError(s3err.ErrNoSuchKey))
			if err != nil {
				return fmt.Errorf("%v: %w", other, err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
				Bucket: &bucket,
				Key:    &obj,
			})
			cancel()
			if err != nil {
				return fmt.Errorf("%v: %w", obj, err)
			}
			if !areTagsSame(res.TagSet, tagSet) {
				return fmt.Errorf("%v: expected the tag set to be %v, instead got %v",
					obj, tagSet, res.TagSet)
			}
		}

		// neither key names the parent directory of an object
		_, err := putObjects(s3client, []string{"my-parent/obj"}, bucket)
		if err != nil {
			return err
		}
		for _, key := range []string{"my-parent/", "my-parent"} {
			err := checkObjectTaggingErr(s3client, bucket, key, "", s3err.GetAPIError(s3err.ErrNoSuchKey))
			if err != nil {
				return fmt.Errorf("%v: %w", key, err)
			}
		}

		return nil
	})
}

func ObjectLock_trailing_slash_counterpart(s *S3Conf) error {
	testName := "ObjectLock_trailing_slash_counterpart"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		rDate := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
		lockedObjs := []objToDelete{}

		for _, keys := range [][2]string{{"my-dir/", "my-dir"}, {"my-obj", "my-obj/"}} {
			obj, other := keys[0], keys[1]
			_, err := putObjectWithData(objDataLen(obj, 10), &s3.PutObjectInput{
				Bucket:                    &bucket,
				Key:                       &obj,
				ChecksumAlgorithm:         types.ChecksumAlgorithmCrc32,
				ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatusOn,
				ObjectLockMode:            types.ObjectLockModeGovernance,
				ObjectLockRetainUntilDate: &rDate,
			}, s3client)
			if err != nil {
				return err
			}
			lockedObjs = append(lockedObjs, objToDelete{key: obj, removeOnlyLeglHold: true})

			err = checkObjectLockErr(s3client, bucket, other, "", s3err.GetAPIError(s3err.ErrNoSuchKey))
			if err != nil {
				return fmt.Errorf("%v: %w", other, err)
			}

			// the lock of the object doesn't protect the other key
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: &bucket,
				Key:    &other,
			})
			cancel()
			if err != nil {
				return fmt.Errorf("%v: %w", other, err)
			}

			err = checkObjectLock(s3client, bucket, obj, "", rDate)
			if err != nil {
				return fmt.Errorf("%v: %w", obj, err)
			}
		}

		return cleanupLockedObjects(s3client, bucket, lockedObjs)
	}, withLock())
}

// PutObject_race_with_delete tests the race between PutObject and DeleteObject
// in the same subdirectory.
// One goroutine sequentially puts "race-dir/0.txt" … "race-dir/N-1.txt".
// A second goroutine loops for the same number of iterations: it lists all
// objects under "race-dir/" and bulk-deletes them.  When the batch delete
// removes the last visible object in the directory, removeParents() rmdir's
// "race-dir/", which can race with the uploader's final link() step.
// The test asserts that no error is returned from either goroutine.
func PutObject_race_with_delete(s *S3Conf) error {
	testName := "PutObject_race_with_delete"
	const iterations = 100
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		eg := errgroup.Group{}

		// Upload goroutine: sequentially puts objects into race-dir/
		eg.Go(func() error {
			for i := range iterations {
				key := fmt.Sprintf("race-dir/%d.txt", i)
				ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
				_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
					Bucket: &bucket,
					Key:    &key,
				})
				cancel()
				if err != nil {
					return fmt.Errorf("put %d: %w", i, err)
				}
			}
			return nil
		})

		// Delete goroutine: repeatedly lists race-dir/ and bulk-deletes everything.
		// When the last object is removed, removeParents() rmdir's the directory,
		// racing with the concurrent link() call in the upload goroutine.
		eg.Go(func() error {
			for range iterations {
				ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
				res, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
					Bucket: &bucket,
					Prefix: getPtr("race-dir/"),
				})
				cancel()
				if err != nil {
					return fmt.Errorf("list: %w", err)
				}
				if len(res.Contents) == 0 {
					continue
				}

				objs := make([]types.ObjectIdentifier, 0, len(res.Contents))
				for _, obj := range res.Contents {
					objs = append(objs, types.ObjectIdentifier{Key: obj.Key})
				}

				ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
				out, err := s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
					Bucket: &bucket,
					Delete: &types.Delete{Objects: objs},
				})
				cancel()
				if err != nil {
					return fmt.Errorf("delete objects: %w", err)
				}
				if len(out.Errors) > 0 {
					return fmt.Errorf("delete error: key=%v code=%v msg=%v",
						aws.ToString(out.Errors[0].Key), aws.ToString(out.Errors[0].Code), aws.ToString(out.Errors[0].Message))
				}
			}
			return nil
		})

		return eg.Wait()
	})
}

// PutObject_race_with_sibling_deletes uploads, reads back and deletes
// distinct objects under the same nested prefix concurrently. The uploads
// stage their data outside of the prefix, so a delete of a sibling object
// removes the parent directories an upload has just made, or is about to
// publish its object in. Every upload must succeed and be readable.
func PutObject_race_with_sibling_deletes(s *S3Conf) error {
	testName := "PutObject_race_with_sibling_deletes"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return putGetDeleteRace(s3client, bucket, siblingRaceKey, func(key string, data []byte) error {
			_, err := putObjectWithData(int64(len(data)), &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &key,
				Body:   bytes.NewReader(data),
			}, s3client)
			return err
		})
	})
}

// PutObject_race_into_new_dirs is PutObject_race_with_sibling_deletes with
// new parent directories for each iteration: the uploads of the workers make
// the same directories at once, while the deletes of the workers that are
// ahead remove them.
func PutObject_race_into_new_dirs(s *S3Conf) error {
	testName := "PutObject_race_into_new_dirs"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return putGetDeleteRace(s3client, bucket, func(w, i int) string {
			return fmt.Sprintf("race/%d/a/b/c/d/e/w%d", i, w)
		}, func(key string, data []byte) error {
			_, err := putObjectWithData(int64(len(data)), &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &key,
				Body:   bytes.NewReader(data),
			}, s3client)
			return err
		})
	})
}

// CopyObject_race_with_sibling_deletes is PutObject_race_with_sibling_deletes
// with the objects made by CopyObject.
func CopyObject_race_with_sibling_deletes(s *S3Conf) error {
	testName := "CopyObject_race_with_sibling_deletes"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return putGetDeleteRace(s3client, bucket, siblingRaceKey, func(key string, data []byte) error {
			// the source is outside of the prefix, so that it doesn't keep
			// the parent directories of the copies in place
			src := "src/" + key
			_, err := putObjectWithData(int64(len(data)), &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &src,
				Body:   bytes.NewReader(data),
			}, s3client)
			if err != nil {
				return fmt.Errorf("put copy source: %w", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
				Bucket:     &bucket,
				Key:        &key,
				CopySource: getPtr(bucket + "/" + src),
			})
			cancel()
			if err != nil {
				return err
			}
			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: &bucket,
				Key:    &src,
			})
			cancel()
			if err != nil {
				return fmt.Errorf("delete copy source: %w", err)
			}
			return nil
		})
	})
}

// CompleteMultipartUpload_race_with_sibling_deletes is
// PutObject_race_with_sibling_deletes with the objects made by multipart
// uploads.
func CompleteMultipartUpload_race_with_sibling_deletes(s *S3Conf) error {
	testName := "CompleteMultipartUpload_race_with_sibling_deletes"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return putGetDeleteRace(s3client, bucket, siblingRaceKey, func(key string, data []byte) error {
			mp, err := createMp(s3client, bucket, key)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			part, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
				Bucket:     &bucket,
				Key:        &key,
				UploadId:   mp.UploadId,
				PartNumber: getPtr(int32(1)),
				Body:       bytes.NewReader(data),
			})
			cancel()
			if err != nil {
				return fmt.Errorf("upload part: %w", err)
			}
			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
				Bucket:   &bucket,
				Key:      &key,
				UploadId: mp.UploadId,
				MultipartUpload: &types.CompletedMultipartUpload{
					Parts: []types.CompletedPart{
						{ETag: part.ETag, PartNumber: getPtr(int32(1))},
					},
				},
			})
			cancel()
			return err
		})
	})
}

// PutObject_race_with_sibling_version_deletes races the uploads and the
// permanent deletes of the versions of distinct objects under the same
// nested prefix in a versioning-enabled bucket. Overwriting an object moves
// its previous version into the versioning directory, where the versions of
// objects share their parent directories too. Deleting a version removes the
// parent directories that hold no other version, and deleting the latest
// version of an object restores the previous one in its place.
func PutObject_race_with_sibling_version_deletes(s *S3Conf) error {
	testName := "PutObject_race_with_sibling_version_deletes"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		return raceWorkers(siblingRaceWorkers, siblingRaceIterations/2, func(w, i int) error {
			key := siblingRaceKey(w, i)
			var versions []string
			var datas [][]byte
			for v := range 2 {
				data := siblingRaceData(fmt.Sprintf("%v-%d", key, v))
				out, err := putObjectWithData(int64(len(data)), &s3.PutObjectInput{
					Bucket: &bucket,
					Key:    &key,
					Body:   bytes.NewReader(data),
				}, s3client)
				if err != nil {
					return fmt.Errorf("put %v version %d: %w", key, v, err)
				}
				versions = append(versions, getString(out.res.VersionId))
				datas = append(datas, data)
			}
			for v := range versions {
				err := checkObjectData(s3client, bucket, key, versions[v], datas[v])
				if err != nil {
					return fmt.Errorf("version %d: %w", v, err)
				}
			}
			// delete the latest version first, which restores the
			// previous one in its place
			for _, v := range []int{1, 0} {
				ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
				_, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
					Bucket:    &bucket,
					Key:       &key,
					VersionId: &versions[v],
				})
				cancel()
				if err != nil {
					return fmt.Errorf("delete %v version %d: %w", key, v, err)
				}
				if v == 1 {
					err := checkObjectData(s3client, bucket, key, "", datas[0])
					if err != nil {
						return fmt.Errorf("restored version: %w", err)
					}
				}
			}
			return nil
		})
	}, withVersioning(types.BucketVersioningStatusEnabled))
}

// ListObjects_race_with_parent_dir_replaced lists prefixes while, under each
// of them, "d" is in turn the parent directory of an object and an object
// itself. Deleting the nested object removes its parent directories and
// uploading "d" puts a file in their place, so a listing can read a directory
// and then find a file in the path of its entries. An object that stays under
// each prefix keeps the prefix directory in place. A listing must not fail,
// and must list the object that stays.
func ListObjects_race_with_parent_dir_replaced(s *S3Conf) error {
	testName := "ListObjects_race_with_parent_dir_replaced"
	const iterations = 200
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		var anchors []string
		for w := 0; w < siblingRaceWorkers; w += 2 {
			anchors = append(anchors, fmt.Sprintf("race/%d/anchor", w/2))
		}
		if _, err := putObjects(s3client, anchors, bucket); err != nil {
			return err
		}

		return raceWorkers(siblingRaceWorkers, iterations, func(w, i int) error {
			// the workers share a prefix in pairs: one lists it, the
			// other turns "d" from a directory into an object and back
			prefix := fmt.Sprintf("race/%d/", w/2)
			anchor := prefix + "anchor"
			isAnchor := func(key *string) bool { return getString(key) == anchor }
			if w%2 == 1 {
				ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
				out, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
					Bucket: &bucket,
					Prefix: &prefix,
				})
				cancel()
				if err != nil {
					return fmt.Errorf("list objects %v: %w", prefix, err)
				}
				if !slices.ContainsFunc(out.Contents, func(o types.Object) bool { return isAnchor(o.Key) }) {
					return fmt.Errorf("list objects %v: expected %v to be listed", prefix, anchor)
				}
				ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
				outV2, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
					Bucket: &bucket,
					Prefix: &prefix,
				})
				cancel()
				if err != nil {
					return fmt.Errorf("list objects v2 %v: %w", prefix, err)
				}
				if !slices.ContainsFunc(outV2.Contents, func(o types.Object) bool { return isAnchor(o.Key) }) {
					return fmt.Errorf("list objects v2 %v: expected %v to be listed", prefix, anchor)
				}
				return nil
			}

			key := prefix + "d/e/obj"
			if i%2 == 1 {
				key = prefix + "d"
			}
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &key,
			})
			cancel()
			if err != nil {
				return fmt.Errorf("put %v: %w", key, err)
			}
			ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: &bucket,
				Key:    &key,
			})
			cancel()
			if err != nil {
				return fmt.Errorf("delete %v: %w", key, err)
			}
			return nil
		})
	})
}

// PutObject_reserved_key checks that no key reaches the .sgwtmp directory of
// a bucket, where its multipart uploads are staged: the parts of an upload at
// .sgwtmp/multipart/<sha256 of the key>/<upload id>/. A client can't replace
// the parts of another client's upload, however the key spells their path.
func PutObject_reserved_key(s *S3Conf) error {
	testName := "PutObject_reserved_key"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}
		parts, _, err := uploadParts(s3client, 100, 1, bucket, obj, *mp.UploadId)
		if err != nil {
			return err
		}

		partKey := fmt.Sprintf(".sgwtmp/multipart/%x/%v/1", sha256.Sum256([]byte(obj)), *mp.UploadId)
		for _, key := range []string{
			partKey,
			".SGWTMP" + strings.TrimPrefix(partKey, ".sgwtmp"),
			".sgwtmp/",
			".sgwtmp/my-obj",
		} {
			_, err := putObjectWithData(objDataLen(key, 10), &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &key,
			}, s3client)
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrReservedObjectKey)); err != nil {
				return fmt.Errorf("%v: %w", key, err)
			}
		}

		// the staged part is the one the client uploaded
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: []types.CompletedPart{
					{ETag: parts[0].ETag, PartNumber: parts[0].PartNumber},
				},
			},
		})
		cancel()
		return err
	})
}

func CreateMultipartUpload_reserved_key(s *S3Conf) error {
	testName := "CreateMultipartUpload_reserved_key"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		_, err := createMp(s3client, bucket, ".sgwtmp/my-obj")
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrReservedObjectKey))
	})
}

func GetObject_reserved_key(s *S3Conf) error {
	testName := "GetObject_reserved_key"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}
		_, _, err = uploadParts(s3client, 100, 1, bucket, obj, *mp.UploadId)
		if err != nil {
			return err
		}

		partKey := fmt.Sprintf(".sgwtmp/multipart/%x/%v/1", sha256.Sum256([]byte(obj)), *mp.UploadId)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &partKey,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrReservedObjectKey)); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &partKey,
		})
		cancel()
		if err == nil {
			return fmt.Errorf("expected HeadObject to fail")
		}
		if err := checkSdkApiErr(err, "BadRequest"); err != nil {
			return err
		}

		return checkAndAbortUpload(s3client, bucket, obj, *mp.UploadId)
	})
}

func CopyObject_reserved_key(s *S3Conf) error {
	testName := "CopyObject_reserved_key"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}
		_, _, err = uploadParts(s3client, 100, 1, bucket, obj, *mp.UploadId)
		if err != nil {
			return err
		}
		_, err = putObjects(s3client, []string{"src-obj"}, bucket)
		if err != nil {
			return err
		}

		partKey := fmt.Sprintf(".sgwtmp/multipart/%x/%v/1", sha256.Sum256([]byte(obj)), *mp.UploadId)
		for _, keys := range [][2]string{
			{partKey, "dst-obj"},
			{"src-obj", partKey},
		} {
			src, dst := keys[0], keys[1]
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
				Bucket:     &bucket,
				Key:        &dst,
				CopySource: getPtr(bucket + "/" + src),
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrReservedObjectKey)); err != nil {
				return fmt.Errorf("%v to %v: %w", src, dst, err)
			}
		}

		return checkAndAbortUpload(s3client, bucket, obj, *mp.UploadId)
	})
}

func DeleteObject_reserved_key(s *S3Conf) error {
	testName := "DeleteObject_reserved_key"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}
		parts, _, err := uploadParts(s3client, 100, 1, bucket, obj, *mp.UploadId)
		if err != nil {
			return err
		}

		partKey := fmt.Sprintf(".sgwtmp/multipart/%x/%v/1", sha256.Sum256([]byte(obj)), *mp.UploadId)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &partKey,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrReservedObjectKey)); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: &bucket,
			Delete: &types.Delete{
				Objects: []types.ObjectIdentifier{{Key: &partKey}},
			},
		})
		cancel()
		if err != nil {
			return err
		}
		expectedErr := s3err.GetAPIError(s3err.ErrReservedObjectKey)
		if len(out.Deleted) != 0 || len(out.Errors) != 1 ||
			getString(out.Errors[0].Key) != partKey ||
			getString(out.Errors[0].Code) != expectedErr.Code ||
			getString(out.Errors[0].Message) != expectedErr.Description {
			return fmt.Errorf("expected the deletion of %v to fail with %v, instead got deleted %v and errors %v",
				partKey, expectedErr.Code, len(out.Deleted), out.Errors)
		}

		// the staged part is still there
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: []types.CompletedPart{
					{ETag: parts[0].ETag, PartNumber: parts[0].PartNumber},
				},
			},
		})
		cancel()
		return err
	})
}

func ListObjectsV2_reserved_prefix(s *S3Conf) error {
	testName := "ListObjectsV2_reserved_prefix"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		mp, err := createMp(s3client, bucket, obj)
		if err != nil {
			return err
		}
		_, _, err = uploadParts(s3client, 100, 1, bucket, obj, *mp.UploadId)
		if err != nil {
			return err
		}

		uploadDir := fmt.Sprintf(".sgwtmp/multipart/%x/%v/", sha256.Sum256([]byte(obj)), *mp.UploadId)
		for _, prefix := range []string{
			".sgwtmp/",
			".sgwtmp/multipart/",
			uploadDir,
			".SGWTMP" + strings.TrimPrefix(uploadDir, ".sgwtmp"),
		} {
			for _, delimiter := range []string{"", "/"} {
				ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
				res, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
					Bucket:    &bucket,
					Prefix:    &prefix,
					Delimiter: &delimiter,
				})
				cancel()
				if err != nil {
					return err
				}
				if len(res.Contents) != 0 || len(res.CommonPrefixes) != 0 {
					return fmt.Errorf("prefix %q delimiter %q: expected nothing to be listed, instead got objects %v and common prefixes %v",
						prefix, delimiter, objStrings(res.Contents), res.CommonPrefixes)
				}
			}
		}

		return checkAndAbortUpload(s3client, bucket, obj, *mp.UploadId)
	})
}

// S3 takes "." and ".." segments as part of the key, but posix stores an
// object at the path of its key, which would resolve them to another
// object or to a path outside the bucket. Such keys are rejected.
func PutObject_dot_segment_key(s *S3Conf) error {
	testName := "PutObject_dot_segment_key"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		keys := []string{
			".",
			"./",
			"/.",
			"x/.",
			"x/..",
			"a/./b",
			"./" + obj,
			"a/../" + obj,
		}
		if !s.hostStyle {
			// without the bucket in the path these climb above its root
			keys = append(keys, "..", "../", "for/../../bar/", "../"+bucket+"/"+obj)
		}
		for _, key := range keys {
			_, err := putObjectWithData(10, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &key,
			}, s3client)
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrBadRequest)); err != nil {
				return fmt.Errorf("%v: %w", key, err)
			}
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
		if res.ContentLength == nil || *res.ContentLength != 0 {
			return fmt.Errorf("expected %v to keep its empty body, instead got size %v", obj, res.ContentLength)
		}

		return nil
	})
}

func PostObject_dot_segment_key(s *S3Conf) error {
	testName := "PostObject_dot_segment_key"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for _, obj := range []string{
			".",
			"..",
			"./",
			"/.",
			"../",
			"/..",
			"../.",
			"a/./b",
			"a/../b",
			"../../../.",
			"../../../etc/passwd",
			"../../../../tmp/foo",
			"for/../../bar/",
			"a/a/a/../../../../../etc/passwd",
			"/a/../../b/../../c/../../../etc/passwd",
		} {
			resp, err := sendPostObject(PostRequestConfig{
				bucket:      bucket,
				key:         obj,
				s3Conf:      s,
				fileContent: []byte("data"),
			})
			if err != nil {
				return err
			}

			if err := checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrBadRequest)); err != nil {
				return fmt.Errorf("%v: %w", obj, err)
			}
		}

		return nil
	})
}

func DeleteObjects_dot_segment_key(s *S3Conf) error {
	testName := "DeleteObjects_dot_segment_key"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, otherObj := "my-obj", "other-obj"
		_, err := putObjects(s3client, []string{obj, otherObj}, bucket)
		if err != nil {
			return err
		}

		// Every key resolves outside the bucket or to the bucket itself;
		// the ones climbing back into it name obj. A request holding any of
		// them is rejected as a whole, so its valid key isn't deleted
		// either.
		for _, key := range []string{
			".",
			"..",
			"../",
			"./" + obj,
			"a/../" + obj,
			"../../../etc/passwd",
			"../" + bucket + "/" + obj,
			"dir/../../" + bucket + "/" + obj,
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
				Bucket: &bucket,
				Delete: &types.Delete{
					Objects: []types.ObjectIdentifier{
						{Key: &otherObj},
						{Key: &key},
					},
				},
			})
			cancel()
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrBadRequest)); err != nil {
				return fmt.Errorf("key %q: %w", key, err)
			}
		}

		for _, key := range []string{obj, otherObj} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: &bucket,
				Key:    &key,
			})
			cancel()
			if err != nil {
				return fmt.Errorf("head %v: %w", key, err)
			}
		}

		return nil
	})
}

func CopyObject_dot_segment_copy_source(s *S3Conf) error {
	testName := "CopyObject_dot_segment_copy_source"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		for _, test := range []struct {
			copySource string
			object     string
		}{
			{"bucket/.", "."},
			{"bucket/..", ".."},
			{"bucket/../", "../"},
			{"bucket/foo/ba/../../../r/baz", "foo/ba/../../../r/baz"},
			// would copy obj
			{bucket + "/a/../" + obj, "a/../" + obj},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
				Bucket:     &bucket,
				Key:        getPtr("obj"),
				CopySource: &test.copySource,
			})
			cancel()
			if err := checkApiErr(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgCopySourceObject, test.object)); err != nil {
				return fmt.Errorf("%v: %w", test.copySource, err)
			}
		}

		return nil
	})
}

func UploadPartCopy_dot_segment_copy_source(s *S3Conf) error {
	testName := "UploadPartCopy_dot_segment_copy_source"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		_, err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		// A malformed upload ID would be rejected before the copy source
		// is checked.
		mp, err := createMp(s3client, bucket, "obj")
		if err != nil {
			return err
		}

		partNumber := int32(1)
		for _, test := range []struct {
			copySource string
			object     string
		}{
			{"bucket/.", "."},
			{"bucket/..", ".."},
			{"bucket/../", "../"},
			{"bucket/foo/ba/../../../r/baz", "foo/ba/../../../r/baz"},
			// would copy obj
			{bucket + "/a/../" + obj, "a/../" + obj},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
				Bucket:     &bucket,
				Key:        getPtr("obj"),
				UploadId:   mp.UploadId,
				CopySource: &test.copySource,
				PartNumber: &partNumber,
			})
			cancel()
			if err := checkApiErr(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgCopySourceObject, test.object)); err != nil {
				return fmt.Errorf("%v: %w", test.copySource, err)
			}
		}

		return nil
	})
}
