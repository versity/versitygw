package integration

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

var (
	shortTimeout = 10 * time.Second
)

func CreateBucket_invalid_bucket_name(s *S3Conf) {
	testName := "CreateBucket_invalid_bucket_name"
	runF(testName)
	err := setup(s, "aa")
	if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidBucketName)); err != nil {
		failF("%v: %v", testName, err.Error())
		return
	}

	err = setup(s, ".gitignore")
	if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidBucketName)); err != nil {
		failF("%v: %v", testName, err.Error())
		return
	}

	err = setup(s, "my-bucket.")
	if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidBucketName)); err != nil {
		failF("%v: %v", testName, err.Error())
		return
	}

	err = setup(s, "bucket-%")
	if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidBucketName)); err != nil {
		failF("%v: %v", testName, err.Error())
		return
	}
	passF(testName)
}

func CreateBucket_existing_bucket(s *S3Conf) {
	testName := "CreateBucket_existing_bucket"
	runF(testName)
	bucket := getBucketName()
	err := setup(s, bucket)
	if err != nil {
		failF("%v: %v", testName, err.Error())
		return
	}
	err = setup(s, bucket)
	var bne *types.BucketAlreadyExists
	if !errors.As(err, &bne) {
		failF("%v: %v", testName, err.Error())
	}

	err = teardown(s, bucket)
	if err != nil {
		failF("%v: %v", err.Error())
		return
	}
	passF(testName)
}

func HeadBucket_non_existing_bucket(s *S3Conf) {
	testName := "HeadBucket_non_existing_bucket"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		bcktName := getBucketName()

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.HeadBucket(ctx, &s3.HeadBucketInput{
			Bucket: &bcktName,
		})
		cancel()
		if err := checkSdkApiErr(err, "NotFound"); err != nil {
			return err
		}
		return nil
	})
}

func HeadBucket_success(s *S3Conf) {
	testName := "HeadBucket_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.HeadBucket(ctx, &s3.HeadBucketInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}
		return nil
	})
}

func CreateDeleteBucket_success(s *S3Conf) {
	testName := "CreateBucket_success"
	runF(testName)
	bucket := getBucketName()

	err := setup(s, bucket)
	if err != nil {
		failF("%v: %v", err.Error())
		return
	}

	err = teardown(s, bucket)
	if err != nil {
		failF("%v: %v", err.Error())
		return
	}

	passF(testName)
}

func DeleteBucket_non_existing_bucket(s *S3Conf) {
	testName := "DeleteBucket_non_existing_bucket"
	runF(testName)
	bucket := getBucketName()
	s3client := s3.NewFromConfig(s.Config())

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	_, err := s3client.DeleteBucket(ctx, &s3.DeleteBucketInput{
		Bucket: &bucket,
	})
	cancel()
	if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
		failF("%v: %v", testName, err.Error())
		return
	}
	passF(testName)
}

func DeleteBucket_non_empty_bucket(s *S3Conf) {
	testName := "DeleteBucket_non_empty_bucket"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putObjects(s3client, []string{"foo"}, bucket)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteBucket(ctx, &s3.DeleteBucketInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrBucketNotEmpty)); err != nil {
			return err
		}

		return nil
	})
}

func PutObject_non_existing_bucket(s *S3Conf) {
	testName := "PutObject_non_existing_bucket"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putObjects(s3client, []string{"my-obj"}, "non-existing-bucket")
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}
		return nil
	})
}

func PutObject_special_chars(s *S3Conf) {
	testName := "PutObject_special_chars"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putObjects(s3client, []string{"foo%%", "bar^", "baz**"}, bucket)
		if err != nil {
			return err
		}
		return nil
	})
}

func PutObject_existing_dir_obj(s *S3Conf) {
	testName := "PutObject_existing_dir_obj"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putObjects(s3client, []string{"foo/bar", "foo"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrExistingObjectIsDirectory)); err != nil {
			return err
		}
		return nil
	})
}

func PutObject_obj_parent_is_file(s *S3Conf) {
	testName := "PutObject_obj_parent_is_file"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putObjects(s3client, []string{"foo", "foo/bar/"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectParentIsFile)); err != nil {
			return err
		}
		return nil
	})
}

func PutObject_success(s *S3Conf) {
	testName := "PutObject_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putObjects(s3client, []string{"my-obj"}, bucket)
		if err != nil {
			return err
		}
		return nil
	})
}

func HeadObject_non_existing_object(s *S3Conf) {
	testName := "HeadObject_non_existing_object"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
		})
		cancel()
		if err := checkSdkApiErr(err, "NotFound"); err != nil {
			return err
		}
		return nil
	})
}

func HeadObject_success(s *S3Conf) {
	testName := "HeadObject_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, dataLen := "my-obj", int64(1234567)
		meta := map[string]string{
			"key1": "val1",
			"key2": "val2",
		}

		_, _, err := putObjectWithData(dataLen, &s3.PutObjectInput{Bucket: &bucket, Key: &obj, Metadata: meta}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		defer cancel()
		if err != nil {
			return err
		}

		if !areMapsSame(out.Metadata, meta) {
			return fmt.Errorf("incorrect object metadata")
		}
		if out.ContentLength != dataLen {
			return fmt.Errorf("expected data length %v, instead got %v", dataLen, out.ContentLength)
		}

		return nil
	})
}

func GetObject_non_existing_key(s *S3Conf) {
	testName := "GetObject_non_existing_key"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    getPtr("non-existing-key"),
		})
		cancel()
		var bae *types.NoSuchKey
		if !errors.As(err, &bae) {
			return err
		}
		return nil
	})
}

func GetObject_invalid_ranges(s *S3Conf) {
	testName := "GetObject_invalid_ranges"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dataLength, obj := int64(1234567), "my-obj"

		_, _, err := putObjectWithData(dataLength, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
			Range:  getPtr("bytes=invalid-range"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidRange)); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
			Range:  getPtr("bytes=33-10"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidRange)); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
			Range:  getPtr("bytes=1000000000-999999999999"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidRange)); err != nil {
			return err
		}
		return nil
	})
}

func GetObject_with_meta(s *S3Conf) {
	testName := "GetObject_with_meta"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		meta := map[string]string{
			"key1": "val1",
			"key2": "val2",
		}

		_, _, err := putObjectWithData(0, &s3.PutObjectInput{Bucket: &bucket, Key: &obj, Metadata: meta}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		defer cancel()
		if err != nil {
			return err
		}

		if !areMapsSame(out.Metadata, meta) {
			return fmt.Errorf("incorrect object metadata")
		}

		return nil
	})
}

func GetObject_success(s *S3Conf) {
	testName := "GetObject_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dataLength, obj := int64(1234567), "my-obj"

		csum, _, err := putObjectWithData(dataLength, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		defer cancel()
		if err != nil {
			return err
		}
		if out.ContentLength != dataLength {
			return fmt.Errorf("expected content-length %v, instead got %v", dataLength, out.ContentLength)
		}

		bdy, err := io.ReadAll(out.Body)
		if err != nil {
			return err
		}
		defer out.Body.Close()
		outCsum := sha256.Sum256(bdy)
		if outCsum != csum {
			return fmt.Errorf("invalid object data")
		}
		return nil
	})
}

func GetObject_by_range_success(s *S3Conf) {
	testName := "GetObject_by_range_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dataLength, obj := int64(1234567), "my-obj"

		_, data, err := putObjectWithData(dataLength, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		rangeString := "bytes=100-200"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
			Range:  &rangeString,
		})
		defer cancel()
		if err != nil {
			return err
		}
		defer out.Body.Close()

		if getString(out.ContentRange) != fmt.Sprintf("bytes 100-200/%v", dataLength) {
			return fmt.Errorf("expected content range: %v, instead got: %v", fmt.Sprintf("bytes 100-200/%v", dataLength), getString(out.ContentRange))
		}
		if getString(out.AcceptRanges) != rangeString {
			return fmt.Errorf("expected accept range: %v, instead got: %v", rangeString, getString(out.AcceptRanges))
		}
		b, err := io.ReadAll(out.Body)
		if err != nil {
			return err
		}

		// bytes range is inclusive, go range for second value is not
		if !isEqual(b, data[100:201]) {
			return fmt.Errorf("data mismatch of range")
		}

		rangeString = "bytes=100-"

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
			Range:  &rangeString,
		})
		defer cancel()
		if err != nil {
			return err
		}
		defer out.Body.Close()

		b, err = io.ReadAll(out.Body)
		if err != nil {
			return err
		}

		// bytes range is inclusive, go range for second value is not
		if !isEqual(b, data[100:]) {
			return fmt.Errorf("data mismatch of range")
		}
		return nil
	})
}

func ListObjects_non_existing_bucket(s *S3Conf) {
	testName := "ListObjects_non_existing_bucket"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
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

func ListObjects_with_prefix(s *S3Conf) {
	testName := "ListObjects_with_prefix"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		prefix := "obj"
		objWithPrefix := []string{prefix + "/foo", prefix + "/bar", prefix + "/baz/bla"}
		err := putObjects(s3client, append(objWithPrefix, []string{"xzy/csf", "hell"}...), bucket)
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

		if *out.Prefix != prefix {
			return fmt.Errorf("expected prefix %v, instead got %v", prefix, *out.Prefix)
		}
		if !compareObjects(objWithPrefix, out.Contents) {
			return fmt.Errorf("unexpected output for list objects with prefix")
		}

		return nil
	})
}

func ListObject_truncated(s *S3Conf) {
	testName := "ListObject_truncated"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		maxKeys := int32(2)
		err := putObjects(s3client, []string{"foo", "bar", "baz"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket:  &bucket,
			MaxKeys: maxKeys,
		})
		cancel()
		if err != nil {
			return err
		}

		if !out.IsTruncated {
			return fmt.Errorf("expected output to be truncated")
		}

		if out.MaxKeys != maxKeys {
			return fmt.Errorf("expected max-keys to be %v, instead got %v", maxKeys, out.MaxKeys)
		}

		if !compareObjects([]string{"bar", "baz"}, out.Contents) {
			return fmt.Errorf("unexpected output for list objects with max-keys")
		}

		//TODO: Add next marker checker after bug-fixing

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err = s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
			Marker: out.NextMarker,
		})
		cancel()
		if err != nil {
			return err
		}

		if out.IsTruncated {
			return fmt.Errorf("expected output not to be truncated")
		}

		if !compareObjects([]string{"foo"}, out.Contents) {
			return fmt.Errorf("unexpected output for list objects with max-keys")
		}
		return nil
	})
}

func ListObjects_invalid_max_keys(s *S3Conf) {
	testName := "ListObjects_invalid_max_keys"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket:  &bucket,
			MaxKeys: -5,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidMaxKeys)); err != nil {
			return err
		}

		return nil
	})
}

func ListObjects_max_keys_0(s *S3Conf) {
	testName := "ListObjects_max_keys_0"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objects := []string{"foo", "bar", "baz"}
		err := putObjects(s3client, objects, bucket)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket:  &bucket,
			MaxKeys: 0,
		})
		cancel()
		if err != nil {
			return nil
		}

		if !compareObjects(objects, out.Contents) {
			return fmt.Errorf("unexpected output for list objects with max-keys 0")
		}

		return nil
	})
}

//TODO: Add a test case for delimiter after buf-fixing, as delimiter doesn't work as intended

func DeleteObject_non_existing_object(s *S3Conf) {
	testName := "DeleteObject_non_existing_object"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchKey)); err != nil {
			return err
		}
		return nil
	})
}

func DeleteObject_success(s *S3Conf) {
	testName := "DeleteObject_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		err := putObjects(s3client, []string{obj}, bucket)
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
		defer cancel()
		if err := checkSdkApiErr(err, "NoSuchKey"); err != nil {
			return err
		}
		return nil
	})
}

func DeleteObjects_empty_input(s *S3Conf) {
	testName := "DeleteObjects_empty_input"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objects := []string{"foo", "bar", "baz"}
		err := putObjects(s3client, objects, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: &bucket,
			Delete: &types.Delete{
				Objects: []types.ObjectIdentifier{},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if len(out.Deleted) != 0 {
			return fmt.Errorf("expected deleted object count 0, instead got %v", len(out.Deleted))
		}
		if len(out.Errors) != 0 {
			return fmt.Errorf("expected 0 errors, instead got %v", len(out.Errors))
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareObjects(objects, res.Contents) {
			return fmt.Errorf("unexpected output for list objects with prefix")
		}

		return nil
	})
}

//TODO: Uncomment the test after fixing the bug: #195
// func DeleteObjects_non_existing_objects(s *S3Conf) {
// 	testName := "DeleteObjects_empty_input"
// 	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
// 		delObjects := []types.ObjectIdentifier{{Key: getPtr("obj1")}, {Key: getPtr("obj2")}}
//
// 		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
// 		out, err := s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
// 			Bucket: &bucket,
// 			Delete: &types.Delete{
// 				Objects: delObjects,
// 			},
// 		})
// 		cancel()
// 		if err != nil {
// 			return err
// 		}

// 		if len(out.Deleted) != 0 {
// 			return fmt.Errorf("expected deleted object count 0, instead got %v", len(out.Deleted))
// 		}
// 		if len(out.Errors) != 2 {
// 			return fmt.Errorf("expected 2 errors, instead got %v", len(out.Errors))
// 		}

// 		for _, delErr := range out.Errors {
// 			if *delErr.Code != "NoSuchKey" {
// 				return fmt.Errorf("expected NoSuchKey error, instead got %v", *delErr.Code)
// 			}
// 		}

// 		return nil
// 	})
// }

func DeleteObjects_success(s *S3Conf) {
	testName := "DeleteObjects_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objects, objToDel := []string{"obj1", "obj2", "obj3"}, []string{"foo", "bar", "baz"}
		err := putObjects(s3client, append(objToDel, objects...), bucket)

		delObjects := []types.ObjectIdentifier{}
		for _, key := range objToDel {
			k := key
			delObjects = append(delObjects, types.ObjectIdentifier{Key: &k})
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: &bucket,
			Delete: &types.Delete{
				Objects: delObjects,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if len(out.Deleted) != 3 {
			return fmt.Errorf("expected deleted object count 3, instead got %v", len(out.Deleted))
		}
		if len(out.Errors) != 0 {
			return fmt.Errorf("expected 2 errors, instead got %v", len(out.Errors))
		}

		if !compareDelObjects(objToDel, out.Deleted) {
			return fmt.Errorf("unexpected deleted output")
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareObjects(objects, res.Contents) {
			return fmt.Errorf("unexpected output for list objects with prefix")
		}

		return nil
	})
}

func CopyObject_non_existing_dst_bucket(s *S3Conf) {
	testName := "CopyObject_non_existing_dst_bucket"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		err := putObjects(s3client, []string{obj}, bucket)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        &obj,
			CopySource: getPtr("bucket/obj"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}
		return nil
	})
}

func CopyObject_success(s *S3Conf) {
	testName := "CopyObject_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dataLength, obj := int64(1234567), "my-obj"
		dstBucket := getBucketName()
		err := setup(s, dstBucket)
		if err != nil {
			return err
		}

		csum, _, err := putObjectWithData(dataLength, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &dstBucket,
			Key:        &obj,
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, obj)),
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &dstBucket,
			Key:    &obj,
		})
		defer cancel()
		if err != nil {
			return err
		}
		if out.ContentLength != dataLength {
			return fmt.Errorf("expected content-length %v, instead got %v", dataLength, out.ContentLength)
		}

		bdy, err := io.ReadAll(out.Body)
		if err != nil {
			return err
		}
		defer out.Body.Close()
		outCsum := sha256.Sum256(bdy)
		if outCsum != csum {
			return fmt.Errorf("invalid object data")
		}

		err = teardown(s, dstBucket)
		if err != nil {
			return nil
		}

		return nil
	})
}

func PutObjectTagging_non_existing_object(s *S3Conf) {
	testName := "PutObjectTagging_non_existing_object"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
			Bucket:  &bucket,
			Key:     getPtr("my-obj"),
			Tagging: &types.Tagging{TagSet: []types.Tag{}}})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchKey)); err != nil {
			return err
		}
		return nil
	})
}

func PutObjectTagging_success(s *S3Conf) {
	testName := "PutObjectTagging_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		tagging := types.Tagging{TagSet: []types.Tag{{Key: getPtr("key1"), Value: getPtr("val2")}, {Key: getPtr("key2"), Value: getPtr("val2")}}}
		err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
			Bucket:  &bucket,
			Key:     &obj,
			Tagging: &tagging})
		cancel()
		if err != nil {
			return err
		}

		return nil
	})
}

func GetObjectTagging_non_existing_object(s *S3Conf) {
	testName := "GetObjectTagging_non_existing_object"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchKey)); err != nil {
			return err
		}
		return nil
	})
}

func GetObjectTagging_success(s *S3Conf) {
	testName := "PutObjectTagging_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		tagging := types.Tagging{TagSet: []types.Tag{{Key: getPtr("key1"), Value: getPtr("val2")}, {Key: getPtr("key2"), Value: getPtr("val2")}}}
		err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
			Bucket:  &bucket,
			Key:     &obj,
			Tagging: &tagging})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return nil
		}

		if !areTagsSame(out.TagSet, tagging.TagSet) {
			return fmt.Errorf("expected %v instead got %v", tagging.TagSet, out.TagSet)
		}

		return nil
	})
}

func DeleteObjectTagging_non_existing_object(s *S3Conf) {
	testName := "DeleteObjectTagging_non_existing_object"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteObjectTagging(ctx, &s3.DeleteObjectTaggingInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchKey)); err != nil {
			return err
		}
		return nil
	})
}

func DeleteObjectTagging_success(s *S3Conf) {
	testName := "DeleteObjectTagging_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		tagging := types.Tagging{TagSet: []types.Tag{{Key: getPtr("key1"), Value: getPtr("val2")}, {Key: getPtr("key2"), Value: getPtr("val2")}}}
		err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
			Bucket:  &bucket,
			Key:     &obj,
			Tagging: &tagging})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObjectTagging(ctx, &s3.DeleteObjectTaggingInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return nil
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return nil
		}

		if len(out.TagSet) > 0 {
			return fmt.Errorf("expected empty tag set, instead got %v", out.TagSet)
		}

		return nil
	})
}

// func TestPutGetMPObject(s *S3Conf) {
// 	testname := "test put/get multipart object"
// 	runF(testname)

// 	bucket := "testbucket2"

// 	err := setup(s, bucket)
// 	if err != nil {
// 		failF("%v: %v", testname, err)
// 		return
// 	}

// 	name := "mympuobject"
// 	s3client := s3.NewFromConfig(s.Config())

// 	datalen := 10*1024*1024 + 15
// 	dr := NewDataReader(datalen, 5*1024*1024)
// 	WithPartSize(5 * 1024 * 1024)
// 	s.PartSize = 5 * 1024 * 1024
// 	err = s.UploadData(dr, bucket, name)
// 	if err != nil {
// 		failF("%v: %v", testname, err)
// 		return
// 	}

// 	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
// 	out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
// 		Bucket: &bucket,
// 		Key:    &name,
// 	})
// 	defer cancel()
// 	if err != nil {
// 		failF("%v: %v", testname, err)
// 		return
// 	}
// 	defer out.Body.Close()

// 	if out.ContentLength != int64(datalen) {
// 		failF("%v: content length got %v expected %v", testname, out.ContentLength, datalen)
// 		return
// 	}

// 	b := make([]byte, 1048576)
// 	h := sha256.New()
// 	for {
// 		n, err := out.Body.Read(b)
// 		if err == io.EOF {
// 			h.Write(b[:n])
// 			break
// 		}
// 		if err != nil {
// 			failF("%v: read %v", err)
// 			return
// 		}
// 		h.Write(b[:n])
// 	}

// 	if !isEqual(dr.Sum(), h.Sum(nil)) {
// 		failF("%v: checksum got %x expected %x", testname, h.Sum(nil), dr.Sum())
// 		return
// 	}

// 	err = teardown(s, bucket)
// 	if err != nil {
// 		failF("%v: %v", testname, err)
// 		return
// 	}
// 	passF(testname)
// }

// func TestListAbortMultiPartObject(s *S3Conf) {
// 	testname := "list/abort multipart objects"
// 	runF(testname)

// 	bucket := "testbucket6"

// 	err := setup(s, bucket)
// 	if err != nil {
// 		failF("%v: %v", testname, err)
// 		return
// 	}

// 	s3client := s3.NewFromConfig(s.Config())

// 	obj := "mympuobject"

// 	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
// 	mpu, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
// 		Bucket: &bucket,
// 		Key:    &obj,
// 	})
// 	cancel()
// 	if err != nil {
// 		failF("%v: create multipart upload: %v", testname, err)
// 		return
// 	}

// 	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
// 	lmpu, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
// 		Bucket: &bucket,
// 	})
// 	cancel()
// 	if err != nil {
// 		failF("%v: list multipart upload: %v", testname, err)
// 		return
// 	}

// 	//for _, item := range lmpu.Uploads {
// 	//	fmt.Println(" -- ", *item.Key, *item.UploadId)
// 	//}

// 	if !containsUID(obj, *mpu.UploadId, lmpu.Uploads) {
// 		failF("%v: upload %v/%v not found", testname, obj, *mpu.UploadId)
// 		return
// 	}

// 	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
// 	_, err = s3client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
// 		Bucket:   &bucket,
// 		Key:      &obj,
// 		UploadId: mpu.UploadId,
// 	})
// 	cancel()
// 	if err != nil {
// 		failF("%v: abort multipart upload: %v", testname, err)
// 		return
// 	}

// 	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
// 	lmpu, err = s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
// 		Bucket: &bucket,
// 	})
// 	cancel()
// 	if err != nil {
// 		failF("%v: list multipart upload: %v", testname, err)
// 		return
// 	}

// 	if len(lmpu.Uploads) != 0 {
// 		for _, item := range lmpu.Uploads {
// 			fmt.Println(" D- ", *item.Key, *item.UploadId)
// 		}
// 		failF("%v: unexpected multipart uploads found", testname)
// 		return
// 	}

// 	err = teardown(s, bucket)
// 	if err != nil {
// 		failF("%v: %v", testname, err)
// 		return
// 	}
// 	passF(testname)
// }

// func TestListMultiParts(s *S3Conf) {
// 	testname := "list multipart parts"
// 	runF(testname)

// 	bucket := "testbucket7"

// 	err := setup(s, bucket)
// 	if err != nil {
// 		failF("%v: %v", testname, err)
// 		return
// 	}

// 	s3client := s3.NewFromConfig(s.Config())

// 	obj := "mympuobject"

// 	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
// 	mpu, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
// 		Bucket: &bucket,
// 		Key:    &obj,
// 	})
// 	cancel()
// 	if err != nil {
// 		failF("%v: create multipart upload: %v", testname, err)
// 		return
// 	}

// 	// check list parts of no parts is good
// 	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
// 	lp, err := s3client.ListParts(ctx, &s3.ListPartsInput{
// 		Bucket:   &bucket,
// 		Key:      &obj,
// 		UploadId: mpu.UploadId,
// 	})
// 	cancel()
// 	if err != nil {
// 		failF("%v: list parts: %v", testname, err)
// 		return
// 	}

// 	if len(lp.Parts) != 0 {
// 		failF("%v: list parts: expected no parts, got %v",
// 			testname, len(lp.Parts))
// 		return
// 	}

// 	// upload 1 part and check list parts
// 	size5MB := 5 * 1024 * 1024
// 	dr := NewDataReader(size5MB, size5MB)

// 	datafile := "rand.data"
// 	w, err := os.Create(datafile)
// 	if err != nil {
// 		failF("%v: create %v: %v", testname, datafile, err)
// 		return
// 	}
// 	defer w.Close()

// 	_, err = io.Copy(w, dr)
// 	if err != nil {
// 		failF("%v: write %v: %v", testname, datafile, err)
// 		return
// 	}

// 	_, err = w.Seek(0, io.SeekStart)
// 	if err != nil {
// 		failF("%v: seek %v: %v", testname, datafile, err)
// 		return
// 	}

// 	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
// 	_, err = s3client.UploadPart(ctx, &s3.UploadPartInput{
// 		Bucket:        &bucket,
// 		Key:           &obj,
// 		PartNumber:    42,
// 		UploadId:      mpu.UploadId,
// 		Body:          w,
// 		ContentLength: int64(size5MB),
// 	})
// 	cancel()
// 	if err != nil {
// 		failF("%v: multipart put part: %v", testname, err)
// 		return
// 	}

// 	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
// 	lp, err = s3client.ListParts(ctx, &s3.ListPartsInput{
// 		Bucket:   &bucket,
// 		Key:      &obj,
// 		UploadId: mpu.UploadId,
// 	})
// 	cancel()
// 	if err != nil {
// 		failF("%v: list parts: %v", testname, err)
// 		return
// 	}

// 	//for _, part := range lp.Parts {
// 	//	fmt.Println(" -- ", part.PartNumber, part.ETag)
// 	//}

// 	if len(lp.Parts) != 1 || lp.Parts[0].PartNumber != 42 {
// 		fmt.Printf("%+v, %v, %v\n", lp.Parts, *lp.Key, *lp.UploadId)
// 		failF("%v: list parts: unexpected parts listing", testname)
// 		return
// 	}

// 	err = teardown(s, bucket)
// 	if err != nil {
// 		failF("%v: %v", testname, err)
// 		return
// 	}
// 	passF(testname)
// }

// func TestIncorrectMultiParts(s *S3Conf) {
// 	testname := "incorrect multipart parts"
// 	runF(testname)

// 	bucket := "testbucket8"

// 	err := setup(s, bucket)
// 	if err != nil {
// 		failF("%v: %v", testname, err)
// 		return
// 	}

// 	s3client := s3.NewFromConfig(s.Config())

// 	obj := "mympuobject"

// 	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
// 	mpu, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
// 		Bucket: &bucket,
// 		Key:    &obj,
// 	})
// 	cancel()
// 	if err != nil {
// 		failF("%v: create multipart upload: %v", testname, err)
// 		return
// 	}

// 	// upload 2 parts
// 	size5MB := 5 * 1024 * 1024
// 	dr := NewDataReader(size5MB, size5MB)

// 	datafile := "rand.data"
// 	w, err := os.Create(datafile)
// 	if err != nil {
// 		failF("%v: create %v: %v", testname, datafile, err)
// 		return
// 	}
// 	defer w.Close()

// 	_, err = io.Copy(w, dr)
// 	if err != nil {
// 		failF("%v: write %v: %v", testname, datafile, err)
// 		return
// 	}

// 	_, err = w.Seek(0, io.SeekStart)
// 	if err != nil {
// 		failF("%v: seek %v: %v", testname, datafile, err)
// 		return
// 	}

// 	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
// 	mp1, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
// 		Bucket:        &bucket,
// 		Key:           &obj,
// 		PartNumber:    42,
// 		UploadId:      mpu.UploadId,
// 		Body:          w,
// 		ContentLength: int64(size5MB),
// 	})
// 	cancel()
// 	if err != nil {
// 		failF("%v: multipart put part 1: %v", testname, err)
// 		return
// 	}

// 	_, err = w.Seek(0, io.SeekStart)
// 	if err != nil {
// 		failF("%v: seek %v: %v", testname, datafile, err)
// 		return
// 	}

// 	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
// 	mp2, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
// 		Bucket:        &bucket,
// 		Key:           &obj,
// 		PartNumber:    96,
// 		UploadId:      mpu.UploadId,
// 		Body:          w,
// 		ContentLength: int64(size5MB),
// 	})
// 	cancel()
// 	if err != nil {
// 		failF("%v: multipart put part 2: %v", testname, err)
// 		return
// 	}

// 	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
// 	_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
// 		Bucket:   &bucket,
// 		Key:      &obj,
// 		UploadId: mpu.UploadId,
// 		MultipartUpload: &types.CompletedMultipartUpload{
// 			Parts: []types.CompletedPart{
// 				{
// 					ETag:       mp2.ETag,
// 					PartNumber: 96,
// 				},
// 				{
// 					ETag:       mp1.ETag,
// 					PartNumber: 99,
// 				},
// 			},
// 		},
// 	})
// 	cancel()
// 	if err == nil {
// 		failF("%v: complete multipart expected err", testname)
// 		return
// 	}

// 	badEtag := "bogusEtagValue"

// 	// Empty multipart upload
// 	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
// 	_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
// 		Bucket:   &bucket,
// 		Key:      &obj,
// 		UploadId: mpu.UploadId,
// 	})
// 	cancel()
// 	if err == nil {
// 		failF("%v: complete multipart expected err", testname)
// 		return
// 	}

// 	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
// 	_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
// 		Bucket:   &bucket,
// 		Key:      &obj,
// 		UploadId: mpu.UploadId,
// 		MultipartUpload: &types.CompletedMultipartUpload{
// 			Parts: []types.CompletedPart{
// 				{
// 					ETag:       mp2.ETag,
// 					PartNumber: 96,
// 				},
// 				{
// 					ETag:       &badEtag,
// 					PartNumber: 42,
// 				},
// 			},
// 		},
// 	})
// 	cancel()
// 	if err == nil {
// 		failF("%v: complete multipart expected err", testname)
// 		return
// 	}

// 	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
// 	_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
// 		Bucket:   &bucket,
// 		Key:      &obj,
// 		UploadId: mpu.UploadId,
// 		MultipartUpload: &types.CompletedMultipartUpload{
// 			Parts: []types.CompletedPart{
// 				{
// 					ETag:       mp1.ETag,
// 					PartNumber: 42,
// 				},
// 				{
// 					ETag:       mp2.ETag,
// 					PartNumber: 96,
// 				},
// 			},
// 		},
// 	})
// 	cancel()
// 	if err != nil {
// 		failF("%v: complete multipart: %v", testname, err)
// 		return
// 	}

// 	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
// 	oi, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
// 		Bucket: &bucket,
// 		Key:    &obj,
// 	})
// 	cancel()
// 	if err != nil {
// 		failF("%v: head object %v: %v", testname, obj, err)
// 		return
// 	}

// 	if oi.ContentLength != (int64(size5MB) * 2) {
// 		failF("%v: object len expected %v, got %v",
// 			testname, int64(size5MB)*2, oi.ContentLength)
// 		return
// 	}

// 	err = teardown(s, bucket)
// 	if err != nil {
// 		failF("%v: %v", testname, err)
// 		return
// 	}
// 	passF(testname)
// }

// func TestIncompleteMultiParts(s *S3Conf) {
// 	testname := "incomplete multipart parts"
// 	runF(testname)

// 	bucket := "testbucket9"

// 	err := setup(s, bucket)
// 	if err != nil {
// 		failF("%v: %v", testname, err)
// 		return
// 	}

// 	s3client := s3.NewFromConfig(s.Config())

// 	obj := "mympuobject"

// 	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
// 	mpu, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
// 		Bucket: &bucket,
// 		Key:    &obj,
// 	})
// 	cancel()
// 	if err != nil {
// 		failF("%v: create multipart upload: %v", testname, err)
// 		return
// 	}

// 	// upload 2 parts
// 	size5MB := 5 * 1024 * 1024
// 	size1MB := 1024 * 1024
// 	dr := NewDataReader(size1MB, size1MB)

// 	datafile := "rand.data"
// 	w, err := os.Create(datafile)
// 	if err != nil {
// 		failF("%v: create %v: %v", testname, datafile, err)
// 		return
// 	}
// 	defer w.Close()

// 	_, err = io.Copy(w, dr)
// 	if err != nil {
// 		failF("%v: write %v: %v", testname, datafile, err)
// 		return
// 	}

// 	_, err = w.Seek(0, io.SeekStart)
// 	if err != nil {
// 		failF("%v: seek %v: %v", testname, datafile, err)
// 		return
// 	}

// 	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
// 	_, err = s3client.UploadPart(ctx, &s3.UploadPartInput{
// 		Bucket:        &bucket,
// 		Key:           &obj,
// 		PartNumber:    42,
// 		UploadId:      mpu.UploadId,
// 		Body:          w,
// 		ContentLength: int64(size5MB),
// 	})
// 	cancel()
// 	if err == nil {
// 		failF("%v: multipart put short part expected error", testname)
// 		return
// 	}

// 	// check list parts does not have incomplete part
// 	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
// 	lp, err := s3client.ListParts(ctx, &s3.ListPartsInput{
// 		Bucket:   &bucket,
// 		Key:      &obj,
// 		UploadId: mpu.UploadId,
// 	})
// 	cancel()
// 	if err != nil {
// 		failF("%v: list parts: %v", testname, err)
// 		return
// 	}

// 	if containsPart(42, lp.Parts) {
// 		failF("%v: list parts: found incomplete part", testname)
// 		return
// 	}

// 	err = teardown(s, bucket)
// 	if err != nil {
// 		failF("%v: %v", testname, err)
// 		return
// 	}
// 	passF(testname)
// }

// func TestIncompletePutObject(s *S3Conf) {
// 	testname := "test incomplete put object"
// 	runF(testname)

// 	bucket := "testbucket10"

// 	err := setup(s, bucket)
// 	if err != nil {
// 		failF("%v: %v", testname, err)
// 		return
// 	}

// 	// use funny size to prevent accidental alignments
// 	datalen := 1234567
// 	shortdatalen := 12345
// 	data := make([]byte, shortdatalen)
// 	rand.Read(data)
// 	r := bytes.NewReader(data)

// 	name := "myobject"
// 	s3client := s3.NewFromConfig(s.Config())

// 	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
// 	_, err = s3client.PutObject(ctx, &s3.PutObjectInput{
// 		Bucket:        &bucket,
// 		Key:           &name,
// 		Body:          r,
// 		ContentLength: int64(datalen),
// 	})
// 	cancel()
// 	if err == nil {
// 		failF("%v: expected error for short data put", testname)
// 		return
// 	}

// 	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
// 	_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
// 		Bucket: &bucket,
// 		Key:    &name,
// 	})
// 	defer cancel()
// 	if err == nil {
// 		failF("%v: expected object not exist", testname)
// 		return
// 	}

// 	err = teardown(s, bucket)
// 	if err != nil {
// 		failF("%v: %v", testname, err)
// 		return
// 	}
// 	passF(testname)
// }

// func TestInvalidMultiParts(s *S3Conf) {
// 	testname := "invalid multipart parts"
// 	runF(testname)

// 	bucket := "bucket12"

// 	err := setup(s, bucket)
// 	if err != nil {
// 		failF("%v: %v", testname, err)
// 		return
// 	}

// 	s3client := s3.NewFromConfig(s.Config())

// 	obj := "mympuobject"

// 	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
// 	mpu, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
// 		Bucket: &bucket,
// 		Key:    &obj,
// 	})
// 	cancel()
// 	if err != nil {
// 		failF("%v: create multipart upload: %v", testname, err)
// 		return
// 	}

// 	// upload 2 parts
// 	size5MB := 5 * 1024 * 1024
// 	dr := NewDataReader(size5MB, size5MB)

// 	datafile := "rand.data"
// 	w, err := os.Create(datafile)
// 	if err != nil {
// 		failF("%v: create %v: %v", testname, datafile, err)
// 		return
// 	}
// 	defer w.Close()

// 	_, err = io.Copy(w, dr)
// 	if err != nil {
// 		failF("%v: write %v: %v", testname, datafile, err)
// 		return
// 	}

// 	_, err = w.Seek(0, io.SeekStart)
// 	if err != nil {
// 		failF("%v: seek %v: %v", testname, datafile, err)
// 		return
// 	}

// 	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
// 	_, err = s3client.UploadPart(ctx, &s3.UploadPartInput{
// 		Bucket:        &bucket,
// 		Key:           &obj,
// 		PartNumber:    -1,
// 		UploadId:      mpu.UploadId,
// 		Body:          w,
// 		ContentLength: int64(size5MB),
// 	})
// 	cancel()
// 	if err == nil {
// 		failF("%v: multipart put part 1 expected error", testname)
// 		return
// 	}

// 	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
// 	_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
// 		Bucket: &bucket,
// 		Key:    &obj,
// 	})
// 	cancel()
// 	if err == nil {
// 		failF("%v: head object %v expected error", testname, obj)
// 		return
// 	}

// 	err = teardown(s, bucket)
// 	if err != nil {
// 		failF("%v: %v", testname, err)
// 		return
// 	}
// 	passF(testname)
// }

// func TestAclActions(s *S3Conf) {
// 	testname := "test put/get acl"
// 	runF(testname)

// 	bucket := "testbucket14"

// 	err := setup(s, bucket)
// 	if err != nil {
// 		failF("%v: %v", testname, err)
// 		return
// 	}

// 	s3client := s3.NewFromConfig(s.Config())

// 	rootAccess := s.awsID
// 	rootSecret := s.awsSecret

// 	s.awsID = "grt1"
// 	s.awsSecret = "grt1secret"

// 	userS3Client := s3.NewFromConfig(s.Config())

// 	s.awsID = rootAccess
// 	s.awsSecret = rootSecret

// 	grt1 := "grt1"

// 	grants := []types.Grant{
// 		{
// 			Permission: "READ",
// 			Grantee: &types.Grantee{
// 				ID:   &grt1,
// 				Type: "CanonicalUser",
// 			},
// 		},
// 	}

// 	succUsrCrt := "The user has been created successfully"
// 	failUsrCrt := "failed to create a user: update iam data: account already exists"

// 	out, err := execCommand("admin", "-a", s.awsID, "-s", s.awsSecret, "create-user", "-a", grt1, "-s", "grt1secret", "-r", "user")
// 	if err != nil {
// 		failF("%v: %v", err)
// 		return
// 	}
// 	if !strings.Contains(string(out), succUsrCrt) && !strings.Contains(string(out), failUsrCrt) {
// 		failF("%v: failed to create user accounts", testname)
// 		return
// 	}

// 	// Validation error case
// 	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
// 	_, err = s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
// 		Bucket: &bucket,
// 		AccessControlPolicy: &types.AccessControlPolicy{
// 			Grants: grants,
// 		},
// 		ACL: "private",
// 	})
// 	cancel()
// 	if err == nil {
// 		failF("%v: expected validation error", testname)
// 		return
// 	}

// 	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
// 	_, err = s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
// 		Bucket: &bucket,
// 		AccessControlPolicy: &types.AccessControlPolicy{
// 			Grants: grants,
// 			Owner:  &types.Owner{ID: &s.awsID},
// 		},
// 	})
// 	cancel()
// 	if err != nil {
// 		failF("%v: %v", testname, err)
// 		return
// 	}

// 	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
// 	acl, err := s3client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
// 		Bucket: &bucket,
// 	})
// 	cancel()
// 	if err != nil {
// 		failF("%v: %v", testname, err)
// 		return
// 	}

// 	if *acl.Owner.ID != s.awsID {
// 		failF("%v: expected bucket owner: %v, instead got: %v", testname, s.awsID, *acl.Owner.ID)
// 		return
// 	}
// 	if !checkGrants(acl.Grants, grants) {
// 		failF("%v: expected %v, instead got %v", testname, grants, acl.Grants)
// 		return
// 	}

// 	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
// 	_, err = userS3Client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
// 		Bucket: &bucket,
// 	})
// 	cancel()
// 	if err == nil {
// 		failF("%v: expected acl access denied error", testname)
// 		return
// 	}

// 	err = teardown(s, bucket)
// 	if err != nil {
// 		failF("%v: %v", testname, err)
// 		return
// 	}
// 	passF(testname)
// }

type prefResult struct {
	elapsed time.Duration
	size    int64
	err     error
}

func TestPerformance(s *S3Conf, upload, download bool, files int, objectSize int64, bucket, prefix string) error {
	var sg sync.WaitGroup
	results := make([]prefResult, files)
	start := time.Now()
	if upload {
		if objectSize == 0 {
			return fmt.Errorf("must specify object size for upload")
		}

		if objectSize > (int64(10000) * s.PartSize) {
			return fmt.Errorf("object size can not exceed 10000 * chunksize")
		}

		runF("performance test: upload/download objects")

		for i := 0; i < files; i++ {
			sg.Add(1)
			go func(i int) {
				var r io.Reader = NewDataReader(int(objectSize), int(s.PartSize))

				start := time.Now()
				err := s.UploadData(r, bucket, fmt.Sprintf("%v%v", prefix, i))
				results[i].elapsed = time.Since(start)
				results[i].err = err
				results[i].size = objectSize
				sg.Done()
			}(i)
		}
	}
	if download {
		for i := 0; i < files; i++ {
			sg.Add(1)
			go func(i int) {
				nw := NewNullWriter()
				start := time.Now()
				n, err := s.DownloadData(nw, bucket, fmt.Sprintf("%v%v", prefix, i))
				results[i].elapsed = time.Since(start)
				results[i].err = err
				results[i].size = n
				sg.Done()
			}(i)
		}
	}
	sg.Wait()
	elapsed := time.Since(start)

	var tot int64
	for i, res := range results {
		if res.err != nil {
			failF("%v: %v\n", i, res.err)
			break
		}
		tot += res.size
		fmt.Printf("%v: %v in %v (%v MB/s)\n",
			i, res.size, res.elapsed,
			int(math.Ceil(float64(res.size)/res.elapsed.Seconds())/1048576))
	}

	fmt.Println()
	passF("run perf: %v in %v (%v MB/s)\n",
		tot, elapsed, int(math.Ceil(float64(tot)/elapsed.Seconds())/1048576))

	return nil
}
