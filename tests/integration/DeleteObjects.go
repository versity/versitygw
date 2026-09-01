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

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

func DeleteObjects_empty_input(s *S3Conf) error {
	testName := "DeleteObjects_empty_input"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		contents, err := putObjects(s3client, []string{"foo", "bar", "baz"}, bucket)
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
			return fmt.Errorf("expected deleted object count 0, instead got %v",
				len(out.Deleted))
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

		if !compareObjects(contents, res.Contents) {
			return fmt.Errorf("expected the output to be %v, instead got %v",
				contents, res.Contents)
		}

		return nil
	})
}

func DeleteObjects_non_existing_objects(s *S3Conf) error {
	testName := "DeleteObjects_empty_input"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		delObjects := []types.ObjectIdentifier{{Key: getPtr("obj1")}, {Key: getPtr("obj2")}}

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

		if len(out.Deleted) != 2 {
			return fmt.Errorf("expected deleted object count 2, instead got %v",
				len(out.Deleted))
		}
		if len(out.Errors) != 0 {
			return fmt.Errorf("expected 0 errors, instead got %v, %v",
				len(out.Errors), out.Errors)
		}

		return nil
	})
}

func DeleteObjects_success(s *S3Conf) error {
	testName := "DeleteObjects_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objects, objToDel := []string{"obj1", "obj2", "obj3"}, []string{"foo", "bar", "baz"}
		contents, err := putObjects(s3client, append(objToDel, objects...), bucket)
		if err != nil {
			return err
		}

		delObjects := []types.ObjectIdentifier{}
		delResult := []types.DeletedObject{}
		for _, key := range objToDel {
			k := key
			delObjects = append(delObjects, types.ObjectIdentifier{Key: &k})
			delResult = append(delResult, types.DeletedObject{Key: &k})
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
			return fmt.Errorf("expected deleted object count 3, instead got %v",
				len(out.Deleted))
		}
		if len(out.Errors) != 0 {
			return fmt.Errorf("expected 2 errors, instead got %v",
				len(out.Errors))
		}

		if !compareDelObjects(delResult, out.Deleted) {
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

		if !compareObjects(contents[3:], res.Contents) {
			return fmt.Errorf("expected the output to be %v, instead got %v",
				contents[3:], res.Contents)
		}

		return nil
	})
}

// DeleteObjects_iam_mixed_denials_and_success covers a single batch mixing
// every DeleteObjects outcome at once: a key the identity policy denies, a
// governance-locked key with no bypass, and keys the caller may freely
// delete. All three outcomes land in one response — no top-level error —
// with Deleted and Errors each preserving the order the keys were
// requested in.
func DeleteObjects_iam_mixed_denials_and_success(s *S3Conf) error {
	testName := "DeleteObjects_iam_mixed_denials_and_success"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		for _, key := range []string{"allowed/one", "allowed/two", "denied/one"} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &key})
			cancel()
			if err != nil {
				return err
			}
		}
		if err := putGovernanceLockedObject(s, bucket, "locked/one"); err != nil {
			return err
		}

		user, cleanup, err := newS3IAMUser(root, s, map[string]string{
			"p": policyDoc(accessStatement{
				Effect: "Allow", Action: actS3DeleteObject,
				Resource: []string{objectArn(bucket, "allowed/*"), objectArn(bucket, "locked/*")},
			}),
		})
		if err != nil {
			return err
		}
		defer cleanup()

		delObjects := []types.ObjectIdentifier{
			{Key: getPtr("allowed/one")},
			{Key: getPtr("denied/one")},
			{Key: getPtr("locked/one")},
			{Key: getPtr("allowed/two")},
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := user.client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: &bucket,
			Delete: &types.Delete{Objects: delObjects},
		})
		cancel()
		if err != nil {
			return fmt.Errorf("expected DeleteObjects to succeed with per-object denials, not fail outright: %w", err)
		}

		if err := checkDeletedKeysInOrder(out.Deleted, []string{"allowed/one", "allowed/two"}); err != nil {
			return err
		}
		return checkDeleteObjectsErrsInOrder(out.Errors, []keyDenial{
			{"denied/one", wantImplicitDeny(user.arn, actS3DeleteObject, objectArn(bucket, "denied/one"))},
			{"locked/one", s3err.GetAPIError(s3err.ErrObjectLocked)},
		})
	}, withLock())
}

// DeleteObjects_iam_all_access_denied covers a batch where the identity
// policy grants nothing at all: the call itself still succeeds — no
// top-level error — with every object reported denied in Errors, in
// request order, and nothing in Deleted.
func DeleteObjects_iam_all_access_denied(s *S3Conf) error {
	testName := "DeleteObjects_iam_all_access_denied"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		for _, key := range []string{"one", "two", "three"} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &key})
			cancel()
			if err != nil {
				return err
			}
		}

		user, cleanup, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanup()

		delObjects := []types.ObjectIdentifier{
			{Key: getPtr("one")}, {Key: getPtr("two")}, {Key: getPtr("three")},
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := user.client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: &bucket,
			Delete: &types.Delete{Objects: delObjects},
		})
		cancel()
		if err != nil {
			return fmt.Errorf("expected DeleteObjects to succeed with per-object denials, not fail outright: %w", err)
		}

		if len(out.Deleted) != 0 {
			return fmt.Errorf("expected nothing deleted, got %+v", out.Deleted)
		}
		return checkDeleteObjectsErrsInOrder(out.Errors, []keyDenial{
			{"one", wantImplicitDeny(user.arn, actS3DeleteObject, objectArn(bucket, "one"))},
			{"two", wantImplicitDeny(user.arn, actS3DeleteObject, objectArn(bucket, "two"))},
			{"three", wantImplicitDeny(user.arn, actS3DeleteObject, objectArn(bucket, "three"))},
		})
	})
}

// DeleteObjects_iam_all_locked covers a batch where every object is
// governance-locked and none is deleted: the call still succeeds — no
// top-level error — with every object reported denied in Errors, in
// request order, and nothing in Deleted. Omitting the bypass header
// entirely reports the generic object-lock message; sending the header
// without s3:BypassGovernanceRetention reports the specific AccessDenied
// naming that action instead — the same distinction the single-object
// DELETE path makes, now confirmed for the batch path too.
func DeleteObjects_iam_all_locked(s *S3Conf) error {
	testName := "DeleteObjects_iam_all_locked"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		for _, key := range []string{"locked/one", "locked/two"} {
			if err := putGovernanceLockedObject(s, bucket, key); err != nil {
				return err
			}
		}

		user, cleanup, err := newS3IAMUser(root, s, map[string]string{
			"p": policyDoc(accessStatement{
				Effect: "Allow", Action: actS3DeleteObject, Resource: objectsArn(bucket),
			}),
		})
		if err != nil {
			return err
		}
		defer cleanup()

		delObjects := []types.ObjectIdentifier{{Key: getPtr("locked/one")}, {Key: getPtr("locked/two")}}

		// No bypass header at all: the generic object-lock message.
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := user.client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: &bucket,
			Delete: &types.Delete{Objects: delObjects},
		})
		cancel()
		if err != nil {
			return fmt.Errorf("expected DeleteObjects to succeed with per-object denials, not fail outright: %w", err)
		}
		if len(out.Deleted) != 0 {
			return fmt.Errorf("expected nothing deleted, got %+v", out.Deleted)
		}
		if err := checkDeleteObjectsErrsInOrder(out.Errors, []keyDenial{
			{"locked/one", s3err.GetAPIError(s3err.ErrObjectLocked)},
			{"locked/two", s3err.GetAPIError(s3err.ErrObjectLocked)},
		}); err != nil {
			return fmt.Errorf("without bypass header: %w", err)
		}

		// Bypass header sent, but the identity policy doesn't grant
		// s3:BypassGovernanceRetention: a specific AccessDenied naming that
		// action, not the generic object-lock message.
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err = user.client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket:                    &bucket,
			Delete:                    &types.Delete{Objects: delObjects},
			BypassGovernanceRetention: getPtr(true),
		})
		cancel()
		if err != nil {
			return fmt.Errorf("expected DeleteObjects to succeed with per-object denials, not fail outright: %w", err)
		}
		if len(out.Deleted) != 0 {
			return fmt.Errorf("expected nothing deleted, got %+v", out.Deleted)
		}
		if err := checkDeleteObjectsErrsInOrder(out.Errors, []keyDenial{
			{"locked/one", wantImplicitDeny(user.arn, actS3BypassGovernance, objectArn(bucket, "locked/one"))},
			{"locked/two", wantImplicitDeny(user.arn, actS3BypassGovernance, objectArn(bucket, "locked/two"))},
		}); err != nil {
			return fmt.Errorf("with bypass header, no permission: %w", err)
		}
		return nil
	}, withLock())
}
