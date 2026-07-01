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

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

func ListBuckets_as_user(s *S3Conf) error {
	testName := "ListBuckets_as_user"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		buckets := []types.Bucket{{Name: &bucket, BucketRegion: &s.awsRegion}}
		for range 6 {
			bckt := getBucketName()

			err := setup(s, bckt)
			if err != nil {
				return err
			}

			buckets = append(buckets, types.Bucket{
				Name:         &bckt,
				BucketRegion: &s.awsRegion,
			})
		}

		testuser := getUser("user")

		err := createUsers(s, []user{testuser})
		if err != nil {
			return err
		}

		bckts := []string{}
		for i := range 3 {
			bckts = append(bckts, *buckets[i].Name)
		}

		err = changeBucketsOwner(s, bckts, testuser.access)
		if err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := userClient.ListBuckets(ctx, &s3.ListBucketsInput{})
		cancel()
		if err != nil {
			return err
		}

		if getString(out.Owner.ID) != testuser.access {
			return fmt.Errorf("expected buckets owner to be %v, instead got %v",
				testuser.access, getString(out.Owner.ID))
		}
		if !compareBuckets(out.Buckets, buckets[:3]) {
			return fmt.Errorf("expected list buckets result to be %v, instead got %v",
				buckets[:3], out.Buckets)
		}

		for _, elem := range buckets[1:] {
			err = teardown(s, *elem.Name)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func ListBuckets_as_admin(s *S3Conf) error {
	testName := "ListBuckets_as_admin"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser, adminUser := getUser("user"), getUser("admin")

		err := createUsers(s, []user{testuser, adminUser})
		if err != nil {
			return err
		}

		adminClient := s.getUserClient(adminUser)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		initOut, err := adminClient.ListBuckets(ctx, &s3.ListBucketsInput{})
		cancel()
		if err != nil {
			return err
		}

		ignore := make([]string, 0, len(initOut.Buckets))
		for _, b := range initOut.Buckets {
			if *b.Name != bucket {
				ignore = append(ignore, *b.Name)
			}
		}

		buckets := []types.Bucket{{Name: &bucket, BucketRegion: &s.awsRegion}}
		for range 6 {
			bckt := getBucketName()

			err := setup(s, bckt)
			if err != nil {
				return err
			}

			buckets = append(buckets, types.Bucket{
				Name:         &bckt,
				BucketRegion: &s.awsRegion,
			})
		}

		bckts := []string{}
		for i := range 3 {
			bckts = append(bckts, *buckets[i].Name)
		}

		err = changeBucketsOwner(s, bckts, testuser.access)
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := adminClient.ListBuckets(ctx, &s3.ListBucketsInput{})
		cancel()
		if err != nil {
			return err
		}

		if getString(out.Owner.ID) != adminUser.access {
			return fmt.Errorf("expected buckets owner to be %v, instead got %v",
				adminUser.access, getString(out.Owner.ID))
		}
		if !compareBuckets(out.Buckets, buckets, ignore...) {
			return fmt.Errorf("expected list buckets result to be %v, instead got %v",
				sprintBuckets(buckets), sprintBuckets(out.Buckets))
		}

		for _, elem := range buckets[1:] {
			err = teardown(s, *elem.Name)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func ListBuckets_with_prefix(s *S3Conf) error {
	testName := "ListBuckets_with_prefix"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		prefix := "my-prefix-"

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		prefixInitOut, err := s3client.ListBuckets(ctx, &s3.ListBucketsInput{
			Prefix: &prefix,
		})
		cancel()
		if err != nil {
			return err
		}

		ignore := make([]string, 0, len(prefixInitOut.Buckets))
		for _, b := range prefixInitOut.Buckets {
			ignore = append(ignore, *b.Name)
		}

		allBuckets, prefixedBuckets := []types.Bucket{{Name: &bucket, BucketRegion: &s.awsRegion}}, []types.Bucket{}
		for i := range 5 {
			bckt := getBucketName()
			if i%2 == 0 {
				bckt = prefix + bckt
			}

			err := setup(s, bckt)
			if err != nil {
				return err
			}

			allBuckets = append(allBuckets, types.Bucket{
				Name:         &bckt,
				BucketRegion: &s.awsRegion,
			})

			if i%2 == 0 {
				prefixedBuckets = append(prefixedBuckets, types.Bucket{
					Name:         &bckt,
					BucketRegion: &s.awsRegion,
				})
			}
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListBuckets(ctx, &s3.ListBucketsInput{
			Prefix: &prefix,
		})
		cancel()
		if err != nil {
			return err
		}

		if getString(out.Owner.ID) != s.awsID {
			return fmt.Errorf("expected owner to be %v, instead got %v",
				s.awsID, getString(out.Owner.ID))
		}
		if getString(out.Prefix) != prefix {
			return fmt.Errorf("expected prefix to be %v, instead got %v",
				prefix, getString(out.Prefix))
		}
		if !compareBuckets(out.Buckets, prefixedBuckets, ignore...) {
			return fmt.Errorf("expected list buckets result to be %v, instead got %v",
				prefixedBuckets, out.Buckets)
		}

		for _, elem := range allBuckets[1:] {
			err = teardown(s, *elem.Name)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func ListBuckets_invalid_max_buckets(s *S3Conf) error {
	testName := "ListBuckets_invalid_max_buckets"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		listBuckets := func(maxBuckets int32) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.ListBuckets(ctx, &s3.ListBucketsInput{
				MaxBuckets: &maxBuckets,
			})
			cancel()
			return err
		}

		invMaxBuckets := int32(-3)
		err := listBuckets(invMaxBuckets)
		if err := checkApiErr(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgMaxBuckets, fmt.Sprint(invMaxBuckets))); err != nil {
			return err
		}

		invMaxBuckets = 2000000
		err = listBuckets(invMaxBuckets)
		if err := checkApiErr(err, s3err.GetInvalidArgumentErr(s3err.InvalidArgMaxBuckets, fmt.Sprint(invMaxBuckets))); err != nil {
			return err
		}

		return nil
	})
}

func ListBuckets_truncated(s *S3Conf) error {
	testName := "ListBuckets_truncated"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		initOut, err := s3client.ListBuckets(ctx, &s3.ListBucketsInput{})
		cancel()
		if err != nil {
			return err
		}

		newBuckets := []types.Bucket{}
		for range 5 {
			bckt := getBucketName()

			err := setup(s, bckt)
			if err != nil {
				return err
			}

			newBuckets = append(newBuckets, types.Bucket{
				Name:         &bckt,
				BucketRegion: &s.awsRegion,
			})
		}

		buckets := append(initOut.Buckets, newBuckets...)
		sort.Slice(buckets, func(i, j int) bool {
			return *buckets[i].Name < *buckets[j].Name
		})

		maxBuckets := int32(3)
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListBuckets(ctx, &s3.ListBucketsInput{
			MaxBuckets: &maxBuckets,
		})
		cancel()
		if err != nil {
			return err
		}

		if getString(out.Owner.ID) != s.awsID {
			return fmt.Errorf("expected owner to be %v, instead got %v",
				s.awsID, getString(out.Owner.ID))
		}
		if !compareBuckets(out.Buckets, buckets[:maxBuckets]) {
			return fmt.Errorf("expected list buckets result to be %v, instead got %v",
				sprintBuckets(buckets[:maxBuckets]), sprintBuckets(out.Buckets))
		}
		if getString(out.ContinuationToken) != getString(buckets[maxBuckets-1].Name) {
			return fmt.Errorf("expected ContinuationToken to be %v, instead got %v",
				getString(buckets[maxBuckets-1].Name), getString(out.ContinuationToken))
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err = s3client.ListBuckets(ctx, &s3.ListBucketsInput{
			ContinuationToken: out.ContinuationToken,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareBuckets(out.Buckets, buckets[maxBuckets:]) {
			return fmt.Errorf("expected list buckets result to be %v, instead got %v",
				sprintBuckets(buckets[maxBuckets:]), sprintBuckets(out.Buckets))
		}
		if out.ContinuationToken != nil {
			return fmt.Errorf("expected nil continuation token, instead got %v",
				*out.ContinuationToken)
		}
		if out.Prefix != nil {
			return fmt.Errorf("expected nil prefix, instead got %v", *out.Prefix)
		}

		for _, elem := range newBuckets {
			err = teardown(s, *elem.Name)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func ListBuckets_empty_success(s *S3Conf) error {
	testName := "ListBuckets_empty_success"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListBuckets(ctx, &s3.ListBucketsInput{})
		cancel()
		if err != nil {
			return err
		}

		if len(out.Buckets) > 0 {
			return fmt.Errorf("expected list buckets result to be %v, instead got %v",
				[]types.Bucket{}, sprintBuckets(out.Buckets))
		}

		return nil
	})
}

func ListBuckets_success(s *S3Conf) error {
	testName := "ListBuckets_success"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		initOut, err := s3client.ListBuckets(ctx, &s3.ListBucketsInput{})
		cancel()
		if err != nil {
			return err
		}

		ignore := make([]string, 0, len(initOut.Buckets))
		for _, b := range initOut.Buckets {
			if *b.Name != bucket {
				ignore = append(ignore, *b.Name)
			}
		}

		buckets := []types.Bucket{{Name: &bucket, BucketRegion: &s.awsRegion}}
		for range 5 {
			bckt := getBucketName()

			err := setup(s, bckt)
			if err != nil {
				return err
			}

			buckets = append(buckets, types.Bucket{
				Name:         &bckt,
				BucketRegion: &s.awsRegion,
			})
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListBuckets(ctx, &s3.ListBucketsInput{})
		cancel()
		if err != nil {
			return err
		}

		if getString(out.Owner.ID) != s.awsID {
			return fmt.Errorf("expected owner to be %v, instead got %v",
				s.awsID, getString(out.Owner.ID))
		}
		if !compareBuckets(out.Buckets, buckets, ignore...) {
			return fmt.Errorf("expected list buckets result to be %v, instead got %v",
				sprintBuckets(buckets), sprintBuckets(out.Buckets))
		}

		for _, elem := range buckets[1:] {
			err = teardown(s, *elem.Name)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func ListBuckets_with_bucket_policy(s *S3Conf) error {
	testName := "ListBuckets_with_bucket_policy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")

		err := createUsers(s, []user{testuser})
		if err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)

		// Before the policy, the user should not see the bucket.
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := userClient.ListBuckets(ctx, &s3.ListBucketsInput{})
		cancel()
		if err != nil {
			return err
		}
		for _, b := range out.Buckets {
			if *b.Name == bucket {
				return fmt.Errorf("bucket %v should not be visible to user %v before policy is set",
					bucket, testuser.access)
			}
		}

		// Grant the test user s3:ListBucket on the bucket via bucket policy.
		policy := genPolicyDoc("Allow",
			fmt.Sprintf(`["%s"]`, testuser.access),
			`["s3:ListBucket"]`,
			fmt.Sprintf(`"arn:aws:s3:::%s"`, bucket))

		err = putBucketPolicy(s3client, bucket, policy)
		if err != nil {
			return err
		}

		// After the policy, the user should see the bucket.
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err = userClient.ListBuckets(ctx, &s3.ListBucketsInput{})
		cancel()
		if err != nil {
			return err
		}

		found := false
		for _, b := range out.Buckets {
			if *b.Name == bucket {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("expected bucket %v in ListBuckets result for user %v after policy, but it was not found",
				bucket, testuser.access)
		}

		return nil
	})
}
