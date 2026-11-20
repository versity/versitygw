// Copyright 2026 Versity Software
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
	"errors"
	"fmt"
	"slices"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// The tests here run against a gateway started with --list-buckets-scope
// accessible or all, and an IAM backend without identity policies. Every
// bucket is created by root, so a new user owns none of them unless a test
// hands it over.

// scopeBuckets creates n buckets as root, returning their names sorted the
// way ListBuckets orders them, and a cleanup deleting them all.
func scopeBuckets(s *S3Conf, n int, opts ...setupOpt) ([]string, func() error, error) {
	var names []string
	cleanup := func() error {
		var err error
		for _, name := range names {
			err = errors.Join(err, teardown(s, name))
		}
		return err
	}
	for range n {
		name := getBucketName()
		if err := setup(s, name, opts...); err != nil {
			return nil, cleanup, err
		}
		names = append(names, name)
	}
	slices.Sort(names)
	return names, cleanup, nil
}

// listBucketNames lists every bucket client sees, maxBuckets at a time (all
// at once for 0), and checks the pages are well formed: each one carries
// the caller as Owner and at least one bucket, and only a page with more
// buckets after it carries a continuation token.
func listBucketNames(client *s3.Client, owner string, maxBuckets int32, prefix string) ([]string, error) {
	var names []string
	var token *string
	for page := 1; ; page++ {
		input := &s3.ListBucketsInput{ContinuationToken: token}
		if maxBuckets > 0 {
			input.MaxBuckets = &maxBuckets
		}
		if prefix != "" {
			input.Prefix = &prefix
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := client.ListBuckets(ctx, input)
		cancel()
		if err != nil {
			return nil, err
		}

		if got := getString(out.Owner.ID); got != owner {
			return nil, fmt.Errorf("page %d: expected owner %q, instead got %q", page, owner, got)
		}
		if len(out.Buckets) == 0 && page > 1 {
			return nil, fmt.Errorf("page %d is empty: the token %q of the page before led nowhere", page, getString(token))
		}
		if maxBuckets > 0 && int32(len(out.Buckets)) > maxBuckets {
			return nil, fmt.Errorf("page %d has %d buckets, more than max-buckets %d", page, len(out.Buckets), maxBuckets)
		}
		for _, b := range out.Buckets {
			names = append(names, getString(b.Name))
		}
		if out.ContinuationToken == nil {
			return names, nil
		}
		token = out.ContinuationToken
	}
}

// expectListed checks that client lists exactly want, out of the buckets
// in among. Buckets outside among, left by other tests, are ignored.
func expectListed(client *s3.Client, owner string, among, want []string) error {
	got, err := listBucketNames(client, owner, 0, "")
	if err != nil {
		return err
	}
	got = slices.DeleteFunc(got, func(name string) bool { return !slices.Contains(among, name) })
	if !slices.Equal(got, want) {
		return fmt.Errorf("expected the listed buckets to be %v, instead got %v", want, got)
	}
	return nil
}

// expectAccessDenied checks that err is an AccessDenied error.
func expectAccessDenied(err error) error {
	if err == nil {
		return errors.New("expected AccessDenied, instead got no error")
	}
	return checkSdkApiErr(err, "AccessDenied")
}

// quotedBucketArn is bucketArn as a JSON string.
func quotedBucketArn(bucket string) string {
	return quoted(bucketArn(bucket))
}

func quoted(s string) string {
	return fmt.Sprintf("%q", s)
}

func ListBucketsAccessible_policy_shared_bucket(s *S3Conf) error {
	testName := "ListBucketsAccessible_policy_shared_bucket"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, _ string) (err error) {
		buckets, cleanup, err := scopeBuckets(s, 2)
		defer func() { err = errors.Join(err, cleanup()) }()
		if err != nil {
			return err
		}
		shared, other := buckets[0], buckets[1]

		testuser, otheruser := getUser("user"), getUser("user")
		if err := createUsers(s, []user{testuser, otheruser}); err != nil {
			return err
		}
		userClient := s.getUserClient(testuser)

		if err := expectListed(userClient, testuser.access, buckets, []string{}); err != nil {
			return fmt.Errorf("before sharing: %w", err)
		}

		policy := genPolicyDoc("Allow", fmt.Sprintf(`{"AWS": %s}`, quoted(testuser.access)), `"s3:ListBucket"`, quotedBucketArn(shared))
		if err := putBucketPolicy(s3client, shared, policy); err != nil {
			return err
		}
		// A grant to someone else shares nothing with this user.
		policy = genPolicyDoc("Allow", quoted(otheruser.access), `"s3:ListBucket"`, quotedBucketArn(other))
		if err := putBucketPolicy(s3client, other, policy); err != nil {
			return err
		}

		if err := expectListed(userClient, testuser.access, buckets, []string{shared}); err != nil {
			return err
		}

		// The grant that shows the bucket is the one that lets the user use it.
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &shared})
		cancel()
		return err
	})
}

func ListBucketsAccessible_acl_shared_bucket(s *S3Conf) error {
	testName := "ListBucketsAccessible_acl_shared_bucket"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, _ string) (err error) {
		buckets, cleanup, err := scopeBuckets(s, 3, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
		defer func() { err = errors.Join(err, cleanup()) }()
		if err != nil {
			return err
		}
		readable, fullControl, writeOnly := buckets[0], buckets[1], buckets[2]

		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}
		grantee := testuser.access

		for _, grant := range []*s3.PutBucketAclInput{
			{Bucket: &readable, GrantRead: &grantee},
			{Bucket: &fullControl, GrantFullControl: &grantee},
			// WRITE doesn't grant s3:ListBucket.
			{Bucket: &writeOnly, GrantWrite: &grantee},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.PutBucketAcl(ctx, grant)
			cancel()
			if err != nil {
				return err
			}
		}

		return expectListed(s.getUserClient(testuser), testuser.access, buckets, []string{readable, fullControl})
	})
}

func ListBucketsAccessible_public_bucket_hidden(s *S3Conf) error {
	testName := "ListBucketsAccessible_public_bucket_hidden"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, _ string) (err error) {
		buckets, cleanup, err := scopeBuckets(s, 2, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
		defer func() { err = errors.Join(err, cleanup()) }()
		if err != nil {
			return err
		}
		publicPolicy, publicACL := buckets[0], buckets[1]

		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		policy := genPolicyDoc("Allow", `"*"`, `"s3:ListBucket"`, quotedBucketArn(publicPolicy))
		if err := putBucketPolicy(s3client, publicPolicy, policy); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &publicACL,
			ACL:    types.BucketCannedACLPublicRead,
		})
		cancel()
		if err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)
		// Public buckets are usable, just not listed.
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &publicPolicy})
		cancel()
		if err != nil {
			return err
		}

		return expectListed(userClient, testuser.access, buckets, []string{})
	})
}

func ListBucketsAccessible_deny_hides_bucket(s *S3Conf) error {
	testName := "ListBucketsAccessible_deny_hides_bucket"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, _ string) (err error) {
		buckets, cleanup, err := scopeBuckets(s, 3, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
		defer func() { err = errors.Join(err, cleanup()) }()
		if err != nil {
			return err
		}
		aclDenied, policyDenied, objectsDenied := buckets[0], buckets[1], buckets[2]

		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}
		principal := fmt.Sprintf(`{"AWS": %s}`, quoted(testuser.access))
		grantee := testuser.access

		for _, bucket := range []string{aclDenied, objectsDenied} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{Bucket: &bucket, GrantRead: &grantee})
			cancel()
			if err != nil {
				return err
			}
		}

		// A Deny to everyone takes back the ACL grant.
		policy := genPolicyDoc("Deny", `"*"`, `"s3:ListBucket"`, quotedBucketArn(aclDenied))
		if err := putBucketPolicy(s3client, aclDenied, policy); err != nil {
			return err
		}
		// A Deny naming the user overrides an Allow naming it.
		policy = fmt.Sprintf(`{"Statement": [
			{"Effect": "Allow", "Principal": %[1]s, "Action": "s3:ListBucket", "Resource": %[2]s},
			{"Effect": "Deny", "Principal": %[1]s, "Action": "s3:ListBucket", "Resource": %[2]s}
		]}`, principal, quotedBucketArn(policyDenied))
		if err := putBucketPolicy(s3client, policyDenied, policy); err != nil {
			return err
		}
		// A Deny of object reads doesn't touch listing.
		policy = genPolicyDoc("Deny", `"*"`, `"s3:GetObject"`, fmt.Sprintf(`"arn:aws:s3:::%s/*"`, objectsDenied))
		if err := putBucketPolicy(s3client, objectsDenied, policy); err != nil {
			return err
		}

		return expectListed(s.getUserClient(testuser), testuser.access, buckets, []string{objectsDenied})
	})
}

func ListBucketsAccessible_prefix_scoped_grant(s *S3Conf) error {
	testName := "ListBucketsAccessible_prefix_scoped_grant"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, _ string) (err error) {
		buckets, cleanup, err := scopeBuckets(s, 3)
		defer func() { err = errors.Join(err, cleanup()) }()
		if err != nil {
			return err
		}
		teamFolder, partlyDenied, objectsOnly := buckets[0], buckets[1], buckets[2]

		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}
		principal := fmt.Sprintf(`{"AWS": %s}`, quoted(testuser.access))

		// The user may list the team-a/ folder only.
		policy := fmt.Sprintf(`{"Statement": [{"Effect": "Allow", "Principal": %s, "Action": "s3:ListBucket", "Resource": %s,
			"Condition": {"StringLike": {"s3:prefix": "team-a/*"}}}]}`, principal, quotedBucketArn(teamFolder))
		if err := putBucketPolicy(s3client, teamFolder, policy); err != nil {
			return err
		}
		// The user may list everything but the private/ folder.
		policy = fmt.Sprintf(`{"Statement": [
			{"Effect": "Allow", "Principal": %[1]s, "Action": "s3:ListBucket", "Resource": %[2]s},
			{"Effect": "Deny", "Principal": "*", "Action": "s3:ListBucket", "Resource": %[2]s,
			 "Condition": {"StringLike": {"s3:prefix": "private/*"}}}
		]}`, principal, quotedBucketArn(partlyDenied))
		if err := putBucketPolicy(s3client, partlyDenied, policy); err != nil {
			return err
		}
		// Object reads alone don't make a bucket listable.
		policy = genPolicyDoc("Allow", principal, `"s3:GetObject"`, fmt.Sprintf(`"arn:aws:s3:::%s/*"`, objectsOnly))
		if err := putBucketPolicy(s3client, objectsOnly, policy); err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)
		if err := expectListed(userClient, testuser.access, buckets, []string{teamFolder, partlyDenied}); err != nil {
			return err
		}

		// ListBuckets' own prefix filters bucket names and is never taken
		// for the s3:prefix a condition tests.
		got, err := listBucketNames(userClient, testuser.access, 0, teamFolder)
		if err != nil {
			return err
		}
		if !slices.Contains(got, teamFolder) {
			return fmt.Errorf("expected %s listed under prefix %q, instead got %v", teamFolder, teamFolder, got)
		}

		// The grant works the way the listing assumed it does.
		teamPrefix := "team-a/"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &teamFolder, Prefix: &teamPrefix})
		cancel()
		if err != nil {
			return err
		}
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &teamFolder})
		cancel()
		return expectAccessDenied(err)
	})
}

func ListBucketsAccessible_pagination(s *S3Conf) error {
	testName := "ListBucketsAccessible_pagination"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, _ string) (err error) {
		buckets, cleanup, err := scopeBuckets(s, 6)
		defer func() { err = errors.Join(err, cleanup()) }()
		if err != nil {
			return err
		}

		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		// In name order: owned, shared, hidden, owned, shared, hidden, so
		// hidden buckets sit between listed ones and after the last.
		var owned, want []string
		for i, bucket := range buckets {
			switch i % 3 {
			case 0:
				owned = append(owned, bucket)
				want = append(want, bucket)
			case 1:
				policy := genPolicyDoc("Allow", quoted(testuser.access), `"s3:ListBucket"`, quotedBucketArn(bucket))
				if err := putBucketPolicy(s3client, bucket, policy); err != nil {
					return err
				}
				want = append(want, bucket)
			}
		}
		if err := changeBucketsOwner(s, owned, testuser.access); err != nil {
			return err
		}

		// Only this test's buckets are owned by or shared with the user,
		// so the listing holds nothing else.
		userClient := s.getUserClient(testuser)
		for _, maxBuckets := range []int32{0, 1, 2, 3, 4, 5} {
			got, err := listBucketNames(userClient, testuser.access, maxBuckets, "")
			if err != nil {
				return fmt.Errorf("max-buckets %d: %w", maxBuckets, err)
			}
			if !slices.Equal(got, want) {
				return fmt.Errorf("max-buckets %d: expected %v, instead got %v", maxBuckets, want, got)
			}
		}
		return nil
	})
}

// listBucketsRootAndAdmin checks that root and an admin list every bucket,
// whatever the scope.
func listBucketsRootAndAdmin(s *S3Conf, testName string) error {
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, _ string) (err error) {
		buckets, cleanup, err := scopeBuckets(s, 3)
		defer func() { err = errors.Join(err, cleanup()) }()
		if err != nil {
			return err
		}

		testuser, adminUser := getUser("user"), getUser("admin")
		if err := createUsers(s, []user{testuser, adminUser}); err != nil {
			return err
		}
		if err := changeBucketsOwner(s, buckets[:1], testuser.access); err != nil {
			return err
		}

		if err := expectListed(s3client, s.awsID, buckets, buckets); err != nil {
			return fmt.Errorf("root: %w", err)
		}
		if err := expectListed(s.getUserClient(adminUser), adminUser.access, buckets, buckets); err != nil {
			return fmt.Errorf("admin: %w", err)
		}
		return nil
	})
}

func ListBucketsAccessible_root_and_admin_unchanged(s *S3Conf) error {
	return listBucketsRootAndAdmin(s, "ListBucketsAccessible_root_and_admin_unchanged")
}

func ListBucketsAll_root_and_admin_unchanged(s *S3Conf) error {
	return listBucketsRootAndAdmin(s, "ListBucketsAll_root_and_admin_unchanged")
}

func ListBucketsAll_user_lists_every_bucket(s *S3Conf) error {
	testName := "ListBucketsAll_user_lists_every_bucket"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, _ string) (err error) {
		buckets, cleanup, err := scopeBuckets(s, 3)
		defer func() { err = errors.Join(err, cleanup()) }()
		if err != nil {
			return err
		}

		testuser, otheruser := getUser("user"), getUser("user")
		if err := createUsers(s, []user{testuser, otheruser}); err != nil {
			return err
		}
		// One of them belongs to another user, and none is shared.
		if err := changeBucketsOwner(s, buckets[:1], otheruser.access); err != nil {
			return err
		}

		userClient := s.getUserClient(testuser)
		if err := expectListed(userClient, testuser.access, buckets, buckets); err != nil {
			return err
		}

		// Listing a bucket doesn't grant using it.
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &buckets[1]})
		cancel()
		return expectAccessDenied(err)
	})
}

func ListBucketsAll_pagination(s *S3Conf) error {
	testName := "ListBucketsAll_pagination"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, _ string) (err error) {
		buckets, cleanup, err := scopeBuckets(s, 4)
		defer func() { err = errors.Join(err, cleanup()) }()
		if err != nil {
			return err
		}

		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		// The user lists what root lists, page by page.
		want, err := listBucketNames(s3client, s.awsID, 0, "")
		if err != nil {
			return err
		}
		userClient := s.getUserClient(testuser)
		for _, maxBuckets := range []int32{1, 2, 3} {
			got, err := listBucketNames(userClient, testuser.access, maxBuckets, "")
			if err != nil {
				return fmt.Errorf("max-buckets %d: %w", maxBuckets, err)
			}
			if !slices.Equal(got, want) {
				return fmt.Errorf("max-buckets %d: expected %v, instead got %v", maxBuckets, want, got)
			}
		}
		for _, bucket := range buckets {
			if !slices.Contains(want, bucket) {
				return fmt.Errorf("expected %s in the listing %v", bucket, want)
			}
		}
		return nil
	})
}
