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
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

// S3IAMAccessControl_no_policy_denies verifies a caller with no identity
// policy and no bucket policy is denied by default — there is no implicit
// grant anywhere for an ordinary IAM user.
func S3IAMAccessControl_no_policy_denies(s *S3Conf) error {
	testName := "S3IAMAccessControl_no_policy_denies"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		user, cleanup, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanup()

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = user.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		return checkApiErr(err, wantImplicitDeny(user.arn, actS3GetObject, objectArn(bucket, "obj")))
	})
}

// S3IAMAccessControl_root_bypasses_policies verifies the gateway's root
// credential is authorized regardless of any policy, including a bucket
// policy that explicitly denies everyone.
func S3IAMAccessControl_root_bypasses_policies(s *S3Conf) error {
	testName := "S3IAMAccessControl_root_bypasses_policies"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect: "Deny", Principal: "*", Action: "s3:*", Resource: []string{bucketArn(bucket), objectsArn(bucket)},
		}); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		return err
	})
}

// S3IAMAccessControl_identity_policy_allows_without_bucket_policy is the
// core same-account behavior: an identity-policy Allow grants the request on
// its own, with no bucket policy and no ACL grant involved at all.
func S3IAMAccessControl_identity_policy_allows_without_bucket_policy(s *S3Conf) error {
	testName := "S3IAMAccessControl_identity_policy_allows_without_bucket_policy"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		user, cleanup, err := newS3IAMUser(root, s, map[string]string{
			"p": policyDoc(accessStatement{Effect: "Allow", Action: actS3PutObject, Resource: objectsArn(bucket)}),
		})
		if err != nil {
			return err
		}
		defer cleanup()

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = user.client.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return fmt.Errorf("expected PutObject to be allowed: %w", err)
		}

		// The same policy grants nothing beyond the action it names.
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = user.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		return checkApiErr(err, wantImplicitDeny(user.arn, actS3GetObject, objectArn(bucket, "obj")))
	})
}

// S3IAMAccessControl_identity_policy_action_wildcards verifies "s3:*" and
// prefix wildcards ("s3:Get*") match the way an exact action name does.
func S3IAMAccessControl_identity_policy_action_wildcards(s *S3Conf) error {
	testName := "S3IAMAccessControl_identity_policy_action_wildcards"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return err
		}

		cases := []struct {
			name      string
			action    any
			wantGetOK bool
			wantPutOK bool
		}{
			{name: "full wildcard", action: "s3:*", wantGetOK: true, wantPutOK: true},
			{name: "prefix wildcard", action: "s3:Get*", wantGetOK: true, wantPutOK: false},
			{name: "bare wildcard", action: "*", wantGetOK: true, wantPutOK: true},
		}
		for _, tc := range cases {
			if err := func() error {
				user, cleanup, err := newS3IAMUser(root, s, map[string]string{
					"p": policyDoc(accessStatement{
						Effect: "Allow", Action: tc.action,
						Resource: []string{bucketArn(bucket), objectsArn(bucket)},
					}),
				})
				if err != nil {
					return err
				}
				defer cleanup()

				ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
				_, err = user.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
				cancel()
				if tc.wantGetOK {
					if err != nil {
						return fmt.Errorf("expected GetObject to be allowed: %w", err)
					}
				} else if err := checkApiErr(err, wantImplicitDeny(user.arn, actS3GetObject, objectArn(bucket, "obj"))); err != nil {
					return err
				}

				ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
				_, err = user.client.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("obj2")})
				cancel()
				if tc.wantPutOK {
					if err != nil {
						return fmt.Errorf("expected PutObject to be allowed: %w", err)
					}
					return nil
				}
				return checkApiErr(err, wantImplicitDeny(user.arn, actS3PutObject, objectArn(bucket, "obj2")))
			}(); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// S3IAMAccessControl_identity_policy_resource_scoping verifies a Resource
// pattern scopes a grant to matching keys only.
func S3IAMAccessControl_identity_policy_resource_scoping(s *S3Conf) error {
	testName := "S3IAMAccessControl_identity_policy_resource_scoping"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		for _, key := range []string{"allowed/obj", "denied/obj"} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr(key)})
			cancel()
			if err != nil {
				return err
			}
		}

		user, cleanup, err := newS3IAMUser(root, s, map[string]string{
			"p": policyDoc(accessStatement{
				Effect: "Allow", Action: actS3GetObject,
				Resource: objectArn(bucket, "allowed/*"),
			}),
		})
		if err != nil {
			return err
		}
		defer cleanup()

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = user.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("allowed/obj")})
		cancel()
		if err != nil {
			return fmt.Errorf("expected GetObject on the matching key to be allowed: %w", err)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = user.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("denied/obj")})
		cancel()
		return checkApiErr(err, wantImplicitDeny(user.arn, actS3GetObject, objectArn(bucket, "denied/obj")))
	})
}

// S3IAMAccessControl_identity_policy_bucket_vs_object_arn verifies a
// bucket-level action evaluates against the bucket ARN, so an object-ARN
// grant ("bucket/*") does not cover it and vice versa.
func S3IAMAccessControl_identity_policy_bucket_vs_object_arn(s *S3Conf) error {
	testName := "S3IAMAccessControl_identity_policy_bucket_vs_object_arn"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		objectOnly, cleanupObj, err := newS3IAMUser(root, s, map[string]string{
			"p": policyDoc(accessStatement{Effect: "Allow", Action: actS3ListBucket, Resource: objectsArn(bucket)}),
		})
		if err != nil {
			return err
		}
		defer cleanupObj()

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = objectOnly.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &bucket})
		cancel()
		if err := checkApiErr(err, wantImplicitDeny(objectOnly.arn, actS3ListBucket, bucketArn(bucket))); err != nil {
			return fmt.Errorf("an object-ARN grant must not cover a bucket-level action: %w", err)
		}

		bucketScoped, cleanupBucket, err := newS3IAMUser(root, s, map[string]string{
			"p": policyDoc(accessStatement{Effect: "Allow", Action: actS3ListBucket, Resource: bucketArn(bucket)}),
		})
		if err != nil {
			return err
		}
		defer cleanupBucket()

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = bucketScoped.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &bucket})
		cancel()
		if err != nil {
			return fmt.Errorf("expected ListObjects to be allowed by a bucket-ARN grant: %w", err)
		}
		return nil
	})
}

// S3IAMAccessControl_identity_policy_not_action_and_not_resource verifies
// NotAction and NotResource grant everything *except* what they name.
func S3IAMAccessControl_identity_policy_not_action_and_not_resource(s *S3Conf) error {
	testName := "S3IAMAccessControl_identity_policy_not_action_and_not_resource"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return err
		}

		notAction, cleanupAction, err := newS3IAMUser(root, s, map[string]string{
			"p": policyDoc(accessStatement{
				Effect: "Allow", NotAction: actS3GetObject,
				Resource: []string{bucketArn(bucket), objectsArn(bucket)},
			}),
		})
		if err != nil {
			return err
		}
		defer cleanupAction()

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = notAction.client.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("other")})
		cancel()
		if err != nil {
			return fmt.Errorf("NotAction must grant an action it does not name: %w", err)
		}
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = notAction.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err := checkApiErr(err, wantImplicitDeny(notAction.arn, actS3GetObject, objectArn(bucket, "obj"))); err != nil {
			return fmt.Errorf("NotAction must not grant the action it names: %w", err)
		}

		notResource, cleanupResource, err := newS3IAMUser(root, s, map[string]string{
			"p": policyDoc(accessStatement{
				Effect: "Allow", Action: actS3GetObject,
				NotResource: objectArn(bucket, "obj"),
			}),
		})
		if err != nil {
			return err
		}
		defer cleanupResource()

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = notResource.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("other")})
		cancel()
		if err != nil {
			return fmt.Errorf("NotResource must grant a resource it does not name: %w", err)
		}
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = notResource.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		return checkApiErr(err, wantImplicitDeny(notResource.arn, actS3GetObject, objectArn(bucket, "obj")))
	})
}

// S3IAMAccessControl_identity_policy_explicit_deny_wins verifies an explicit
// Deny beats a matching Allow regardless of statement order or of whether
// the two live in the same inline policy document.
func S3IAMAccessControl_identity_policy_explicit_deny_wins(s *S3Conf) error {
	testName := "S3IAMAccessControl_identity_policy_explicit_deny_wins"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return err
		}

		allow := accessStatement{Effect: "Allow", Action: actS3GetObject, Resource: objectsArn(bucket)}
		deny := accessStatement{Effect: "Deny", Action: actS3GetObject, Resource: objectsArn(bucket)}

		cases := []struct {
			name     string
			policies map[string]string
		}{
			{"deny after allow, same document", map[string]string{"p": policyDoc(allow, deny)}},
			{"deny before allow, same document", map[string]string{"p": policyDoc(deny, allow)}},
			{"allow and deny in separate documents", map[string]string{"a": policyDoc(allow), "d": policyDoc(deny)}},
		}
		for _, tc := range cases {
			if err := func() error {
				user, cleanup, err := newS3IAMUser(root, s, tc.policies)
				if err != nil {
					return err
				}
				defer cleanup()

				ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
				_, err = user.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
				cancel()
				return checkApiErr(err, wantExplicitIdentityDeny(user.arn, actS3GetObject, objectArn(bucket, "obj")))
			}(); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// S3IAMAccessControl_multiple_inline_policies_combine verifies separate
// inline policy documents are unioned, so an action allowed by either one is
// allowed overall.
func S3IAMAccessControl_multiple_inline_policies_combine(s *S3Conf) error {
	testName := "S3IAMAccessControl_multiple_inline_policies_combine"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		user, cleanup, err := newS3IAMUser(root, s, map[string]string{
			"reader": policyDoc(accessStatement{Effect: "Allow", Action: actS3GetObject, Resource: objectsArn(bucket)}),
			"writer": policyDoc(accessStatement{Effect: "Allow", Action: actS3PutObject, Resource: objectsArn(bucket)}),
		})
		if err != nil {
			return err
		}
		defer cleanup()

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = user.client.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return fmt.Errorf("expected PutObject to be allowed by the second document: %w", err)
		}
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = user.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return fmt.Errorf("expected GetObject to be allowed by the first document: %w", err)
		}
		return nil
	})
}

// S3IAMAccessControl_bucket_policy_allows_without_identity_policy verifies
// the resource side is independently sufficient too: a bucket policy naming
// the user's access key grants the request with no identity policy at all.
func S3IAMAccessControl_bucket_policy_allows_without_identity_policy(s *S3Conf) error {
	testName := "S3IAMAccessControl_bucket_policy_allows_without_identity_policy"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		user, cleanup, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanup()

		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect: "Allow", Principal: user.conf.awsID, Action: actS3PutObject, Resource: objectsArn(bucket),
		}); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = user.client.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return fmt.Errorf("expected PutObject to be allowed by the bucket policy: %w", err)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = user.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		return checkApiErr(err, wantImplicitDeny(user.arn, actS3GetObject, objectArn(bucket, "obj")))
	})
}

// S3IAMAccessControl_bucket_policy_explicit_deny verifies a bucket-policy
// Deny denies on its own, and reports the resource-based-policy message.
func S3IAMAccessControl_bucket_policy_explicit_deny(s *S3Conf) error {
	testName := "S3IAMAccessControl_bucket_policy_explicit_deny"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		user, cleanup, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanup()

		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect: "Deny", Principal: user.conf.awsID, Action: actS3GetObject, Resource: objectsArn(bucket),
		}); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = user.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		// The resource-based denial names the access key, not the ARN:
		// bucket-policy principals are access-key-based for every backend,
		// so the gateway has no ARN in hand at that point.
		return checkApiErr(err, wantExplicitResourceDeny(user.conf.awsID, actS3GetObject, objectArn(bucket, "obj")))
	})
}

// S3IAMAccessControl_policy_combinations walks the full precedence matrix
// between the identity policy and the bucket policy for one action, checking
// the exact outcome and message for each of the nine combinations that
// matter.
func S3IAMAccessControl_policy_combinations(s *S3Conf) error {
	testName := "S3IAMAccessControl_policy_combinations"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return err
		}

		const (
			silent = "silent"
			allow  = "allow"
			deny   = "deny"
		)
		cases := []struct {
			identity string
			resource string
			// wantErr builds the expected error, or is nil when the request
			// must succeed.
			wantErr func(user *s3IAMPrincipal) s3err.S3Error
		}{
			{identity: silent, resource: silent, wantErr: func(u *s3IAMPrincipal) s3err.S3Error {
				return wantImplicitDeny(u.arn, actS3GetObject, objectArn(bucket, "obj"))
			}},
			{identity: allow, resource: silent},
			{identity: silent, resource: allow},
			{identity: allow, resource: allow},
			{identity: deny, resource: silent, wantErr: func(u *s3IAMPrincipal) s3err.S3Error {
				return wantExplicitIdentityDeny(u.arn, actS3GetObject, objectArn(bucket, "obj"))
			}},
			{identity: deny, resource: allow, wantErr: func(u *s3IAMPrincipal) s3err.S3Error {
				return wantExplicitIdentityDeny(u.arn, actS3GetObject, objectArn(bucket, "obj"))
			}},
			{identity: silent, resource: deny, wantErr: func(u *s3IAMPrincipal) s3err.S3Error {
				return wantExplicitResourceDeny(u.conf.awsID, actS3GetObject, objectArn(bucket, "obj"))
			}},
			{identity: allow, resource: deny, wantErr: func(u *s3IAMPrincipal) s3err.S3Error {
				return wantExplicitResourceDeny(u.conf.awsID, actS3GetObject, objectArn(bucket, "obj"))
			}},
			// A Deny on both sides is reported as the resource-based one:
			// VerifyAccess evaluates the bucket policy first and returns
			// immediately, which also saves an IAM round trip.
			{identity: deny, resource: deny, wantErr: func(u *s3IAMPrincipal) s3err.S3Error {
				return wantExplicitResourceDeny(u.conf.awsID, actS3GetObject, objectArn(bucket, "obj"))
			}},
		}

		for _, tc := range cases {
			if err := func() error {
				policies := map[string]string{}
				if tc.identity != silent {
					effect := "Allow"
					if tc.identity == deny {
						effect = "Deny"
					}
					policies["p"] = policyDoc(accessStatement{
						Effect: effect, Action: actS3GetObject, Resource: objectsArn(bucket),
					})
				}

				user, cleanup, err := newS3IAMUser(root, s, policies)
				if err != nil {
					return err
				}
				defer cleanup()

				if tc.resource == silent {
					if err := deleteBucketPolicyIfAny(s, bucket); err != nil {
						return err
					}
				} else {
					effect := "Allow"
					if tc.resource == deny {
						effect = "Deny"
					}
					if err := putBucketPolicyDoc(s, bucket, bucketStatement{
						Effect: effect, Principal: user.conf.awsID, Action: actS3GetObject, Resource: objectsArn(bucket),
					}); err != nil {
						return err
					}
				}

				ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
				_, err = user.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
				cancel()
				if tc.wantErr == nil {
					if err != nil {
						return fmt.Errorf("expected the request to be allowed: %w", err)
					}
					return nil
				}
				return checkApiErr(err, tc.wantErr(user))
			}(); err != nil {
				return fmt.Errorf("identity=%s resource=%s: %w", tc.identity, tc.resource, err)
			}
		}
		return nil
	})
}

// S3IAMAccessControl_copy_object_requires_both_sides verifies a CopyObject
// is authorized against both its source (GetObject) and its destination
// (PutObject), so a policy granting only one of the two is not enough.
func S3IAMAccessControl_copy_object_requires_both_sides(s *S3Conf) error {
	testName := "S3IAMAccessControl_copy_object_requires_both_sides"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("src")})
		cancel()
		if err != nil {
			return err
		}

		cases := []struct {
			name       string
			action     any
			wantAction string
			wantArn    string
		}{
			{name: "destination only", action: actS3PutObject, wantAction: actS3GetObject, wantArn: objectArn(bucket, "src")},
			{name: "source only", action: actS3GetObject, wantAction: actS3PutObject, wantArn: objectArn(bucket, "dst")},
		}
		for _, tc := range cases {
			if err := func() error {
				user, cleanup, err := newS3IAMUser(root, s, map[string]string{
					"p": policyDoc(accessStatement{Effect: "Allow", Action: tc.action, Resource: objectsArn(bucket)}),
				})
				if err != nil {
					return err
				}
				defer cleanup()

				ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
				_, err = user.client.CopyObject(ctx, &s3.CopyObjectInput{
					Bucket:     &bucket,
					Key:        aws.String("dst"),
					CopySource: aws.String(bucket + "/src"),
				})
				cancel()
				return checkApiErr(err, wantImplicitDeny(user.arn, tc.wantAction, tc.wantArn))
			}(); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}

		// Granting both sides completes the copy.
		user, cleanup, err := newS3IAMUser(root, s, map[string]string{
			"p": policyDoc(accessStatement{
				Effect: "Allow", Action: []string{actS3GetObject, actS3PutObject}, Resource: objectsArn(bucket),
			}),
		})
		if err != nil {
			return err
		}
		defer cleanup()

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		defer cancel()
		if _, err := user.client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        aws.String("dst"),
			CopySource: aws.String(bucket + "/src"),
		}); err != nil {
			return fmt.Errorf("expected CopyObject to be allowed once both sides are granted: %w", err)
		}
		return nil
	})
}

// S3IAMAccessControl_create_bucket verifies s3:CreateBucket is gated by the
// identity policy alone — the bucket doesn't exist yet, so there is no
// bucket policy or ACL to consult — and that the grant is resource-scoped to
// the bucket name.
func S3IAMAccessControl_create_bucket(s *S3Conf) error {
	testName := "S3IAMAccessControl_create_bucket"
	return actionHandlerNoSetup(s, testName, func(_ *s3.Client, _ string) error {
		root := s.GetIAMClient()
		allowedName, otherName := getBucketName(), getBucketName()

		cases := []struct {
			name    string
			policy  func() string
			bucket  string
			wantErr func(user *s3IAMPrincipal, bucket string) s3err.S3Error
		}{
			{
				name:   "no policy denies",
				policy: func() string { return "" },
				bucket: otherName,
				wantErr: func(u *s3IAMPrincipal, b string) s3err.S3Error {
					return wantImplicitDeny(u.arn, actS3CreateBucket, bucketArn(b))
				},
			},
			{
				name: "explicit deny",
				policy: func() string {
					return policyDoc(accessStatement{Effect: "Deny", Action: actS3CreateBucket, Resource: "*"})
				},
				bucket: otherName,
				wantErr: func(u *s3IAMPrincipal, b string) s3err.S3Error {
					return wantExplicitIdentityDeny(u.arn, actS3CreateBucket, bucketArn(b))
				},
			},
			{
				name: "scoped grant allows the named bucket",
				policy: func() string {
					return policyDoc(accessStatement{Effect: "Allow", Action: actS3CreateBucket, Resource: bucketArn(allowedName)})
				},
				bucket: allowedName,
			},
			{
				name: "scoped grant denies another bucket",
				policy: func() string {
					return policyDoc(accessStatement{Effect: "Allow", Action: actS3CreateBucket, Resource: bucketArn(allowedName)})
				},
				bucket: otherName,
				wantErr: func(u *s3IAMPrincipal, b string) s3err.S3Error {
					return wantImplicitDeny(u.arn, actS3CreateBucket, bucketArn(b))
				},
			},
			{
				name: "wildcard grant allows any bucket",
				policy: func() string {
					return policyDoc(accessStatement{Effect: "Allow", Action: actS3CreateBucket, Resource: "arn:aws:s3:::*"})
				},
				bucket: otherName,
			},
		}

		for _, tc := range cases {
			if err := func() error {
				policies := map[string]string{}
				if doc := tc.policy(); doc != "" {
					policies["p"] = doc
				}
				user, cleanup, err := newS3IAMUser(root, s, policies)
				if err != nil {
					return err
				}
				defer cleanup()

				ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
				_, err = user.client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &tc.bucket})
				cancel()

				if tc.wantErr == nil {
					if err != nil {
						return fmt.Errorf("expected CreateBucket to be allowed: %w", err)
					}
					return teardown(s, tc.bucket)
				}
				return checkApiErr(err, tc.wantErr(user, tc.bucket))
			}(); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// S3IAMAccessControl_governance_bypass_sources verifies s3:BypassGovernance
// Retention follows the same precedence as any other action: an Allow from
// either the identity policy or the bucket policy is enough on its own, and
// an explicit Deny from either wins over the other's Allow.
func S3IAMAccessControl_governance_bypass_sources(s *S3Conf) error {
	testName := "S3IAMAccessControl_governance_bypass_sources"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		const (
			silent = "silent"
			allow  = "allow"
			deny   = "deny"
		)
		cases := []struct {
			identity   string
			resource   string
			wantDenied bool
		}{
			{identity: allow, resource: silent},
			{identity: silent, resource: allow},
			{identity: allow, resource: allow},
			{identity: silent, resource: silent, wantDenied: true},
			{identity: deny, resource: allow, wantDenied: true},
			{identity: allow, resource: deny, wantDenied: true},
		}

		for i, tc := range cases {
			if err := func() error {
				key := fmt.Sprintf("locked-%d", i)
				if err := putGovernanceLockedObject(s, bucket, key); err != nil {
					return err
				}

				// Deleting the object always needs s3:DeleteObject as well;
				// only the bypass permission is what varies per case.
				statements := []accessStatement{
					{Effect: "Allow", Action: actS3DeleteObject, Resource: objectsArn(bucket)},
				}
				if tc.identity != silent {
					effect := "Allow"
					if tc.identity == deny {
						effect = "Deny"
					}
					statements = append(statements, accessStatement{
						Effect: effect, Action: actS3BypassGovernance, Resource: objectsArn(bucket),
					})
				}

				user, cleanup, err := newS3IAMUser(root, s, map[string]string{"p": policyDoc(statements...)})
				if err != nil {
					return err
				}
				defer cleanup()

				if tc.resource == silent {
					if err := deleteBucketPolicyIfAny(s, bucket); err != nil {
						return err
					}
				} else {
					effect := "Allow"
					if tc.resource == deny {
						effect = "Deny"
					}
					if err := putBucketPolicyDoc(s, bucket, bucketStatement{
						Effect: effect, Principal: user.conf.awsID,
						Action: actS3BypassGovernance, Resource: objectsArn(bucket),
					}); err != nil {
						return err
					}
				}

				ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
				_, err = user.client.DeleteObject(ctx, &s3.DeleteObjectInput{
					Bucket:                    &bucket,
					Key:                       &key,
					BypassGovernanceRetention: aws.Bool(true),
				})
				cancel()

				if !tc.wantDenied {
					if err != nil {
						return fmt.Errorf("expected the governance-bypassing delete to be allowed: %w", err)
					}
					return nil
				}
				if err == nil {
					return fmt.Errorf("expected the governance-bypassing delete to be denied")
				}
				// Whichever way bypass was denied, the error names the
				// bypass action specifically — not the generic
				// "object protected by object lock" message, which the
				// gateway reserves for a request with no bypass header.
				if err := checkSdkApiErr(err, "AccessDenied"); err != nil {
					return err
				}
				if !strings.Contains(err.Error(), actS3BypassGovernance) {
					return fmt.Errorf("expected the denial to name %s, got: %v", actS3BypassGovernance, err)
				}
				return nil
			}(); err != nil {
				return fmt.Errorf("identity=%s resource=%s: %w", tc.identity, tc.resource, err)
			}
		}

		// Release the keys still under retention: the cases that expected a
		// denial left theirs locked, and teardown cannot remove those.
		var locked []objToDelete
		for i, tc := range cases {
			if tc.wantDenied {
				locked = append(locked, objToDelete{key: fmt.Sprintf("locked-%d", i)})
			}
		}
		return cleanupLockedObjects(s.GetClient(), bucket, locked)
	}, withLock())
}

// S3IAMAccessControl_governance_without_bypass_header verifies the bypass
// permission is irrelevant when the request doesn't ask to bypass: the
// object stays protected, and the error is the generic object-lock one.
func S3IAMAccessControl_governance_without_bypass_header(s *S3Conf) error {
	testName := "S3IAMAccessControl_governance_without_bypass_header"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		const key = "locked"
		if err := putGovernanceLockedObject(s, bucket, key); err != nil {
			return err
		}

		user, cleanup, err := newS3IAMUser(root, s, map[string]string{
			"p": policyDoc(accessStatement{
				Effect: "Allow", Action: []string{actS3DeleteObject, actS3BypassGovernance},
				Resource: objectsArn(bucket),
			}),
		})
		if err != nil {
			return err
		}
		defer cleanup()

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = user.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: aws.String(key)})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
			return err
		}

		return cleanupLockedObjects(s.GetClient(), bucket, []objToDelete{{key: key}})
	}, withLock())
}

// S3IAMAccessControl_compliance_mode_not_bypassable verifies COMPLIANCE
// retention is absolute: no identity or bucket policy can grant a bypass of
// it, unlike GOVERNANCE.
func S3IAMAccessControl_compliance_mode_not_bypassable(s *S3Conf) error {
	testName := "S3IAMAccessControl_compliance_mode_not_bypassable"
	return s3IAMComplianceActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		const key = "compliance-locked"
		retainUntil := time.Now().UTC().Add(time.Hour)
		if _, err := putObjectWithData(0, &s3.PutObjectInput{
			Bucket:                    &bucket,
			Key:                       aws.String(key),
			ObjectLockMode:            types.ObjectLockModeCompliance,
			ObjectLockRetainUntilDate: &retainUntil,
		}, s.GetClient()); err != nil {
			return err
		}

		user, cleanup, err := newS3IAMUser(root, s, map[string]string{
			"p": policyDoc(accessStatement{
				Effect: "Allow", Action: []string{actS3DeleteObject, actS3BypassGovernance},
				Resource: objectsArn(bucket),
			}),
		})
		if err != nil {
			return err
		}
		defer cleanup()

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = user.client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:                    &bucket,
			Key:                       aws.String(key),
			BypassGovernanceRetention: aws.Bool(true),
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked))
	})
}

// S3IAMAccessControl_delete_objects_authorizes_each_key verifies the batch
// DeleteObjects path authorizes s3:DeleteObject against each object's own
// ARN, the way real AWS does — a policy naming only "bucket/*" is
// sufficient — and that it supports partial success: verified live against
// real AWS (niksis02, account 792168558830), a key outside the granted
// prefix denies only that key, reported in the response's Errors list, while
// every other key in the same batch is still deleted and reported in
// Deleted. Both lists preserve the order the keys were requested in.
func S3IAMAccessControl_delete_objects_authorizes_each_key(s *S3Conf) error {
	testName := "S3IAMAccessControl_delete_objects_authorizes_each_key"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		for _, key := range []string{"allowed/one", "allowed/two", "denied/three"} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr(key)})
			cancel()
			if err != nil {
				return err
			}
		}

		user, cleanup, err := newS3IAMUser(root, s, map[string]string{
			"p": policyDoc(accessStatement{
				Effect: "Allow", Action: actS3DeleteObject,
				Resource: objectArn(bucket, "allowed/*"),
			}),
		})
		if err != nil {
			return err
		}
		defer cleanup()

		// A key outside the grant, mixed in with two that aren't, denies
		// only that key — the request as a whole succeeds.
		out, err := deleteObjectsWithBypass(user.client, bucket, "allowed/one", "denied/three", "allowed/two")
		if err != nil {
			return fmt.Errorf("expected DeleteObjects to succeed with a per-object denial, not fail outright: %w", err)
		}
		wantErr := wantImplicitDeny(user.arn, actS3DeleteObject, objectArn(bucket, "denied/three"))
		if len(out.Errors) != 1 {
			return fmt.Errorf("expected exactly 1 per-object error, got %+v", out.Errors)
		}
		if err := checkDeleteObjectsErr(out.Errors[0], "denied/three", wantErr); err != nil {
			return err
		}
		wantDeleted := []string{"allowed/one", "allowed/two"}
		if err := checkDeletedKeysInOrder(out.Deleted, wantDeleted); err != nil {
			return err
		}

		// Every key inside the grant succeeds, with no bucket-ARN grant
		// anywhere, and no per-object errors.
		out, err = deleteObjectsWithBypass(user.client, bucket, "allowed/one")
		if err != nil {
			return fmt.Errorf("expected DeleteObjects to be allowed by an object-ARN-only grant: %w", err)
		}
		if len(out.Errors) != 0 {
			return fmt.Errorf("expected no per-object errors, got %+v", out.Errors)
		}
		return nil
	})
}

// S3IAMAccessControl_delete_objects_version_needs_separate_permission
// verifies that naming a VersionId in a DeleteObjects entry is authorized
// against s3:DeleteObjectVersion, a distinct permission from the
// s3:DeleteObject a keyed (unversioned) delete needs — verified live against
// real AWS (niksis02, account 792168558830): a policy granting only
// s3:DeleteObject denies the versioned deletes in a batch while its keyed
// deletes in the same batch still succeed, each independently, matching the
// single-object DELETE path's existing behavior for the same distinction.
//
// The denial happens at authorization, before the backend ever resolves the
// named version, so this doesn't need a real object version (and the
// gateway this test group runs against has no --versioning-dir configured
// to produce one): an arbitrary VersionId is enough to exercise the
// s3:DeleteObjectVersion check and prove the batch still partially
// succeeds.
func S3IAMAccessControl_delete_objects_version_needs_separate_permission(s *S3Conf) error {
	testName := "S3IAMAccessControl_delete_objects_version_needs_separate_permission"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return err
		}

		user, cleanup, err := newS3IAMUser(root, s, map[string]string{
			"p": policyDoc(accessStatement{
				Effect: "Allow", Action: actS3DeleteObject,
				Resource: objectsArn(bucket),
			}),
		})
		if err != nil {
			return err
		}
		defer cleanup()

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		defer cancel()
		out, err := user.client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: &bucket,
			Delete: &types.Delete{
				Objects: []types.ObjectIdentifier{
					{Key: aws.String("obj")},
					{Key: aws.String("versioned-obj"), VersionId: aws.String("some-version-id")},
				},
			},
		})
		if err != nil {
			return fmt.Errorf("expected DeleteObjects to succeed with a per-object denial, not fail outright: %w", err)
		}

		wantErr := wantImplicitDeny(user.arn, actS3DeleteObjectVersion, objectArn(bucket, "versioned-obj"))
		if len(out.Errors) != 1 {
			return fmt.Errorf("expected exactly 1 per-object error, got %+v", out.Errors)
		}
		if err := checkDeleteObjectsErr(out.Errors[0], "versioned-obj", wantErr); err != nil {
			return err
		}
		if len(out.Deleted) != 1 || out.Deleted[0].Key == nil || *out.Deleted[0].Key != "obj" {
			return fmt.Errorf("expected the keyed delete to succeed, got %+v", out.Deleted)
		}
		return nil
	})
}

// S3IAMAccessControl_governance_bypass_delete_objects verifies the batch
// DeleteObjects path enforces the bypass permission per object, the same way
// the single-object delete does.
func S3IAMAccessControl_governance_bypass_delete_objects(s *S3Conf) error {
	testName := "S3IAMAccessControl_governance_bypass_delete_objects"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		const key = "locked"
		if err := putGovernanceLockedObject(s, bucket, key); err != nil {
			return err
		}

		withoutBypass, cleanupWithout, err := newS3IAMUser(root, s, map[string]string{
			"p": policyDoc(accessStatement{Effect: "Allow", Action: actS3DeleteObject, Resource: objectsArn(bucket)}),
		})
		if err != nil {
			return err
		}
		defer cleanupWithout()

		out, err := deleteObjectsWithBypass(withoutBypass.client, bucket, key)
		if err != nil {
			return fmt.Errorf("expected DeleteObjects to succeed with a per-object denial, not fail outright: %w", err)
		}
		if err := checkDeleteObjectsErr(out.Errors[0], key,
			wantImplicitDeny(withoutBypass.arn, actS3BypassGovernance, objectArn(bucket, key))); err != nil {
			return fmt.Errorf("expected DeleteObjects to be denied without the bypass permission: %w", err)
		}

		withBypass, cleanupWith, err := newS3IAMUser(root, s, map[string]string{
			"p": policyDoc(accessStatement{
				Effect: "Allow", Action: []string{actS3DeleteObject, actS3BypassGovernance},
				Resource: objectsArn(bucket),
			}),
		})
		if err != nil {
			return err
		}
		defer cleanupWith()

		out, err = deleteObjectsWithBypass(withBypass.client, bucket, key)
		if err != nil {
			return fmt.Errorf("expected DeleteObjects to be allowed with the bypass permission: %w", err)
		}
		if len(out.Errors) != 0 {
			return fmt.Errorf("expected no per-object errors, got %+v", out.Errors)
		}
		return nil
	}, withLock())
}

// S3IAMAccessControl_retention_extension_needs_no_bypass verifies the
// direction of the change is what decides whether a bypass is needed:
// pushing a retention date further out only strengthens the lock, so it
// needs nothing beyond s3:PutObjectRetention — in either mode. Shortening
// is the case that needs a bypass, covered by the test below.
func S3IAMAccessControl_retention_extension_needs_no_bypass(s *S3Conf) error {
	testName := "S3IAMAccessControl_retention_extension_needs_no_bypass"
	return s3IAMComplianceActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		user, cleanup, err := newS3IAMUser(root, s, map[string]string{
			"p": policyDoc(accessStatement{
				Effect: "Allow", Action: "s3:PutObjectRetention", Resource: objectsArn(bucket),
			}),
		})
		if err != nil {
			return err
		}
		defer cleanup()

		modes := []types.ObjectLockRetentionMode{
			types.ObjectLockRetentionModeGovernance,
			types.ObjectLockRetentionModeCompliance,
		}
		for _, mode := range modes {
			key := "extend-" + strings.ToLower(string(mode))
			retainUntil := time.Now().UTC().Add(time.Minute)
			if _, err := putObjectWithData(0, &s3.PutObjectInput{
				Bucket:                    &bucket,
				Key:                       &key,
				ObjectLockMode:            types.ObjectLockMode(mode),
				ObjectLockRetainUntilDate: &retainUntil,
			}, s.GetClient()); err != nil {
				return err
			}

			extended := retainUntil.Add(time.Minute)
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := user.client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
				Bucket:    &bucket,
				Key:       &key,
				Retention: &types.ObjectLockRetention{Mode: mode, RetainUntilDate: &extended},
			})
			cancel()
			if err != nil {
				return fmt.Errorf("%s: expected extending a retention to need no bypass: %w", mode, err)
			}
		}
		return nil
	})
}

// S3IAMAccessControl_governance_bypass_put_object_retention verifies the
// bypass permission gates weakening a GOVERNANCE retention through
// PutObjectRetention — here by switching its mode to COMPLIANCE, which the
// gateway only permits with the bypass header.
func S3IAMAccessControl_governance_bypass_put_object_retention(s *S3Conf) error {
	testName := "S3IAMAccessControl_governance_bypass_put_object_retention"
	return s3IAMComplianceActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		retainUntil := time.Now().UTC().Add(time.Hour)
		toCompliance := func(client *s3.Client, key string) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			defer cancel()
			_, err := client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
				Bucket:                    &bucket,
				Key:                       aws.String(key),
				BypassGovernanceRetention: aws.Bool(true),
				Retention: &types.ObjectLockRetention{
					Mode:            types.ObjectLockRetentionModeCompliance,
					RetainUntilDate: &retainUntil,
				},
			})
			return err
		}

		withoutBypass, cleanupWithout, err := newS3IAMUser(root, s, map[string]string{
			"p": policyDoc(accessStatement{Effect: "Allow", Action: "s3:PutObjectRetention", Resource: objectsArn(bucket)}),
		})
		if err != nil {
			return err
		}
		defer cleanupWithout()

		if err := putGovernanceLockedObject(s, bucket, "no-bypass"); err != nil {
			return err
		}
		if err := toCompliance(withoutBypass.client, "no-bypass"); err == nil {
			return fmt.Errorf("expected the retention mode change to be denied without the bypass permission")
		}

		withBypass, cleanupWith, err := newS3IAMUser(root, s, map[string]string{
			"p": policyDoc(accessStatement{
				Effect: "Allow", Action: []string{"s3:PutObjectRetention", actS3BypassGovernance},
				Resource: objectsArn(bucket),
			}),
		})
		if err != nil {
			return err
		}
		defer cleanupWith()

		if err := putGovernanceLockedObject(s, bucket, "with-bypass"); err != nil {
			return err
		}
		if err := toCompliance(withBypass.client, "with-bypass"); err != nil {
			return fmt.Errorf("expected the retention mode change to be allowed with the bypass permission: %w", err)
		}
		return nil
	})
}

// S3IAMAccessControl_retention_shortening_needs_bypass verifies that moving
// a retention date earlier — weakening the lock without changing its mode —
// needs both the bypass header and s3:BypassGovernanceRetention for
// GOVERNANCE, and is refused outright for COMPLIANCE however the caller
// asks.
//
// Extending is the control: it only ever strengthens the lock, so it needs
// neither, in either mode.
func S3IAMAccessControl_retention_shortening_needs_bypass(s *S3Conf) error {
	testName := "S3IAMAccessControl_retention_shortening_needs_bypass"
	return s3IAMComplianceActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		withBypass, cleanupWith, err := newS3IAMUser(root, s, map[string]string{
			"p": policyDoc(accessStatement{
				Effect: "Allow", Action: []string{"s3:PutObjectRetention", actS3BypassGovernance},
				Resource: objectsArn(bucket),
			}),
		})
		if err != nil {
			return err
		}
		defer cleanupWith()

		withoutBypass, cleanupWithout, err := newS3IAMUser(root, s, map[string]string{
			"p": policyDoc(accessStatement{
				Effect: "Allow", Action: "s3:PutObjectRetention", Resource: objectsArn(bucket),
			}),
		})
		if err != nil {
			return err
		}
		defer cleanupWithout()

		cases := []struct {
			name       string
			mode       types.ObjectLockRetentionMode
			user       *s3IAMPrincipal
			shorten    bool
			sendHeader bool
			// wantErr is nil when the change must be allowed.
			wantErr func(user *s3IAMPrincipal, key string) s3err.S3Error
		}{
			{
				name: "governance extended needs nothing",
				mode: types.ObjectLockRetentionModeGovernance, user: withoutBypass,
			},
			{
				name: "compliance extended needs nothing",
				mode: types.ObjectLockRetentionModeCompliance, user: withoutBypass,
			},
			{
				// No header at all: the object is simply reported as locked,
				// with no mention of a permission the caller never invoked.
				name: "governance shortened without the bypass header",
				mode: types.ObjectLockRetentionModeGovernance, user: withBypass, shorten: true,
				wantErr: func(*s3IAMPrincipal, string) s3err.S3Error {
					return s3err.GetAPIError(s3err.ErrObjectLocked)
				},
			},
			{
				// Header sent but the permission missing: the denial names
				// the permission that was needed.
				name: "governance shortened without the bypass permission",
				mode: types.ObjectLockRetentionModeGovernance, user: withoutBypass, shorten: true, sendHeader: true,
				wantErr: func(u *s3IAMPrincipal, key string) s3err.S3Error {
					return wantImplicitDeny(u.arn, actS3BypassGovernance, objectArn(bucket, key))
				},
			},
			{
				name: "governance shortened with header and permission",
				mode: types.ObjectLockRetentionModeGovernance, user: withBypass, shorten: true, sendHeader: true,
			},
			{
				// COMPLIANCE is absolute: neither the header nor the
				// permission can weaken it.
				name: "compliance shortened even with header and permission",
				mode: types.ObjectLockRetentionModeCompliance, user: withBypass, shorten: true, sendHeader: true,
				wantErr: func(*s3IAMPrincipal, string) s3err.S3Error {
					return s3err.GetAPIError(s3err.ErrObjectLocked)
				},
			},
		}

		for i, tc := range cases {
			if err := func() error {
				key := fmt.Sprintf("retained-%d", i)
				original := time.Now().UTC().Add(time.Hour)
				if _, err := putObjectWithData(0, &s3.PutObjectInput{
					Bucket:                    &bucket,
					Key:                       &key,
					ObjectLockMode:            types.ObjectLockMode(tc.mode),
					ObjectLockRetainUntilDate: &original,
				}, s.GetClient()); err != nil {
					return err
				}

				want := original.Add(time.Minute)
				if tc.shorten {
					want = original.Add(-30 * time.Second)
				}

				input := &s3.PutObjectRetentionInput{
					Bucket: &bucket,
					Key:    &key,
					Retention: &types.ObjectLockRetention{
						Mode:            tc.mode,
						RetainUntilDate: &want,
					},
				}
				if tc.sendHeader {
					input.BypassGovernanceRetention = aws.Bool(true)
				}

				ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
				_, err := tc.user.client.PutObjectRetention(ctx, input)
				cancel()

				if tc.wantErr == nil {
					if err != nil {
						return fmt.Errorf("expected the retention change to be allowed: %w", err)
					}
					return nil
				}
				return checkApiErr(err, tc.wantErr(tc.user, key))
			}(); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// S3IAMAccessControl_condition_source_ip verifies aws:SourceIp is populated
// from the real request, both as a grant that matches and as one that
// doesn't.
func S3IAMAccessControl_condition_source_ip(s *S3Conf) error {
	testName := "S3IAMAccessControl_condition_source_ip"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return err
		}
		callerIP, err := callerSourceIP(s)
		if err != nil {
			return err
		}

		return runS3ConditionCases(root, s, bucket, "obj", []s3ConditionCase{
			{
				name:        "matching source ip",
				condition:   cond("IpAddress", "aws:SourceIp", callerIP+"/32"),
				wantAllowed: true,
			},
			{
				name:      "non-matching source ip",
				condition: cond("IpAddress", "aws:SourceIp", "203.0.113.0/24"),
			},
			{
				name:        "negated operator with a matching key",
				condition:   cond("NotIpAddress", "aws:SourceIp", "203.0.113.0/24"),
				wantAllowed: true,
			},
		})
	})
}

// S3IAMAccessControl_condition_negated_operator_needs_context is a
// regression test for a fail-open bug: the gateway used to send no condition
// context at all for S3 requests, and iamapi/policy treats a negated
// operator over an absent key as vacuously true — so a Deny guarded by
// NotIpAddress silently never fired, and an Allow guarded by one fired for
// everybody. With the context populated, a NotIpAddress Deny naming the
// caller's own address must actually deny.
func S3IAMAccessControl_condition_negated_operator_needs_context(s *S3Conf) error {
	testName := "S3IAMAccessControl_condition_negated_operator_needs_context"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return err
		}
		callerIP, err := callerSourceIP(s)
		if err != nil {
			return err
		}

		user, cleanup, err := newS3IAMUser(root, s, map[string]string{
			"p": policyDoc(
				accessStatement{Effect: "Allow", Action: actS3GetObject, Resource: objectsArn(bucket)},
				accessStatement{
					Effect: "Deny", Action: actS3GetObject, Resource: objectsArn(bucket),
					Condition: cond("NotIpAddress", "aws:SourceIp", "203.0.113.0/24"),
				},
			),
		})
		if err != nil {
			return err
		}
		defer cleanup()

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = user.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err := checkApiErr(err, wantExplicitIdentityDeny(user.arn, actS3GetObject, objectArn(bucket, "obj"))); err != nil {
			return fmt.Errorf("a NotIpAddress Deny must fire when the caller's address (%s) is outside the named range: %w", callerIP, err)
		}
		return nil
	})
}

// S3IAMAccessControl_condition_request_keys covers the remaining condition
// keys the gateway derives from the request itself.
func S3IAMAccessControl_condition_request_keys(s *S3Conf) error {
	testName := "S3IAMAccessControl_condition_request_keys"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return err
		}

		// The integration harness always drives the gateway over plain
		// HTTP or TLS, never both in one run, so aws:SecureTransport is
		// asserted against whichever this run actually uses rather than
		// hardcoded.
		secure := strings.HasPrefix(s.endpoint, "https")

		return runS3ConditionCases(root, s, bucket, "obj", []s3ConditionCase{
			{
				name:        "secure transport matches the endpoint scheme",
				condition:   cond("Bool", "aws:SecureTransport", fmt.Sprintf("%t", secure)),
				wantAllowed: true,
			},
			{
				name:      "secure transport mismatch",
				condition: cond("Bool", "aws:SecureTransport", fmt.Sprintf("%t", !secure)),
			},
			{
				name:        "current time inside a broad window",
				condition:   cond("DateLessThan", "aws:CurrentTime", "2999-01-01T00:00:00Z"),
				wantAllowed: true,
			},
			{
				name:      "current time outside the window",
				condition: cond("DateLessThan", "aws:CurrentTime", "2000-01-01T00:00:00Z"),
			},
			{
				name:        "epoch time inside a broad window",
				condition:   cond("NumericGreaterThan", "aws:EpochTime", "1000000000"),
				wantAllowed: true,
			},
			{
				name:        "user agent is present",
				condition:   cond("Null", "aws:UserAgent", "false"),
				wantAllowed: true,
			},
		})
	})
}

// S3IAMAccessControl_condition_identity_keys verifies the identity-derived
// condition keys — which the IAM service fills in, since the gateway never
// learns who an access key belongs to — reach policy evaluation.
func S3IAMAccessControl_condition_identity_keys(s *S3Conf) error {
	testName := "S3IAMAccessControl_condition_identity_keys"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return err
		}

		user, cleanup, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanup()

		cases := []struct {
			name        string
			condition   func() []byte
			wantAllowed bool
		}{
			{
				name:        "principal arn matches",
				condition:   func() []byte { return cond("StringEquals", "aws:PrincipalArn", user.arn) },
				wantAllowed: true,
			},
			{
				name: "principal arn mismatch",
				condition: func() []byte {
					return cond("StringEquals", "aws:PrincipalArn", "arn:aws:iam::000000000000:user/somebodyelse")
				},
			},
			{
				name:        "username matches",
				condition:   func() []byte { return cond("StringEquals", "aws:username", user.name) },
				wantAllowed: true,
			},
			{
				name:        "principal type is User",
				condition:   func() []byte { return cond("StringEquals", "aws:PrincipalType", "User") },
				wantAllowed: true,
			},
			{
				name:        "principal account matches",
				condition:   func() []byte { return cond("StringEquals", "aws:PrincipalAccount", testAccountID) },
				wantAllowed: true,
			},
		}

		for _, tc := range cases {
			if err := func() error {
				if err := putS3IAMUserPolicy(root, user, "p", policyDoc(accessStatement{
					Effect: "Allow", Action: actS3GetObject, Resource: objectsArn(bucket),
					Condition: tc.condition(),
				})); err != nil {
					return err
				}

				ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
				_, err = user.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
				cancel()
				if tc.wantAllowed {
					if err != nil {
						return fmt.Errorf("expected the request to be allowed: %w", err)
					}
					return nil
				}
				return checkApiErr(err, wantImplicitDeny(user.arn, actS3GetObject, objectArn(bucket, "obj")))
			}(); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// S3IAMAccessControl_condition_principal_tag verifies aws:PrincipalTag/<key>
// is populated from the calling user's own IAM tags, and that a tag the user
// doesn't carry is treated as absent rather than as an empty match.
func S3IAMAccessControl_condition_principal_tag(s *S3Conf) error {
	testName := "S3IAMAccessControl_condition_principal_tag"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return err
		}

		userName := newIAMUserName()
		createOut, err := createIAMUser(root, &iam.CreateUserInput{
			UserName: aws.String(userName),
			Tags:     []iamtypes.Tag{{Key: aws.String("team"), Value: aws.String("storage")}},
		})
		if err != nil {
			return err
		}
		defer deleteS3IAMUser(root, userName)

		keyOut, err := createIAMAccessKey(root, &iam.CreateAccessKeyInput{UserName: aws.String(userName)})
		if err != nil {
			return err
		}
		conf := *s
		conf.awsID = aws.ToString(keyOut.AccessKey.AccessKeyId)
		conf.awsSecret = aws.ToString(keyOut.AccessKey.SecretAccessKey)
		user := &s3IAMPrincipal{name: userName, arn: aws.ToString(createOut.User.Arn), conf: conf, client: conf.GetClient()}

		cases := []struct {
			name        string
			condition   []byte
			wantAllowed bool
		}{
			{name: "matching tag value", condition: cond("StringEquals", "aws:PrincipalTag/team", "storage"), wantAllowed: true},
			{name: "wrong tag value", condition: cond("StringEquals", "aws:PrincipalTag/team", "networking")},
			{name: "tag the user does not carry", condition: cond("StringEquals", "aws:PrincipalTag/other", "anything")},
			{name: "absent tag reported by Null", condition: cond("Null", "aws:PrincipalTag/other", "true"), wantAllowed: true},
		}
		for _, tc := range cases {
			if err := func() error {
				if err := putS3IAMUserPolicy(root, user, "p", policyDoc(accessStatement{
					Effect: "Allow", Action: actS3GetObject, Resource: objectsArn(bucket),
					Condition: tc.condition,
				})); err != nil {
					return err
				}

				ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
				_, err = user.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
				cancel()
				if tc.wantAllowed {
					if err != nil {
						return fmt.Errorf("expected the request to be allowed: %w", err)
					}
					return nil
				}
				return checkApiErr(err, wantImplicitDeny(user.arn, actS3GetObject, objectArn(bucket, "obj")))
			}(); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// S3IAMAccessControl_condition_on_deny_statement verifies a Condition
// attached to a Deny narrows that Deny — when the condition doesn't hold,
// the statement contributes nothing and an unconditional Allow still stands.
func S3IAMAccessControl_condition_on_deny_statement(s *S3Conf) error {
	testName := "S3IAMAccessControl_condition_on_deny_statement"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return err
		}
		callerIP, err := callerSourceIP(s)
		if err != nil {
			return err
		}

		user, cleanup, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanup()

		allow := accessStatement{Effect: "Allow", Action: actS3GetObject, Resource: objectsArn(bucket)}

		// Deny conditioned on an address the caller does not have: it must
		// not fire, leaving the Allow in force.
		if err := putS3IAMUserPolicy(root, user, "p", policyDoc(allow, accessStatement{
			Effect: "Deny", Action: actS3GetObject, Resource: objectsArn(bucket),
			Condition: cond("IpAddress", "aws:SourceIp", "203.0.113.0/24"),
		})); err != nil {
			return err
		}
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = user.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return fmt.Errorf("a Deny whose condition does not hold must not block an unconditional Allow: %w", err)
		}

		// Deny conditioned on the caller's real address: it must fire and
		// override the Allow.
		if err := putS3IAMUserPolicy(root, user, "p", policyDoc(allow, accessStatement{
			Effect: "Deny", Action: actS3GetObject, Resource: objectsArn(bucket),
			Condition: cond("IpAddress", "aws:SourceIp", callerIP+"/32"),
		})); err != nil {
			return err
		}
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = user.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		return checkApiErr(err, wantExplicitIdentityDeny(user.arn, actS3GetObject, objectArn(bucket, "obj")))
	})
}

// S3IAMAccessControl_condition_multiple_keys_anded verifies multiple keys
// within one Condition block must all hold, while multiple values for one
// key are ORed.
func S3IAMAccessControl_condition_multiple_keys_anded(s *S3Conf) error {
	testName := "S3IAMAccessControl_condition_multiple_keys_anded"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return err
		}
		callerIP, err := callerSourceIP(s)
		if err != nil {
			return err
		}

		user, cleanup, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanup()

		cases := []struct {
			name        string
			condition   []byte
			wantAllowed bool
		}{
			{
				name: "both keys hold",
				condition: condAll(map[string]map[string]any{
					"IpAddress":    {"aws:SourceIp": callerIP + "/32"},
					"StringEquals": {"aws:username": user.name},
				}),
				wantAllowed: true,
			},
			{
				name: "one key fails",
				condition: condAll(map[string]map[string]any{
					"IpAddress":    {"aws:SourceIp": callerIP + "/32"},
					"StringEquals": {"aws:username": "somebodyelse"},
				}),
			},
			{
				name:        "one of several values for a key matches",
				condition:   cond("StringEquals", "aws:username", []string{"somebodyelse", user.name}),
				wantAllowed: true,
			},
		}
		for _, tc := range cases {
			if err := func() error {
				if err := putS3IAMUserPolicy(root, user, "p", policyDoc(accessStatement{
					Effect: "Allow", Action: actS3GetObject, Resource: objectsArn(bucket),
					Condition: tc.condition,
				})); err != nil {
					return err
				}

				ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
				_, err = user.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
				cancel()
				if tc.wantAllowed {
					if err != nil {
						return fmt.Errorf("expected the request to be allowed: %w", err)
					}
					return nil
				}
				return checkApiErr(err, wantImplicitDeny(user.arn, actS3GetObject, objectArn(bucket, "obj")))
			}(); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// S3IAMAccessControl_inactive_and_deleted_credentials verifies the gateway
// stops accepting an access key as soon as the IAM service stops vouching
// for it — whether it was deactivated, deleted, or its user was removed.
func S3IAMAccessControl_inactive_and_deleted_credentials(s *S3Conf) error {
	testName := "S3IAMAccessControl_inactive_and_deleted_credentials"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		grantAll := map[string]string{
			"p": policyDoc(accessStatement{
				Effect: "Allow", Action: "s3:*",
				Resource: []string{bucketArn(bucket), objectsArn(bucket)},
			}),
		}

		cases := []struct {
			name    string
			disable func(user *s3IAMPrincipal) error
		}{
			{
				name: "deactivated access key",
				disable: func(user *s3IAMPrincipal) error {
					ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
					defer cancel()
					_, err := root.UpdateAccessKey(ctx, &iam.UpdateAccessKeyInput{
						UserName:    aws.String(user.name),
						AccessKeyId: aws.String(user.conf.awsID),
						Status:      iamtypes.StatusTypeInactive,
					})
					return err
				},
			},
			{
				name: "deleted access key",
				disable: func(user *s3IAMPrincipal) error {
					return deleteIAMAccessKey(root, user.name, user.conf.awsID)
				},
			},
			{
				name: "deleted user",
				disable: func(user *s3IAMPrincipal) error {
					return deleteS3IAMUser(root, user.name)
				},
			},
		}

		for _, tc := range cases {
			if err := func() error {
				user, cleanup, err := newS3IAMUser(root, s, grantAll)
				if err != nil {
					return err
				}
				defer cleanup()

				ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
				_, err = user.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &bucket})
				cancel()
				if err != nil {
					return fmt.Errorf("expected the credential to work before being disabled: %w", err)
				}

				if err := tc.disable(user); err != nil {
					return err
				}

				ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
				_, err = user.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &bucket})
				cancel()
				return checkApiErr(err, s3err.GetInvalidAccessKeyIdErr(user.conf.awsID))
			}(); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// S3IAMAccessControl_bucket_policy_unknown_principal_rejected verifies
// PutBucketPolicy validates its principals against the IAM service, so a
// policy naming somebody who doesn't exist is rejected instead of being
// stored as a statement that can never match.
func S3IAMAccessControl_bucket_policy_unknown_principal_rejected(s *S3Conf) error {
	testName := "S3IAMAccessControl_bucket_policy_unknown_principal_rejected"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect: "Allow", Principal: "AKIADOESNOTEXIST", Action: actS3GetObject, Resource: objectsArn(bucket),
		})
		return checkApiErr(err, s3err.APIError{
			Code:           "MalformedPolicy",
			Description:    "Invalid principal in policy",
			HTTPStatusCode: 400,
		})
	})
}
