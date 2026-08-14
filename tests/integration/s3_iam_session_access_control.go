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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/s3err"
)

// S3IAMSession_role_policy_allows verifies a session inherits the assumed
// role's inline policies, and that they are sufficient on their own with no
// bucket policy in play.
func S3IAMSession_role_policy_allows(s *S3Conf) error {
	testName := "S3IAMSession_role_policy_allows"
	return s3IAMSessionActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		session, cleanup, err := newGitHubSession(root, s, map[string]string{
			"p": policyDoc(accessStatement{
				Effect: "Allow", Action: "s3:*",
				Resource: []string{bucketArn(bucket), objectsArn(bucket)},
			}),
		}, "")
		if err != nil {
			return err
		}
		defer cleanup()

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = session.client.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return fmt.Errorf("expected PutObject to be allowed by the role policy: %w", err)
		}
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = session.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return fmt.Errorf("expected GetObject to be allowed by the role policy: %w", err)
		}
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = session.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &bucket})
		cancel()
		if err != nil {
			return fmt.Errorf("expected ListObjects to be allowed by the role policy: %w", err)
		}
		return nil
	})
}

// S3IAMSession_role_without_policy_denied verifies a session with no role
// policy and no bucket policy is denied, and that the denial names the
// assumed-role session ARN rather than the temporary access key.
func S3IAMSession_role_without_policy_denied(s *S3Conf) error {
	testName := "S3IAMSession_role_without_policy_denied"
	return s3IAMSessionActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		session, cleanup, err := newGitHubSession(root, s, nil, "")
		if err != nil {
			return err
		}
		defer cleanup()

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = session.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		return checkApiErr(err, wantImplicitDeny(session.arn, actS3GetObject, objectArn(bucket, "obj")))
	})
}

// S3IAMSession_role_policy_explicit_deny_wins verifies an explicit Deny in
// the role's own policy overrides its Allow, exactly as for a long-term
// user.
func S3IAMSession_role_policy_explicit_deny_wins(s *S3Conf) error {
	testName := "S3IAMSession_role_policy_explicit_deny_wins"
	return s3IAMSessionActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		session, cleanup, err := newGitHubSession(root, s, map[string]string{
			"p": policyDoc(
				accessStatement{Effect: "Allow", Action: "s3:*", Resource: objectsArn(bucket)},
				accessStatement{Effect: "Deny", Action: actS3GetObject, Resource: objectsArn(bucket)},
			),
		}, "")
		if err != nil {
			return err
		}
		defer cleanup()

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = session.client.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return fmt.Errorf("expected PutObject to still be allowed: %w", err)
		}
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = session.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		return checkApiErr(err, wantExplicitIdentityDeny(session.arn, actS3GetObject, objectArn(bucket, "obj")))
	})
}

// S3IAMSession_role_policy_resource_scoped verifies a role policy's Resource
// pattern scopes what the session may touch.
func S3IAMSession_role_policy_resource_scoped(s *S3Conf) error {
	testName := "S3IAMSession_role_policy_resource_scoped"
	return s3IAMSessionActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		session, cleanup, err := newGitHubSession(root, s, map[string]string{
			"p": policyDoc(accessStatement{
				Effect: "Allow", Action: "s3:*", Resource: objectArn(bucket, "allowed/*"),
			}),
		}, "")
		if err != nil {
			return err
		}
		defer cleanup()

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = session.client.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("allowed/obj")})
		cancel()
		if err != nil {
			return fmt.Errorf("expected the in-scope key to be allowed: %w", err)
		}
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = session.client.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("denied/obj")})
		cancel()
		return checkApiErr(err, wantImplicitDeny(session.arn, actS3PutObject, objectArn(bucket, "denied/obj")))
	})
}

// S3IAMSession_session_policy_narrows_role verifies a session policy
// restricts what the role would otherwise permit — the primary reason to
// pass one.
func S3IAMSession_session_policy_narrows_role(s *S3Conf) error {
	testName := "S3IAMSession_session_policy_narrows_role"
	return s3IAMSessionActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return err
		}

		session, cleanup, err := newGitHubSession(root, s, map[string]string{
			"p": policyDoc(accessStatement{
				Effect: "Allow", Action: "s3:*",
				Resource: []string{bucketArn(bucket), objectsArn(bucket)},
			}),
		}, policyDoc(accessStatement{
			Effect: "Allow", Action: actS3GetObject, Resource: objectsArn(bucket),
		}))
		if err != nil {
			return err
		}
		defer cleanup()

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = session.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return fmt.Errorf("expected GetObject to be allowed by both layers: %w", err)
		}
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = session.client.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("other")})
		cancel()
		return checkApiErr(err, wantImplicitDeny(session.arn, actS3PutObject, objectArn(bucket, "other")))
	})
}

// S3IAMSession_session_policy_cannot_widen_role verifies a session policy
// can only ever subtract: granting more than the role has does not add
// anything.
func S3IAMSession_session_policy_cannot_widen_role(s *S3Conf) error {
	testName := "S3IAMSession_session_policy_cannot_widen_role"
	return s3IAMSessionActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return err
		}

		session, cleanup, err := newGitHubSession(root, s, map[string]string{
			"p": policyDoc(accessStatement{
				Effect: "Allow", Action: actS3GetObject, Resource: objectsArn(bucket),
			}),
		}, policyDoc(accessStatement{
			Effect: "Allow", Action: "s3:*", Resource: "*",
		}))
		if err != nil {
			return err
		}
		defer cleanup()

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = session.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return fmt.Errorf("expected GetObject to be allowed by both layers: %w", err)
		}
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = session.client.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("other")})
		cancel()
		return checkApiErr(err, wantImplicitDeny(session.arn, actS3PutObject, objectArn(bucket, "other")))
	})
}

// S3IAMSession_session_policy_explicit_deny_overrides_role verifies an
// explicit Deny in the session policy beats the role's Allow.
func S3IAMSession_session_policy_explicit_deny_overrides_role(s *S3Conf) error {
	testName := "S3IAMSession_session_policy_explicit_deny_overrides_role"
	return s3IAMSessionActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return err
		}

		session, cleanup, err := newGitHubSession(root, s, map[string]string{
			"p": policyDoc(accessStatement{
				Effect: "Allow", Action: "s3:*",
				Resource: []string{bucketArn(bucket), objectsArn(bucket)},
			}),
		}, policyDoc(
			accessStatement{Effect: "Allow", Action: "s3:*", Resource: "*"},
			accessStatement{Effect: "Deny", Action: actS3GetObject, Resource: objectsArn(bucket)},
		))
		if err != nil {
			return err
		}
		defer cleanup()

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = session.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		return checkApiErr(err, wantExplicitIdentityDeny(session.arn, actS3GetObject, objectArn(bucket, "obj")))
	})
}

// S3IAMSession_role_policy_deny_overrides_session_allow verifies the reverse
// direction: an explicit Deny in the role's policy is not escapable by a
// permissive session policy.
func S3IAMSession_role_policy_deny_overrides_session_allow(s *S3Conf) error {
	testName := "S3IAMSession_role_policy_deny_overrides_session_allow"
	return s3IAMSessionActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return err
		}

		session, cleanup, err := newGitHubSession(root, s, map[string]string{
			"p": policyDoc(
				accessStatement{Effect: "Allow", Action: "s3:*", Resource: objectsArn(bucket)},
				accessStatement{Effect: "Deny", Action: actS3GetObject, Resource: objectsArn(bucket)},
			),
		}, policyDoc(accessStatement{Effect: "Allow", Action: "s3:*", Resource: "*"}))
		if err != nil {
			return err
		}
		defer cleanup()

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = session.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		return checkApiErr(err, wantExplicitIdentityDeny(session.arn, actS3GetObject, objectArn(bucket, "obj")))
	})
}

// S3IAMSession_session_policy_without_role_policy_denied verifies a session
// policy alone grants nothing: with the role carrying no policy and no
// bucket policy in play, there is nothing for it to narrow.
func S3IAMSession_session_policy_without_role_policy_denied(s *S3Conf) error {
	testName := "S3IAMSession_session_policy_without_role_policy_denied"
	return s3IAMSessionActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		session, cleanup, err := newGitHubSession(root, s, nil,
			policyDoc(accessStatement{Effect: "Allow", Action: "s3:*", Resource: "*"}))
		if err != nil {
			return err
		}
		defer cleanup()

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = session.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		return checkApiErr(err, wantImplicitDeny(session.arn, actS3GetObject, objectArn(bucket, "obj")))
	})
}

// S3IAMSession_bucket_policy_allows_without_role_policy verifies the bucket
// policy is independently sufficient for a session too, exactly as it is for
// a long-term user.
//
// The bucket policy names "*" rather than the session: this gateway matches
// bucket-policy principals against the caller's access key, and a session's
// key is ephemeral, so auth.CheckIfAccountsExist rejects one as a principal
// outright rather than let a policy come to reference a principal that stops
// existing. See bucketStatement.
func S3IAMSession_bucket_policy_allows_without_role_policy(s *S3Conf) error {
	testName := "S3IAMSession_bucket_policy_allows_without_role_policy"
	return s3IAMSessionActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return err
		}
		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect: "Allow", Principal: "*", Action: actS3GetObject, Resource: objectsArn(bucket),
		}); err != nil {
			return err
		}

		session, cleanup, err := newGitHubSession(root, s, nil, "")
		if err != nil {
			return err
		}
		defer cleanup()

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = session.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return fmt.Errorf("expected GetObject to be allowed by the bucket policy: %w", err)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = session.client.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("other")})
		cancel()
		return checkApiErr(err, wantImplicitDeny(session.arn, actS3PutObject, objectArn(bucket, "other")))
	})
}

// S3IAMSession_session_policy_filters_bucket_policy_grant is the property
// that distinguishes a session policy from an ordinary identity policy: it
// filters *everything* the session can do, including permissions that came
// from the bucket policy rather than from the role.
//
// Verified against real AWS with a role carrying no identity policy at all,
// a bucket policy granting it both s3:GetObject and s3:PutObject, and a
// session policy allowing only s3:GetObject — the Get succeeds and the Put
// is denied.
func S3IAMSession_session_policy_filters_bucket_policy_grant(s *S3Conf) error {
	testName := "S3IAMSession_session_policy_filters_bucket_policy_grant"
	return s3IAMSessionActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return err
		}
		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect: "Allow", Principal: "*",
			Action: []string{actS3GetObject, actS3PutObject}, Resource: objectsArn(bucket),
		}); err != nil {
			return err
		}

		session, cleanup, err := newGitHubSession(root, s, nil,
			policyDoc(accessStatement{Effect: "Allow", Action: actS3GetObject, Resource: objectsArn(bucket)}))
		if err != nil {
			return err
		}
		defer cleanup()

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = session.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return fmt.Errorf("expected GetObject to be allowed by the bucket policy within the session policy: %w", err)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = session.client.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("other")})
		cancel()
		return checkApiErr(err, wantImplicitDeny(session.arn, actS3PutObject, objectArn(bucket, "other")))
	})
}

// S3IAMSession_bucket_policy_deny_overrides_role_allow verifies a
// bucket-policy Deny beats the role's Allow for a session, and reports the
// resource-based-policy message.
func S3IAMSession_bucket_policy_deny_overrides_role_allow(s *S3Conf) error {
	testName := "S3IAMSession_bucket_policy_deny_overrides_role_allow"
	return s3IAMSessionActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return err
		}
		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect: "Deny", Principal: "*", Action: actS3GetObject, Resource: objectsArn(bucket),
		}); err != nil {
			return err
		}

		session, cleanup, err := newGitHubSession(root, s, map[string]string{
			"p": policyDoc(accessStatement{Effect: "Allow", Action: "s3:*", Resource: objectsArn(bucket)}),
		}, "")
		if err != nil {
			return err
		}
		defer cleanup()

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = session.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		// A resource-based denial names the raw access key: bucket-policy
		// principals are access-key-based for every backend, so no ARN is in
		// hand at that point.
		return checkApiErr(err, wantExplicitResourceDeny(session.conf.awsID, actS3GetObject, objectArn(bucket, "obj")))
	})
}

// S3IAMSession_missing_and_wrong_security_token verifies the two ways a
// session credential can be presented wrongly, each with the error real S3
// returns for it.
func S3IAMSession_missing_and_wrong_security_token(s *S3Conf) error {
	testName := "S3IAMSession_missing_and_wrong_security_token"
	return s3IAMSessionActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		session, cleanup, err := newGitHubSession(root, s, map[string]string{
			"p": policyDoc(accessStatement{Effect: "Allow", Action: "s3:*", Resource: objectsArn(bucket)}),
		}, "")
		if err != nil {
			return err
		}
		defer cleanup()

		// No token at all: with nothing to resolve the temporary access key
		// against, it simply does not name any identity.
		noToken := s3ClientWithSessionCreds(s, session.conf.awsID, session.conf.awsSecret, "")
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = noToken.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err := checkApiErr(err, s3err.GetInvalidAccessKeyIdErr(session.conf.awsID)); err != nil {
			return fmt.Errorf("missing security token: %w", err)
		}

		// A token that doesn't match the session it names.
		wrongToken := s3ClientWithSessionCreds(s, session.conf.awsID, session.conf.awsSecret, "not-the-real-session-token")
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = wrongToken.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidToken)); err != nil {
			return fmt.Errorf("wrong security token: %w", err)
		}
		return nil
	})
}

// S3IAMSession_presigned_url_with_session_credentials verifies a presigned
// URL signed with temporary credentials works: the security token rides in
// the query string, where it is part of the signed canonical request.
func S3IAMSession_presigned_url_with_session_credentials(s *S3Conf) error {
	testName := "S3IAMSession_presigned_url_with_session_credentials"
	return s3IAMSessionActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return err
		}

		session, cleanup, err := newGitHubSession(root, s, map[string]string{
			"p": policyDoc(accessStatement{Effect: "Allow", Action: actS3GetObject, Resource: objectsArn(bucket)}),
		}, "")
		if err != nil {
			return err
		}
		defer cleanup()

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		presigned, err := s3.NewPresignClient(session.client).PresignGetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket, Key: aws.String("obj"),
		})
		cancel()
		if err != nil {
			return fmt.Errorf("presign: %w", err)
		}
		if !strings.Contains(presigned.URL, "X-Amz-Security-Token") {
			return fmt.Errorf("expected the presigned URL to carry X-Amz-Security-Token")
		}

		resp, err := s.httpClient.Get(presigned.URL)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("expected the presigned request to succeed, got status %d", resp.StatusCode)
		}
		return nil
	})
}

// S3IAMSession_deleted_role_denies verifies a session outlives its role's
// deletion as a credential — it still authenticates — but loses every
// permission the role gave it.
func S3IAMSession_deleted_role_denies(s *S3Conf) error {
	testName := "S3IAMSession_deleted_role_denies"
	return s3IAMSessionActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return err
		}

		session, cleanup, err := newGitHubSession(root, s, map[string]string{
			"p": policyDoc(accessStatement{Effect: "Allow", Action: "s3:*", Resource: objectsArn(bucket)}),
		}, "")
		if err != nil {
			return err
		}
		defer cleanup()

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = session.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return fmt.Errorf("expected GetObject to be allowed before the role is deleted: %w", err)
		}

		if err := deleteIAMRoleAndPolicies(root, session.name); err != nil {
			return fmt.Errorf("delete role: %w", err)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = session.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		return checkApiErr(err, wantImplicitDeny(session.arn, actS3GetObject, objectArn(bucket, "obj")))
	})
}

// S3IAMSession_create_bucket_via_role_policy verifies s3:CreateBucket is
// grantable to a session by its role policy, and denied without it.
func S3IAMSession_create_bucket_via_role_policy(s *S3Conf) error {
	testName := "S3IAMSession_create_bucket_via_role_policy"
	// The skip is checked before actionHandlerNoSetup rather than inside it,
	// so a skipped run doesn't also report itself as a pass.
	if _, ok := gitHubOIDCToken(); !ok {
		skipF("%v: %v", testName, gitHubOIDCSkipReason)
		return nil
	}

	return actionHandlerNoSetup(s, testName, func(_ *s3.Client, _ string) error {
		root := s.GetIAMClient()
		allowed, denied := getBucketName(), getBucketName()

		session, cleanup, err := newGitHubSession(root, s, map[string]string{
			"p": policyDoc(accessStatement{
				Effect: "Allow", Action: actS3CreateBucket, Resource: bucketArn(allowed),
			}),
		}, "")
		if err != nil {
			return err
		}
		defer cleanup()

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = session.client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &allowed})
		cancel()
		if err != nil {
			return fmt.Errorf("expected CreateBucket to be allowed for the granted name: %w", err)
		}
		defer teardown(s, allowed)

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = session.client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &denied})
		cancel()
		return checkApiErr(err, wantImplicitDeny(session.arn, actS3CreateBucket, bucketArn(denied)))
	})
}

// S3IAMSession_governance_bypass_via_role_policy verifies a session can be
// granted s3:BypassGovernanceRetention through its role, and that a session
// policy withholding it takes it away again.
func S3IAMSession_governance_bypass_via_role_policy(s *S3Conf) error {
	testName := "S3IAMSession_governance_bypass_via_role_policy"
	return s3IAMSessionActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		grantAll := map[string]string{
			"p": policyDoc(accessStatement{
				Effect: "Allow", Action: []string{actS3DeleteObject, actS3BypassGovernance},
				Resource: objectsArn(bucket),
			}),
		}

		// Role grants the bypass, session policy withholds it: denied.
		withheld, cleanupWithheld, err := newGitHubSession(root, s, grantAll,
			policyDoc(accessStatement{Effect: "Allow", Action: actS3DeleteObject, Resource: objectsArn(bucket)}))
		if err != nil {
			return err
		}
		defer cleanupWithheld()

		if err := putGovernanceLockedObject(s, bucket, "locked-withheld"); err != nil {
			return err
		}
		if err := deleteObjectBypassingGovernance(withheld.client, bucket, "locked-withheld"); err == nil {
			return fmt.Errorf("expected the delete to be denied when the session policy withholds the bypass permission")
		}

		// Role grants it and no session policy narrows it: allowed.
		granted, cleanupGranted, err := newGitHubSession(root, s, grantAll, "")
		if err != nil {
			return err
		}
		defer cleanupGranted()

		if err := putGovernanceLockedObject(s, bucket, "locked-granted"); err != nil {
			return err
		}
		if err := deleteObjectBypassingGovernance(granted.client, bucket, "locked-granted"); err != nil {
			return fmt.Errorf("expected the delete to be allowed by the role's bypass grant: %w", err)
		}
		return nil
	}, withLock())
}

// S3IAMSession_delete_objects_authorizes_each_key verifies the per-key
// authorization of a batch delete applies to a session's role policy too.
func S3IAMSession_delete_objects_authorizes_each_key(s *S3Conf) error {
	testName := "S3IAMSession_delete_objects_authorizes_each_key"
	return s3IAMSessionActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		for _, key := range []string{"allowed/one", "denied/two"} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr(key)})
			cancel()
			if err != nil {
				return err
			}
		}

		session, cleanup, err := newGitHubSession(root, s, map[string]string{
			"p": policyDoc(accessStatement{
				Effect: "Allow", Action: actS3DeleteObject, Resource: objectArn(bucket, "allowed/*"),
			}),
		}, "")
		if err != nil {
			return err
		}
		defer cleanup()

		out, err := deleteObjectsWithBypass(session.client, bucket, "allowed/one", "denied/two")
		if err != nil {
			return fmt.Errorf("expected DeleteObjects to succeed with a per-object denial, not fail outright: %w", err)
		}
		if len(out.Errors) != 1 {
			return fmt.Errorf("expected exactly 1 per-object error, got %+v", out.Errors)
		}
		if err := checkDeleteObjectsErr(out.Errors[0], "denied/two", wantImplicitDeny(session.arn, actS3DeleteObject, objectArn(bucket, "denied/two"))); err != nil {
			return err
		}

		if _, err := deleteObjectsWithBypass(session.client, bucket, "allowed/one"); err != nil {
			return fmt.Errorf("expected the in-scope key to be deletable: %w", err)
		}
		return nil
	})
}

// S3IAMSession_condition_identity_keys verifies the identity-derived
// condition keys describe the *session*, not the underlying role: aws:userid
// carries the role id and session name, and aws:PrincipalArn the
// assumed-role ARN.
func S3IAMSession_condition_identity_keys(s *S3Conf) error {
	testName := "S3IAMSession_condition_identity_keys"
	return s3IAMSessionActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		if err != nil {
			return err
		}

		cases := []struct {
			name        string
			condition   func(session *s3IAMPrincipal) []byte
			wantAllowed bool
		}{
			{
				name:        "principal arn matches the assumed-role session",
				condition:   func(p *s3IAMPrincipal) []byte { return cond("StringEquals", "aws:PrincipalArn", p.arn) },
				wantAllowed: true,
			},
			{
				name:        "principal type is AssumedRole",
				condition:   func(p *s3IAMPrincipal) []byte { return cond("StringEquals", "aws:PrincipalType", "AssumedRole") },
				wantAllowed: true,
			},
			{
				name:        "userid ends with the session name",
				condition:   func(p *s3IAMPrincipal) []byte { return cond("StringLike", "aws:userid", "*:"+sessionNameFor(p)) },
				wantAllowed: true,
			},
			{
				name: "principal arn mismatch",
				condition: func(p *s3IAMPrincipal) []byte {
					return cond("StringEquals", "aws:PrincipalArn", "arn:aws:sts::000000000000:assumed-role/other/other")
				},
			},
			{
				name:      "aws:username is absent for a session",
				condition: func(p *s3IAMPrincipal) []byte { return cond("Null", "aws:username", "false") },
			},
		}

		for _, tc := range cases {
			if err := func() error {
				session, cleanup, err := newGitHubSession(root, s, nil, "")
				if err != nil {
					return err
				}
				defer cleanup()

				if _, err := putIAMRolePolicy(root, &iam.PutRolePolicyInput{
					RoleName:   aws.String(session.name),
					PolicyName: aws.String("p"),
					PolicyDocument: aws.String(policyDoc(accessStatement{
						Effect: "Allow", Action: actS3GetObject, Resource: objectsArn(bucket),
						Condition: tc.condition(session),
					})),
				}); err != nil {
					return err
				}

				ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
				_, err = session.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
				cancel()
				if tc.wantAllowed {
					if err != nil {
						return fmt.Errorf("expected the request to be allowed: %w", err)
					}
					return nil
				}
				return checkApiErr(err, wantImplicitDeny(session.arn, actS3GetObject, objectArn(bucket, "obj")))
			}(); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// S3IAMSession_get_caller_identity_matches_s3_principal verifies STS and the
// S3 data plane agree on who the session is: the ARN GetCallerIdentity
// reports is the one an S3 denial names.
func S3IAMSession_get_caller_identity_matches_s3_principal(s *S3Conf) error {
	testName := "S3IAMSession_get_caller_identity_matches_s3_principal"
	return s3IAMSessionActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		session, cleanup, err := newGitHubSession(root, s, nil, "")
		if err != nil {
			return err
		}
		defer cleanup()

		callerOut, err := getCallerIdentityWithSessionCreds(*s, session.conf.awsID, session.conf.awsSecret, session.sessionToken)
		if err != nil {
			return fmt.Errorf("GetCallerIdentity: %w", err)
		}
		if aws.ToString(callerOut.Arn) != session.arn {
			return fmt.Errorf("GetCallerIdentity reported Arn %q, want %q", aws.ToString(callerOut.Arn), session.arn)
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = session.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("obj")})
		cancel()
		return checkApiErr(err, wantImplicitDeny(session.arn, actS3GetObject, objectArn(bucket, "obj")))
	})
}
