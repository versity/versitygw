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

// wantInvalidPrincipal is the error PutBucketPolicy reports for a Principal
// that names nothing this IAM service knows.
func wantInvalidPrincipal() s3err.APIError {
	return getMalformedPolicyError("Invalid principal in policy")
}

// S3IAMPrincipal_accepted_forms covers every Principal form PutBucketPolicy
// accepts: the wildcard in both its shapes, an existing user's ARN, an
// existing role's ARN, an assumed-role ARN naming a session of an existing
// role, the account root ARN, the bare account id, and a list mixing them.
func S3IAMPrincipal_accepted_forms(s *S3Conf) error {
	testName := "S3IAMPrincipal_accepted_forms"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		user, cleanup, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanup()

		roleName, roleCleanup, err := newS3IAMBareRole(root)
		if err != nil {
			return err
		}
		defer roleCleanup()

		cases := []struct {
			name      string
			principal any
		}{
			{"wildcard string", "*"},
			{"wildcard aws struct", map[string]any{"AWS": "*"}},
			{"user arn", user.arn},
			{"user arn in an aws struct", map[string]any{"AWS": user.arn}},
			{"role arn", roleArnFor(roleName)},
			// The session name is never validated: it names a session that
			// need not have been minted when the policy is written.
			{"assumed role arn", assumedRoleArnFor(roleName, "any-session-name")},
			{"account root arn", accountArn()},
			{"bare account id", testAccountID},
			{"list of arns", []string{user.arn, roleArnFor(roleName)}},
			{"aws struct with a list", map[string]any{"AWS": []string{user.arn, accountArn()}}},
		}

		for _, tc := range cases {
			err := putBucketPolicyDoc(s, bucket, bucketStatement{
				Effect: "Allow", Principal: tc.principal, Action: actS3GetObject, Resource: objectsArn(bucket),
			})
			if err != nil {
				return fmt.Errorf("%s: expected the policy to be accepted: %w", tc.name, err)
			}
		}
		return nil
	})
}

// S3IAMPrincipal_rejected_forms covers what PutBucketPolicy refuses to
// store, all of it with the same MalformedPolicy error real S3 reports. The
// two that matter most are an access key id — what every other IAM backend
// names principals by, and what this one no longer accepts — and any
// wildcard inside an ARN: only a whole Principal of "*" is a wildcard, so
// there is no pattern form of a principal at all.
func S3IAMPrincipal_rejected_forms(s *S3Conf) error {
	testName := "S3IAMPrincipal_rejected_forms"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		user, cleanup, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanup()

		roleName, roleCleanup, err := newS3IAMBareRole(root)
		if err != nil {
			return err
		}
		defer roleCleanup()

		cases := []struct {
			name      string
			principal any
		}{
			{"access key id", user.conf.awsID},
			{"bare user name", user.name},
			{"non existing user arn", userArnFor("no-such-user")},
			{"non existing role arn", roleArnFor("no-such-role")},
			{"assumed role arn of a non existing role", assumedRoleArnFor("no-such-role", "sess")},
			{"assumed role arn missing the session name", "arn:aws:sts::" + testAccountID + ":assumed-role/" + roleName},
			// A session name is not checked for existence, but it must be
			// one that could exist: a form no session can ever carry would
			// be stored as a statement that can never match.
			{"wildcard session name", assumedRoleArnFor(roleName, "*")},
			{"session name too short", assumedRoleArnFor(roleName, "s")},
			{"session name with a space", assumedRoleArnFor(roleName, "sess name")},
			{"session name too long", assumedRoleArnFor(roleName, strings.Repeat("s", 65))},
			{"wrong case role name in an assumed role arn", assumedRoleArnFor(strings.ToUpper(roleName), "sess")},
			{"wildcard within an arn", userArnFor("*")},
			{"wildcard suffix within an arn", userArnFor(user.name[:4] + "*")},
			{"wildcard account in an arn", "arn:aws:iam::*:user/" + user.name},
			{"wrong case resource type", "arn:aws:iam::" + testAccountID + ":USER/" + user.name},
			{"wrong case user name", userArnFor(strings.ToUpper(user.name))},
			{"trailing slash after the user name", user.arn + "/"},
			{"leading whitespace", " " + user.arn},
			{"trailing whitespace", user.arn + " "},
			{"another account", "arn:aws:iam::111111111111:root"},
			{"another account user", "arn:aws:iam::111111111111:user/" + user.name},
			{"account id of another account", "111111111111"},
			{"region bearing arn", "arn:aws:iam:us-east-1:" + testAccountID + ":root"},
			{"wrong partition", "arn:aws-cn:iam::" + testAccountID + ":root"},
			{"group arn", "arn:aws:iam::" + testAccountID + ":group/admins"},
			{"non iam arn", bucketArn(bucket)},
			{"not an arn", "not-an-arn"},
			{"wildcard mixed with an arn", []string{"*", user.arn}},
			{"list with one unresolvable entry", []string{user.arn, userArnFor("no-such-user")}},
		}

		for _, tc := range cases {
			err := putBucketPolicyDoc(s, bucket, bucketStatement{
				Effect: "Allow", Principal: tc.principal, Action: actS3GetObject, Resource: objectsArn(bucket),
			})
			if err := checkApiErr(err, wantInvalidPrincipal()); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// S3IAMPrincipal_empty_forms covers the Principal shapes that carry no
// principal at all. They are rejected the same way they were before
// principals were ARNs — the check is on the element's shape, not on what it
// names — so this pins that the ARN change left them alone.
func S3IAMPrincipal_empty_forms(s *S3Conf) error {
	testName := "S3IAMPrincipal_empty_forms"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		cases := []struct {
			name      string
			principal any
		}{
			{"empty string", ""},
			{"empty list", []string{}},
			{"empty aws struct", map[string]any{"AWS": ""}},
			{"empty aws list", map[string]any{"AWS": []string{}}},
		}

		for _, tc := range cases {
			err := putBucketPolicyDoc(s, bucket, bucketStatement{
				Effect: "Allow", Principal: tc.principal, Action: actS3GetObject, Resource: objectsArn(bucket),
			})
			if err := checkApiErr(err, wantInvalidPrincipal()); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// S3IAMPrincipal_user_arn_names_only_that_user verifies a user ARN grants
// the user it names and nobody else — neither another user, nor a caller
// named by the access key that used to be the principal form.
func S3IAMPrincipal_user_arn_names_only_that_user(s *S3Conf) error {
	testName := "S3IAMPrincipal_user_arn_names_only_that_user"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		if err := putObjectAsRoot(s, bucket, "obj"); err != nil {
			return err
		}

		granted, cleanupGranted, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanupGranted()

		other, cleanupOther, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanupOther()

		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect: "Allow", Principal: granted.arn, Action: actS3GetObject, Resource: objectsArn(bucket),
		}); err != nil {
			return err
		}

		if err := getObjectAllowed(granted, bucket, "obj"); err != nil {
			return err
		}
		return getObjectDenied(other, bucket, "obj", wantImplicitDeny(other.arn, actS3GetObject, objectArn(bucket, "obj")))
	})
}

// S3IAMPrincipal_pathed_user_arn verifies a user's IAM path is part of the
// ARN naming it: only the full-path form resolves at all, and it matches the
// user it names.
func S3IAMPrincipal_pathed_user_arn(s *S3Conf) error {
	testName := "S3IAMPrincipal_pathed_user_arn"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		if err := putObjectAsRoot(s, bucket, "obj"); err != nil {
			return err
		}

		userName := newIAMUserName()
		createOut, err := createIAMUser(root, &iam.CreateUserInput{
			UserName: aws.String(userName),
			Path:     aws.String("/team/sub/"),
		})
		if err != nil {
			return err
		}
		defer deleteS3IAMUser(root, userName)

		user, err := s3IAMUserWithNewKey(root, s, userName, aws.ToString(createOut.User.Arn))
		if err != nil {
			return err
		}

		// The path-less form names no identity, so it never reaches
		// storage.
		err = putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect: "Allow", Principal: userArnFor(userName), Action: actS3GetObject, Resource: objectsArn(bucket),
		})
		if err := checkApiErr(err, wantInvalidPrincipal()); err != nil {
			return fmt.Errorf("path-less user arn: %w", err)
		}

		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect: "Allow", Principal: user.arn, Action: actS3GetObject, Resource: objectsArn(bucket),
		}); err != nil {
			return fmt.Errorf("full user arn: %w", err)
		}
		return getObjectAllowed(user, bucket, "obj")
	})
}

// S3IAMPrincipal_account_delegates_but_does_not_grant is the asymmetry the
// account-level principal forms carry: naming the account in an Allow
// delegates to the account's own IAM rather than granting anything, so a
// user with no identity policy is still denied and the same user with one is
// allowed. Naming it in a Deny delegates nothing and denies outright.
func S3IAMPrincipal_account_delegates_but_does_not_grant(s *S3Conf) error {
	testName := "S3IAMPrincipal_account_delegates_but_does_not_grant"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		if err := putObjectAsRoot(s, bucket, "obj"); err != nil {
			return err
		}

		// Both account forms are the same principal and must behave
		// identically.
		for _, principal := range []string{accountArn(), testAccountID} {
			if err := func() error {
				user, cleanup, err := newS3IAMUser(root, s, nil)
				if err != nil {
					return err
				}
				defer cleanup()

				if err := putBucketPolicyDoc(s, bucket, bucketStatement{
					Effect: "Allow", Principal: principal, Action: actS3GetObject, Resource: objectsArn(bucket),
				}); err != nil {
					return err
				}

				// Delegation grants nothing on its own.
				if err := getObjectDenied(user, bucket, "obj",
					wantImplicitDeny(user.arn, actS3GetObject, objectArn(bucket, "obj"))); err != nil {
					return fmt.Errorf("allow without an identity policy: %w", err)
				}

				// ...and the identity policy it delegates to does.
				if err := putS3IAMUserPolicy(root, user, "p", policyDoc(accessStatement{
					Effect: "Allow", Action: actS3GetObject, Resource: objectsArn(bucket),
				})); err != nil {
					return err
				}
				if err := getObjectAllowed(user, bucket, "obj"); err != nil {
					return fmt.Errorf("allow with an identity policy: %w", err)
				}

				// A Deny naming the account is not a delegation: it denies
				// the same user its own identity policy just allowed.
				if err := putBucketPolicyDoc(s, bucket, bucketStatement{
					Effect: "Deny", Principal: principal, Action: actS3GetObject, Resource: objectsArn(bucket),
				}); err != nil {
					return err
				}
				return getObjectDenied(user, bucket, "obj",
					wantExplicitResourceDeny(user.arn, actS3GetObject, objectArn(bucket, "obj")))
			}(); err != nil {
				return fmt.Errorf("principal %q: %w", principal, err)
			}
		}
		return nil
	})
}

// S3IAMPrincipal_role_arn_does_not_match_a_user verifies a role ARN names
// sessions of that role and nothing else: a long-term user is not covered by
// it, however the role is otherwise configured. The session side — that a
// role ARN does match every session of the role — needs a real OIDC token
// and lives in the s3-iam-session group.
func S3IAMPrincipal_role_arn_does_not_match_a_user(s *S3Conf) error {
	testName := "S3IAMPrincipal_role_arn_does_not_match_a_user"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		if err := putObjectAsRoot(s, bucket, "obj"); err != nil {
			return err
		}

		user, cleanup, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanup()

		roleName, roleCleanup, err := newS3IAMBareRole(root)
		if err != nil {
			return err
		}
		defer roleCleanup()

		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect: "Allow", Principal: roleArnFor(roleName), Action: actS3GetObject, Resource: objectsArn(bucket),
		}); err != nil {
			return err
		}
		return getObjectDenied(user, bucket, "obj",
			wantImplicitDeny(user.arn, actS3GetObject, objectArn(bucket, "obj")))
	})
}

// S3IAMPrincipal_deleted_user_arn_rejected verifies the write-time check
// tracks the IAM service rather than a snapshot of it: an ARN that resolved
// when a policy naming it was written no longer resolves once the user is
// gone, so the same document can no longer be stored.
func S3IAMPrincipal_deleted_user_arn_rejected(s *S3Conf) error {
	testName := "S3IAMPrincipal_deleted_user_arn_rejected"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		user, cleanup, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		// The test deletes the user itself; cleanup tolerates that and
		// still runs if an earlier step fails first.
		defer cleanup()

		statement := bucketStatement{
			Effect: "Allow", Principal: user.arn, Action: actS3GetObject, Resource: objectsArn(bucket),
		}
		if err := putBucketPolicyDoc(s, bucket, statement); err != nil {
			return fmt.Errorf("expected a live user's arn to be accepted: %w", err)
		}

		if err := deleteS3IAMUser(root, user.name); err != nil {
			return err
		}

		err = putBucketPolicyDoc(s, bucket, statement)
		return checkApiErr(err, wantInvalidPrincipal())
	})
}

// S3IAMPrincipal_wildcard_grants_everyone verifies "*" still names every
// caller, the one principal form that does not have to resolve to anything.
func S3IAMPrincipal_wildcard_grants_everyone(s *S3Conf) error {
	testName := "S3IAMPrincipal_wildcard_grants_everyone"
	return s3IAMActionHandler(s, testName, func(root *iam.Client, bucket string) error {
		if err := putObjectAsRoot(s, bucket, "obj"); err != nil {
			return err
		}

		user, cleanup, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanup()

		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect: "Allow", Principal: "*", Action: actS3GetObject, Resource: objectsArn(bucket),
		}); err != nil {
			return err
		}
		return getObjectAllowed(user, bucket, "obj")
	})
}

// newS3IAMBareRole creates a role nothing ever assumes: these tests only
// need one to exist, so that a Principal naming it resolves. Its trust
// policy names the account rather than an OIDC provider, which keeps the
// fixture free of the whole web-identity setup a session needs — those tests
// live in the s3-iam-session group.
func newS3IAMBareRole(root *iam.Client) (roleName string, cleanup func(), err error) {
	roleName = newIAMRoleName()
	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` +
		accountArn() + `"},"Action":"sts:AssumeRole"}]}`

	if _, err := createIAMRole(root, &iam.CreateRoleInput{
		RoleName:                 aws.String(roleName),
		AssumeRolePolicyDocument: aws.String(trust),
	}); err != nil {
		return "", nil, fmt.Errorf("create role: %w", err)
	}
	return roleName, func() { deleteIAMRole(root, roleName) }, nil
}

// s3IAMUserWithNewKey mints an access key for an already-created user and
// returns it as an s3IAMPrincipal, for the tests that need a user
// newS3IAMUser cannot create — one with an IAM path, for instance.
func s3IAMUserWithNewKey(root *iam.Client, s *S3Conf, userName, userArn string) (*s3IAMPrincipal, error) {
	keyOut, err := createIAMAccessKey(root, &iam.CreateAccessKeyInput{UserName: aws.String(userName)})
	if err != nil {
		return nil, fmt.Errorf("create access key: %w", err)
	}

	conf := *s
	conf.awsID = aws.ToString(keyOut.AccessKey.AccessKeyId)
	conf.awsSecret = aws.ToString(keyOut.AccessKey.SecretAccessKey)

	return &s3IAMPrincipal{name: userName, arn: userArn, conf: conf, client: conf.GetClient()}, nil
}

// putObjectAsRoot puts an object the test's principals then read, so what a
// test measures is their authorization rather than their ability to set the
// scene.
func putObjectAsRoot(s *S3Conf, bucket, key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()

	_, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &key})
	return err
}

// getObjectAllowed and getObjectDenied assert the two outcomes a principal
// test cares about, so each case reads as the one line it is.
func getObjectAllowed(p *s3IAMPrincipal, bucket, key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()

	if _, err := p.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &key}); err != nil {
		return fmt.Errorf("expected GetObject to be allowed for %v: %w", p.arn, err)
	}
	return nil
}

func getObjectDenied(p *s3IAMPrincipal, bucket, key string, want s3err.S3Error) error {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()

	_, err := p.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &key})
	return checkApiErr(err, want)
}
