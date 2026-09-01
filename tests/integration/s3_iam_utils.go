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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/versity/versitygw/s3err"
)

const (
	actS3GetObject           = "s3:GetObject"
	actS3PutObject           = "s3:PutObject"
	actS3DeleteObject        = "s3:DeleteObject"
	actS3DeleteObjectVersion = "s3:DeleteObjectVersion"
	actS3ListBucket          = "s3:ListBucket"
	actS3CreateBucket        = "s3:CreateBucket"
	actS3ListAllMyBuckets    = "s3:ListAllMyBuckets"
	actS3BypassGovernance    = "s3:BypassGovernanceRetention"
)

const (
	// githubOIDCIssuerURL is GitHub Actions' own OIDC token issuer: a real,
	// publicly reachable HTTPS endpoint with a CA-issued certificate.
	githubOIDCIssuerURL = "https://token.actions.githubusercontent.com"

	// githubOIDCTestAudience is deliberately distinct from GitHub's default
	// audience (which is the caller's own server URL). If this org ever
	// configures a real cloud-provider role trusting
	// token.actions.githubusercontent.com for this repo (e.g. for
	// publishing/deploys), a leaked test token must not be replayable
	// against that unrelated trust relationship - binding the throwaway
	// role's trust policy to this audience (instead of GitHub's default)
	// is what prevents that.
	githubOIDCTestAudience = "versitygw-integration-tests"
)

// s3IAMPrincipal is an identity that can make S3 requests: an IAM user with
// a long-term access key, or an assumed-role session with temporary
// credentials. Tests assert against arn when checking a denial message,
// since the gateway names the principal by ARN once a PolicyEvaluator
// resolves it.
type s3IAMPrincipal struct {
	// name is the IAM user name or, for a session, the role name.
	name string
	arn  string
	// conf is a copy of the suite's S3Conf carrying this principal's
	// credentials, so tests can build additional clients (presign, STS)
	// beyond the plain s3 one.
	conf   S3Conf
	client *s3.Client
	// sessionToken is set only for an assumed-role session, for the tests
	// that need to build a differently-credentialed client from the same
	// session (a presigned URL, an STS call, a deliberately wrong token).
	sessionToken string
}

// s3IAMActionHandler is actionHandler for the S3+IAM groups: it runs handler
// with a root-owned bucket and the root IAM client the fixtures below need,
// then tears the bucket down. Root creates every bucket and object a test
// operates on, so that what the test measures is the principal's
// authorization, never its ability to set the scene.
func s3IAMActionHandler(s *S3Conf, testName string, handler func(root *iam.Client, bucket string) error, opts ...setupOpt) error {
	return actionHandler(s, testName, func(_ *s3.Client, bucket string) error {
		return handler(s.GetIAMClient(), bucket)
	}, opts...)
}

// s3IAMComplianceActionHandler is s3IAMActionHandler for the tests that put
// an object under COMPLIANCE retention. Such an object cannot be deleted
// before its retention expires — by anyone, with any permission, by design —
// so its bucket cannot be torn down either.
//
// Rather than fail teardown, the bucket is left behind, and its name gets a
// random suffix so that a leftover from an earlier run against the same data
// directory can't collide with this one. The shared getBucketName counter
// restarts with each test process, so without the suffix a second local run
// would fail every one of these tests with BucketAlreadyOwnedByYou.
func s3IAMComplianceActionHandler(s *S3Conf, testName string, handler func(root *iam.Client, bucket string) error) error {
	runF(testName)

	// Lower-cased because genRandString's charset includes capitals, which
	// bucket names do not allow.
	bucket := getBucketName() + "-" + strings.ToLower(genRandString(8))
	if err := setup(s, bucket, withLock()); err != nil {
		failF("%v: failed to create a bucket: %v", testName, err)
		return fmt.Errorf("%v: failed to create a bucket: %w", testName, err)
	}

	if err := handler(s.GetIAMClient(), bucket); err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	passF(testName)
	return nil
}

// newS3IAMUser creates an IAM user with the given inline policies
// (policyName -> document, may be nil) and one long-term access key, and
// returns a principal whose S3 client is authenticated as that user, plus a
// cleanup func removing the key, the policies, and the user.
func newS3IAMUser(root *iam.Client, s *S3Conf, policies map[string]string) (*s3IAMPrincipal, func(), error) {
	userName := newIAMUserName()

	createOut, err := createIAMUser(root, &iam.CreateUserInput{UserName: aws.String(userName)})
	if err != nil {
		return nil, nil, fmt.Errorf("create user: %w", err)
	}

	cleanup := func() { deleteS3IAMUser(root, userName) }

	for name, doc := range policies {
		if _, err := putIAMUserPolicy(root, &iam.PutUserPolicyInput{
			UserName: aws.String(userName), PolicyName: aws.String(name), PolicyDocument: aws.String(doc),
		}); err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("attach policy %q: %w", name, err)
		}
	}

	keyOut, err := createIAMAccessKey(root, &iam.CreateAccessKeyInput{UserName: aws.String(userName)})
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("create access key: %w", err)
	}

	conf := *s
	conf.awsID = aws.ToString(keyOut.AccessKey.AccessKeyId)
	conf.awsSecret = aws.ToString(keyOut.AccessKey.SecretAccessKey)

	return &s3IAMPrincipal{
		name:   userName,
		arn:    aws.ToString(createOut.User.Arn),
		conf:   conf,
		client: conf.GetClient(),
	}, cleanup, nil
}

// putS3IAMUserPolicy attaches (or replaces) one inline policy on an existing
// principal, for tests that vary a policy in place across sub-cases rather
// than recreating the whole user each time.
func putS3IAMUserPolicy(root *iam.Client, principal *s3IAMPrincipal, policyName, document string) error {
	_, err := putIAMUserPolicy(root, &iam.PutUserPolicyInput{
		UserName:       aws.String(principal.name),
		PolicyName:     aws.String(policyName),
		PolicyDocument: aws.String(document),
	})
	return err
}

// deleteS3IAMUser removes every dependency DeleteUser would otherwise reject
// — inline policies and access keys — before deleting the user. The existing
// deleteIAMUserAndPolicies/deleteIAMUserAndAccessKeys helpers each cover
// only one of the two, and these fixtures always create both.
func deleteS3IAMUser(root *iam.Client, userName string) error {
	polOut, err := listIAMUserPolicies(root, &iam.ListUserPoliciesInput{UserName: aws.String(userName)})
	if err != nil {
		return err
	}
	for _, name := range polOut.PolicyNames {
		if err := deleteIAMUserPolicy(root, userName, name); err != nil {
			return err
		}
	}

	keyOut, err := listIAMAccessKeys(root, &iam.ListAccessKeysInput{UserName: aws.String(userName)})
	if err != nil {
		return err
	}
	for _, key := range keyOut.AccessKeyMetadata {
		if err := deleteIAMAccessKey(root, userName, aws.ToString(key.AccessKeyId)); err != nil {
			return err
		}
	}

	return deleteIAMUser(root, userName)
}

// putBucketPolicyDoc installs a bucket policy as root. Statements are built
// with bucketStatement so a test's intent stays readable and a typo becomes
// a compile error rather than a silently-malformed document.
func putBucketPolicyDoc(s *S3Conf, bucket string, statements ...bucketStatement) error {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()

	doc := bucketPolicyDoc(statements...)
	_, err := s.GetClient().PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
		Bucket: &bucket,
		Policy: &doc,
	})
	return err
}

// bucketStatement is one S3 bucket-policy statement, built as a typed value
// rather than a formatted JSON string so a test typo is a compile error.
// It mirrors accessStatement (iam_access_control.go) for identity policies;
// the difference is Principal, which bucket policies require and identity
// policies forbid.
//
// Principal is matched against the caller's raw access key by this gateway
// (auth.Principals.Contains) — deliberately not against an ARN, for
// compatibility with the non-IAM backends that have no ARNs at all. A
// long-term user is therefore named by its AKIA… access key. An assumed-role
// session cannot be named at all: its ASIA… key is ephemeral, so
// auth.IAMService.ResolveAccounts rejects it outright rather than let a bucket
// policy come to reference a principal that stops existing. Session tests
// use "*" for that reason.
type bucketStatement struct {
	Sid       string          `json:"Sid,omitempty"`
	Effect    string          `json:"Effect"`
	Principal any             `json:"Principal"`
	Action    any             `json:"Action"`
	Resource  any             `json:"Resource"`
	Condition json.RawMessage `json:"Condition,omitempty"`
}

// bucketPolicyDoc marshals statements into a complete bucket-policy
// document. Marshaling a fixed struct of strings cannot fail in practice; a
// panic here means a test itself is malformed.
func bucketPolicyDoc(statements ...bucketStatement) string {
	doc := struct {
		Version   string            `json:"Version"`
		Statement []bucketStatement `json:"Statement"`
	}{"2012-10-17", statements}
	b, err := json.Marshal(doc)
	if err != nil {
		panic(fmt.Sprintf("s3_iam_utils: bucketPolicyDoc: %v", err))
	}
	return string(b)
}

// bucketArn and objectArn build the resource ARNs an S3 policy statement
// names, matching how the gateway builds the resource it evaluates against.
func bucketArn(bucket string) string      { return "arn:aws:s3:::" + bucket }
func objectArn(bucket, key string) string { return "arn:aws:s3:::" + bucket + "/" + key }
func objectsArn(bucket string) string     { return "arn:aws:s3:::" + bucket + "/*" }

// wantExplicitIdentityDeny, wantExplicitResourceDeny and wantImplicitDeny
// name the three denial shapes VerifyAccess produces. All three share Code
// AccessDenied and HTTP 403 and differ only in message text, which is
// exactly why these tests assert on the full message: a test checking only
// the code could not tell an identity-policy deny from a bucket-policy one,
// and the precedence between them is the whole point of this group.
func wantExplicitIdentityDeny(principal, action, resourceArn string) s3err.S3Error {
	return s3err.GetExplicitDenyAccessErr(principal, action, resourceArn, "an identity-based policy")
}

func wantExplicitResourceDeny(principal, action, resourceArn string) s3err.S3Error {
	return s3err.GetExplicitDenyAccessErr(principal, action, resourceArn, "a resource-based policy")
}

func wantImplicitDeny(principal, action, resourceArn string) s3err.S3Error {
	return s3err.GetImplicitDenyAccessErr(principal, action, resourceArn)
}

// s3ClientWithSessionCreds builds an *s3.Client authenticated with a full
// access/secret/session-token triple, for the assumed-role session tests.
func s3ClientWithSessionCreds(s *S3Conf, access, secret, token string) *s3.Client {
	conf := *s
	conf.awsID = access
	conf.awsSecret = secret

	cfg := conf.Config()
	cfg.Credentials = credentials.NewStaticCredentialsProvider(access, secret, token)
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		if s.hostStyle {
			o.BaseEndpoint = &s.endpoint
			o.UsePathStyle = false
		}
	})
}

// s3ConditionCase is one row of a table-driven condition test: the Condition
// block to attach to an otherwise-unconditional GetObject Allow, and whether
// it should grant.
type s3ConditionCase struct {
	name        string
	condition   []byte
	wantAllowed bool
}

// runS3ConditionCases attaches each case's condition to a fresh user's
// GetObject Allow and checks whether the resulting request is authorized.
// A failing condition voids the statement entirely, leaving nothing to
// grant — hence the implicit-deny expectation rather than an explicit one.
func runS3ConditionCases(root *iam.Client, s *S3Conf, bucket, key string, cases []s3ConditionCase) error {
	user, cleanup, err := newS3IAMUser(root, s, nil)
	if err != nil {
		return err
	}
	defer cleanup()

	for _, tc := range cases {
		if err := func() error {
			if err := putS3IAMUserPolicy(root, user, "p", policyDoc(accessStatement{
				Effect: "Allow", Action: actS3GetObject, Resource: objectsArn(bucket),
				Condition: tc.condition,
			})); err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err = user.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr(key)})
			cancel()
			if tc.wantAllowed {
				if err != nil {
					return fmt.Errorf("expected the request to be allowed: %w", err)
				}
				return nil
			}
			return checkApiErr(err, wantImplicitDeny(user.arn, actS3GetObject, objectArn(bucket, key)))
		}(); err != nil {
			return fmt.Errorf("%s: %w", tc.name, err)
		}
	}
	return nil
}

func deleteObjectsWithBypass(client *s3.Client, bucket string, keys ...string) (*s3.DeleteObjectsOutput, error) {
	objects := make([]types.ObjectIdentifier, len(keys))
	for i, key := range keys {
		objects[i] = types.ObjectIdentifier{Key: aws.String(key)}
	}

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
		Bucket:                    &bucket,
		Delete:                    &types.Delete{Objects: objects},
		BypassGovernanceRetention: aws.Bool(true),
	})
}

// checkDeleteObjectsErr checks one DeleteObjects response entry against the
// key and denial it's expected to carry.
func checkDeleteObjectsErr(got types.Error, wantKey string, wantErr s3err.S3Error) error {
	if got.Key == nil || *got.Key != wantKey {
		return fmt.Errorf("expected the per-object error to be for key %q, got %+v", wantKey, got)
	}
	base := wantErr.BaseError()
	if got.Code == nil || *got.Code != base.Code {
		return fmt.Errorf("expected error code %q for key %q, got %+v", base.Code, wantKey, got)
	}
	if got.Message == nil || *got.Message != base.Description {
		return fmt.Errorf("expected error message %q for key %q, got %+v", base.Description, wantKey, got)
	}
	return nil
}

// checkDeletedKeysInOrder checks that a DeleteObjects response's Deleted
// list names exactly wantKeys, in that order — DeleteObjects preserves the
// order objects were requested in across both the Deleted and Error lists.
func checkDeletedKeysInOrder(got []types.DeletedObject, wantKeys []string) error {
	if len(got) != len(wantKeys) {
		return fmt.Errorf("expected %d deleted objects %v, got %+v", len(wantKeys), wantKeys, got)
	}
	for i, want := range wantKeys {
		if got[i].Key == nil || *got[i].Key != want {
			return fmt.Errorf("expected deleted object %d to be %q, got %+v", i, want, got)
		}
	}
	return nil
}

// putGovernanceLockedObject writes an object under GOVERNANCE retention, as
// root, for the bypass-permission tests to then try to delete.
func putGovernanceLockedObject(s *S3Conf, bucket, key string) error {
	retainUntil := time.Now().UTC().Add(time.Hour)
	_, err := putObjectWithData(0, &s3.PutObjectInput{
		Bucket:                    &bucket,
		Key:                       &key,
		ObjectLockMode:            types.ObjectLockModeGovernance,
		ObjectLockRetainUntilDate: &retainUntil,
	}, s.GetClient())
	return err
}

// deleteBucketPolicyIfAny clears the bucket policy for a sub-case that needs
// the resource side silent, tolerating there being none to delete — the
// table-driven tests reuse one bucket across cases rather than paying for a
// fresh bucket per row.
func deleteBucketPolicyIfAny(s *S3Conf, bucket string) error {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()

	_, err := s.GetClient().DeleteBucketPolicy(ctx, &s3.DeleteBucketPolicyInput{Bucket: &bucket})
	if err != nil && checkSdkApiErr(err, "NoSuchBucketPolicy") == nil {
		return nil
	}
	return err
}

// gitHubOIDCSkipReason explains, in the skip message, why a run outside the
// OIDC workflow can't exercise any of this.
const gitHubOIDCSkipReason = "ACTIONS_ID_TOKEN_REQUEST_URL/ACTIONS_ID_TOKEN_REQUEST_TOKEN not set " +
	"(expected outside a GitHub Actions job with id-token: write permission)"

var (
	gitHubOIDCTokenOnce sync.Once
	gitHubOIDCTokenVal  string
	gitHubOIDCTokenOK   bool
)

// gitHubOIDCToken fetches one real ID token for the whole group and reuses
// it. Every test needs a token, and they all want the same audience and the
// same repo subject, so fetching one per test would only add round trips to
// GitHub's runtime endpoint for no additional coverage.
func gitHubOIDCToken() (string, bool) {
	gitHubOIDCTokenOnce.Do(func() {
		reqURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
		reqToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
		if reqURL == "" || reqToken == "" {
			return
		}
		token, err := fetchGitHubIDToken(reqURL, reqToken, githubOIDCTestAudience)
		if err != nil {
			// The error is deliberately not propagated as a token: a fetch
			// failure inside the workflow shows up as every test failing to
			// assume a role, with the reason on the first one.
			return
		}
		gitHubOIDCTokenVal, gitHubOIDCTokenOK = token, true
	})
	return gitHubOIDCTokenVal, gitHubOIDCTokenOK
}

// s3IAMSessionActionHandler is s3IAMActionHandler that first skips the test
// when no GitHub OIDC token can be minted — which is every environment but
// the one workflow holding id-token: write permission.
func s3IAMSessionActionHandler(s *S3Conf, testName string, handler func(root *iam.Client, bucket string) error, opts ...setupOpt) error {
	if _, ok := gitHubOIDCToken(); !ok {
		skipF("%v: %v", testName, gitHubOIDCSkipReason)
		return nil
	}
	return s3IAMActionHandler(s, testName, handler, opts...)
}

// newGitHubSession registers a throwaway OIDC provider for GitHub Actions'
// issuer and a role trusting it, attaches rolePolicies as the role's inline
// permission policies, then assumes it with a real ID token and (when
// sessionPolicy is non-empty) an inline session policy.
//
// The returned principal's name is the role name, so a test can put another
// role policy on it or delete the role mid-test; arn is the assumed-role
// session ARN, which is what a denial message names.
func newGitHubSession(root *iam.Client, s *S3Conf, rolePolicies map[string]string, sessionPolicy string) (*s3IAMPrincipal, func(), error) {
	token, ok := gitHubOIDCToken()
	if !ok {
		return nil, nil, fmt.Errorf("no GitHub OIDC token available")
	}
	repo := os.Getenv("GITHUB_REPOSITORY")
	if repo == "" {
		return nil, nil, fmt.Errorf("GITHUB_REPOSITORY is not set, but the OIDC token request variables are - unexpected environment")
	}

	roleName, _, cleanup, err := createGitHubOIDCTrust(root, repo)
	if err != nil {
		return nil, nil, err
	}

	for name, doc := range rolePolicies {
		if _, err := putIAMRolePolicy(root, &iam.PutRolePolicyInput{
			RoleName: aws.String(roleName), PolicyName: aws.String(name), PolicyDocument: aws.String(doc),
		}); err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("attach role policy %q: %w", name, err)
		}
	}

	sessionName := "s3-sess-" + genRandString(8)
	out, err := assumeRoleWithWebIdentitySessionPolicy(s, roleArnFor(roleName), sessionName, token, sessionPolicy)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("AssumeRoleWithWebIdentity: %w", err)
	}

	access := aws.ToString(out.Credentials.AccessKeyId)
	secret := aws.ToString(out.Credentials.SecretAccessKey)
	sessionToken := aws.ToString(out.Credentials.SessionToken)

	conf := *s
	conf.awsID = access
	conf.awsSecret = secret

	principal := &s3IAMPrincipal{
		name:         roleName,
		arn:          aws.ToString(out.AssumedRoleUser.Arn),
		conf:         conf,
		client:       s3ClientWithSessionCreds(s, access, secret, sessionToken),
		sessionToken: sessionToken,
	}
	// The role may already have been deleted by the test itself
	// (S3IAMSession_deleted_role_denies); cleanup tolerates that.
	return principal, cleanup, nil
}

// assumeRoleWithWebIdentitySessionPolicy is assumeRoleWithWebIdentity with
// the optional inline session-policy parameter, which no other test in this
// package needs.
func assumeRoleWithWebIdentitySessionPolicy(s *S3Conf, roleArn, sessionName, token, sessionPolicy string) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	input := &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(roleArn),
		RoleSessionName:  aws.String(sessionName),
		WebIdentityToken: aws.String(token),
	}
	if sessionPolicy != "" {
		input.Policy = aws.String(sessionPolicy)
	}

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return s.GetSTSClient().AssumeRoleWithWebIdentity(ctx, input)
}

// roleArnFor builds the ARN of a role in this gateway's single fixed
// account.
func roleArnFor(roleName string) string {
	return "arn:aws:iam::" + testAccountID + ":role/" + roleName
}

// sessionNameFor recovers the session name from an assumed-role ARN, whose
// last path element it is.
func sessionNameFor(p *s3IAMPrincipal) string {
	idx := strings.LastIndex(p.arn, "/")
	if idx < 0 {
		return ""
	}
	return p.arn[idx+1:]
}

// deleteObjectBypassingGovernance deletes one object with the
// bypass-governance-retention header set.
func deleteObjectBypassingGovernance(client *s3.Client, bucket, key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	_, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket:                    &bucket,
		Key:                       &key,
		BypassGovernanceRetention: aws.Bool(true),
	})
	return err
}

// createGitHubOIDCTrust registers a throwaway OIDC provider for GitHub
// Actions' own issuer (ThumbprintList omitted, exercising
// CreateOpenIDConnectProvider's autofetch-and-CA-verify path against a real
// publicly reachable HTTPS endpoint instead of thumbprint pinning) and a
// throwaway role trusting it, returning the role's name, its ARN, and a
// cleanup func that removes both unconditionally.
//
// The trust policy's Condition requires both:
//   - the effective audience to equal githubOIDCTestAudience (not GitHub's
//     default audience - see that constant's doc comment), and
//   - the sub claim to match "repo:<repo>:*".
//
// The sub match is a repo-wide wildcard rather than pinning an exact
// ref/event suffix: GitHub's sub claim differs by trigger and branch (e.g.
// "repo:o/r:pull_request" for a pull_request event vs.
// "repo:o/r:ref:refs/heads/main" for a push to main), and pinning one exact
// form would make this test fail depending on how it was triggered. That
// tradeoff only holds because this role is created and deleted within a
// single test run - the same repo-wide wildcard left in a real production
// trust policy would grant every workflow run in the repo, on any branch,
// the same trust, which is far too broad outside this throwaway context.
func createGitHubOIDCTrust(client *iam.Client, repo string) (roleName, roleArn string, cleanup func(), err error) {
	// The provider is keyed by URL alone — a second CreateOpenIDConnectProvider
	// for the same githubOIDCIssuerURL fails with EntityAlreadyExists, same as
	// real AWS. Some tests mint more than one session (and so call this more
	// than once) within a single run, so a provider left by an earlier call
	// that hasn't been cleaned up yet is expected, not a leak: reuse it rather
	// than failing, and only this call's cleanup deletes it if this call is
	// the one that actually created it.
	ownsProvider := true
	out, err := createOIDCProvider(client, &iam.CreateOpenIDConnectProviderInput{
		Url:          aws.String(githubOIDCIssuerURL),
		ClientIDList: []string{githubOIDCTestAudience},
	})
	var providerArn string
	if err != nil {
		var ae smithy.APIError
		if !errors.As(err, &ae) || ae.ErrorCode() != "EntityAlreadyExists" {
			return "", "", nil, fmt.Errorf("create GitHub OIDC provider: %w", err)
		}
		ownsProvider = false
		providerArn = oidcProviderArn(githubOIDCIssuerURL)
	} else {
		providerArn = aws.ToString(out.OpenIDConnectProviderArn)
	}

	host := trimProviderScheme(githubOIDCIssuerURL)
	roleName = "github-oidc-" + genRandString(12)
	trust := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":%q},"Action":"sts:AssumeRoleWithWebIdentity",`+
		`"Condition":{"StringEquals":{"%s:aud":%q},"StringLike":{"%s:sub":%q}}}]}`,
		providerArn, host, githubOIDCTestAudience, host, "repo:"+repo+":*")
	if _, err := createIAMRole(client, &iam.CreateRoleInput{RoleName: &roleName, AssumeRolePolicyDocument: &trust}); err != nil {
		if ownsProvider {
			deleteOIDCProvider(client, providerArn)
		}
		return "", "", nil, fmt.Errorf("create GitHub OIDC trust role: %w", err)
	}

	roleArn = "arn:aws:iam::000000000000:role/" + roleName
	cleanup = func() {
		deleteIAMRole(client, roleName)
		if ownsProvider {
			deleteOIDCProvider(client, providerArn)
		}
	}
	return roleName, roleArn, cleanup, nil
}

// githubIDTokenResponse is the JSON body GitHub's runtime ID-token endpoint
// returns: {"value": "<jwt>", "count": <n>}. Only value is needed here.
type githubIDTokenResponse struct {
	Value string `json:"value"`
}

// fetchGitHubIDToken fetches a real, signed OIDC ID token for audience from
// GitHub Actions' runtime token endpoint (requestURL/requestToken are
// ACTIONS_ID_TOKEN_REQUEST_URL/ACTIONS_ID_TOKEN_REQUEST_TOKEN, only present
// inside a GitHub Actions job with id-token: write permission).
//
// The returned token is a real, unmasked bearer credential - unlike a
// secrets.* value, GitHub does not scrub it from logs automatically since it
// never appears in the workflow YAML. Every error path here is deliberately
// built from fixed strings and status codes only, never from the response
// body or the request's Authorization header, so a failure here can never
// leak the token into CI output.
func fetchGitHubIDToken(requestURL, requestToken, audience string) (string, error) {
	parsed, err := url.Parse(requestURL)
	if err != nil {
		return "", fmt.Errorf("parse ACTIONS_ID_TOKEN_REQUEST_URL: invalid URL")
	}
	q := parsed.Query()
	q.Set("audience", audience)
	parsed.RawQuery = q.Encode()

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return "", fmt.Errorf("build GitHub OIDC token request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+requestToken)
	req.Header.Set("Accept", "application/json; api-version=2.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch GitHub OIDC token: request failed")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read GitHub OIDC token response: failed after status %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub OIDC token endpoint returned status %d", resp.StatusCode)
	}

	var out githubIDTokenResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("parse GitHub OIDC token response: malformed JSON")
	}
	if out.Value == "" {
		return "", fmt.Errorf("GitHub OIDC token endpoint returned an empty token value")
	}
	return out.Value, nil
}

// getCallerIdentityWithSessionCreds calls GetCallerIdentity authenticated
// with a full access/secret/session-token triple.
func getCallerIdentityWithSessionCreds(cfg S3Conf, access, secret, token string) (*sts.GetCallerIdentityOutput, error) {
	cfg.awsID = access
	cfg.awsSecret = secret
	stsCfg := cfg.iamConfig()
	stsCfg.Credentials = credentials.NewStaticCredentialsProvider(access, secret, token)

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return sts.NewFromConfig(stsCfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
}
