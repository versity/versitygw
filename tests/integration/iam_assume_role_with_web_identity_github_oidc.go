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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
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

// IAMAssumeRoleWithWebIdentity_github_oidc_live exercises
// AssumeRoleWithWebIdentity against a REAL external OIDC identity provider —
// GitHub Actions' own OIDC issuer — end-to-end: discovery-document fetch,
// JWKS fetch, real RS256 signature verification, claims mapping, and
// session credential issuance. It's the only web-identity test that does
// this; every other one in this package uses a fake token that never
// reaches real signature verification.
func IAMAssumeRoleWithWebIdentity_github_oidc_live(s *S3Conf) error {
	testName := "IAMAssumeRoleWithWebIdentity_github_oidc_live"

	reqURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	reqToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if reqURL == "" || reqToken == "" {
		skipF("%v: ACTIONS_ID_TOKEN_REQUEST_URL/ACTIONS_ID_TOKEN_REQUEST_TOKEN not set "+
			"(expected outside a GitHub Actions job with id-token: write permission)", testName)
		return nil
	}

	return iamActionHandler(s, testName, func(client *iam.Client) error {
		repo := os.Getenv("GITHUB_REPOSITORY")
		if repo == "" {
			return fmt.Errorf("GITHUB_REPOSITORY is not set, but ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN are - unexpected environment")
		}

		roleName, roleArn, cleanup, err := createGitHubOIDCTrust(client, repo)
		if err != nil {
			return err
		}
		defer cleanup()

		token, err := fetchGitHubIDToken(reqURL, reqToken, githubOIDCTestAudience)
		if err != nil {
			return err
		}

		const sessionName = "github-oidc-live"
		assumeOut, err := assumeRoleWithWebIdentity(s, roleArn, sessionName, token, 0)
		if err != nil {
			// checkIAMApiErr-style wrapping isn't used here since a live
			// AssumeRoleWithWebIdentity SDK error carries no token material
			// of its own to guard against - it's the request we build
			// (never printed) and GitHub's response (never printed either,
			// see fetchGitHubIDToken) that could leak the token.
			return fmt.Errorf("AssumeRoleWithWebIdentity: %w", err)
		}
		if assumeOut.Credentials == nil {
			return fmt.Errorf("expected Credentials in AssumeRoleWithWebIdentity response")
		}
		accessKeyID := aws.ToString(assumeOut.Credentials.AccessKeyId)
		secretAccessKey := aws.ToString(assumeOut.Credentials.SecretAccessKey)
		sessionToken := aws.ToString(assumeOut.Credentials.SessionToken)
		if accessKeyID == "" || secretAccessKey == "" || sessionToken == "" {
			return fmt.Errorf("expected a full AccessKeyId/SecretAccessKey/SessionToken triple in AssumeRoleWithWebIdentity response")
		}

		wantArn := fmt.Sprintf("arn:aws:sts::000000000000:assumed-role/%s/%s", roleName, sessionName)
		if aws.ToString(assumeOut.AssumedRoleUser.Arn) != wantArn {
			return fmt.Errorf("expected AssumedRoleUser.Arn %q, instead got %q", wantArn, aws.ToString(assumeOut.AssumedRoleUser.Arn))
		}

		// A follow-up call authenticated with the session credentials
		// AssumeRoleWithWebIdentity just issued proves the whole chain -
		// discovery, JWKS, signature verification, claims mapping, and
		// session creds - actually works, not just that a 200 came back.
		callerOut, err := getCallerIdentityWithSessionCreds(*s, accessKeyID, secretAccessKey, sessionToken)
		if err != nil {
			return fmt.Errorf("GetCallerIdentity with assumed-role session credentials: %w", err)
		}
		if aws.ToString(callerOut.Arn) != wantArn {
			return fmt.Errorf("GetCallerIdentity: expected Arn %q, instead got %q", wantArn, aws.ToString(callerOut.Arn))
		}
		return nil
	})
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
	out, err := createOIDCProvider(client, &iam.CreateOpenIDConnectProviderInput{
		Url:          aws.String(githubOIDCIssuerURL),
		ClientIDList: []string{githubOIDCTestAudience},
	})
	if err != nil {
		return "", "", nil, fmt.Errorf("create GitHub OIDC provider: %w", err)
	}
	providerArn := aws.ToString(out.OpenIDConnectProviderArn)

	host := trimProviderScheme(githubOIDCIssuerURL)
	roleName = "github-oidc-" + genRandString(12)
	trust := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":%q},"Action":"sts:AssumeRoleWithWebIdentity",`+
		`"Condition":{"StringEquals":{"%s:aud":%q},"StringLike":{"%s:sub":%q}}}]}`,
		providerArn, host, githubOIDCTestAudience, host, "repo:"+repo+":*")
	if _, err := createIAMRole(client, &iam.CreateRoleInput{RoleName: &roleName, AssumeRolePolicyDocument: &trust}); err != nil {
		deleteOIDCProvider(client, providerArn)
		return "", "", nil, fmt.Errorf("create GitHub OIDC trust role: %w", err)
	}

	roleArn = "arn:aws:iam::000000000000:role/" + roleName
	cleanup = func() {
		deleteIAMRole(client, roleName)
		deleteOIDCProvider(client, providerArn)
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
	stsCfg := cfg.Config()
	stsCfg.Credentials = credentials.NewStaticCredentialsProvider(access, secret, token)

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return sts.NewFromConfig(stsCfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
}
