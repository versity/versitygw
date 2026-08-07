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
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/versity/versitygw/iamapi/iamerr"
)

// stsUnauthConfig builds an authConfig for AssumeRoleWithWebIdentity, the
// one action in this whole gateway that requires no credentials at all: it
// still gets signed (as root, for convenience — reusing authHandler's
// request-building/runF/failF/passF plumbing) but the signature is never
// even checked server-side, so every request-validation test below reaches
// the server's own validation exactly as an entirely unsigned client would.
func stsUnauthConfig(testName string, params url.Values) *authConfig {
	if !params.Has("Version") {
		params.Set("Version", "2011-06-15")
	}
	return &authConfig{
		testName: testName,
		method:   http.MethodPost,
		service:  "sts",
		region:   iamAuthRegion,
		body:     []byte(params.Encode()),
		date:     time.Now().UTC(),
		headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
	}
}

// checkSTSApiErr checks resp against expected, the way requireSTSError does
// in the iamapi package's own controller-level tests: STS errors render
// under a different XML namespace than IAM's (STSNamespace, or
// AWSFaultNamespace for InvalidAction specifically), so this can't reuse
// checkHTTPResponseIAMErr, which hard-codes iamerr.Namespace.
func checkSTSApiErr(resp *http.Response, expected iamerr.Error) error {
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != expected.HTTPStatusCode {
		return fmt.Errorf("expected response status code to be %v, instead got %v: %s", expected.HTTPStatusCode, resp.StatusCode, body)
	}

	var errResp IAMErrorResponse
	if err := xml.Unmarshal(body, &errResp); err != nil {
		return fmt.Errorf("unmarshal STS error response: %w: %s", err, body)
	}

	wantNamespace := iamerr.STSNamespace
	if expected.Code == "InvalidAction" {
		wantNamespace = iamerr.AWSFaultNamespace
	}
	if errResp.XMLName.Space != wantNamespace {
		return fmt.Errorf("expected STS error namespace %q, instead got %q", wantNamespace, errResp.XMLName.Space)
	}
	if errResp.Error.Type != string(expected.Type) || errResp.Error.Code != expected.Code || errResp.Error.Message != expected.Message {
		return fmt.Errorf("expected error type=%q code=%q message=%q, instead got type=%q code=%q message=%q",
			expected.Type, expected.Code, expected.Message, errResp.Error.Type, errResp.Error.Code, errResp.Error.Message)
	}
	if errResp.RequestID == "" {
		return fmt.Errorf("expected STS error response request id")
	}
	return nil
}

// webIdentityTokenWithClaims builds an unverified (but structurally valid)
// JWT carrying claims. Sufficient for every trust-evaluation test below,
// none of which ever reach real signature verification (a trust-policy
// mismatch, audience mismatch, or condition failure is always detected
// first) — the sole exception, the IDP communication error test, needs
// exactly this and no more: real signature verification never succeeds
// against a fake identity provider regardless of what the token contains.
func webIdentityTokenWithClaims(claims map[string]any) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".c2lnbmF0dXJl", nil
}

// validWebIdentityToken is a structurally valid (but unverifiable — no
// registered provider will ever match its issuer) JWT carrying every claim
// AWS requires (including iat — its absence would itself be a rejection
// reason, see VerifyWebIdentityRequiredClaims), sufficient for exercising
// every AssumeRoleWithWebIdentity validation step that runs before a role is
// even looked up.
const validWebIdentityToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
	"eyJpc3MiOiJodHRwczovL3VucmVnaXN0ZXJlZC5leGFtcGxlLmNvbSIsImF1ZCI6ImNsaWVudDEiLCJzdWIiOiJ1c2VyMSIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjo5OTk5OTk5OTk5fQ." +
	"c2lnbmF0dXJl"

func IAMAssumeRoleWithWebIdentity_missing_role_arn(s *S3Conf) error {
	testName := "IAMAssumeRoleWithWebIdentity_missing_role_arn"
	cfg := stsUnauthConfig(testName, url.Values{"Action": {"AssumeRoleWithWebIdentity"}})
	return authHandler(s, cfg, func(req *http.Request) error {
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		return checkSTSApiErr(resp, iamerr.MissingValue("roleArn"))
	})
}

func IAMAssumeRoleWithWebIdentity_role_arn_too_short(s *S3Conf) error {
	testName := "IAMAssumeRoleWithWebIdentity_role_arn_too_short"
	cfg := stsUnauthConfig(testName, url.Values{
		"Action": {"AssumeRoleWithWebIdentity"}, "RoleArn": {"short"},
		"RoleSessionName": {"session1"}, "WebIdentityToken": {validWebIdentityToken},
	})
	return authHandler(s, cfg, func(req *http.Request) error {
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		return checkSTSApiErr(resp, iamerr.ValueTooShort("roleArn", 20))
	})
}

func IAMAssumeRoleWithWebIdentity_malformed_duration(s *S3Conf) error {
	testName := "IAMAssumeRoleWithWebIdentity_malformed_duration"
	cfg := stsUnauthConfig(testName, url.Values{
		"Action": {"AssumeRoleWithWebIdentity"}, "RoleArn": {"arn:aws:iam::000000000000:role/does-not-exist"},
		"RoleSessionName": {"session1"}, "WebIdentityToken": {validWebIdentityToken}, "DurationSeconds": {"notanumber"},
	})
	return authHandler(s, cfg, func(req *http.Request) error {
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		return checkSTSApiErr(resp, iamerr.MalformedInput())
	})
}

func IAMAssumeRoleWithWebIdentity_wrong_version_is_invalid_action(s *S3Conf) error {
	testName := "IAMAssumeRoleWithWebIdentity_wrong_version_is_invalid_action"
	cfg := stsUnauthConfig(testName, url.Values{"Action": {"AssumeRoleWithWebIdentity"}, "Version": {"2010-05-08"}})
	return authHandler(s, cfg, func(req *http.Request) error {
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		return checkSTSApiErr(resp, iamerr.InvalidAction("AssumeRoleWithWebIdentity", "2010-05-08"))
	})
}

func IAMAssumeRoleWithWebIdentity_malformed_token(s *S3Conf) error {
	testName := "IAMAssumeRoleWithWebIdentity_malformed_token"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleArn, cleanup, err := createTestRoleForWebIdentityTrust(client, newIAMOIDCProviderURL(), "client1")
		if err != nil {
			return err
		}
		defer cleanup()

		_, assumeErr := assumeRoleWithWebIdentity(s, roleArn, "session1", "not-a-real-jwt-token", 0)
		return checkIAMApiErr(assumeErr, iamerr.InvalidIdentityTokenMalformed())
	})
}

func IAMAssumeRoleWithWebIdentity_duration_exceeds_role_max(s *S3Conf) error {
	testName := "IAMAssumeRoleWithWebIdentity_duration_exceeds_role_max"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleArn, cleanup, err := createTestRoleForWebIdentityTrust(client, newIAMOIDCProviderURL(), "client1")
		if err != nil {
			return err
		}
		defer cleanup()

		// The role's default MaxSessionDuration is 3600.
		_, assumeErr := assumeRoleWithWebIdentity(s, roleArn, "session1", validWebIdentityToken, 7200)
		return checkIAMApiErr(assumeErr, iamerr.DurationExceedsMaxSessionDuration())
	})
}

func IAMAssumeRoleWithWebIdentity_nonexistent_role(s *S3Conf) error {
	testName := "IAMAssumeRoleWithWebIdentity_nonexistent_role"
	return iamActionHandler(s, testName, func(_ *iam.Client) error {
		roleArn := "arn:aws:iam::000000000000:role/" + genRandString(16)
		_, assumeErr := assumeRoleWithWebIdentity(s, roleArn, "session1", validWebIdentityToken, 0)
		return checkIAMApiErr(assumeErr, iamerr.AccessDeniedAssumeRoleWithWebIdentity())
	})
}

func IAMAssumeRoleWithWebIdentity_no_matching_principal(s *S3Conf) error {
	testName := "IAMAssumeRoleWithWebIdentity_no_matching_principal"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		// The trust policy's Federated principal never corresponds to a
		// real, registered OIDC provider (it was never created) — reported
		// identically to a nonexistent role, never confirming or denying
		// whether the role itself exists.
		roleName := "dangling-trust-" + genRandString(12)
		trust := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":%q},"Action":"sts:AssumeRoleWithWebIdentity"}]}`,
			oidcProviderArn("https://never-created-"+genRandString(12)+".example.com"))
		if _, err := createIAMRole(client, &iam.CreateRoleInput{RoleName: &roleName, AssumeRolePolicyDocument: &trust}); err != nil {
			return err
		}
		defer deleteIAMRole(client, roleName)

		roleArn := "arn:aws:iam::000000000000:role/" + roleName
		_, assumeErr := assumeRoleWithWebIdentity(s, roleArn, "session1", validWebIdentityToken, 0)
		return checkIAMApiErr(assumeErr, iamerr.AccessDeniedAssumeRoleWithWebIdentity())
	})
}

func IAMAssumeRoleWithWebIdentity_no_issuer_match(s *S3Conf) error {
	testName := "IAMAssumeRoleWithWebIdentity_no_issuer_match"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		// The Federated principal resolves to a real, registered provider —
		// but that provider's own Url doesn't match the token's iss claim.
		// Unlike no_matching_principal, this confirms the role exists
		// (InvalidIdentityToken instead of AccessDenied).
		roleArn, cleanup, err := createTestRoleForWebIdentityTrust(client, newIAMOIDCProviderURL(), "client1")
		if err != nil {
			return err
		}
		defer cleanup()

		token, err := webIdentityTokenWithClaims(map[string]any{
			"iss": "https://different-issuer-" + genRandString(8) + ".example.com", "aud": "client1", "sub": "user1", "exp": 9999999999,
		})
		if err != nil {
			return err
		}

		_, assumeErr := assumeRoleWithWebIdentity(s, roleArn, "session1", token, 0)
		return checkIAMApiErr(assumeErr, iamerr.InvalidIdentityTokenClaims())
	})
}

func IAMAssumeRoleWithWebIdentity_condition_failed(s *S3Conf) error {
	testName := "IAMAssumeRoleWithWebIdentity_condition_failed"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		providerURL := newIAMOIDCProviderURL()
		providerArn, err := createTestOIDCProviderWithURL(client, providerURL)
		if err != nil {
			return err
		}
		defer deleteOIDCProvider(client, providerArn)

		host := trimProviderScheme(providerURL)
		roleName := "condition-failed-" + genRandString(12)
		trust := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":%q},"Action":"sts:AssumeRoleWithWebIdentity",`+
			`"Condition":{"StringEquals":{"%s:sub":"expected-user"}}}]}`, providerArn, host)
		if _, err := createIAMRole(client, &iam.CreateRoleInput{RoleName: &roleName, AssumeRolePolicyDocument: &trust}); err != nil {
			return err
		}
		defer deleteIAMRole(client, roleName)

		token, err := webIdentityTokenWithClaims(map[string]any{
			"iss": providerURL, "aud": "client1", "sub": "someone-else", "exp": 9999999999,
		})
		if err != nil {
			return err
		}

		roleArn := "arn:aws:iam::000000000000:role/" + roleName
		_, assumeErr := assumeRoleWithWebIdentity(s, roleArn, "session1", token, 0)
		return checkIAMApiErr(assumeErr, iamerr.InvalidIdentityTokenClaims())
	})
}

func IAMAssumeRoleWithWebIdentity_explicit_deny(s *S3Conf) error {
	testName := "IAMAssumeRoleWithWebIdentity_explicit_deny"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		providerURL := newIAMOIDCProviderURL()
		providerArn, err := createTestOIDCProviderWithURL(client, providerURL)
		if err != nil {
			return err
		}
		defer deleteOIDCProvider(client, providerArn)

		host := trimProviderScheme(providerURL)
		roleName := "explicit-deny-" + genRandString(12)
		// A broad Allow is present, but a Deny statement matching the same
		// provider/action/condition takes precedence — reported as
		// AccessDenied, never InvalidIdentityToken.
		trust := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[`+
			`{"Effect":"Allow","Principal":{"Federated":%q},"Action":"sts:AssumeRoleWithWebIdentity"},`+
			`{"Effect":"Deny","Principal":{"Federated":%q},"Action":"sts:AssumeRoleWithWebIdentity",`+
			`"Condition":{"StringEquals":{"%s:sub":"blocked-user"}}}]}`, providerArn, providerArn, host)
		if _, err := createIAMRole(client, &iam.CreateRoleInput{RoleName: &roleName, AssumeRolePolicyDocument: &trust}); err != nil {
			return err
		}
		defer deleteIAMRole(client, roleName)

		token, err := webIdentityTokenWithClaims(map[string]any{
			"iss": providerURL, "aud": "client1", "sub": "blocked-user", "exp": 9999999999,
		})
		if err != nil {
			return err
		}

		roleArn := "arn:aws:iam::000000000000:role/" + roleName
		_, assumeErr := assumeRoleWithWebIdentity(s, roleArn, "session1", token, 0)
		return checkIAMApiErr(assumeErr, iamerr.AccessDeniedAssumeRoleWithWebIdentity())
	})
}

func IAMAssumeRoleWithWebIdentity_audience_not_in_client_id_list(s *S3Conf) error {
	testName := "IAMAssumeRoleWithWebIdentity_audience_not_in_client_id_list"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		providerURL := newIAMOIDCProviderURL()
		roleArn, cleanup, err := createTestRoleForWebIdentityTrust(client, providerURL, "allowed-client")
		if err != nil {
			return err
		}
		defer cleanup()

		token, err := webIdentityTokenWithClaims(map[string]any{
			"iss": providerURL, "aud": "not-the-allowed-client", "sub": "user1", "exp": 9999999999,
		})
		if err != nil {
			return err
		}

		_, assumeErr := assumeRoleWithWebIdentity(s, roleArn, "session1", token, 0)
		return checkIAMApiErr(assumeErr, iamerr.InvalidIdentityTokenClaims())
	})
}

func IAMAssumeRoleWithWebIdentity_empty_client_id_list(s *S3Conf) error {
	testName := "IAMAssumeRoleWithWebIdentity_empty_client_id_list"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		providerURL := newIAMOIDCProviderURL()
		// No ClientIDList entries at all — can never satisfy the audience
		// check, no matter what the token's aud claim is.
		roleArn, cleanup, err := createTestRoleForWebIdentityTrust(client, providerURL, "")
		if err != nil {
			return err
		}
		defer cleanup()

		token, err := webIdentityTokenWithClaims(map[string]any{
			"iss": providerURL, "aud": "anything", "sub": "user1", "exp": 9999999999,
		})
		if err != nil {
			return err
		}

		_, assumeErr := assumeRoleWithWebIdentity(s, roleArn, "session1", token, 0)
		return checkIAMApiErr(assumeErr, iamerr.InvalidIdentityTokenClaims())
	})
}

// IAMAssumeRoleWithWebIdentity_idp_communication_error confirms the
// network-dependent signature-verification step is wired all the way
// through the real HTTP action handler: a provider Url that's a loopback IP
// literal is rejected by VerifyWebIdentitySignature's mandatory SSRF guard
// before any real network attempt, deterministically and without requiring
// outbound network access from the test environment — the same technique
// IAMCreateOpenIDConnectProvider_thumbprint_autofetch_communication_error
// uses for CreateOpenIDConnectProvider's own auto-fetch path.
func IAMAssumeRoleWithWebIdentity_idp_communication_error(s *S3Conf) error {
	testName := "IAMAssumeRoleWithWebIdentity_idp_communication_error"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		roleArn, cleanup, err := createTestRoleForWebIdentityTrust(client, "https://127.0.0.1", "client1")
		if err != nil {
			return err
		}
		defer cleanup()

		token, err := webIdentityTokenWithClaims(map[string]any{
			"iss": "https://127.0.0.1", "aud": "client1", "sub": "user1", "exp": 9999999999,
		})
		if err != nil {
			return err
		}

		_, assumeErr := assumeRoleWithWebIdentity(s, roleArn, "session1", token, 0)
		return checkIAMApiErr(assumeErr, iamerr.InvalidIdentityTokenIDPCommunicationError())
	})
}

func IAMAssumeRoleWithWebIdentity_role_arn_path_mismatch(s *S3Conf) error {
	testName := "IAMAssumeRoleWithWebIdentity_role_arn_path_mismatch"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		// The role is created with the default "/" path, so its real Arn is
		// arn:...:role/<name> — not arn:...:role/some/path/<name>. Only the
		// role name (the ARN's final path segment) is used to look the role
		// up; the full ARN, path included, must still match the role's
		// actual Arn, or trust is never evaluated at all.
		roleName := "path-mismatch-" + genRandString(12)
		trust := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":%q},"Action":"sts:AssumeRoleWithWebIdentity"}]}`,
			oidcProviderArn("https://never-created-"+genRandString(12)+".example.com"))
		if _, err := createIAMRole(client, &iam.CreateRoleInput{RoleName: &roleName, AssumeRolePolicyDocument: &trust}); err != nil {
			return err
		}
		defer deleteIAMRole(client, roleName)

		roleArn := "arn:aws:iam::000000000000:role/some/path/" + roleName
		_, assumeErr := assumeRoleWithWebIdentity(s, roleArn, "session1", validWebIdentityToken, 0)
		return checkIAMApiErr(assumeErr, iamerr.AccessDeniedAssumeRoleWithWebIdentity())
	})
}

// IAMAssumeRoleWithWebIdentity_policy_arns_rejected and
// IAMAssumeRoleWithWebIdentity_provider_id_rejected confirm PolicyArns and
// ProviderId — valid AssumeRoleWithWebIdentity parameters this
// implementation doesn't support — are rejected outright rather than
// silently ignored. Both checks run before the role is even looked up, so
// (matching the other request-validation tests above) RoleArn need not name
// a real role.
func IAMAssumeRoleWithWebIdentity_policy_arns_rejected(s *S3Conf) error {
	testName := "IAMAssumeRoleWithWebIdentity_policy_arns_rejected"
	cfg := stsUnauthConfig(testName, url.Values{
		"Action": {"AssumeRoleWithWebIdentity"}, "RoleArn": {"arn:aws:iam::000000000000:role/does-not-exist"},
		"RoleSessionName": {"session1"}, "WebIdentityToken": {validWebIdentityToken},
		"PolicyArns.member.1.arn": {"arn:aws:iam::000000000000:policy/some-policy"},
	})
	return authHandler(s, cfg, func(req *http.Request) error {
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		return checkSTSApiErr(resp, iamerr.UnsupportedParameter("PolicyArns"))
	})
}

func IAMAssumeRoleWithWebIdentity_provider_id_rejected(s *S3Conf) error {
	testName := "IAMAssumeRoleWithWebIdentity_provider_id_rejected"
	cfg := stsUnauthConfig(testName, url.Values{
		"Action": {"AssumeRoleWithWebIdentity"}, "RoleArn": {"arn:aws:iam::000000000000:role/does-not-exist"},
		"RoleSessionName": {"session1"}, "WebIdentityToken": {validWebIdentityToken}, "ProviderId": {"www.amazon.com"},
	})
	return authHandler(s, cfg, func(req *http.Request) error {
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		return checkSTSApiErr(resp, iamerr.UnsupportedParameter("ProviderId"))
	})
}

func IAMAssumeRoleWithWebIdentity_session_policy_too_large(s *S3Conf) error {
	testName := "IAMAssumeRoleWithWebIdentity_session_policy_too_large"
	cfg := stsUnauthConfig(testName, url.Values{
		"Action": {"AssumeRoleWithWebIdentity"}, "RoleArn": {"arn:aws:iam::000000000000:role/does-not-exist"},
		"RoleSessionName": {"session1"}, "WebIdentityToken": {validWebIdentityToken}, "Policy": {genRandString(2049)},
	})
	return authHandler(s, cfg, func(req *http.Request) error {
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		return checkSTSApiErr(resp, iamerr.ValueTooLong("policy", 2048))
	})
}

func IAMAssumeRoleWithWebIdentity_session_policy_invalid(s *S3Conf) error {
	testName := "IAMAssumeRoleWithWebIdentity_session_policy_invalid"
	cfg := stsUnauthConfig(testName, url.Values{
		"Action": {"AssumeRoleWithWebIdentity"}, "RoleArn": {"arn:aws:iam::000000000000:role/does-not-exist"},
		"RoleSessionName": {"session1"}, "WebIdentityToken": {validWebIdentityToken},
		"Policy": {`{"Version":"2012-10-17"}`}, // no Statement
	})
	return authHandler(s, cfg, func(req *http.Request) error {
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		return checkSTSApiErr(resp, iamerr.MalformedPolicyDocument("Syntax errors in policy."))
	})
}

func IAMAssumeRoleWithWebIdentity_oaud_condition_matches(s *S3Conf) error {
	testName := "IAMAssumeRoleWithWebIdentity_oaud_condition_matches"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		// A loopback provider URL guarantees a deterministic
		// InvalidIdentityToken IDP-communication error once the request
		// reaches the network-dependent signature-verification step —
		// reaching that far (rather than being rejected earlier by trust
		// evaluation) is what confirms the oaud Condition below matched.
		providerURL := "https://127.0.0.7"
		out, err := createOIDCProvider(client, &iam.CreateOpenIDConnectProviderInput{
			Url:            aws.String(providerURL),
			ClientIDList:   []string{"azp-client"},
			ThumbprintList: []string{validOIDCThumbprint},
		})
		if err != nil {
			return err
		}
		providerArn := aws.ToString(out.OpenIDConnectProviderArn)
		defer deleteOIDCProvider(client, providerArn)

		host := trimProviderScheme(providerURL)
		roleName := "oaud-match-" + genRandString(12)
		trust := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":%q},"Action":"sts:AssumeRoleWithWebIdentity",`+
			`"Condition":{"StringEquals":{"%s:oaud":"backend-project"}}}]}`, providerArn, host)
		if _, err := createIAMRole(client, &iam.CreateRoleInput{RoleName: &roleName, AssumeRolePolicyDocument: &trust}); err != nil {
			return err
		}
		defer deleteIAMRole(client, roleName)

		// azp overrides aud as the effective audience (checked against the
		// provider's ClientIDList below), exposing the original aud
		// ("backend-project") for the oaud mapping instead.
		token, err := webIdentityTokenWithClaims(map[string]any{
			"iss": providerURL, "aud": "backend-project", "azp": "azp-client", "sub": "user1", "exp": 9999999999,
		})
		if err != nil {
			return err
		}

		roleArn := "arn:aws:iam::000000000000:role/" + roleName
		_, assumeErr := assumeRoleWithWebIdentity(s, roleArn, "session1", token, 0)
		return checkIAMApiErr(assumeErr, iamerr.InvalidIdentityTokenIDPCommunicationError())
	})
}

func IAMAssumeRoleWithWebIdentity_oaud_condition_mismatch(s *S3Conf) error {
	testName := "IAMAssumeRoleWithWebIdentity_oaud_condition_mismatch"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		providerURL := newIAMOIDCProviderURL()
		out, err := createOIDCProvider(client, &iam.CreateOpenIDConnectProviderInput{
			Url:            aws.String(providerURL),
			ClientIDList:   []string{"azp-client"},
			ThumbprintList: []string{validOIDCThumbprint},
		})
		if err != nil {
			return err
		}
		providerArn := aws.ToString(out.OpenIDConnectProviderArn)
		defer deleteOIDCProvider(client, providerArn)

		host := trimProviderScheme(providerURL)
		roleName := "oaud-mismatch-" + genRandString(12)
		trust := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":%q},"Action":"sts:AssumeRoleWithWebIdentity",`+
			`"Condition":{"StringEquals":{"%s:oaud":"backend-project"}}}]}`, providerArn, host)
		if _, err := createIAMRole(client, &iam.CreateRoleInput{RoleName: &roleName, AssumeRolePolicyDocument: &trust}); err != nil {
			return err
		}
		defer deleteIAMRole(client, roleName)

		// Original aud is "different-project", not "backend-project" — the
		// azp-effective audience still matches the provider's ClientIDList,
		// so only the oaud Condition is what fails this request.
		token, err := webIdentityTokenWithClaims(map[string]any{
			"iss": providerURL, "aud": "different-project", "azp": "azp-client", "sub": "user1", "exp": 9999999999,
		})
		if err != nil {
			return err
		}

		roleArn := "arn:aws:iam::000000000000:role/" + roleName
		_, assumeErr := assumeRoleWithWebIdentity(s, roleArn, "session1", token, 0)
		return checkIAMApiErr(assumeErr, iamerr.InvalidIdentityTokenClaims())
	})
}

func IAMAssumeRoleWithWebIdentity_issuer_trailing_slash_mismatch(s *S3Conf) error {
	testName := "IAMAssumeRoleWithWebIdentity_issuer_trailing_slash_mismatch"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		providerURL := newIAMOIDCProviderURL()
		roleArn, cleanup, err := createTestRoleForWebIdentityTrust(client, providerURL, "client1")
		if err != nil {
			return err
		}
		defer cleanup()

		token, err := webIdentityTokenWithClaims(map[string]any{
			"iss": providerURL + "/", "aud": "client1", "sub": "user1", "exp": 9999999999,
		})
		if err != nil {
			return err
		}

		_, assumeErr := assumeRoleWithWebIdentity(s, roleArn, "session1", token, 0)
		return checkIAMApiErr(assumeErr, iamerr.InvalidIdentityTokenClaims())
	})
}

func IAMAssumeRoleWithWebIdentity_issuer_scheme_mismatch(s *S3Conf) error {
	testName := "IAMAssumeRoleWithWebIdentity_issuer_scheme_mismatch"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		providerURL := newIAMOIDCProviderURL()
		roleArn, cleanup, err := createTestRoleForWebIdentityTrust(client, providerURL, "client1")
		if err != nil {
			return err
		}
		defer cleanup()

		token, err := webIdentityTokenWithClaims(map[string]any{
			"iss": "http://" + trimProviderScheme(providerURL), "aud": "client1", "sub": "user1", "exp": 9999999999,
		})
		if err != nil {
			return err
		}

		_, assumeErr := assumeRoleWithWebIdentity(s, roleArn, "session1", token, 0)
		return checkIAMApiErr(assumeErr, iamerr.InvalidIdentityTokenClaims())
	})
}

// createTestRoleForWebIdentityTrust registers a fresh OIDC provider at
// providerURL (with clientID in its ClientIDList, unless clientID is
// empty) and a role whose trust policy allows sts:AssumeRoleWithWebIdentity
// for that provider with no Condition, returning the role's ARN and a
// cleanup function that removes both.
func createTestRoleForWebIdentityTrust(client *iam.Client, providerURL, clientID string) (roleArn string, cleanup func(), err error) {
	var clientIDs []string
	if clientID != "" {
		clientIDs = []string{clientID}
	}
	out, err := createOIDCProvider(client, &iam.CreateOpenIDConnectProviderInput{
		Url:            aws.String(providerURL),
		ClientIDList:   clientIDs,
		ThumbprintList: []string{validOIDCThumbprint},
	})
	if err != nil {
		return "", nil, err
	}
	providerArn := aws.ToString(out.OpenIDConnectProviderArn)

	roleName := "web-identity-trust-" + genRandString(12)
	trust := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":%q},"Action":"sts:AssumeRoleWithWebIdentity"}]}`, providerArn)
	if _, err := createIAMRole(client, &iam.CreateRoleInput{RoleName: &roleName, AssumeRolePolicyDocument: &trust}); err != nil {
		deleteOIDCProvider(client, providerArn)
		return "", nil, err
	}

	cleanup = func() {
		deleteIAMRole(client, roleName)
		deleteOIDCProvider(client, providerArn)
	}
	return "arn:aws:iam::000000000000:role/" + roleName, cleanup, nil
}

// assumeRoleWithWebIdentity calls AssumeRoleWithWebIdentity through a real
// STS SDK client — the action needs no credentials, so this works
// regardless of what (if anything) s itself is configured to sign with.
// durationSeconds of 0 omits DurationSeconds entirely (STS's own default
// applies).
func assumeRoleWithWebIdentity(s *S3Conf, roleArn, sessionName, token string, durationSeconds int32) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()

	input := &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          &roleArn,
		RoleSessionName:  &sessionName,
		WebIdentityToken: &token,
	}
	if durationSeconds > 0 {
		input.DurationSeconds = aws.Int32(durationSeconds)
	}
	return s.GetSTSClient().AssumeRoleWithWebIdentity(ctx, input)
}

// trimProviderScheme mirrors iamutil.WebIdentityIssuer's scheme-stripping,
// for building Condition context keys ("<provider-url>:<claim>") against a
// provider's stored (scheme-stripped) Url.
func trimProviderScheme(rawURL string) string {
	for _, prefix := range []string{"https://", "http://"} {
		if len(rawURL) > len(prefix) && rawURL[:len(prefix)] == prefix {
			return rawURL[len(prefix):]
		}
	}
	return rawURL
}
