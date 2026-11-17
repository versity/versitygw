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
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/versity/versitygw/iamapi/iamerr"
)

const actSTSAssumeRole = "sts:AssumeRole"

// allowAssumeAnyRole is an identity policy letting its holder assume any role
// whose trust policy delegates to the account.
var allowAssumeAnyRole = policyDoc(accessStatement{Effect: "Allow", Action: actSTSAssumeRole, Resource: "*"})

func IAMAssumeRole_missing_role_arn(s *S3Conf) error {
	testName := "IAMAssumeRole_missing_role_arn"
	cfg := assumeRoleRawConfig(testName, url.Values{"RoleSessionName": {"session1"}})
	return authHandler(s, cfg, func(req *http.Request) error {
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		return checkSTSApiErr(resp, iamerr.MissingValue("roleArn"))
	})
}

func IAMAssumeRole_missing_role_session_name(s *S3Conf) error {
	testName := "IAMAssumeRole_missing_role_session_name"
	cfg := assumeRoleRawConfig(testName, url.Values{"RoleArn": {roleArnFor("does-not-exist")}})
	return authHandler(s, cfg, func(req *http.Request) error {
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		return checkSTSApiErr(resp, iamerr.MissingValue("roleSessionName"))
	})
}

func IAMAssumeRole_malformed_duration(s *S3Conf) error {
	testName := "IAMAssumeRole_malformed_duration"
	cfg := assumeRoleRawConfig(testName, url.Values{
		"RoleArn": {roleArnFor("does-not-exist")}, "RoleSessionName": {"session1"}, "DurationSeconds": {"notanumber"},
	})
	return authHandler(s, cfg, func(req *http.Request) error {
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		return checkSTSApiErr(resp, iamerr.MalformedInput())
	})
}

func IAMAssumeRole_wrong_version_is_invalid_action(s *S3Conf) error {
	testName := "IAMAssumeRole_wrong_version_is_invalid_action"
	cfg := assumeRoleRawConfig(testName, url.Values{
		"RoleArn": {roleArnFor("does-not-exist")}, "RoleSessionName": {"session1"}, "Version": {"2010-05-08"},
	})
	return authHandler(s, cfg, func(req *http.Request) error {
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		return checkSTSApiErr(resp, iamerr.InvalidAction("AssumeRole", "2010-05-08"))
	})
}

func IAMAssumeRole_incorrect_service_scope(s *S3Conf) error {
	testName := "IAMAssumeRole_incorrect_service_scope"
	cfg := assumeRoleRawConfig(testName, url.Values{"RoleArn": {roleArnFor("does-not-exist")}, "RoleSessionName": {"session1"}})
	cfg.service = "iam"
	return authHandler(s, cfg, func(req *http.Request) error {
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		return checkSTSApiErr(resp, iamerr.IncorrectServiceScope("sts"))
	})
}

// IAMAssumeRole_no_auth verifies AssumeRole, unlike AssumeRoleWithWebIdentity,
// is refused without a signature, and before any of its parameters is looked
// at.
func IAMAssumeRole_no_auth(s *S3Conf) error {
	testName := "IAMAssumeRole_no_auth"
	runF(testName)

	body := []byte(url.Values{"Action": {"AssumeRole"}, "Version": {"2011-06-15"}}.Encode())
	req, err := http.NewRequest(http.MethodPost, s.endpoint+"/", bytes.NewReader(body))
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}
	if err := checkSTSApiErr(resp, iamerr.GetAPIError(iamerr.ErrMissingAuthenticationToken)); err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	passF(testName)
	return nil
}

func IAMAssumeRole_unknown_access_key(s *S3Conf) error {
	testName := "IAMAssumeRole_unknown_access_key"
	return iamActionHandler(s, testName, func(_ *iam.Client) error {
		conf := *s
		conf.awsID, conf.awsSecret = "AKIAuNKNOWNACCESSKEYID", "does-not-matter"
		_, err := assumeRoleAs(&s3IAMPrincipal{conf: conf}, &sts.AssumeRoleInput{RoleArn: aws.String(roleArnFor("does-not-exist"))})
		return checkIAMApiErr(err, iamerr.GetAPIError(iamerr.ErrInvalidClientTokenID))
	})
}

// IAMAssumeRole_invalid_credentials verifies every way the AssumeRole call's
// own credentials can be wrong is refused before the request is looked at:
// a wrong secret, a key that is inactive or deleted, a long-term key sent
// with a security token, and a session key with a wrong token or none.
func IAMAssumeRole_invalid_credentials(s *S3Conf) error {
	testName := "IAMAssumeRole_invalid_credentials"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		user, cleanup, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanup()
		_, roleArn, cleanupRole, err := newAssumableRole(root, trustAllowingAWS(user.arn))
		if err != nil {
			return err
		}
		defer cleanupRole()
		input := func() *sts.AssumeRoleInput { return &sts.AssumeRoleInput{RoleArn: aws.String(roleArn)} }

		out, err := assumeRoleAs(user, input())
		if err != nil {
			return fmt.Errorf("with valid credentials: %w", err)
		}
		session := roleSession(s, "", out)

		invalidToken := iamerr.GetAPIError(iamerr.ErrInvalidClientTokenID)
		cases := []struct {
			name    string
			caller  *s3IAMPrincipal
			wantErr iamerr.Error
		}{
			{"wrong secret", withCredentials(user, user.conf.awsID, "wrong-secret", ""), iamerr.GetAPIError(iamerr.ErrSignatureDoesNotMatch)},
			{"long-term key with a security token", withCredentials(user, user.conf.awsID, user.conf.awsSecret, session.sessionToken), invalidToken},
			{"session key with another session's token", withCredentials(session, session.conf.awsID, session.conf.awsSecret, "wrong-token"), invalidToken},
			{"session key without its token", withCredentials(session, session.conf.awsID, session.conf.awsSecret, ""), invalidToken},
			{"session secret with the wrong key", withCredentials(session, "ASIA"+strings.ToUpper(genRandString(16)), session.conf.awsSecret, session.sessionToken), invalidToken},
		}
		for _, tc := range cases {
			_, err := assumeRoleAs(tc.caller, input())
			if err := checkIAMApiErr(err, tc.wantErr); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}

		if _, err := updateIAMAccessKey(root, &iam.UpdateAccessKeyInput{
			UserName: aws.String(user.name), AccessKeyId: aws.String(user.conf.awsID), Status: iamtypes.StatusTypeInactive,
		}); err != nil {
			return err
		}
		_, err = assumeRoleAs(user, input())
		if err := checkIAMApiErr(err, invalidToken); err != nil {
			return fmt.Errorf("inactive access key: %w", err)
		}

		if err := deleteIAMAccessKey(root, user.name, user.conf.awsID); err != nil {
			return err
		}
		_, err = assumeRoleAs(user, input())
		if err := checkIAMApiErr(err, invalidToken); err != nil {
			return fmt.Errorf("deleted access key: %w", err)
		}
		return nil
	})
}

// IAMAssumeRole_invalid_parameters covers the constraints on each parameter's
// shape. They are checked before anything about the caller or the role, so
// every case here is signed by the root account, which may never assume a
// role at all.
func IAMAssumeRole_invalid_parameters(s *S3Conf) error {
	testName := "IAMAssumeRole_invalid_parameters"
	return iamActionHandler(s, testName, func(_ *iam.Client) error {
		root := &s3IAMPrincipal{conf: *s}
		roleArn := roleArnFor("does-not-exist")

		cases := []struct {
			name    string
			input   *sts.AssumeRoleInput
			wantErr iamerr.Error
		}{
			{"empty role arn", &sts.AssumeRoleInput{RoleArn: aws.String("")}, iamerr.MissingValue("roleArn")},
			{"empty session name", &sts.AssumeRoleInput{RoleArn: &roleArn, RoleSessionName: aws.String("")}, iamerr.MissingValue("roleSessionName")},
			{"role arn too short", &sts.AssumeRoleInput{RoleArn: aws.String("short")}, iamerr.ValueTooShort("roleArn", 20)},
			{"role arn too long", &sts.AssumeRoleInput{RoleArn: aws.String(roleArn + strings.Repeat("a", 2049))}, iamerr.ValueTooLong("roleArn", 2048)},
			{"session name too short", &sts.AssumeRoleInput{RoleArn: &roleArn, RoleSessionName: aws.String("a")}, iamerr.ValueTooShort("roleSessionName", 2)},
			{"session name too long", &sts.AssumeRoleInput{RoleArn: &roleArn, RoleSessionName: aws.String(strings.Repeat("a", 65))}, iamerr.ValueTooLong("roleSessionName", 64)},
			{"session name with a slash", &sts.AssumeRoleInput{RoleArn: &roleArn, RoleSessionName: aws.String("a/b")}, iamerr.InvalidRoleSessionName("a/b")},
			{"session name with a space", &sts.AssumeRoleInput{RoleArn: &roleArn, RoleSessionName: aws.String("a b")}, iamerr.InvalidRoleSessionName("a b")},
			{"duration below the minimum", &sts.AssumeRoleInput{RoleArn: &roleArn, DurationSeconds: aws.Int32(899)}, iamerr.DurationSecondsTooLow("899")},
			{"duration above the maximum", &sts.AssumeRoleInput{RoleArn: &roleArn, DurationSeconds: aws.Int32(43201)}, iamerr.DurationSecondsTooHigh("43201")},
			{"empty external id", &sts.AssumeRoleInput{RoleArn: &roleArn, ExternalId: aws.String("")}, iamerr.ValueTooShort("externalId", 2)},
			{"external id too short", &sts.AssumeRoleInput{RoleArn: &roleArn, ExternalId: aws.String("a")}, iamerr.ValueTooShort("externalId", 2)},
			{"external id too long", &sts.AssumeRoleInput{RoleArn: &roleArn, ExternalId: aws.String(strings.Repeat("a", 1225))}, iamerr.ValueTooLong("externalId", 1224)},
			{"external id with a space", &sts.AssumeRoleInput{RoleArn: &roleArn, ExternalId: aws.String("a b")}, iamerr.InvalidExternalID("a b")},
			{"external id with a hash", &sts.AssumeRoleInput{RoleArn: &roleArn, ExternalId: aws.String("a#b")}, iamerr.InvalidExternalID("a#b")},
			{"empty session policy", &sts.AssumeRoleInput{RoleArn: &roleArn, Policy: aws.String("")}, iamerr.ValueTooShort("policy", 1)},
			{"session policy too long", &sts.AssumeRoleInput{RoleArn: &roleArn, Policy: aws.String(strings.Repeat("a", 2049))}, iamerr.ValueTooLong("policy", 2048)},
			{"session policy outside the allowed character set", &sts.AssumeRoleInput{RoleArn: &roleArn, Policy: aws.String("{\"Sid\":\"Ā\"}")}, iamerr.InvalidCharset("policy")},
		}
		for _, tc := range cases {
			_, err := assumeRoleAs(root, tc.input)
			if err := checkIAMApiErr(err, tc.wantErr); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// IAMAssumeRole_unsupported_parameters verifies the parameters that would
// change the resulting session, and that this service does not implement,
// are refused rather than accepted and ignored.
func IAMAssumeRole_unsupported_parameters(s *S3Conf) error {
	testName := "IAMAssumeRole_unsupported_parameters"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		caller, cleanup, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanup()
		_, roleArn, cleanupRole, err := newAssumableRole(root, trustAllowingAWS(caller.arn))
		if err != nil {
			return err
		}
		defer cleanupRole()

		cases := []struct {
			name  string
			input *sts.AssumeRoleInput
		}{
			{"PolicyArns", &sts.AssumeRoleInput{PolicyArns: []ststypes.PolicyDescriptorType{{Arn: aws.String("arn:aws:iam::aws:policy/ReadOnlyAccess")}}}},
			{"Tags", &sts.AssumeRoleInput{Tags: []ststypes.Tag{{Key: aws.String("team"), Value: aws.String("blue")}}}},
			{"TransitiveTagKeys", &sts.AssumeRoleInput{TransitiveTagKeys: []string{"team"}}},
			{"SourceIdentity", &sts.AssumeRoleInput{SourceIdentity: aws.String("alice")}},
			{"ProvidedContexts", &sts.AssumeRoleInput{ProvidedContexts: []ststypes.ProvidedContext{{
				ProviderArn: aws.String("arn:aws:iam::aws:contextProvider/IdentityCenter"), ContextAssertion: aws.String("assertion"),
			}}}},
		}
		for _, tc := range cases {
			tc.input.RoleArn = aws.String(roleArn)
			_, err := assumeRoleAs(caller, tc.input)
			if err := checkIAMApiErr(err, iamerr.UnsupportedParameter(tc.name)); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// IAMAssumeRole_root_refused verifies the root account can never assume a
// role, whatever the role's trust policy says and whether or not the role
// exists.
func IAMAssumeRole_root_refused(s *S3Conf) error {
	testName := "IAMAssumeRole_root_refused"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		_, roleArn, cleanupRole, err := newAssumableRole(root, trustAllowingAWS("*"))
		if err != nil {
			return err
		}
		defer cleanupRole()

		rootCaller := &s3IAMPrincipal{conf: *s}
		for name, arn := range map[string]string{
			"role trusting every principal": roleArn,
			"role that does not exist":      roleArnFor("does-not-exist"),
			"role arn that is not an arn":   "reader-role-by-its-name",
		} {
			_, err := assumeRoleAs(rootCaller, &sts.AssumeRoleInput{RoleArn: aws.String(arn)})
			if err := checkIAMApiErr(err, iamerr.AccessDeniedRootAssumeRole()); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
		return nil
	})
}

// IAMAssumeRole_role_arn_not_an_arn verifies a RoleArn that is not an ARN at
// all is a validation error, while one that is well-formed but names no role
// is an authorization failure.
func IAMAssumeRole_role_arn_not_an_arn(s *S3Conf) error {
	testName := "IAMAssumeRole_role_arn_not_an_arn"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		caller, cleanup, err := newS3IAMUser(root, s, map[string]string{"assume": allowAssumeAnyRole})
		if err != nil {
			return err
		}
		defer cleanup()

		for _, arn := range []string{
			"reader-role-by-its-name",
			"arn:aws:iam:" + testAccountID + ":role/reader",
			"urn:aws:iam::" + testAccountID + ":role/reader",
		} {
			_, err := assumeRoleAs(caller, &sts.AssumeRoleInput{RoleArn: aws.String(arn)})
			if err := checkIAMApiErr(err, iamerr.InvalidRoleArn(arn)); err != nil {
				return fmt.Errorf("%q: %w", arn, err)
			}
		}

		arn := "arn:aws:iam::" + testAccountID + ":not-a-role-resource"
		_, err = assumeRoleAs(caller, &sts.AssumeRoleInput{RoleArn: aws.String(arn)})
		return wantAssumeRoleDenied(caller, arn, err)
	})
}

// IAMAssumeRole_mfa_not_supported verifies MFA parameters are answered the
// way they are for a user that has no MFA device, which here is every user,
// and that this is reported even to a caller that could not have assumed the
// role anyway.
func IAMAssumeRole_mfa_not_supported(s *S3Conf) error {
	testName := "IAMAssumeRole_mfa_not_supported"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		trusted, cleanup, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanup()
		untrusted, cleanupUntrusted, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanupUntrusted()
		_, roleArn, cleanupRole, err := newAssumableRole(root, trustAllowingAWS(trusted.arn))
		if err != nil {
			return err
		}
		defer cleanupRole()

		serial := "arn:aws:iam::" + testAccountID + ":mfa/" + trusted.name
		cases := []struct {
			name    string
			caller  *s3IAMPrincipal
			input   *sts.AssumeRoleInput
			wantErr iamerr.Error
		}{
			{"serial number and token code", trusted, &sts.AssumeRoleInput{SerialNumber: &serial, TokenCode: aws.String("123456")}, iamerr.AccessDeniedMFAUnverifiable()},
			{"serial number alone", trusted, &sts.AssumeRoleInput{SerialNumber: &serial}, iamerr.AccessDeniedMFAIncomplete()},
			{"token code alone", trusted, &sts.AssumeRoleInput{TokenCode: aws.String("123456")}, iamerr.AccessDeniedMFAIncomplete()},
			{"untrusted caller", untrusted, &sts.AssumeRoleInput{SerialNumber: &serial, TokenCode: aws.String("123456")}, iamerr.AccessDeniedMFAUnverifiable()},
		}
		for _, tc := range cases {
			tc.input.RoleArn = aws.String(roleArn)
			_, err := assumeRoleAs(tc.caller, tc.input)
			if err := checkIAMApiErr(err, tc.wantErr); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// IAMAssumeRole_success verifies the response of a successful call, and that
// the credentials in it authenticate as the assumed-role session it
// describes.
func IAMAssumeRole_success(s *S3Conf) error {
	testName := "IAMAssumeRole_success"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		caller, cleanup, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanup()

		roleName := newIAMRoleName()
		createOut, err := createIAMRole(root, &iam.CreateRoleInput{
			RoleName:                 aws.String(roleName),
			Path:                     aws.String("/team/sub/"),
			AssumeRolePolicyDocument: aws.String(trustAllowingAWS(caller.arn)),
		})
		if err != nil {
			return err
		}
		defer deleteIAMRole(root, roleName)
		roleArn := aws.ToString(createOut.Role.Arn)

		before := time.Now().UTC().Truncate(time.Second)
		out, err := assumeRoleAs(caller, &sts.AssumeRoleInput{RoleArn: aws.String(roleArn), RoleSessionName: aws.String("a_+=,.@-Z9")})
		if err != nil {
			return err
		}
		if out.AssumedRoleUser == nil || out.Credentials == nil {
			return fmt.Errorf("expected AssumedRoleUser and Credentials in the response, got %#v", out)
		}

		// An assumed-role ARN carries the role's name but never its path.
		wantArn := assumedRoleArnFor(roleName, "a_+=,.@-Z9")
		if got := aws.ToString(out.AssumedRoleUser.Arn); got != wantArn {
			return fmt.Errorf("expected AssumedRoleUser.Arn %q, instead got %q", wantArn, got)
		}
		wantID := aws.ToString(createOut.Role.RoleId) + ":a_+=,.@-Z9"
		if got := aws.ToString(out.AssumedRoleUser.AssumedRoleId); got != wantID {
			return fmt.Errorf("expected AssumedRoleUser.AssumedRoleId %q, instead got %q", wantID, got)
		}

		access := aws.ToString(out.Credentials.AccessKeyId)
		secret := aws.ToString(out.Credentials.SecretAccessKey)
		token := aws.ToString(out.Credentials.SessionToken)
		if !strings.HasPrefix(access, "ASIA") || secret == "" || token == "" {
			return fmt.Errorf("expected a temporary access key, a secret and a session token, got access key %q", access)
		}
		// The session lasts an hour when no duration is asked for.
		wantExpiration := before.Add(time.Hour)
		if exp := aws.ToTime(out.Credentials.Expiration); exp.Before(wantExpiration) || exp.After(wantExpiration.Add(time.Minute)) {
			return fmt.Errorf("expected Expiration about %v, instead got %v", wantExpiration, exp)
		}

		callerOut, err := getCallerIdentityWithSessionCreds(*s, access, secret, token)
		if err != nil {
			return fmt.Errorf("GetCallerIdentity with the session credentials: %w", err)
		}
		if aws.ToString(callerOut.Arn) != wantArn || aws.ToString(callerOut.UserId) != wantID {
			return fmt.Errorf("expected GetCallerIdentity to report %q/%q, instead got %q/%q",
				wantArn, wantID, aws.ToString(callerOut.Arn), aws.ToString(callerOut.UserId))
		}
		return nil
	})
}

// IAMAssumeRole_response_wire_shape verifies the raw response a client
// parses: the STS namespace, the result's elements, PackedPolicySize only
// when a session policy was passed, and the request id.
func IAMAssumeRole_response_wire_shape(s *S3Conf) error {
	testName := "IAMAssumeRole_response_wire_shape"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		user, cleanup, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanup()
		roleName, roleArn, cleanupRole, err := newAssumableRole(root, trustAllowingAWS(user.arn))
		if err != nil {
			return err
		}
		defer cleanupRole()
		roleOut, err := getIAMRole(root, roleName)
		if err != nil {
			return err
		}
		roleID := aws.ToString(roleOut.Role.RoleId)

		sessionPolicy := policyDoc(accessStatement{Effect: "Allow", Action: actS3GetObject, Resource: "*"})
		for _, tc := range []struct {
			name       string
			params     url.Values
			wantPacked *int
		}{
			{"without a session policy", url.Values{}, nil},
			{"with a session policy", url.Values{"Policy": {sessionPolicy}}, aws.Int(len(sessionPolicy) * 100 / 2048)},
		} {
			tc.params.Set("RoleArn", roleArn)
			tc.params.Set("RoleSessionName", "wire-shape")
			out, raw, err := assumeRoleRaw(s, user, tc.params)
			if err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
			if out.XMLName.Space != iamerr.STSNamespace {
				return fmt.Errorf("%s: expected namespace %q, instead got %q", tc.name, iamerr.STSNamespace, out.XMLName.Space)
			}
			if got, want := out.Result.AssumedRoleUser.Arn, assumedRoleArnFor(roleName, "wire-shape"); got != want {
				return fmt.Errorf("%s: expected AssumedRoleUser.Arn %q, instead got %q", tc.name, want, got)
			}
			if got, want := out.Result.AssumedRoleUser.AssumedRoleId, roleID+":wire-shape"; got != want {
				return fmt.Errorf("%s: expected AssumedRoleUser.AssumedRoleId %q, instead got %q", tc.name, want, got)
			}
			creds := out.Result.Credentials
			if !strings.HasPrefix(creds.AccessKeyId, "ASIA") || creds.SecretAccessKey == "" || creds.SessionToken == "" {
				return fmt.Errorf("%s: expected a full set of temporary credentials, got access key %q", tc.name, creds.AccessKeyId)
			}
			if _, err := time.Parse(time.RFC3339, creds.Expiration); err != nil {
				return fmt.Errorf("%s: expected an RFC 3339 Expiration, instead got %q", tc.name, creds.Expiration)
			}
			switch {
			case tc.wantPacked == nil && strings.Contains(raw, "PackedPolicySize"):
				return fmt.Errorf("%s: expected no PackedPolicySize, instead got %s", tc.name, raw)
			case tc.wantPacked != nil && (out.Result.PackedPolicySize == nil || *out.Result.PackedPolicySize != *tc.wantPacked):
				return fmt.Errorf("%s: expected PackedPolicySize %d, instead got %v", tc.name, *tc.wantPacked, out.Result.PackedPolicySize)
			}
			if out.ResponseMetadata.RequestID == "" {
				return fmt.Errorf("%s: expected a request id", tc.name)
			}
		}
		return nil
	})
}

// IAMAssumeRole_presigned_url verifies AssumeRole can be called with
// query-string authentication, as a plain GET of a presigned URL, and that a
// presigned URL whose parameters were changed after signing is refused.
func IAMAssumeRole_presigned_url(s *S3Conf) error {
	testName := "IAMAssumeRole_presigned_url"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		user, cleanup, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanup()
		roleName, roleArn, cleanupRole, err := newAssumableRole(root, trustAllowingAWS(user.arn))
		if err != nil {
			return err
		}
		defer cleanupRole()

		cfg := user.conf.iamConfig()
		cfg.Credentials = credentials.NewStaticCredentialsProvider(user.conf.awsID, user.conf.awsSecret, "")
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		presigned, err := sts.NewPresignClient(sts.NewFromConfig(cfg)).PresignAssumeRole(ctx, &sts.AssumeRoleInput{
			RoleArn: aws.String(roleArn), RoleSessionName: aws.String("presigned"),
		})
		cancel()
		if err != nil {
			return fmt.Errorf("presign AssumeRole: %w", err)
		}

		resp, err := sendPresigned(s, presigned.Method, presigned.URL)
		if err != nil {
			return err
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("expected the presigned AssumeRole to succeed, instead got %d: %s", resp.StatusCode, body)
		}
		var out assumeRoleXMLResponse
		if err := xml.Unmarshal(body, &out); err != nil {
			return fmt.Errorf("parse AssumeRole response: %w: %s", err, body)
		}
		creds := out.Result.Credentials
		callerOut, err := getCallerIdentityWithSessionCreds(*s, creds.AccessKeyId, creds.SecretAccessKey, creds.SessionToken)
		if err != nil {
			return fmt.Errorf("GetCallerIdentity with the presigned call's credentials: %w", err)
		}
		if got, want := aws.ToString(callerOut.Arn), assumedRoleArnFor(roleName, "presigned"); got != want {
			return fmt.Errorf("expected the credentials to be %q, instead they are %q", want, got)
		}

		tampered, err := url.Parse(presigned.URL)
		if err != nil {
			return err
		}
		query := tampered.Query()
		query.Set("RoleSessionName", "tampered")
		tampered.RawQuery = query.Encode()
		resp, err = sendPresigned(s, presigned.Method, tampered.String())
		if err != nil {
			return err
		}
		if err := checkSTSApiErr(resp, iamerr.GetAPIError(iamerr.ErrSignatureDoesNotMatch)); err != nil {
			return fmt.Errorf("presigned URL changed after signing: %w", err)
		}
		return nil
	})
}

// IAMAssumeRole_unresolved_role_arn verifies a RoleArn that names no role is
// refused exactly as a role the caller is not trusted by, so the response
// never reveals whether a role exists.
func IAMAssumeRole_unresolved_role_arn(s *S3Conf) error {
	testName := "IAMAssumeRole_unresolved_role_arn"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		caller, cleanup, err := newS3IAMUser(root, s, map[string]string{"assume": allowAssumeAnyRole})
		if err != nil {
			return err
		}
		defer cleanup()

		roleName := newIAMRoleName()
		if _, err := createIAMRole(root, &iam.CreateRoleInput{
			RoleName:                 aws.String(roleName),
			Path:                     aws.String("/team/"),
			AssumeRolePolicyDocument: aws.String(trustAllowingAWS("*")),
		}); err != nil {
			return err
		}
		defer deleteIAMRole(root, roleName)

		prefix := "arn:aws:iam::" + testAccountID + ":role/"
		for name, arn := range map[string]string{
			"role that does not exist":  prefix + "does-not-exist",
			"role without its path":     prefix + roleName,
			"role with another path":    prefix + "other/" + roleName,
			"role name in another case": prefix + "team/" + strings.ToUpper(roleName),
			"role in another account":   "arn:aws:iam::111111111111:role/team/" + roleName,
			"another partition":         "arn:aws-cn:iam::" + testAccountID + ":role/team/" + roleName,
			"trailing slash":            prefix + "team/" + roleName + "/",
			"wildcard":                  prefix + "team/*",
			"user arn":                  caller.arn,
			"account arn":               accountArn(),
			"assumed-role arn":          assumedRoleArnFor(roleName, "session1"),
		} {
			_, err := assumeRoleAs(caller, &sts.AssumeRoleInput{RoleArn: aws.String(arn)})
			if err := wantAssumeRoleDenied(caller, arn, err); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}

		_, err = assumeRoleAs(caller, &sts.AssumeRoleInput{RoleArn: aws.String(prefix + "team/" + roleName)})
		return wantAssumeRoleAllowed(caller, prefix+"team/"+roleName, err)
	})
}

// IAMAssumeRole_account_trust_requires_identity_policy verifies a trust
// policy naming the account, by its root ARN or its bare id, only delegates:
// the caller's own identity policy has to allow sts:AssumeRole as well.
func IAMAssumeRole_account_trust_requires_identity_policy(s *S3Conf) error {
	testName := "IAMAssumeRole_account_trust_requires_identity_policy"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		allowed, cleanup, err := newS3IAMUser(root, s, map[string]string{"assume": allowAssumeAnyRole})
		if err != nil {
			return err
		}
		defer cleanup()
		bare, cleanupBare, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanupBare()

		for name, principal := range map[string]string{"account root arn": accountArn(), "bare account id": testAccountID} {
			if err := func() error {
				_, roleArn, cleanupRole, err := newAssumableRole(root, trustAllowingAWS(principal))
				if err != nil {
					return err
				}
				defer cleanupRole()

				_, err = assumeRoleAs(allowed, &sts.AssumeRoleInput{RoleArn: aws.String(roleArn)})
				if err := wantAssumeRoleAllowed(allowed, roleArn, err); err != nil {
					return err
				}
				_, err = assumeRoleAs(bare, &sts.AssumeRoleInput{RoleArn: aws.String(roleArn)})
				return wantAssumeRoleDenied(bare, roleArn, err)
			}(); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
		return nil
	})
}

// IAMAssumeRole_direct_trust_needs_no_identity_policy verifies a trust policy
// naming the calling user, or every principal, is sufficient on its own, and
// that an identity policy is never a substitute for trust.
func IAMAssumeRole_direct_trust_needs_no_identity_policy(s *S3Conf) error {
	testName := "IAMAssumeRole_direct_trust_needs_no_identity_policy"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		bare, cleanup, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanup()
		other, cleanupOther, err := newS3IAMUser(root, s, map[string]string{"assume": allowAssumeAnyRole})
		if err != nil {
			return err
		}
		defer cleanupOther()

		_, userTrusted, cleanupRole, err := newAssumableRole(root, trustAllowingAWS(bare.arn))
		if err != nil {
			return err
		}
		defer cleanupRole()
		_, starTrusted, cleanupStar, err := newAssumableRole(root, trustAllowingAWS("*"))
		if err != nil {
			return err
		}
		defer cleanupStar()
		_, severalTrusted, cleanupSeveral, err := newAssumableRole(root, trustAllowingAWS([]string{other.arn, bare.arn}))
		if err != nil {
			return err
		}
		defer cleanupSeveral()

		_, err = assumeRoleAs(bare, &sts.AssumeRoleInput{RoleArn: aws.String(userTrusted)})
		if err := wantAssumeRoleAllowed(bare, userTrusted, err); err != nil {
			return fmt.Errorf("trust names the user: %w", err)
		}
		_, err = assumeRoleAs(other, &sts.AssumeRoleInput{RoleArn: aws.String(userTrusted)})
		if err := wantAssumeRoleDenied(other, userTrusted, err); err != nil {
			return fmt.Errorf("trust names another user, caller holds an identity allow: %w", err)
		}
		_, err = assumeRoleAs(bare, &sts.AssumeRoleInput{RoleArn: aws.String(starTrusted)})
		if err := wantAssumeRoleAllowed(bare, starTrusted, err); err != nil {
			return fmt.Errorf("trust names every principal: %w", err)
		}
		_, err = assumeRoleAs(bare, &sts.AssumeRoleInput{RoleArn: aws.String(severalTrusted)})
		if err := wantAssumeRoleAllowed(bare, severalTrusted, err); err != nil {
			return fmt.Errorf("trust names the user among several: %w", err)
		}
		return nil
	})
}

// IAMAssumeRole_explicit_deny verifies a Deny on either side wins: in the
// caller's identity policy over a trust policy naming the caller, and in the
// trust policy over an identity Allow. A trust Deny naming the account hits
// every principal in it, a directly trusted one included.
func IAMAssumeRole_explicit_deny(s *S3Conf) error {
	testName := "IAMAssumeRole_explicit_deny"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		caller, cleanup, err := newS3IAMUser(root, s, map[string]string{"assume": allowAssumeAnyRole})
		if err != nil {
			return err
		}
		defer cleanup()
		bystander, cleanupBystander, err := newS3IAMUser(root, s, map[string]string{"assume": allowAssumeAnyRole})
		if err != nil {
			return err
		}
		defer cleanupBystander()

		accountAllow := trustStatement{Effect: "Allow", Principal: map[string]any{"AWS": accountArn()}, Action: actSTSAssumeRole}
		callerAllow := trustStatement{Effect: "Allow", Principal: map[string]any{"AWS": caller.arn}, Action: actSTSAssumeRole}

		_, trustDeniesCaller, cleanupA, err := newAssumableRole(root, trustDoc(accountAllow,
			trustStatement{Effect: "Deny", Principal: map[string]any{"AWS": caller.arn}, Action: actSTSAssumeRole}))
		if err != nil {
			return err
		}
		defer cleanupA()
		_, trustDeniesAccount, cleanupB, err := newAssumableRole(root, trustDoc(callerAllow,
			trustStatement{Effect: "Deny", Principal: map[string]any{"AWS": accountArn()}, Action: actSTSAssumeRole}))
		if err != nil {
			return err
		}
		defer cleanupB()
		_, identityDenied, cleanupC, err := newAssumableRole(root, trustDoc(callerAllow))
		if err != nil {
			return err
		}
		defer cleanupC()

		_, err = assumeRoleAs(caller, &sts.AssumeRoleInput{RoleArn: aws.String(trustDeniesCaller)})
		if err := wantAssumeRoleDenied(caller, trustDeniesCaller, err); err != nil {
			return fmt.Errorf("trust deny naming the caller: %w", err)
		}
		_, err = assumeRoleAs(bystander, &sts.AssumeRoleInput{RoleArn: aws.String(trustDeniesCaller)})
		if err := wantAssumeRoleAllowed(bystander, trustDeniesCaller, err); err != nil {
			return fmt.Errorf("trust deny naming someone else: %w", err)
		}
		_, err = assumeRoleAs(caller, &sts.AssumeRoleInput{RoleArn: aws.String(trustDeniesAccount)})
		if err := wantAssumeRoleDenied(caller, trustDeniesAccount, err); err != nil {
			return fmt.Errorf("trust deny naming the account: %w", err)
		}

		_, err = assumeRoleAs(caller, &sts.AssumeRoleInput{RoleArn: aws.String(identityDenied)})
		if err := wantAssumeRoleAllowed(caller, identityDenied, err); err != nil {
			return fmt.Errorf("before the identity deny: %w", err)
		}
		if err := putS3IAMUserPolicy(root, caller, "deny", policyDoc(accessStatement{
			Effect: "Deny", Action: actSTSAssumeRole, Resource: identityDenied,
		})); err != nil {
			return err
		}
		_, err = assumeRoleAs(caller, &sts.AssumeRoleInput{RoleArn: aws.String(identityDenied)})
		if err := wantAssumeRoleDenied(caller, identityDenied, err); err != nil {
			return fmt.Errorf("identity deny against a trust policy naming the caller: %w", err)
		}
		return nil
	})
}

// IAMAssumeRole_trust_statement_must_cover_the_caller verifies the trust
// statements that never let an IAM principal in: one for another action, and
// ones naming only a service or a web identity provider.
func IAMAssumeRole_trust_statement_must_cover_the_caller(s *S3Conf) error {
	testName := "IAMAssumeRole_trust_statement_must_cover_the_caller"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		caller, cleanup, err := newS3IAMUser(root, s, map[string]string{"assume": allowAssumeAnyRole})
		if err != nil {
			return err
		}
		defer cleanup()

		cases := []struct {
			name  string
			trust string
		}{
			{"statement for another action", trustDoc(trustStatement{
				Effect: "Allow", Principal: map[string]any{"AWS": "*"}, Action: "sts:AssumeRoleWithWebIdentity",
			})},
			{"service principal", trustDoc(trustStatement{
				Effect: "Allow", Principal: map[string]any{"Service": "sts.amazonaws.com"}, Action: actSTSAssumeRole,
			})},
			{"federated principal", trustDoc(trustStatement{
				Effect: "Allow", Principal: map[string]any{"Federated": oidcProviderArn(newIAMOIDCProviderURL())}, Action: actSTSAssumeRole,
			})},
			{"condition on the account principal that the caller does not meet", trustDoc(trustStatement{
				Effect: "Allow", Principal: map[string]any{"AWS": accountArn()}, Action: actSTSAssumeRole,
				Condition: cond("ArnEquals", "aws:PrincipalArn", userArnFor("someone-else")),
			})},
		}
		for _, tc := range cases {
			if err := func() error {
				_, roleArn, cleanupRole, err := newAssumableRole(root, tc.trust)
				if err != nil {
					return err
				}
				defer cleanupRole()
				_, err = assumeRoleAs(caller, &sts.AssumeRoleInput{RoleArn: aws.String(roleArn)})
				return wantAssumeRoleDenied(caller, roleArn, err)
			}(); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// IAMAssumeRole_identity_policy_resource_scoping verifies the identity
// policy's Resource is matched against the role's own ARN, path included.
func IAMAssumeRole_identity_policy_resource_scoping(s *S3Conf) error {
	testName := "IAMAssumeRole_identity_policy_resource_scoping"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		caller, cleanup, err := newS3IAMUser(root, s, map[string]string{"assume": policyDoc(accessStatement{
			Effect: "Allow", Action: actSTSAssumeRole, Resource: "arn:aws:iam::" + testAccountID + ":role/team/*",
		})})
		if err != nil {
			return err
		}
		defer cleanup()

		inPath := newIAMRoleName()
		inOut, err := createIAMRole(root, &iam.CreateRoleInput{
			RoleName: aws.String(inPath), Path: aws.String("/team/sub/"), AssumeRolePolicyDocument: aws.String(trustAllowingAWS(accountArn())),
		})
		if err != nil {
			return err
		}
		defer deleteIAMRole(root, inPath)
		_, outOfPath, cleanupRole, err := newAssumableRole(root, trustAllowingAWS(accountArn()))
		if err != nil {
			return err
		}
		defer cleanupRole()

		inArn := aws.ToString(inOut.Role.Arn)
		_, err = assumeRoleAs(caller, &sts.AssumeRoleInput{RoleArn: aws.String(inArn)})
		if err := wantAssumeRoleAllowed(caller, inArn, err); err != nil {
			return err
		}
		_, err = assumeRoleAs(caller, &sts.AssumeRoleInput{RoleArn: aws.String(outOfPath)})
		return wantAssumeRoleDenied(caller, outOfPath, err)
	})
}

// IAMAssumeRole_external_id verifies ExternalId is matched, case-sensitively,
// by a trust policy that asks for one, and ignored by one that does not.
func IAMAssumeRole_external_id(s *S3Conf) error {
	testName := "IAMAssumeRole_external_id"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		caller, cleanup, err := newS3IAMUser(root, s, map[string]string{"assume": allowAssumeAnyRole})
		if err != nil {
			return err
		}
		defer cleanup()

		_, required, cleanupRequired, err := newAssumableRole(root, trustDoc(trustStatement{
			Effect: "Allow", Principal: map[string]any{"AWS": accountArn()}, Action: actSTSAssumeRole,
			Condition: cond("StringEquals", "sts:ExternalId", "secret-123"),
		}))
		if err != nil {
			return err
		}
		defer cleanupRequired()
		_, deniedWithout, cleanupDenied, err := newAssumableRole(root, trustDoc(
			trustStatement{Effect: "Allow", Principal: map[string]any{"AWS": accountArn()}, Action: actSTSAssumeRole},
			trustStatement{
				Effect: "Deny", Principal: map[string]any{"AWS": "*"}, Action: actSTSAssumeRole,
				Condition: cond("StringNotEquals", "sts:ExternalId", "secret-123"),
			},
		))
		if err != nil {
			return err
		}
		defer cleanupDenied()
		_, open, cleanupOpen, err := newAssumableRole(root, trustAllowingAWS(accountArn()))
		if err != nil {
			return err
		}
		defer cleanupOpen()

		cases := []struct {
			name       string
			roleArn    string
			externalID *string
			allowed    bool
		}{
			{"required and missing", required, nil, false},
			{"required and wrong", required, aws.String("wrong-1"), false},
			{"required and in another case", required, aws.String("SECRET-123"), false},
			{"required and matching", required, aws.String("secret-123"), true},
			{"denied when missing", deniedWithout, nil, false},
			{"denied when wrong", deniedWithout, aws.String("wrong-1"), false},
			{"not denied when matching", deniedWithout, aws.String("secret-123"), true},
			{"not asked for and absent", open, nil, true},
			{"not asked for and present", open, aws.String("whatever"), true},
		}
		for _, tc := range cases {
			_, err := assumeRoleAs(caller, &sts.AssumeRoleInput{RoleArn: aws.String(tc.roleArn), ExternalId: tc.externalID})
			if err := wantAssumeRoleOutcome(caller, tc.roleArn, tc.allowed, err); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}

		// A trust statement naming one user and requiring an external id, the
		// way a credential-vending service is set up, needs no identity policy.
		vendor, cleanupVendor, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanupVendor()
		_, vended, cleanupVended, err := newAssumableRole(root, trustDoc(trustStatement{
			Effect: "Allow", Principal: map[string]any{"AWS": vendor.arn}, Action: actSTSAssumeRole,
			Condition: cond("StringEquals", "sts:ExternalId", "secret-123"),
		}))
		if err != nil {
			return err
		}
		defer cleanupVended()
		_, err = assumeRoleAs(vendor, &sts.AssumeRoleInput{RoleArn: aws.String(vended)})
		if err := wantAssumeRoleDenied(vendor, vended, err); err != nil {
			return fmt.Errorf("trusted user without the external id: %w", err)
		}
		_, err = assumeRoleAs(vendor, &sts.AssumeRoleInput{RoleArn: aws.String(vended), ExternalId: aws.String("secret-123")})
		if err := wantAssumeRoleAllowed(vendor, vended, err); err != nil {
			return fmt.Errorf("trusted user with the external id: %w", err)
		}
		return nil
	})
}

// IAMAssumeRole_role_session_name_condition verifies a trust policy can
// constrain the session name, here to the calling user's own name.
func IAMAssumeRole_role_session_name_condition(s *S3Conf) error {
	testName := "IAMAssumeRole_role_session_name_condition"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		caller, cleanup, err := newS3IAMUser(root, s, map[string]string{"assume": allowAssumeAnyRole})
		if err != nil {
			return err
		}
		defer cleanup()
		_, roleArn, cleanupRole, err := newAssumableRole(root, trustDoc(trustStatement{
			Effect: "Allow", Principal: map[string]any{"AWS": accountArn()}, Action: actSTSAssumeRole,
			Condition: cond("StringLike", "sts:RoleSessionName", "${aws:username}"),
		}))
		if err != nil {
			return err
		}
		defer cleanupRole()

		_, err = assumeRoleAs(caller, &sts.AssumeRoleInput{RoleArn: aws.String(roleArn), RoleSessionName: aws.String("someone-else")})
		if err := wantAssumeRoleDenied(caller, roleArn, err); err != nil {
			return fmt.Errorf("session named after someone else: %w", err)
		}
		_, err = assumeRoleAs(caller, &sts.AssumeRoleInput{RoleArn: aws.String(roleArn), RoleSessionName: aws.String(caller.name)})
		if err := wantAssumeRoleAllowed(caller, roleArn, err); err != nil {
			return fmt.Errorf("session named after the user: %w", err)
		}
		return nil
	})
}

// IAMAssumeRole_trust_policy_principal_conditions verifies the keys that
// describe the caller are visible to the trust policy: aws:PrincipalArn,
// aws:PrincipalType and aws:username for a user, and for a role session
// aws:PrincipalArn as the session's role ARN, not the session's own ARN.
func IAMAssumeRole_trust_policy_principal_conditions(s *S3Conf) error {
	testName := "IAMAssumeRole_trust_policy_principal_conditions"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		user, cleanup, err := newS3IAMUser(root, s, map[string]string{"assume": allowAssumeAnyRole})
		if err != nil {
			return err
		}
		defer cleanup()
		other, cleanupOther, err := newS3IAMUser(root, s, map[string]string{"assume": allowAssumeAnyRole})
		if err != nil {
			return err
		}
		defer cleanupOther()

		// A session of chainerName may assume any role that delegates to the
		// account.
		chainerName, chainerArn, cleanupChainer, err := newAssumableRole(root, trustAllowingAWS(user.arn))
		if err != nil {
			return err
		}
		defer cleanupChainer()
		if _, err := putIAMRolePolicy(root, &iam.PutRolePolicyInput{
			RoleName: aws.String(chainerName), PolicyName: aws.String("p"), PolicyDocument: aws.String(allowAssumeAnyRole),
		}); err != nil {
			return err
		}
		out, err := assumeRoleAs(user, &sts.AssumeRoleInput{RoleArn: aws.String(chainerArn), RoleSessionName: aws.String("first")})
		if err != nil {
			return err
		}
		session := roleSession(s, chainerName, out)

		accountTrust := func(condition json.RawMessage) string {
			return trustDoc(trustStatement{Effect: "Allow", Principal: map[string]any{"AWS": accountArn()}, Action: actSTSAssumeRole, Condition: condition})
		}
		cases := []struct {
			name    string
			trust   string
			caller  *s3IAMPrincipal
			allowed bool
		}{
			{"principal arn is the user", accountTrust(cond("ArnEquals", "aws:PrincipalArn", user.arn)), user, true},
			{"principal arn is another user", accountTrust(cond("ArnEquals", "aws:PrincipalArn", user.arn)), other, false},
			{"principal type of a user", accountTrust(cond("StringEquals", "aws:PrincipalType", "User")), user, true},
			{"principal type of a session", accountTrust(cond("StringEquals", "aws:PrincipalType", "AssumedRole")), session, true},
			{"user principal type does not cover a session", accountTrust(cond("StringEquals", "aws:PrincipalType", "User")), session, false},
			{"user name", accountTrust(cond("StringEquals", "aws:username", user.name)), user, true},
			{"another user's name", accountTrust(cond("StringEquals", "aws:username", user.name)), other, false},
			{"session's principal arn is its role", accountTrust(cond("ArnEquals", "aws:PrincipalArn", chainerArn)), session, true},
			{"session's principal arn is not its own arn", accountTrust(cond("ArnEquals", "aws:PrincipalArn", session.arn)), session, false},
		}
		for _, tc := range cases {
			if err := func() error {
				_, roleArn, cleanupRole, err := newAssumableRole(root, tc.trust)
				if err != nil {
					return err
				}
				defer cleanupRole()
				_, err = assumeRoleAs(tc.caller, &sts.AssumeRoleInput{RoleArn: aws.String(roleArn), RoleSessionName: aws.String("conditioned")})
				return wantAssumeRoleOutcome(tc.caller, roleArn, tc.allowed, err)
			}(); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// IAMAssumeRole_identity_policy_conditions verifies the request's own values
// and the role's tags are visible to the caller's identity policy, not just
// to the trust policy.
func IAMAssumeRole_identity_policy_conditions(s *S3Conf) error {
	testName := "IAMAssumeRole_identity_policy_conditions"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		taggedName := newIAMRoleName()
		taggedOut, err := createIAMRole(root, &iam.CreateRoleInput{
			RoleName: aws.String(taggedName), AssumeRolePolicyDocument: aws.String(trustAllowingAWS(accountArn())),
			Tags: []iamtypes.Tag{{Key: aws.String("team"), Value: aws.String("blue")}},
		})
		if err != nil {
			return err
		}
		defer deleteIAMRole(root, taggedName)
		tagged := aws.ToString(taggedOut.Role.Arn)
		_, plain, cleanupPlain, err := newAssumableRole(root, trustAllowingAWS(accountArn()))
		if err != nil {
			return err
		}
		defer cleanupPlain()

		caller, cleanup, err := newS3IAMUser(root, s, map[string]string{"assume": policyDoc(
			accessStatement{Sid: "tagged", Effect: "Allow", Action: actSTSAssumeRole, Resource: "*", Condition: cond("StringEquals", "iam:ResourceTag/team", "blue")},
			accessStatement{Sid: "external", Effect: "Allow", Action: actSTSAssumeRole, Resource: plain, Condition: cond("StringEquals", "sts:ExternalId", "identity-side")},
			accessStatement{Sid: "named", Effect: "Allow", Action: actSTSAssumeRole, Resource: plain, Condition: cond("StringEquals", "sts:RoleSessionName", "named")},
		)})
		if err != nil {
			return err
		}
		defer cleanup()

		cases := []struct {
			name    string
			input   *sts.AssumeRoleInput
			allowed bool
		}{
			{"role carries the tag the policy asks for", &sts.AssumeRoleInput{RoleArn: &tagged}, true},
			{"role lacks the tag", &sts.AssumeRoleInput{RoleArn: &plain}, false},
			{"external id the policy asks for", &sts.AssumeRoleInput{RoleArn: &plain, ExternalId: aws.String("identity-side")}, true},
			{"another external id", &sts.AssumeRoleInput{RoleArn: &plain, ExternalId: aws.String("other-side")}, false},
			{"session name the policy asks for", &sts.AssumeRoleInput{RoleArn: &plain, RoleSessionName: aws.String("named")}, true},
		}
		for _, tc := range cases {
			_, err := assumeRoleAs(caller, tc.input)
			if err := wantAssumeRoleOutcome(caller, aws.ToString(tc.input.RoleArn), tc.allowed, err); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// IAMAssumeRole_duration verifies the session lasts an hour by default
// whatever the role allows, up to the role's MaxSessionDuration on request,
// and never longer.
func IAMAssumeRole_duration(s *S3Conf) error {
	testName := "IAMAssumeRole_duration"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		caller, cleanup, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanup()

		roleName := newIAMRoleName()
		createOut, err := createIAMRole(root, &iam.CreateRoleInput{
			RoleName: aws.String(roleName), AssumeRolePolicyDocument: aws.String(trustAllowingAWS(caller.arn)),
			MaxSessionDuration: aws.Int32(7200),
		})
		if err != nil {
			return err
		}
		defer deleteIAMRole(root, roleName)
		roleArn := aws.ToString(createOut.Role.Arn)

		for _, tc := range []struct {
			name     string
			duration *int32
			want     time.Duration
		}{
			{"default", nil, time.Hour},
			{"minimum", aws.Int32(900), 15 * time.Minute},
			{"the role's maximum", aws.Int32(7200), 2 * time.Hour},
		} {
			before := time.Now().UTC().Truncate(time.Second)
			out, err := assumeRoleAs(caller, &sts.AssumeRoleInput{RoleArn: aws.String(roleArn), DurationSeconds: tc.duration})
			if err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
			want := before.Add(tc.want)
			if exp := aws.ToTime(out.Credentials.Expiration); exp.Before(want) || exp.After(want.Add(time.Minute)) {
				return fmt.Errorf("%s: expected Expiration about %v, instead got %v", tc.name, want, exp)
			}
		}

		_, err = assumeRoleAs(caller, &sts.AssumeRoleInput{RoleArn: aws.String(roleArn), DurationSeconds: aws.Int32(7201)})
		return checkIAMApiErr(err, iamerr.DurationExceedsMaxSessionDuration())
	})
}

// IAMAssumeRole_session_policy verifies an inline session policy narrows what
// the role allows, on the IAM API as much as anywhere else.
func IAMAssumeRole_session_policy(s *S3Conf) error {
	testName := "IAMAssumeRole_session_policy"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		caller, cleanup, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanup()
		roleName, roleArn, cleanupRole, err := newAssumableRole(root, trustAllowingAWS(caller.arn))
		if err != nil {
			return err
		}
		defer cleanupRole()
		if _, err := putIAMRolePolicy(root, &iam.PutRolePolicyInput{
			RoleName: aws.String(roleName), PolicyName: aws.String("p"),
			PolicyDocument: aws.String(policyDoc(accessStatement{Effect: "Allow", Action: []string{actGetUser, actListUsers}, Resource: "*"})),
		}); err != nil {
			return err
		}

		sessionPolicy := policyDoc(accessStatement{Effect: "Allow", Action: actListUsers, Resource: "*"})
		out, err := assumeRoleAs(caller, &sts.AssumeRoleInput{RoleArn: aws.String(roleArn), Policy: aws.String(sessionPolicy)})
		if err != nil {
			return err
		}

		narrowed := roleSession(s, roleName, out)
		narrowedIAM := iamClientWithCreds(s, narrowed.conf.awsID, narrowed.conf.awsSecret, narrowed.sessionToken)
		if _, err := listIAMUsers(narrowedIAM, &iam.ListUsersInput{}); err != nil {
			return fmt.Errorf("expected ListUsers to be allowed by both the role and the session policy: %w", err)
		}
		_, err = getIAMUser(narrowedIAM, &iam.GetUserInput{UserName: aws.String(caller.name)})
		if err := wantDenied(narrowed.arn, actGetUser, caller.arn, err); err != nil {
			return fmt.Errorf("the session policy does not list GetUser: %w", err)
		}

		// Without a session policy the role's own policies apply in full.
		out, err = assumeRoleAs(caller, &sts.AssumeRoleInput{RoleArn: aws.String(roleArn)})
		if err != nil {
			return err
		}
		full := roleSession(s, roleName, out)
		fullIAM := iamClientWithCreds(s, full.conf.awsID, full.conf.awsSecret, full.sessionToken)
		if _, err := getIAMUser(fullIAM, &iam.GetUserInput{UserName: aws.String(caller.name)}); err != nil {
			return fmt.Errorf("expected GetUser to be allowed by the role policy: %w", err)
		}
		return nil
	})
}

// IAMAssumeRole_session_policy_documents verifies which session policy
// documents are accepted. The accepted ones are shaped the way catalogs that
// vend scoped credentials generate them.
func IAMAssumeRole_session_policy_documents(s *S3Conf) error {
	testName := "IAMAssumeRole_session_policy_documents"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		caller, cleanup, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanup()
		_, roleArn, cleanupRole, err := newAssumableRole(root, trustAllowingAWS(caller.arn))
		if err != nil {
			return err
		}
		defer cleanupRole()

		cases := []struct {
			name     string
			document string
			wantErr  iamerr.APIError // nil means the document must be accepted
		}{
			{"table read and write scoped to a prefix", `{"Version":"2012-10-17","Statement":[` +
				`{"Effect":"Allow","Action":["s3:PutObject","s3:DeleteObject"],"Resource":"arn:aws:s3:::b/ns/t/*"},` +
				`{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::b","Condition":{"StringLike":{"s3:prefix":"ns/t/*"}}},` +
				`{"Effect":"Allow","Action":"s3:GetBucketLocation","Resource":"arn:aws:s3:::b"},` +
				`{"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":"arn:aws:s3:::b/ns/t/*"}]}`, nil},
			{"single statement as an object", `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"*","Resource":"*"}}`, nil},
			{"actions of a service this gateway does not offer", `{"Version":"2012-10-17","Statement":[` +
				`{"Effect":"Allow","Action":["kms:DescribeKey","kms:Decrypt"],"Resource":"arn:aws:kms:us-east-1:000000000000:key/*"}]}`, nil},
			{"statement ids and multipart actions", `{"Version":"2012-10-17","Statement":[` +
				`{"Sid":"TableAccess","Effect":"Allow","Action":["s3:GetObject","s3:PutObject","s3:DeleteObject","s3:AbortMultipartUpload","s3:ListMultipartUploadParts"],"Resource":"arn:aws:s3:::b/ns/t/*"},` +
				`{"Sid":"ListBucketForFolder","Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::b","Condition":{"StringLike":{"s3:prefix":"ns/t/*"}}}]}`, nil},
			{"several prefix patterns and a wildcard inside a resource", `{"Version":"2012-10-17","Statement":[` +
				`{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::b","Condition":{"StringLike":{"s3:prefix":["ns/t","ns/t/*","*/ns/t","*/ns/t/*"]}}},` +
				`{"Effect":"Allow","Action":"s3:GetObject","Resource":["arn:aws:s3:::b/ns/t/*","arn:aws:s3:::b/*/ns/t/*"]}]}`, nil},
			{"no version", `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`, nil},

			{"not json", `not json`, iamerr.MalformedPolicyDocument("Syntax errors in policy.")},
			{"no statement", `{"Version":"2012-10-17"}`, iamerr.MalformedPolicyDocument("Syntax errors in policy.")},
			{"unknown version", `{"Version":"2020-01-01","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`, iamerr.MalformedPolicyDocument("Syntax errors in policy.")},
			{"principal", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}]}`, iamerr.MalformedPolicyDocument("Policy document should not specify a principal.")},
			{"no resource", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject"}]}`, iamerr.MalformedPolicyDocument("Policy statement must contain resources.")},
			{"no action", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Resource":"*"}]}`, iamerr.MalformedPolicyDocument("Policy statement must contain actions.")},
			{"action without a service prefix", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"GetObject","Resource":"*"}]}`, iamerr.MalformedPolicyDocument("Actions/Conditions must be prefaced by a vendor, e.g., iam, sdb, ec2, etc.")},
		}
		for _, tc := range cases {
			_, err := assumeRoleAs(caller, &sts.AssumeRoleInput{RoleArn: aws.String(roleArn), Policy: aws.String(tc.document)})
			if tc.wantErr == nil {
				if err != nil {
					return fmt.Errorf("%s: expected the session policy to be accepted: %w", tc.name, err)
				}
				continue
			}
			if err := checkIAMApiErr(err, tc.wantErr); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// IAMAssumeRole_error_precedence verifies which error a request that fails
// more than one check gets: the caller learns it is not authorized before it
// learns anything about the role's limits or its own session policy, and the
// duration is reported before the session policy's grammar.
func IAMAssumeRole_error_precedence(s *S3Conf) error {
	testName := "IAMAssumeRole_error_precedence"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		trusted, cleanup, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanup()
		untrusted, cleanupUntrusted, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanupUntrusted()
		_, roleArn, cleanupRole, err := newAssumableRole(root, trustAllowingAWS(trusted.arn))
		if err != nil {
			return err
		}
		defer cleanupRole()

		// The role's default MaxSessionDuration is 3600.
		_, err = assumeRoleAs(untrusted, &sts.AssumeRoleInput{RoleArn: aws.String(roleArn), DurationSeconds: aws.Int32(7200)})
		if err := wantAssumeRoleDenied(untrusted, roleArn, err); err != nil {
			return fmt.Errorf("untrusted caller asking for too long a session: %w", err)
		}
		_, err = assumeRoleAs(untrusted, &sts.AssumeRoleInput{RoleArn: aws.String(roleArn), Policy: aws.String("not json")})
		if err := wantAssumeRoleDenied(untrusted, roleArn, err); err != nil {
			return fmt.Errorf("untrusted caller sending a malformed session policy: %w", err)
		}
		missing := roleArnFor("does-not-exist")
		_, err = assumeRoleAs(trusted, &sts.AssumeRoleInput{RoleArn: aws.String(missing), Policy: aws.String("not json")})
		if err := wantAssumeRoleDenied(trusted, missing, err); err != nil {
			return fmt.Errorf("malformed session policy for a role that does not exist: %w", err)
		}
		_, err = assumeRoleAs(trusted, &sts.AssumeRoleInput{RoleArn: aws.String(roleArn), DurationSeconds: aws.Int32(7200), Policy: aws.String("not json")})
		if err := checkIAMApiErr(err, iamerr.DurationExceedsMaxSessionDuration()); err != nil {
			return fmt.Errorf("too long a session and a malformed session policy: %w", err)
		}
		return nil
	})
}

// IAMAssumeRole_role_chaining covers a role session assuming another role.
// What it needs depends on how the target's trust policy names it: by its
// role, by the session itself, or only through the account.
func IAMAssumeRole_role_chaining(s *S3Conf) error {
	testName := "IAMAssumeRole_role_chaining"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		user, cleanup, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanup()

		// plain has no policy of its own; chainer may assume any role.
		plainName, plainArn, cleanupPlain, err := newAssumableRole(root, trustAllowingAWS(user.arn))
		if err != nil {
			return err
		}
		defer cleanupPlain()
		chainerName, chainerArn, cleanupChainer, err := newAssumableRole(root, trustAllowingAWS(user.arn))
		if err != nil {
			return err
		}
		defer cleanupChainer()
		if _, err := putIAMRolePolicy(root, &iam.PutRolePolicyInput{
			RoleName: aws.String(chainerName), PolicyName: aws.String("p"), PolicyDocument: aws.String(allowAssumeAnyRole),
		}); err != nil {
			return err
		}

		_, trustsRole, cleanupA, err := newAssumableRole(root, trustAllowingAWS(plainArn))
		if err != nil {
			return err
		}
		defer cleanupA()
		_, trustsSession, cleanupB, err := newAssumableRole(root, trustAllowingAWS(assumedRoleArnFor(plainName, "first")))
		if err != nil {
			return err
		}
		defer cleanupB()
		_, trustsAccount, cleanupC, err := newAssumableRole(root, trustAllowingAWS(accountArn()))
		if err != nil {
			return err
		}
		defer cleanupC()
		_, trustsUser, cleanupD, err := newAssumableRole(root, trustAllowingAWS(user.arn))
		if err != nil {
			return err
		}
		defer cleanupD()

		session := func(roleName, roleArn, sessionName string) (*s3IAMPrincipal, error) {
			out, err := assumeRoleAs(user, &sts.AssumeRoleInput{RoleArn: aws.String(roleArn), RoleSessionName: aws.String(sessionName)})
			if err != nil {
				return nil, fmt.Errorf("assume %s as %s: %w", roleName, sessionName, err)
			}
			return roleSession(s, roleName, out), nil
		}
		plainFirst, err := session(plainName, plainArn, "first")
		if err != nil {
			return err
		}
		plainSecond, err := session(plainName, plainArn, "second")
		if err != nil {
			return err
		}
		chainer, err := session(chainerName, chainerArn, "first")
		if err != nil {
			return err
		}

		cases := []struct {
			name    string
			caller  *s3IAMPrincipal
			roleArn string
			allowed bool
		}{
			{"trust names the session's role", plainFirst, trustsRole, true},
			{"trust names the role, so any session of it", plainSecond, trustsRole, true},
			{"trust names the session itself", plainFirst, trustsSession, true},
			{"trust names another session of the role", plainSecond, trustsSession, false},
			{"trust names the account and the role allows nothing", plainFirst, trustsAccount, false},
			{"trust names the account and the role allows it", chainer, trustsAccount, true},
			{"trust names a user, which a session never is", chainer, trustsUser, false},
			{"a role is not implicitly trusted by itself", plainFirst, plainArn, false},
		}
		for _, tc := range cases {
			_, err := assumeRoleAs(tc.caller, &sts.AssumeRoleInput{RoleArn: aws.String(tc.roleArn), RoleSessionName: aws.String("chained")})
			if err := wantAssumeRoleOutcome(tc.caller, tc.roleArn, tc.allowed, err); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}

		// The chained session is a session of the target role in its own right.
		out, err := assumeRoleAs(plainFirst, &sts.AssumeRoleInput{RoleArn: aws.String(trustsRole), RoleSessionName: aws.String("chained")})
		if err != nil {
			return err
		}
		callerOut, err := getCallerIdentityWithSessionCreds(*s, aws.ToString(out.Credentials.AccessKeyId),
			aws.ToString(out.Credentials.SecretAccessKey), aws.ToString(out.Credentials.SessionToken))
		if err != nil {
			return fmt.Errorf("GetCallerIdentity with the chained session credentials: %w", err)
		}
		if aws.ToString(callerOut.Arn) != aws.ToString(out.AssumedRoleUser.Arn) {
			return fmt.Errorf("expected GetCallerIdentity to report %q, instead got %q", aws.ToString(out.AssumedRoleUser.Arn), aws.ToString(callerOut.Arn))
		}
		return nil
	})
}

// IAMAssumeRole_role_chaining_session_policy verifies how the calling
// session's own session policy bears on role chaining. It limits a grant made
// to the session's role or to the account, but not one made to the session
// by name or to every principal, and a Deny in it always holds.
func IAMAssumeRole_role_chaining_session_policy(s *S3Conf) error {
	testName := "IAMAssumeRole_role_chaining_session_policy"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		user, cleanup, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanup()

		callerName, callerArn, cleanupCaller, err := newAssumableRole(root, trustAllowingAWS(user.arn))
		if err != nil {
			return err
		}
		defer cleanupCaller()
		if _, err := putIAMRolePolicy(root, &iam.PutRolePolicyInput{
			RoleName: aws.String(callerName), PolicyName: aws.String("p"), PolicyDocument: aws.String(allowAssumeAnyRole),
		}); err != nil {
			return err
		}

		_, trustsRole, cleanupA, err := newAssumableRole(root, trustAllowingAWS(callerArn))
		if err != nil {
			return err
		}
		defer cleanupA()
		_, trustsSession, cleanupB, err := newAssumableRole(root, trustAllowingAWS(assumedRoleArnFor(callerName, "first")))
		if err != nil {
			return err
		}
		defer cleanupB()
		_, trustsEveryone, cleanupC, err := newAssumableRole(root, trustAllowingAWS("*"))
		if err != nil {
			return err
		}
		defer cleanupC()
		_, trustsAccount, cleanupD, err := newAssumableRole(root, trustAllowingAWS(accountArn()))
		if err != nil {
			return err
		}
		defer cleanupD()

		session := func(sessionPolicy string) (*s3IAMPrincipal, error) {
			out, err := assumeRoleAs(user, &sts.AssumeRoleInput{
				RoleArn: aws.String(callerArn), RoleSessionName: aws.String("first"), Policy: aws.String(sessionPolicy),
			})
			if err != nil {
				return nil, err
			}
			return roleSession(s, callerName, out), nil
		}
		s3Only, err := session(policyDoc(accessStatement{Effect: "Allow", Action: actS3GetObject, Resource: "*"}))
		if err != nil {
			return err
		}
		stsAllowed, err := session(policyDoc(accessStatement{Effect: "Allow", Action: actSTSAssumeRole, Resource: "*"}))
		if err != nil {
			return err
		}
		stsDenied, err := session(policyDoc(
			accessStatement{Effect: "Allow", Action: "*", Resource: "*"},
			accessStatement{Effect: "Deny", Action: actSTSAssumeRole, Resource: "*"},
		))
		if err != nil {
			return err
		}

		cases := []struct {
			name    string
			caller  *s3IAMPrincipal
			roleArn string
			allowed bool
		}{
			{"role trust, session policy without sts:AssumeRole", s3Only, trustsRole, false},
			{"role trust, session policy with sts:AssumeRole", stsAllowed, trustsRole, true},
			{"session trust is not limited by the session policy", s3Only, trustsSession, true},
			{"wildcard trust is not limited by the session policy", s3Only, trustsEveryone, true},
			{"account trust, session policy without sts:AssumeRole", s3Only, trustsAccount, false},
			{"account trust, session policy with sts:AssumeRole", stsAllowed, trustsAccount, true},
			{"session trust still yields to a session policy deny", stsDenied, trustsSession, false},
			{"wildcard trust still yields to a session policy deny", stsDenied, trustsEveryone, false},
		}
		for _, tc := range cases {
			_, err := assumeRoleAs(tc.caller, &sts.AssumeRoleInput{RoleArn: aws.String(tc.roleArn), RoleSessionName: aws.String("chained")})
			if err := wantAssumeRoleOutcome(tc.caller, tc.roleArn, tc.allowed, err); err != nil {
				return fmt.Errorf("%s: %w", tc.name, err)
			}
		}
		return nil
	})
}

// IAMAssumeRole_role_chaining_duration_limit verifies a session obtained by
// role chaining lasts an hour at most, even where the target role allows
// longer and an IAM user could have asked for it.
func IAMAssumeRole_role_chaining_duration_limit(s *S3Conf) error {
	testName := "IAMAssumeRole_role_chaining_duration_limit"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		user, cleanup, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanup()
		callerName, callerArn, cleanupCaller, err := newAssumableRole(root, trustAllowingAWS(user.arn))
		if err != nil {
			return err
		}
		defer cleanupCaller()

		targetName := newIAMRoleName()
		targetOut, err := createIAMRole(root, &iam.CreateRoleInput{
			RoleName:                 aws.String(targetName),
			AssumeRolePolicyDocument: aws.String(trustAllowingAWS([]string{user.arn, callerArn})),
			MaxSessionDuration:       aws.Int32(7200),
		})
		if err != nil {
			return err
		}
		defer deleteIAMRole(root, targetName)
		target := aws.ToString(targetOut.Role.Arn)

		out, err := assumeRoleAs(user, &sts.AssumeRoleInput{RoleArn: aws.String(callerArn)})
		if err != nil {
			return err
		}
		session := roleSession(s, callerName, out)

		if _, err := assumeRoleAs(session, &sts.AssumeRoleInput{RoleArn: aws.String(target), DurationSeconds: aws.Int32(3600)}); err != nil {
			return fmt.Errorf("expected a chained session of an hour to be allowed: %w", err)
		}
		_, err = assumeRoleAs(session, &sts.AssumeRoleInput{RoleArn: aws.String(target), DurationSeconds: aws.Int32(3601)})
		if err := checkIAMApiErr(err, iamerr.DurationExceedsRoleChainingLimit()); err != nil {
			return fmt.Errorf("chained session of more than an hour: %w", err)
		}
		// The role's own maximum is reported first.
		_, err = assumeRoleAs(session, &sts.AssumeRoleInput{RoleArn: aws.String(target), DurationSeconds: aws.Int32(7201)})
		if err := checkIAMApiErr(err, iamerr.DurationExceedsMaxSessionDuration()); err != nil {
			return fmt.Errorf("chained session of more than the role allows: %w", err)
		}
		if _, err := assumeRoleAs(user, &sts.AssumeRoleInput{RoleArn: aws.String(target), DurationSeconds: aws.Int32(7200)}); err != nil {
			return fmt.Errorf("expected a user to get the role's full duration: %w", err)
		}
		return nil
	})
}

// IAMAssumeRole_session_of_deleted_role verifies a session that has
// outlived its role can assume no role at all, not even one whose trust
// policy names every principal, and that recreating the role under the same
// name does not hand its old sessions the trust the new one was given.
func IAMAssumeRole_session_of_deleted_role(s *S3Conf) error {
	testName := "IAMAssumeRole_session_of_deleted_role"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		user, cleanup, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanup()

		callerName := newIAMRoleName()
		callerTrust := trustAllowingAWS(user.arn)
		createOut, err := createIAMRole(root, &iam.CreateRoleInput{RoleName: aws.String(callerName), AssumeRolePolicyDocument: aws.String(callerTrust)})
		if err != nil {
			return err
		}
		defer deleteIAMRole(root, callerName)
		callerArn := aws.ToString(createOut.Role.Arn)

		_, namesRole, cleanupNamesRole, err := newAssumableRole(root, trustAllowingAWS(callerArn))
		if err != nil {
			return err
		}
		defer cleanupNamesRole()
		_, everyone, cleanupEveryone, err := newAssumableRole(root, trustAllowingAWS("*"))
		if err != nil {
			return err
		}
		defer cleanupEveryone()

		out, err := assumeRoleAs(user, &sts.AssumeRoleInput{RoleArn: aws.String(callerArn)})
		if err != nil {
			return err
		}
		stale := roleSession(s, callerName, out)
		wantOutcomes := func(when string, allowed bool) error {
			for _, target := range []string{namesRole, everyone} {
				_, err := assumeRoleAs(stale, &sts.AssumeRoleInput{RoleArn: aws.String(target)})
				if err := wantAssumeRoleOutcome(stale, target, allowed, err); err != nil {
					return fmt.Errorf("%s: %w", when, err)
				}
			}
			return nil
		}

		if err := wantOutcomes("while the role exists", true); err != nil {
			return err
		}

		if err := deleteIAMRole(root, callerName); err != nil {
			return err
		}
		if err := wantOutcomes("after the role was deleted", false); err != nil {
			return err
		}

		if _, err := createIAMRole(root, &iam.CreateRoleInput{RoleName: aws.String(callerName), AssumeRolePolicyDocument: aws.String(callerTrust)}); err != nil {
			return err
		}
		return wantOutcomes("after the role was recreated", false)
	})
}

// IAMAssumeRole_trust_policy_update_takes_effect verifies a change to a
// role's trust policy decides the very next AssumeRole call, while a session
// minted before it keeps working until it expires.
func IAMAssumeRole_trust_policy_update_takes_effect(s *S3Conf) error {
	testName := "IAMAssumeRole_trust_policy_update_takes_effect"
	return iamActionHandler(s, testName, func(root *iam.Client) error {
		user, cleanup, err := newS3IAMUser(root, s, nil)
		if err != nil {
			return err
		}
		defer cleanup()
		roleName, roleArn, cleanupRole, err := newAssumableRole(root, trustAllowingAWS(accountArn()))
		if err != nil {
			return err
		}
		defer cleanupRole()

		_, err = assumeRoleAs(user, &sts.AssumeRoleInput{RoleArn: aws.String(roleArn)})
		if err := wantAssumeRoleDenied(user, roleArn, err); err != nil {
			return fmt.Errorf("before the trust policy names the user: %w", err)
		}

		if _, err := updateIAMAssumeRolePolicy(root, &iam.UpdateAssumeRolePolicyInput{
			RoleName: aws.String(roleName), PolicyDocument: aws.String(trustAllowingAWS(user.arn)),
		}); err != nil {
			return err
		}
		out, err := assumeRoleAs(user, &sts.AssumeRoleInput{RoleArn: aws.String(roleArn)})
		if err := wantAssumeRoleAllowed(user, roleArn, err); err != nil {
			return fmt.Errorf("after the trust policy names the user: %w", err)
		}

		if _, err := updateIAMAssumeRolePolicy(root, &iam.UpdateAssumeRolePolicyInput{
			RoleName: aws.String(roleName), PolicyDocument: aws.String(trustAllowingAWS(accountArn())),
		}); err != nil {
			return err
		}
		_, err = assumeRoleAs(user, &sts.AssumeRoleInput{RoleArn: aws.String(roleArn)})
		if err := wantAssumeRoleDenied(user, roleArn, err); err != nil {
			return fmt.Errorf("after the trust policy stops naming the user: %w", err)
		}

		if _, err := getCallerIdentityWithSessionCreds(*s, aws.ToString(out.Credentials.AccessKeyId),
			aws.ToString(out.Credentials.SecretAccessKey), aws.ToString(out.Credentials.SessionToken)); err != nil {
			return fmt.Errorf("expected the session minted earlier to keep working: %w", err)
		}
		return nil
	})
}

// assumeRoleRawConfig builds an authConfig for a hand-built AssumeRole
// request signed by the root account, for the cases an SDK client refuses to
// send. params need not carry Action or Version.
func assumeRoleRawConfig(testName string, params url.Values) *authConfig {
	params.Set("Action", "AssumeRole")
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

// trustAllowingAWS is a trust policy with one statement allowing principal,
// a single AWS principal or a []string of them, to call sts:AssumeRole.
func trustAllowingAWS(principal any) string {
	return trustDoc(trustStatement{Effect: "Allow", Principal: map[string]any{"AWS": principal}, Action: actSTSAssumeRole})
}

// newAssumableRole creates a role in the default path with the given trust
// policy, and returns its name, its ARN and a cleanup func removing it along
// with any inline policy a test put on it.
func newAssumableRole(root *iam.Client, trust string) (roleName, roleArn string, cleanup func(), err error) {
	roleName = newIAMRoleName()
	out, err := createIAMRole(root, &iam.CreateRoleInput{RoleName: aws.String(roleName), AssumeRolePolicyDocument: aws.String(trust)})
	if err != nil {
		return "", "", nil, fmt.Errorf("create role: %w", err)
	}
	return roleName, aws.ToString(out.Role.Arn), func() { deleteIAMRoleAndPolicies(root, roleName) }, nil
}

// assumeRoleAs calls AssumeRole signed with caller's credentials: an IAM
// user's access key, a role session's temporary credentials, or the root
// account's. The session is named "session1" unless input says otherwise.
func assumeRoleAs(caller *s3IAMPrincipal, input *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
	if input.RoleSessionName == nil {
		input.RoleSessionName = aws.String("session1")
	}
	cfg := caller.conf.iamConfig()
	cfg.Credentials = credentials.NewStaticCredentialsProvider(caller.conf.awsID, caller.conf.awsSecret, caller.sessionToken)

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return sts.NewFromConfig(cfg).AssumeRole(ctx, input)
}

// roleSession is the principal the credentials in out authenticate as: a
// session of roleName, which is also what the returned principal's name is.
func roleSession(s *S3Conf, roleName string, out *sts.AssumeRoleOutput) *s3IAMPrincipal {
	access := aws.ToString(out.Credentials.AccessKeyId)
	secret := aws.ToString(out.Credentials.SecretAccessKey)
	token := aws.ToString(out.Credentials.SessionToken)

	conf := *s
	conf.awsID = access
	conf.awsSecret = secret

	return &s3IAMPrincipal{
		name:         roleName,
		arn:          aws.ToString(out.AssumedRoleUser.Arn),
		conf:         conf,
		client:       s3ClientWithSessionCreds(s, access, secret, token),
		sessionToken: token,
	}
}

// wantAssumeRoleAllowed reports a descriptive error if err is non-nil.
func wantAssumeRoleAllowed(caller *s3IAMPrincipal, roleArn string, err error) error {
	if err != nil {
		return fmt.Errorf("caller=%s role=%s: expected ALLOW, got error: %v", caller.arn, roleArn, err)
	}
	return nil
}

// wantAssumeRoleDenied asserts err is exactly the error AssumeRole reports
// for every authorization failure, naming caller and the RoleArn as sent.
func wantAssumeRoleDenied(caller *s3IAMPrincipal, roleArn string, err error) error {
	if cerr := checkIAMApiErr(err, iamerr.AccessDeniedAssumeRole(caller.arn, roleArn)); cerr != nil {
		return fmt.Errorf("caller=%s role=%s: expected DENY: %w", caller.arn, roleArn, cerr)
	}
	return nil
}

func wantAssumeRoleOutcome(caller *s3IAMPrincipal, roleArn string, allowed bool, err error) error {
	if allowed {
		return wantAssumeRoleAllowed(caller, roleArn, err)
	}
	return wantAssumeRoleDenied(caller, roleArn, err)
}

// withCredentials is caller signing with access, secret and token instead
// of its own credentials.
func withCredentials(caller *s3IAMPrincipal, access, secret, token string) *s3IAMPrincipal {
	conf := caller.conf
	conf.awsID = access
	conf.awsSecret = secret
	return &s3IAMPrincipal{name: caller.name, arn: caller.arn, conf: conf, sessionToken: token}
}

// assumeRoleXMLResponse is the AssumeRole response as it is on the wire.
type assumeRoleXMLResponse struct {
	XMLName xml.Name `xml:"AssumeRoleResponse"`
	Result  struct {
		AssumedRoleUser struct {
			AssumedRoleId string
			Arn           string
		}
		Credentials struct {
			AccessKeyId     string
			SecretAccessKey string
			SessionToken    string
			Expiration      string
		}
		PackedPolicySize *int
	} `xml:"AssumeRoleResult"`
	ResponseMetadata struct {
		RequestID string `xml:"RequestId"`
	}
}

// assumeRoleRaw sends an AssumeRole request with params, signed by caller,
// and returns both the parsed response and its raw body.
func assumeRoleRaw(s *S3Conf, caller *s3IAMPrincipal, params url.Values) (*assumeRoleXMLResponse, string, error) {
	params.Set("Action", "AssumeRole")
	params.Set("Version", "2011-06-15")
	req, err := createSignedReq(http.MethodPost, s.endpoint, "", caller.conf.awsID, caller.conf.awsSecret, "sts", iamAuthRegion, "",
		[]byte(params.Encode()), time.Now().UTC(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if err != nil {
		return nil, "", err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("expected AssumeRole to succeed, instead got %d: %s", resp.StatusCode, body)
	}
	var out assumeRoleXMLResponse
	if err := xml.Unmarshal(body, &out); err != nil {
		return nil, "", fmt.Errorf("parse AssumeRole response: %w: %s", err, body)
	}
	return &out, string(body), nil
}

// sendPresigned sends a presigned request with no credentials of its own.
func sendPresigned(s *S3Conf, method, rawURL string) (*http.Response, error) {
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		return nil, err
	}
	return s.httpClient.Do(req)
}
