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
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/iamapi/storage"
)

// validOIDCThumbprint is a syntactically valid (40 hex chars) thumbprint
// used whenever a test needs a ThumbprintList entry but isn't specifically
// exercising thumbprint validation.
const validOIDCThumbprint = "6938fd4d98bab03faadb97b34396831e3780aea1"

func IAMCreateOpenIDConnectProvider_missing_url(s *S3Conf) error {
	testName := "IAMCreateOpenIDConnectProvider_missing_url"
	body := []byte(url.Values{
		"Action":  {"CreateOpenIDConnectProvider"},
		"Version": {"2010-05-08"},
	}.Encode())
	return authHandler(s, &authConfig{
		testName: testName,
		method:   http.MethodPost,
		service:  "iam",
		region:   iamAuthRegion,
		body:     body,
		date:     time.Now().UTC(),
		headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
	}, func(req *http.Request) error {
		return checkIAMAuthRequest(s, req, iamerr.MissingValue("url"))
	})
}

func IAMCreateOpenIDConnectProvider_invalid_url(s *S3Conf) error {
	testName := "IAMCreateOpenIDConnectProvider_invalid_url"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		for _, tt := range []struct {
			name string
			url  string
			want iamerr.Error
		}{
			{"no_scheme", "example.com", iamerr.ValidationError("Invalid Open ID Connect Provider URL")},
			{"wrong_scheme", "http://example.com", iamerr.InvalidInput("Invalid Open ID Connect Provider URL. The URL must begin with https://.")},
			{"empty_host", "https://", iamerr.ValidationError("Invalid Open ID Connect Provider URL")},
			{"userinfo", "https://user:pass@example.com", iamerr.InvalidInput("Invalid Open ID Connect Provider URL.")},
			{"query_params", "https://example.com?foo=1", iamerr.InvalidInput("Invalid Open ID Connect Provider URL.")},
			{"fragment", "https://example.com#frag", iamerr.InvalidInput("Invalid Open ID Connect Provider URL.")},
			{"explicit_port", "https://example.com:8443", iamerr.InvalidInput("Invalid Open ID Connect Provider URL.")},
			{"invalid_hostname_chars", "https://exa_mple.com", iamerr.InvalidInput("Invalid Open ID Connect Provider URL.")},
			{"too_long", "https://" + strings.Repeat("a", 250) + ".com", iamerr.ValueTooLong("url", 255)},
		} {
			_, err := createOIDCProvider(client, &iam.CreateOpenIDConnectProviderInput{Url: aws.String(tt.url)})
			if checkErr := checkIAMApiErr(err, tt.want); checkErr != nil {
				return fmt.Errorf("%s: %w", tt.name, checkErr)
			}
		}
		return nil
	})
}

func IAMCreateOpenIDConnectProvider_client_id_too_long(s *S3Conf) error {
	testName := "IAMCreateOpenIDConnectProvider_client_id_too_long"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := createOIDCProvider(client, &iam.CreateOpenIDConnectProviderInput{
			Url:          aws.String(newIAMOIDCProviderURL()),
			ClientIDList: []string{strings.Repeat("c", 256)},
		})
		return checkIAMApiErr(err, iamerr.ValueTooLong("clientID", 255))
	})
}

func IAMCreateOpenIDConnectProvider_too_many_client_ids(s *S3Conf) error {
	testName := "IAMCreateOpenIDConnectProvider_too_many_client_ids"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		clientIDs := make([]string, storage.MaxClientIDsPerOIDCProvider+1)
		for i := range clientIDs {
			clientIDs[i] = fmt.Sprintf("client-%d", i)
		}
		_, err := createOIDCProvider(client, &iam.CreateOpenIDConnectProviderInput{
			Url:            aws.String(newIAMOIDCProviderURL()),
			ClientIDList:   clientIDs,
			ThumbprintList: []string{validOIDCThumbprint},
		})
		return checkIAMApiErr(err, iamerr.ClientIdsPerOpenIdConnectProviderLimitExceeded(storage.MaxClientIDsPerOIDCProvider))
	})
}

func IAMCreateOpenIDConnectProvider_invalid_thumbprint(s *S3Conf) error {
	testName := "IAMCreateOpenIDConnectProvider_invalid_thumbprint"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := createOIDCProvider(client, &iam.CreateOpenIDConnectProviderInput{
			Url:            aws.String(newIAMOIDCProviderURL()),
			ThumbprintList: []string{strings.Repeat("a", 39)},
		})
		if checkErr := checkIAMApiErr(err, iamerr.InvalidInput("Thumbprint must be exactly 40 characters.")); checkErr != nil {
			return fmt.Errorf("wrong_length: %w", checkErr)
		}

		_, err = createOIDCProvider(client, &iam.CreateOpenIDConnectProviderInput{
			Url:            aws.String(newIAMOIDCProviderURL()),
			ThumbprintList: []string{strings.Repeat("1", 40), strings.Repeat("2", 40), strings.Repeat("3", 40), strings.Repeat("4", 40), strings.Repeat("5", 40), strings.Repeat("6", 40)},
		})
		if checkErr := checkIAMApiErr(err, iamerr.ThumbprintListTooLong(5)); checkErr != nil {
			return fmt.Errorf("too_many: %w", checkErr)
		}
		return nil
	})
}

func IAMCreateOpenIDConnectProvider_duplicate_tag_keys(s *S3Conf) error {
	testName := "IAMCreateOpenIDConnectProvider_duplicate_tag_keys"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := createOIDCProvider(client, &iam.CreateOpenIDConnectProviderInput{
			Url:            aws.String(newIAMOIDCProviderURL()),
			ThumbprintList: []string{validOIDCThumbprint},
			Tags: []iamtypes.Tag{
				{Key: aws.String("key"), Value: aws.String("one")},
				{Key: aws.String("KEY"), Value: aws.String("two")},
			},
		})
		return checkIAMApiErr(err, iamerr.InvalidInput("Duplicate tag keys found. Please note that Tag keys are case insensitive."))
	})
}

func IAMCreateOpenIDConnectProvider_already_exists(s *S3Conf) error {
	testName := "IAMCreateOpenIDConnectProvider_already_exists"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		providerURL := newIAMOIDCProviderURL()
		arn, err := createTestOIDCProviderWithURL(client, providerURL)
		if err != nil {
			return err
		}

		_, dupErr := createOIDCProvider(client, &iam.CreateOpenIDConnectProviderInput{
			Url:            aws.String(providerURL),
			ThumbprintList: []string{validOIDCThumbprint},
		})
		checkErr := checkIAMApiErr(dupErr, iamerr.EntityAlreadyExistsOIDCProvider(providerURL))

		deleteErr := deleteOIDCProvider(client, arn)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

// IAMCreateOpenIDConnectProvider_thumbprint_autofetch_communication_error
// confirms the network-dependent auto-fetch fallback (triggered by
// omitting ThumbprintList) is wired all the way through the real HTTP
// action handler: a loopback URL is rejected by the fetch's mandatory
// SSRF guard before any real network attempt, deterministically and
// without requiring outbound network access from the test environment.
func IAMCreateOpenIDConnectProvider_thumbprint_autofetch_communication_error(s *S3Conf) error {
	testName := "IAMCreateOpenIDConnectProvider_thumbprint_autofetch_communication_error"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		_, err := createOIDCProvider(client, &iam.CreateOpenIDConnectProviderInput{
			Url: aws.String("https://127.0.0.1"),
		})
		return checkIAMApiErr(err, iamerr.OpenIdIdpCommunicationError("https://127.0.0.1"))
	})
}

// IAMCreateOpenIDConnectProvider_quota_exceeded tops the account up to
// storage.MaxOIDCProvidersPerAccount from whatever baseline count already
// exists, then confirms one more Create is rejected. It only ever creates
// (and cleans up) providers relative to the observed baseline, so it
// tolerates a non-empty account, but — like any test of a truly
// account-global, unscoped quota — it assumes no other test is
// concurrently creating/deleting OIDC providers, which holds for this
// suite's default sequential execution (not necessarily under --parallel).
func IAMCreateOpenIDConnectProvider_quota_exceeded(s *S3Conf) error {
	testName := "IAMCreateOpenIDConnectProvider_quota_exceeded"
	return iamActionHandler(s, testName, func(client *iam.Client) (err error) {
		baseline, err := listIAMOIDCProviders(client)
		if err != nil {
			return err
		}

		var created []string
		defer func() {
			for _, arn := range created {
				if deleteErr := deleteOIDCProvider(client, arn); deleteErr != nil {
					err = errors.Join(err, fmt.Errorf("delete IAM OIDC provider %q: %w", arn, deleteErr))
				}
			}
		}()

		for i := len(baseline.OpenIDConnectProviderList); i < storage.MaxOIDCProvidersPerAccount; i++ {
			arn, createErr := createTestOIDCProvider(client)
			if createErr != nil {
				return fmt.Errorf("topping up to quota: %w", createErr)
			}
			created = append(created, arn)
		}

		_, overErr := createOIDCProvider(client, &iam.CreateOpenIDConnectProviderInput{
			Url:            aws.String(newIAMOIDCProviderURL()),
			ThumbprintList: []string{validOIDCThumbprint},
		})
		return checkIAMApiErr(overErr, iamerr.OIDCProvidersPerAccountLimitExceeded(storage.MaxOIDCProvidersPerAccount))
	})
}

func IAMCreateOpenIDConnectProvider_success(s *S3Conf) error {
	testName := "IAMCreateOpenIDConnectProvider_success"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		providerURL := newIAMOIDCProviderURL()
		out, err := createOIDCProvider(client, &iam.CreateOpenIDConnectProviderInput{
			Url:            aws.String(providerURL),
			ClientIDList:   []string{"sts.amazonaws.com"},
			ThumbprintList: []string{strings.ToUpper(validOIDCThumbprint)},
			Tags: []iamtypes.Tag{
				{Key: aws.String("env"), Value: aws.String("test")},
			},
		})
		if err != nil {
			return err
		}

		checkErr := func() error {
			wantArn := oidcProviderArn(providerURL)
			if aws.ToString(out.OpenIDConnectProviderArn) != wantArn {
				return fmt.Errorf("expected OpenIDConnectProviderArn %q, instead got %q", wantArn, aws.ToString(out.OpenIDConnectProviderArn))
			}
			if len(out.Tags) != 1 || aws.ToString(out.Tags[0].Key) != "env" || aws.ToString(out.Tags[0].Value) != "test" {
				return fmt.Errorf("expected create output tag env=test, instead got %#v", out.Tags)
			}
			if requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata); !ok || requestID == "" {
				return fmt.Errorf("expected CreateOpenIDConnectProvider response request id")
			}

			get, getErr := getIAMOIDCProvider(client, aws.ToString(out.OpenIDConnectProviderArn))
			if getErr != nil {
				return getErr
			}
			wantURL := strings.TrimPrefix(providerURL, "https://")
			if aws.ToString(get.Url) != wantURL {
				return fmt.Errorf("expected Url %q (scheme stripped), instead got %q", wantURL, aws.ToString(get.Url))
			}
			if len(get.ClientIDList) != 1 || get.ClientIDList[0] != "sts.amazonaws.com" {
				return fmt.Errorf("expected ClientIDList [sts.amazonaws.com], instead got %#v", get.ClientIDList)
			}
			// Submitted uppercase; AWS lowercases whatever is stored.
			if len(get.ThumbprintList) != 1 || get.ThumbprintList[0] != validOIDCThumbprint {
				return fmt.Errorf("expected ThumbprintList [%s] (lowercased), instead got %#v", validOIDCThumbprint, get.ThumbprintList)
			}
			if get.CreateDate == nil || get.CreateDate.IsZero() {
				return fmt.Errorf("expected CreateDate to be set")
			}
			return nil
		}()

		deleteErr := deleteOIDCProvider(client, aws.ToString(out.OpenIDConnectProviderArn))
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

func IAMCreateOpenIDConnectProvider_defaults(s *S3Conf) error {
	testName := "IAMCreateOpenIDConnectProvider_defaults"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		providerURL := newIAMOIDCProviderURL()
		out, err := createOIDCProvider(client, &iam.CreateOpenIDConnectProviderInput{
			Url:            aws.String(providerURL),
			ThumbprintList: []string{validOIDCThumbprint},
		})
		if err != nil {
			return err
		}

		checkErr := func() error {
			if len(out.Tags) != 0 {
				return fmt.Errorf("expected no tags in create output, instead got %#v", out.Tags)
			}
			get, getErr := getIAMOIDCProvider(client, aws.ToString(out.OpenIDConnectProviderArn))
			if getErr != nil {
				return getErr
			}
			if len(get.ClientIDList) != 0 {
				return fmt.Errorf("expected no client ids, instead got %#v", get.ClientIDList)
			}
			if len(get.Tags) != 0 {
				return fmt.Errorf("expected no tags, instead got %#v", get.Tags)
			}
			return nil
		}()

		deleteErr := deleteOIDCProvider(client, aws.ToString(out.OpenIDConnectProviderArn))
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

// IAMCreateOpenIDConnectProvider_ip_literal_host confirms an IP-literal
// host is accepted by exercising isValidOIDCHostname's net.ParseIP branch
// end-to-end.
func IAMCreateOpenIDConnectProvider_ip_literal_host(s *S3Conf) error {
	testName := "IAMCreateOpenIDConnectProvider_ip_literal_host"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		host := newIAMOIDCProviderIPHost()
		arn, err := createTestOIDCProviderWithURL(client, "https://"+host)
		if err != nil {
			return err
		}

		get, getErr := getIAMOIDCProvider(client, arn)
		checkErr := getErr
		if getErr == nil && aws.ToString(get.Url) != host {
			checkErr = fmt.Errorf("expected Url %q, instead got %q", host, aws.ToString(get.Url))
		}

		deleteErr := deleteOIDCProvider(client, arn)
		if checkErr != nil {
			return checkErr
		}
		return deleteErr
	})
}

// IAMCreateOpenIDConnectProvider_thumbprint_edge_cases exercises two
// success-path ThumbprintList edge cases in one pass: exactly
// MaxThumbprintsPerOIDCProvider entries (the limit message says "fewer
// than 5", but 5 itself is accepted), and a 40-character entry outside the
// hex charset (AWS does not check for a hex charset).
func IAMCreateOpenIDConnectProvider_thumbprint_edge_cases(s *S3Conf) error {
	testName := "IAMCreateOpenIDConnectProvider_thumbprint_edge_cases"
	return iamActionHandler(s, testName, func(client *iam.Client) error {
		checkThumbprints := func(thumbprints []string) error {
			arn, err := createOIDCProviderReturningArn(client, thumbprints)
			if err != nil {
				return err
			}
			return deleteOIDCProvider(client, arn)
		}

		if err := checkThumbprints([]string{
			strings.Repeat("1", 40), strings.Repeat("2", 40), strings.Repeat("3", 40),
			strings.Repeat("4", 40), strings.Repeat("5", 40),
		}); err != nil {
			return fmt.Errorf("max_thumbprints_boundary: %w", err)
		}

		if err := checkThumbprints([]string{strings.Repeat("z", 40)}); err != nil {
			return fmt.Errorf("non_hex_thumbprint: %w", err)
		}
		return nil
	})
}

// IAMCreateOpenIDConnectProvider_trailing_slash_distinct_identity confirms
// that a trailing slash is part of a provider's identity: "https://host"
// and "https://host/" register as two distinct providers, not a
// collision.
func IAMCreateOpenIDConnectProvider_trailing_slash_distinct_identity(s *S3Conf) error {
	testName := "IAMCreateOpenIDConnectProvider_trailing_slash_distinct_identity"
	return iamActionHandler(s, testName, func(client *iam.Client) (err error) {
		host := "oidc-test-" + genRandString(16) + ".example.com"
		withoutSlash, err := createTestOIDCProviderWithURL(client, "https://"+host)
		if err != nil {
			return err
		}
		defer func() {
			if deleteErr := deleteOIDCProvider(client, withoutSlash); deleteErr != nil {
				err = errors.Join(err, deleteErr)
			}
		}()

		withSlash, err := createTestOIDCProviderWithURL(client, "https://"+host+"/")
		if err != nil {
			return err
		}
		defer func() {
			if deleteErr := deleteOIDCProvider(client, withSlash); deleteErr != nil {
				err = errors.Join(err, deleteErr)
			}
		}()

		if withoutSlash == withSlash {
			return fmt.Errorf("expected distinct ARNs for %q and %q, both got %q", host, host+"/", withoutSlash)
		}
		return nil
	})
}

// newIAMOIDCProviderURL returns a fresh https:// URL for a throwaway OIDC
// provider. Provider identity is the URL itself (there is no separate
// name), so genRandString's collision-free counter is what keeps
// concurrent/repeated test runs from colliding with each other or with any
// provider left over from a prior run.
func newIAMOIDCProviderURL() string {
	return "https://oidc-test-" + genRandString(16) + ".example.com"
}

// newIAMOIDCProviderIPHost returns a host string within the TEST-NET-2
// documentation range (RFC 5737, 198.51.100.0/24 — never publicly
// routable), used to exercise CreateOpenIDConnectProvider's IP-literal
// hostname path without depending on any real, reachable host.
func newIAMOIDCProviderIPHost() string {
	suffix := genRandString(1)
	return fmt.Sprintf("198.51.100.%d", int(suffix[0])%254+1)
}

func createOIDCProvider(client *iam.Client, input *iam.CreateOpenIDConnectProviderInput) (*iam.CreateOpenIDConnectProviderOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.CreateOpenIDConnectProvider(ctx, input)
}

// createTestOIDCProvider creates a provider at a fresh random URL with a
// single explicit valid thumbprint (bypassing the network-dependent
// auto-fetch path) and returns its ARN.
func createTestOIDCProvider(client *iam.Client) (string, error) {
	return createTestOIDCProviderWithURL(client, newIAMOIDCProviderURL())
}

func createTestOIDCProviderWithURL(client *iam.Client, providerURL string) (string, error) {
	out, err := createOIDCProvider(client, &iam.CreateOpenIDConnectProviderInput{
		Url:            aws.String(providerURL),
		ThumbprintList: []string{validOIDCThumbprint},
	})
	if err != nil {
		return "", err
	}
	return aws.ToString(out.OpenIDConnectProviderArn), nil
}

func deleteOIDCProvider(client *iam.Client, arn string) error {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	_, err := client.DeleteOpenIDConnectProvider(ctx, &iam.DeleteOpenIDConnectProviderInput{OpenIDConnectProviderArn: &arn})
	return err
}

// oidcProviderArn builds the expected ARN for a provider created at
// providerURL, mirroring iamutil.BuildOIDCProviderArn without importing an
// internal package from this external test tree.
func oidcProviderArn(providerURL string) string {
	return "arn:aws:iam::000000000000:oidc-provider/" + strings.TrimPrefix(providerURL, "https://")
}

func createOIDCProviderReturningArn(client *iam.Client, thumbprints []string) (string, error) {
	out, err := createOIDCProvider(client, &iam.CreateOpenIDConnectProviderInput{
		Url:            aws.String(newIAMOIDCProviderURL()),
		ThumbprintList: thumbprints,
	})
	if err != nil {
		return "", err
	}
	return aws.ToString(out.OpenIDConnectProviderArn), nil
}
