// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/versity/versitygw/iamapi/private"
	"github.com/versity/versitygw/internal/netutil"
	"github.com/versity/versitygw/internal/sigv4auth"
	"github.com/versity/versitygw/s3err"
)

const (
	// standaloneSigningRegion/standaloneSigningService are the SigV4
	// envelope this client signs its own calls to the private endpoints with
	standaloneSigningRegion  = "us-east-1"
	standaloneSigningService = sigv4auth.ServiceIAM

	standaloneRequestTimeout = 10 * time.Second
)

// standaloneProbeWindow bounds how long NewIAMServiceStandalone waits for the
// IAM service to answer compatibly before it gives up, and
// standaloneProbeInterval how often it retries within that window. Both
// failures are retried, for different reasons: an unreachable service is the
// ordinary case of the two processes starting in parallel, and an
// incompatible one is what a gateway sees while the IAM service it is paired
// with is still rolling. Failing immediately on either would turn a routine
// deployment into a crash loop whose backoff long outlives the condition.
//
// Variables rather than constants so tests can shorten the window; nothing
// else writes them.
var (
	standaloneProbeWindow   = 30 * time.Second
	standaloneProbeInterval = 2 * time.Second
)

// protocolMismatchError reports that whatever answered the private endpoints
// is not a standalone IAM service this gateway can use. It is a distinct type
// so the startup probe can tell an incompatible peer, which is fatal, from an
// unreachable one, which is not.
type protocolMismatchError struct {
	detail string
}

func (e *protocolMismatchError) Error() string {
	return "iam standalone: " + e.detail
}

// IAMServiceStandaloneConfig configures IAMServiceStandalone.
type IAMServiceStandaloneConfig struct {
	// Endpoint is either a "host:port" TCP address (mTLS required -
	// ClientCert/ClientCertKey/ServerCA) or a unix socket path, matching
	// the standalone IAM service's own --private-ports address shape.
	Endpoint string
	// Access/Secret are this client's own SigV4 identity — the credential
	// it signs its private requests with. Both must be set together, or
	// both left empty to sign with the gateway's root account.
	Access string
	Secret string
	// ClientCert/ClientCertKey/ServerCA configure outbound mTLS. Required
	// (all three) for a TCP Endpoint; unused for a unix socket Endpoint.
	ClientCert    string
	ClientCertKey string
	ServerCA      string
	// DefaultUserID/GroupID/ProjectID are assigned to every account this
	// client resolves, the locally-held root account included: bucket
	// ownership is fixed to root here, so root must carry the same POSIX
	// identity as everyone else or a backend chowning to it would target
	// uid/gid 0. The standalone IAM service's user model
	// (iamapi/types.User, mirroring real AWS IAM) has no POSIX uid/gid/
	// project-id concept, so there is no per-user value to fetch instead —
	// every standalone-backed account shares one POSIX identity for
	// backend file-ownership purposes.
	DefaultUserID    int
	DefaultGroupID   int
	DefaultProjectID int
	// Region is the gateway's own configured region, reported to the IAM
	// service as the region an S3 request was made in when it records the
	// caller's last-used metadata. It is taken from configuration rather
	// than from the request's credential scope on purpose: the scope is
	// attacker-controlled until the signature is verified. Empty disables
	// the reporting rather than storing a blank region.
	Region string
}

// IAMServiceStandalone is the S3 gateway's client for a standalone IAM
// service's private endpoints. It never holds a plaintext secret for any account
// but its own signing identity and the locally-known root account — every
// other account's secret stays inside the IAM service process.
// CreateAccount/UpdateUserAccount/ DeleteUserAccount/ListUserAccounts
// are unsupported here for the same reason: mutating a user requires setting a secret, which must never
// flow into this process — manage users via the IAM service's own control-plane API instead.
type IAMServiceStandalone struct {
	client  *http.Client
	baseURL string
	access  string
	secret  string
	rootAcc Account
	cfg     IAMServiceStandaloneConfig
}

var (
	_ IAMService         = (*IAMServiceStandalone)(nil)
	_ SigningKeyProvider = (*IAMServiceStandalone)(nil)
	_ PolicyEvaluator    = (*IAMServiceStandalone)(nil)
	_ FixedBucketOwner   = (*IAMServiceStandalone)(nil)
)

// NewIAMServiceStandalone constructs the standalone IAM service client.
// rootAcc is the gateway's own root account — always resolved locally,
// never round-tripped through the IAM service.
func NewIAMServiceStandalone(rootAcc Account, cfg IAMServiceStandaloneConfig) (*IAMServiceStandalone, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("iam standalone: endpoint is required")
	}

	if (cfg.Access == "") != (cfg.Secret == "") {
		return nil, fmt.Errorf("iam standalone: access and secret must both be set, or both left empty to sign with the root account")
	}

	access, secret := cfg.Access, cfg.Secret
	if access == "" {
		access, secret = rootAcc.Access, rootAcc.Secret
	}

	client, baseURL, err := newStandaloneHTTPClient(cfg)
	if err != nil {
		return nil, err
	}

	svc := &IAMServiceStandalone{
		client:  client,
		baseURL: baseURL,
		access:  access,
		secret:  secret,
		rootAcc: rootAcc,
		cfg:     cfg,
	}

	if err := svc.probeProtocol(); err != nil {
		return nil, err
	}

	return svc, nil
}

// probeProtocol verifies at startup what every request verifies anyway, so a
// version skew is diagnosed once, here, instead of once per S3 request as an
// opaque 500. Because it is a signed request to a root-authenticated
// endpoint, reaching a compatible answer also proves the transport, the mTLS
// material, and this gateway's own IAM credential.
//
// An incompatible service is fatal: a gateway that cannot authorize a single
// request is more useful refusing to start, with the reason in its log, than
// running and serving errors. An unreachable one is only a warning — the two
// processes legitimately start in parallel, and every request checks the
// version regardless.
func (s *IAMServiceStandalone) probeProtocol() error {
	deadline := time.Now().Add(standaloneProbeWindow)

	for {
		var resp private.VersionResponse
		// The endpoint takes no arguments; an empty object is the request.
		err := s.doPrivateRequest(private.VersionPath, struct{}{}, &resp)

		// The version endpoint answers even a gateway the service will not
		// serve — that is the whole point of exempting it from the service's
		// own check — so the probe has to draw that conclusion itself from
		// the minimum the service reports. Without this the one direction a
		// gateway cannot detect from a response header would pass startup and
		// fail on every request afterwards.
		if err == nil && private.ProtocolVersion < resp.MinClient {
			err = &protocolMismatchError{fmt.Sprintf(
				"IAM service at %q serves private protocol %d and newer, this gateway speaks %d: upgrade the gateway",
				s.cfg.Endpoint, resp.MinClient, private.ProtocolVersion)}
		}

		if err == nil {
			serverVersion := resp.ServerVersion
			if serverVersion == "" {
				serverVersion = "unknown"
			}
			fmt.Printf("standalone IAM service %q: version %s, private protocol %d\n",
				s.cfg.Endpoint, serverVersion, resp.Protocol)
			return nil
		}

		if probeRetryable(err) && time.Now().Before(deadline) {
			time.Sleep(standaloneProbeInterval)
			continue
		}

		var mismatch *protocolMismatchError
		if errors.As(err, &mismatch) {
			return fmt.Errorf("%w (still incompatible after %v, so this is a version skew rather than a rollout in progress)",
				err, standaloneProbeWindow)
		}

		log.Printf("WARNING: iam standalone: could not verify the IAM service at %q: %v; "+
			"the private protocol version is still checked on every request",
			s.cfg.Endpoint, err)
		return nil
	}
}

// probeRetryable reports whether a failed probe could resolve on its own.
// Only two can: the service not being up yet, and it being mid-rollout at an
// incompatible version. Anything it answered definitively — a rejected
// gateway credential above all — will answer the same way in thirty seconds,
// so retrying only delays the warning that says so.
func probeRetryable(err error) bool {
	var mismatch *protocolMismatchError
	if errors.As(err, &mismatch) {
		return true
	}
	var transport *url.Error
	return errors.As(err, &transport)
}

func newStandaloneHTTPClient(cfg IAMServiceStandaloneConfig) (*http.Client, string, error) {
	if netutil.IsUnixSocketPath(cfg.Endpoint) {
		sock := cfg.Endpoint
		transport := &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			},
		}
		// The host in this URL is never actually resolved/dialed — the
		// DialContext override above always connects to the unix socket
		// regardless — it just needs to be a syntactically valid URL.
		return &http.Client{Transport: transport, Timeout: standaloneRequestTimeout}, "http://unix", nil
	}

	if cfg.ClientCert == "" || cfg.ClientCertKey == "" || cfg.ServerCA == "" {
		return nil, "", fmt.Errorf("iam standalone: client-cert, client-cert-key, and server-ca are all required for a TCP endpoint (%q)", cfg.Endpoint)
	}

	cert, err := netutil.LoadClientCert(cfg.ClientCert, cfg.ClientCertKey)
	if err != nil {
		return nil, "", fmt.Errorf("iam standalone: %w", err)
	}
	pool, err := netutil.LoadCACertPool(cfg.ServerCA)
	if err != nil {
		return nil, "", fmt.Errorf("iam standalone: %w", err)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
			RootCAs:      pool,
		},
	}
	return &http.Client{Transport: transport, Timeout: standaloneRequestTimeout}, "https://" + cfg.Endpoint, nil
}

// doPrivateRequest signs reqBody as this client's own identity (s.access/
// s.secret, the one place in this file that touches a secret directly —
// signing an outbound request as itself, not verifying an inbound one) and
// POSTs it to path, unmarshaling the response into respBody.
//
// A 403 is dispatched on the error body's code: an unresolvable access key
// becomes ErrNoSuchUser (matching IAMService.GetUserAccount's contract), a
// rejected security token becomes ErrInvalidSessionToken, and anything
// else — most importantly this gateway's own IAM-client credential being
// rejected — stays a plain error, so a gateway misconfiguration surfaces as
// a server fault instead of telling the end user their access key doesn't
// exist.
func (s *IAMServiceStandalone) doPrivateRequest(path string, reqBody, respBody any) error {
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("iam standalone: marshal request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, s.baseURL+path, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("iam standalone: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Set before signing, so it is covered by the signature: SigningInput
	// FromRequest leaves SignedHeaders nil, and sigv4auth's default policy
	// excludes only Authorization, User-Agent, X-Amzn-Trace-Id, Expect and
	// Transfer-Encoding.
	req.Header.Set(private.ProtocolHeader, strconv.Itoa(private.ProtocolVersion))

	payloadHash := sigv4auth.PayloadSHA256Hex(bodyBytes)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	signingTime := time.Now().UTC()
	yyyymmdd := signingTime.Format(sigv4auth.YYYYMMDD)
	derivedKey := sigv4auth.DeriveKey(s.secret, yyyymmdd, standaloneSigningRegion, standaloneSigningService)
	in := sigv4auth.SigningInputFromRequest(req)
	in.AccessKeyID = s.access
	in.CredentialScope = sigv4auth.BuildCredentialScope(yyyymmdd, standaloneSigningRegion, standaloneSigningService)
	in.PayloadHash = payloadHash
	in.SigningTime = signingTime
	in.DisableURIPathEscaping = true
	result := sigv4auth.BuildAndSign(derivedKey, in)
	req.Header.Set("X-Amz-Date", result.AmzDate)
	req.Header.Set("Authorization", result.AuthorizationHeader)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("iam standalone: request to %s failed: %w", path, err)
	}
	defer resp.Body.Close()

	// Checked before the status and before the body: a peer whose protocol
	// this gateway cannot read is not one whose response it should interpret.
	if err := s.checkServerProtocol(path, resp); err != nil {
		return err
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("iam standalone: read response from %s: %w", path, err)
	}

	if resp.StatusCode != http.StatusOK {
		return standaloneResponseError(path, resp.StatusCode, respBytes)
	}

	if respBody != nil {
		if err := json.Unmarshal(respBytes, respBody); err != nil {
			return fmt.Errorf("iam standalone: unmarshal response from %s: %w", path, err)
		}
	}
	return nil
}

// standaloneResponseError turns a non-200 private-endpoint response into
// the sentinel the S3 request pipeline dispatches on, using the JSON error
// body's machine-readable code rather than the status alone (403 covers
// several distinct failures, only two of which are about the *end user's*
// credential).
func standaloneResponseError(path string, status int, body []byte) error {
	var errBody struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	// A body that doesn't parse leaves Code empty, which falls through to
	// the generic error below — the safe direction, since misreporting a
	// server fault as "no such user" is what this dispatch exists to avoid.
	_ = json.Unmarshal(body, &errBody)

	switch errBody.Code {
	case private.CodeNoSuchIdentity:
		return ErrNoSuchUser
	case private.CodeInvalidToken:
		return ErrInvalidSessionToken
	case private.CodeProtocolMismatch:
		// The other direction of the same check: this gateway is too old for
		// the IAM service to serve safely, which only that service can know.
		return &protocolMismatchError{fmt.Sprintf(
			"IAM service refused this gateway's private protocol version %d at %s: %s",
			private.ProtocolVersion, path, errBody.Error)}
	}

	return fmt.Errorf("iam standalone: %s returned %d: %s", path, status, string(body))
}

// checkServerProtocol verifies the private protocol version the IAM service
// declared on a response.
//
// A missing version fails just as hard as an incompatible one. No build of
// this protocol omits the header, so a response without one did not come from
// a compatible IAM service — it came from something else answering on that
// address, such as a proxy returning its own error page. The message says
// what was observed rather than naming a cause, since both look identical from here.
func (s *IAMServiceStandalone) checkServerProtocol(path string, resp *http.Response) error {
	value := resp.Header.Get(private.ProtocolHeader)
	if value == "" {
		return &protocolMismatchError{fmt.Sprintf(
			"no %s header on the %d response from %s at %q: not a versioned IAM service",
			private.ProtocolHeader, resp.StatusCode, path, s.cfg.Endpoint)}
	}

	server, err := private.ParseProtocolVersion(value)
	if err != nil {
		return &protocolMismatchError{fmt.Sprintf("response from %s at %q: %v", path, s.cfg.Endpoint, err)}
	}

	if server < private.ProtocolVersion {
		return &protocolMismatchError{fmt.Sprintf(
			"IAM service at %q speaks private protocol %d, this gateway requires %d or newer: upgrade the IAM service before the gateway",
			s.cfg.Endpoint, server, private.ProtocolVersion)}
	}

	return nil
}

// DeriveSigningKey implements SigningKeyProvider. Root is special-cased
// locally: its secret is already known to this process either way, so
// there's no reason to round-trip it through the IAM service.
func (s *IAMServiceStandalone) DeriveSigningKey(access, sessionToken, date, region, service string) ([]byte, Account, error) {
	if access == s.rootAcc.Access {
		if sessionToken != "" {
			return nil, Account{}, ErrInvalidSessionToken
		}
		return sigv4auth.DeriveKey(s.rootAcc.Secret, date, region, service), s.rootAccount(), nil
	}

	var resp private.DeriveSigningKeyResponse
	err := s.doPrivateRequest(private.DerivePath, private.DeriveSigningKeyRequest{
		AccessKeyID:  access,
		SessionToken: sessionToken,
		Date:         date,
		Region:       region,
		Service:      service,
	}, &resp)
	if err != nil {
		return nil, Account{}, err
	}

	return resp.DerivedKey, s.accountFor(access, sessionToken), nil
}

// accountFor builds the Account metadata DeriveSigningKey/GetUserAccount
// return for a resolved non-root identity
func (s *IAMServiceStandalone) accountFor(access, sessionToken string) Account {
	return Account{
		Access:       access,
		Role:         RoleUser,
		UserID:       s.cfg.DefaultUserID,
		GroupID:      s.cfg.DefaultGroupID,
		ProjectID:    s.cfg.DefaultProjectID,
		SessionToken: sessionToken,
		IsSession:    sigv4auth.IsTempAccessKeyID(access),
	}
}

// EvaluatePolicy implements PolicyEvaluator, evaluating every action in
// actions against resource in a single request rather than one round trip
// per action.
func (s *IAMServiceStandalone) EvaluatePolicy(access, sessionToken string, actions []Action, resources []string, condition map[string][]string) (PolicyEvaluation, error) {
	actionStrs := make([]string, len(actions))
	for i, action := range actions {
		actionStrs[i] = string(action)
	}

	var resp private.EvaluatePolicyResponse
	err := s.doPrivateRequest(private.EvaluatePath, private.EvaluatePolicyRequest{
		AccessKeyID:  access,
		SessionToken: sessionToken,
		Actions:      actionStrs,
		Resources:    resources,
		Condition:    condition,
		// Reported for last-used metadata only; see EvaluatePolicyRequest.
		Region:  s.cfg.Region,
		Service: sigv4auth.ServiceS3,
	}, &resp)
	if err != nil {
		return PolicyEvaluation{}, err
	}
	if len(resp.Decisions) != len(resources) {
		// A protocol mismatch between the gateway and IAM service builds —
		// fail closed rather than silently under- or over-evaluating the
		// requested matrix.
		return PolicyEvaluation{}, fmt.Errorf("iam standalone: evaluate-policy returned %d resource decisions for %d resources", len(resp.Decisions), len(resources))
	}

	decisions, err := decisionMatrixFromWire(resp.Decisions, len(actions))
	if err != nil {
		return PolicyEvaluation{}, err
	}

	eval := PolicyEvaluation{
		Decisions:    decisions,
		PrincipalArn: resp.PrincipalArn,
	}

	if resp.HasSessionPolicy {
		if len(resp.SessionDecisions) != len(resources) {
			return PolicyEvaluation{}, fmt.Errorf("iam standalone: evaluate-policy returned %d session-decision rows for %d resources", len(resp.SessionDecisions), len(resources))
		}
		sessionDecisions, err := decisionMatrixFromWire(resp.SessionDecisions, len(actions))
		if err != nil {
			return PolicyEvaluation{}, err
		}
		eval.HasSessionPolicy = true
		eval.SessionDecisions = sessionDecisions
	}

	return eval, nil
}

// decisionMatrixFromWire converts one wire decision matrix, checking every
// row is the expected width. A short row is a protocol mismatch between
// gateway and IAM service builds, and is failed closed rather than padded.
func decisionMatrixFromWire(rows [][]string, actionCount int) ([][]policyDecision, error) {
	out := make([][]policyDecision, len(rows))
	for i, perAction := range rows {
		if len(perAction) != actionCount {
			return nil, fmt.Errorf("iam standalone: evaluate-policy returned %d action decisions for %d actions", len(perAction), actionCount)
		}
		out[i] = make([]policyDecision, len(perAction))
		for j, d := range perAction {
			out[i][j] = decisionFromWireValue(d)
		}
	}
	return out, nil
}

// decisionFromWireValue translates the private endpoint's wire-format
// Decision string to the auth package's own policyDecision. An unrecognized
// value (a protocol mismatch between mismatched gateway/IAM-service builds)
// fails closed as Deny rather than silently granting access.
func decisionFromWireValue(v string) policyDecision {
	switch v {
	case private.DecisionAllow:
		return policyDecisionAllow
	case private.DecisionNoMatch:
		return policyDecisionNoMatch
	default:
		return policyDecisionDeny
	}
}

// GetUserAccount resolves access via the resolve-identity endpoint, which
// answers existence and principal identity while returning no credential
// material at all. This is not blanket-unsupported like the mutating
// methods below: ResolveAccounts (bucket-policy Principal and ACL grantee
// validation) depends on GetUserAccount working to tell a nonexistent
// grantee (ErrNoSuchUser) apart from an unsupported one
// (ErrAdminMethodNotSupported, which it treats as fatal).
//
// Callers that need to validate several access keys at once should use
// ResolveAccounts instead — one round trip for the whole set rather than
// one per key.
func (s *IAMServiceStandalone) GetUserAccount(access string) (Account, error) {
	if access == s.rootAcc.Access {
		return s.rootAccount(), nil
	}

	accounts, err := s.resolveAccountDetails([]string{access})
	if err != nil {
		return Account{}, err
	}
	if !accounts[0].Found {
		return Account{}, ErrNoSuchUser
	}
	return accounts[0].Account, nil
}

// resolvedAccount is one resolveAccountDetails result. The zero value means
// "no such access key".
type resolvedAccount struct {
	Found bool
	// IsSession distinguishes an ephemeral AssumeRoleWithWebIdentity
	// session from a long-term user. Callers persisting a reference to a
	// principal (a bucket policy Principal, an ACL grantee, a bucket owner)
	// must refuse a session: the ASIA… key it is named by stops existing
	// when the session expires, leaving a reference that can never match
	// and, for a bucket owner, a bucket nobody but root can administer.
	IsSession bool
	Account   Account
}

// resolveAccountDetails resolves every access key in accesses in a single
// round trip, returning one positional result per input. Only the root
// account is answered locally; a root access key mixed into the batch still
// costs nothing, since it never reaches the IAM service.
func (s *IAMServiceStandalone) resolveAccountDetails(accesses []string) ([]resolvedAccount, error) {
	out := make([]resolvedAccount, len(accesses))

	// Root is known to this process, so it is answered here and left out of
	// the request entirely — the IAM service has no record of it.
	remote := make([]string, 0, len(accesses))
	remoteIdx := make([]int, 0, len(accesses))
	for i, access := range accesses {
		if access == s.rootAcc.Access {
			out[i] = resolvedAccount{Found: true, Account: s.rootAccount()}
			continue
		}
		remote = append(remote, access)
		remoteIdx = append(remoteIdx, i)
	}
	if len(remote) == 0 {
		return out, nil
	}

	var resp private.ResolveIdentityResponse
	err := s.doPrivateRequest(private.ResolveIdentityPath, private.ResolveIdentityRequest{
		AccessKeyIDs: remote,
	}, &resp)
	if err != nil {
		return nil, err
	}
	if len(resp.Identities) != len(remote) {
		// A protocol mismatch between the gateway and IAM service builds —
		// fail closed rather than silently mis-attributing results to the
		// wrong access keys.
		return nil, fmt.Errorf("iam standalone: resolve-identity returned %d identities for %d access keys", len(resp.Identities), len(remote))
	}

	for i, identity := range resp.Identities {
		if !identity.Found {
			continue
		}
		out[remoteIdx[i]] = resolvedAccount{
			Found:     true,
			IsSession: identity.Kind == private.KindSession,
			// No session token is known here, and none is needed: this
			// Account answers "who is this" for validation, never
			// authenticates a request.
			Account: s.accountFor(remote[i], ""),
		}
	}
	return out, nil
}

// ResolveAccounts returns the subset of accessKeyIDs that do not exist, in
// a single round trip. A temporary (ASIA…) session access key counts as
// nonexistent even while its session is live — see resolvedAccount.IsSession.
func (s *IAMServiceStandalone) ResolveAccounts(accessKeyIDs []string) ([]string, error) {
	resolved, err := s.resolveAccountDetails(accessKeyIDs)
	if err != nil {
		return nil, fmt.Errorf("check user account: %w", err)
	}
	missing := []string{}
	for i, acc := range resolved {
		if !acc.Found || acc.IsSession {
			missing = append(missing, accessKeyIDs[i])
		}
	}
	return missing, nil
}

// BucketOwner implements FixedBucketOwner: every bucket is owned by the
// gateway's root account, the only account this process knows locally.
func (s *IAMServiceStandalone) BucketOwner() Account {
	return s.rootAccount()
}

// rootAccount returns the root account as an identity: a copy of the locally
// held root credentials carrying the same POSIX identity every other
// standalone-backed account gets.
func (s *IAMServiceStandalone) rootAccount() Account {
	acc := s.rootAcc
	acc.UserID = s.cfg.DefaultUserID
	acc.GroupID = s.cfg.DefaultGroupID
	acc.ProjectID = s.cfg.DefaultProjectID
	return acc
}

// CreateAccount is not supported
func (s *IAMServiceStandalone) CreateAccount(Account) error {
	return s3err.GetAPIError(s3err.ErrAdminMethodNotSupported)
}

// UpdateUserAccount is not supported
func (s *IAMServiceStandalone) UpdateUserAccount(string, MutableProps) error {
	return s3err.GetAPIError(s3err.ErrAdminMethodNotSupported)
}

// DeleteUserAccount is not supported
func (s *IAMServiceStandalone) DeleteUserAccount(string) error {
	return s3err.GetAPIError(s3err.ErrAdminMethodNotSupported)
}

// ListUserAccounts is not supported
func (s *IAMServiceStandalone) ListUserAccounts() ([]Account, error) {
	return nil, s3err.GetAPIError(s3err.ErrAdminMethodNotSupported)
}

func (s *IAMServiceStandalone) Shutdown() error {
	s.client.CloseIdleConnections()
	return nil
}
