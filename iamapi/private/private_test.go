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

package private

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/versity/versitygw/iamapi/internal/iammiddleware"
	"github.com/versity/versitygw/iamapi/internal/iamutil"
	"github.com/versity/versitygw/iamapi/storage"
	"github.com/versity/versitygw/iamapi/types"
	"github.com/versity/versitygw/internal/sigv4auth"
)

var testRoot = iammiddleware.RootCredentials{Access: "AKIDTESTROOT", Secret: "TESTROOTSECRET"}

// newTestServer builds a fresh file-backed store rooted at t.TempDir() and a
// PrivateAPI on top of it — no public control-plane IAMApiServer involved,
// since this package's handlers only ever need a populated storage.Storer.
func newTestServer(t *testing.T) (*PrivateAPI, storage.Storer) {
	t.Helper()

	store, err := storage.New(storage.Config{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}

	p, err := New(store, testRoot)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p, store
}

// createTestUser creates a user with the given name, access key, and
// (optional) inline policy directly against store — bypassing the public
// control-plane API entirely, since it isn't under test here. Arn is set
// explicitly (iamutil.BuildUserArn, matching what the control-plane
// controller computes before calling storage.CreateUser — storage.CreateUser
// itself never populates it) so tests can assert on a realistic principal
// ARN in an evaluate-policy response.
func createTestUser(t *testing.T, store storage.Storer, userName, accessKeyID, secret, policyDocument string) {
	t.Helper()
	ctx := context.Background()

	if _, err := store.CreateUser(ctx, types.User{
		UserName:   userName,
		Path:       "/",
		Arn:        iamutil.BuildUserArn(iamutil.DefaultAccountID, "/", userName),
		CreateDate: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if _, err := store.CreateAccessKey(ctx, storage.CreateAccessKeyInput{
		UserName:        userName,
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secret,
		Status:          "Active",
		CreateDate:      time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateAccessKey: %v", err)
	}

	if policyDocument != "" {
		if err := store.PutUserPolicy(ctx, storage.PutUserPolicyInput{
			UserName:       userName,
			PolicyName:     "P",
			PolicyDocument: policyDocument,
		}); err != nil {
			t.Fatalf("PutUserPolicy: %v", err)
		}
	}
}

// signPrivateRequest signs req as access/secret for the private endpoints'
// SigV4 protocol (service "iam", iammiddleware.SigningRegion), mutating its
// Authorization/X-Amz-Date headers in place.
func signPrivateRequest(t *testing.T, req *http.Request, access, secret string, payloadHash string) {
	t.Helper()

	signingTime := time.Now().UTC()
	yyyymmdd := signingTime.Format(sigv4auth.YYYYMMDD)
	derivedKey := sigv4auth.DeriveKey(secret, yyyymmdd, iammiddleware.SigningRegion, privateService)
	in := sigv4auth.SigningInputFromRequest(req)
	in.AccessKeyID = access
	in.CredentialScope = sigv4auth.BuildCredentialScope(yyyymmdd, iammiddleware.SigningRegion, privateService)
	in.PayloadHash = payloadHash
	in.SigningTime = signingTime
	result := sigv4auth.BuildAndSign(derivedKey, in)
	req.Header.Set("X-Amz-Date", result.AmzDate)
	req.Header.Set("Authorization", result.AuthorizationHeader)
}

func doPrivateRequest(t *testing.T, p *PrivateAPI, method, target, access, secret string, body []byte) *http.Response {
	t.Helper()

	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(ProtocolHeader, strconv.Itoa(ProtocolVersion))
	req.ContentLength = int64(len(body))

	hash := sigv4auth.PayloadSHA256Hex(body)
	signPrivateRequest(t, req, access, secret, hash)

	resp, err := p.app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	return resp
}

// doPrivateRequestWithProtocol is doPrivateRequest with the protocol header
// set to an arbitrary value — including "" for a gateway build that predates
// versioning and sends none at all.
func doPrivateRequestWithProtocol(t *testing.T, p *PrivateAPI, target, protocol string, body []byte) *http.Response {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if protocol != "" {
		req.Header.Set(ProtocolHeader, protocol)
	}
	req.ContentLength = int64(len(body))

	signPrivateRequest(t, req, testRoot.Access, testRoot.Secret, sigv4auth.PayloadSHA256Hex(body))

	resp, err := p.app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(body)
}

func TestPrivateAPIDeriveSigningKey(t *testing.T) {
	p, store := newTestServer(t)
	createTestUser(t, store, "alice", "AKIAALICE", "alicesecret", "")

	yyyymmdd := time.Now().UTC().Format(sigv4auth.YYYYMMDD)
	body, _ := json.Marshal(DeriveSigningKeyRequest{
		AccessKeyID: "AKIAALICE",
		Date:        yyyymmdd,
		Region:      "us-east-1",
		Service:     "s3",
	})

	resp := doPrivateRequest(t, p, http.MethodPost, DerivePath, testRoot.Access, testRoot.Secret, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}

	var got DeriveSigningKeyResponse
	if err := json.Unmarshal([]byte(readBody(t, resp)), &got); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	want := sigv4auth.DeriveKey("alicesecret", yyyymmdd, "us-east-1", "s3")
	if !bytes.Equal(got.DerivedKey, want) {
		t.Errorf("DerivedKey = %x, want %x", got.DerivedKey, want)
	}
}

func TestPrivateAPIDeriveSigningKeyRejectsUnknownAccessKey(t *testing.T) {
	p, _ := newTestServer(t)

	body, _ := json.Marshal(DeriveSigningKeyRequest{
		AccessKeyID: "AKIADOESNOTEXIST",
		Date:        time.Now().UTC().Format(sigv4auth.YYYYMMDD),
		Region:      "us-east-1",
		Service:     "s3",
	})

	resp := doPrivateRequest(t, p, http.MethodPost, DerivePath, testRoot.Access, testRoot.Secret, body)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want %d; body=%s", resp.StatusCode, http.StatusForbidden, readBody(t, resp))
	}
}

// TestPrivateAPIDeriveSigningKeySessionToken covers every way a temporary
// (ASIA…) access key can be presented to derive-signing-key. The security of
// the whole session path rests on exactly one thing — that a signing key is
// handed out only for a session token matching the one stored — so each
// wrong-token shape is pinned, along with the error code that tells the S3
// gateway to report InvalidToken rather than InvalidAccessKeyId.
func TestPrivateAPIDeriveSigningKeySessionToken(t *testing.T) {
	p, store := newTestServer(t)
	role := createTestRole(t, store, "testrole", "")
	session := createTestSessionForRole(t, store, role, "ASIASOMESESSIONKEY", "sessionsecret", "correct-session-token", "")

	tests := []struct {
		name       string
		token      string
		wantStatus int
		wantCode   string
	}{
		{name: "no token at all", token: "", wantStatus: http.StatusForbidden, wantCode: CodeNoSuchIdentity},
		{name: "wrong token", token: "wrong-session-token", wantStatus: http.StatusForbidden, wantCode: CodeInvalidToken},
		{name: "correct token", token: session.SessionToken, wantStatus: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(DeriveSigningKeyRequest{
				AccessKeyID:  session.AccessKeyId,
				SessionToken: tt.token,
				Date:         time.Now().UTC().Format(sigv4auth.YYYYMMDD),
				Region:       "us-east-1",
				Service:      "s3",
			})

			resp := doPrivateRequest(t, p, http.MethodPost, DerivePath, testRoot.Access, testRoot.Secret, body)
			raw := readBody(t, resp)
			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", resp.StatusCode, tt.wantStatus, raw)
			}
			if tt.wantCode != "" {
				var errBody struct{ Code string }
				if err := json.Unmarshal([]byte(raw), &errBody); err != nil {
					t.Fatalf("unmarshal error body %s: %v", raw, err)
				}
				if errBody.Code != tt.wantCode {
					t.Fatalf("error code = %q, want %q", errBody.Code, tt.wantCode)
				}
				return
			}

			var out DeriveSigningKeyResponse
			if err := json.Unmarshal([]byte(raw), &out); err != nil {
				t.Fatalf("unmarshal %s: %v", raw, err)
			}
			want := sigv4auth.DeriveKey("sessionsecret", time.Now().UTC().Format(sigv4auth.YYYYMMDD), "us-east-1", "s3")
			if string(out.DerivedKey) != string(want) {
				t.Errorf("derived key = %x, want %x", out.DerivedKey, want)
			}
		})
	}
}

// TestPrivateAPIDeriveSigningKeyRejectsTokenWithPermanentKey confirms a
// session token offered alongside a long-term (AKIA…) key is rejected rather
// than ignored — accepting it silently would mask a misrouted request.
func TestPrivateAPIDeriveSigningKeyRejectsTokenWithPermanentKey(t *testing.T) {
	p, store := newTestServer(t)
	createTestUser(t, store, "alice", "AKIAALICE", "alicesecret", "")

	body, _ := json.Marshal(DeriveSigningKeyRequest{
		AccessKeyID:  "AKIAALICE",
		SessionToken: "some-session-token",
		Date:         time.Now().UTC().Format(sigv4auth.YYYYMMDD),
		Region:       "us-east-1",
		Service:      "s3",
	})

	resp := doPrivateRequest(t, p, http.MethodPost, DerivePath, testRoot.Access, testRoot.Secret, body)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want %d; body=%s", resp.StatusCode, http.StatusForbidden, readBody(t, resp))
	}
}

// TestPrivateAPIEvaluatePolicySessionPolicy confirms the role's own policies
// and the session policy are reported *separately*, not folded together.
//
// The S3 gateway needs them apart because a bucket policy is also in play
// there: a session policy filters permissions that came from the bucket
// policy too, while the role's own decision does not. See
// iammiddleware.AuthorizeSplit.
func TestPrivateAPIEvaluatePolicySessionPolicy(t *testing.T) {
	rolePolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"*"}]}`

	tests := []struct {
		name             string
		sessionPolicy    string
		action           string
		want             string
		wantSession      string
		wantHasSessionPo bool
	}{
		{
			name:   "no session policy: role decision stands alone",
			action: "s3:GetObject",
			want:   DecisionAllow,
		},
		{
			name:             "session policy narrows to a subset",
			sessionPolicy:    `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
			action:           "s3:PutObject",
			want:             DecisionAllow,
			wantSession:      DecisionNoMatch,
			wantHasSessionPo: true,
		},
		{
			name:             "session policy cannot widen beyond the role",
			sessionPolicy:    `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`,
			action:           "s3:DeleteObject",
			want:             DecisionNoMatch,
			wantSession:      DecisionAllow,
			wantHasSessionPo: true,
		},
		{
			name:             "session policy explicit deny against the role's allow",
			sessionPolicy:    `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}]}`,
			action:           "s3:GetObject",
			want:             DecisionAllow,
			wantSession:      DecisionDeny,
			wantHasSessionPo: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, store := newTestServer(t)
			role := createTestRole(t, store, "testrole", rolePolicy)
			session := createTestSessionForRole(t, store, role, "ASIASESSION", "sessionsecret", "tok", tt.sessionPolicy)

			body, _ := json.Marshal(EvaluatePolicyRequest{
				AccessKeyID:  session.AccessKeyId,
				SessionToken: session.SessionToken,
				Actions:      []string{tt.action},
				Resources:    []string{"*"},
			})

			resp := doPrivateRequest(t, p, http.MethodPost, EvaluatePath, testRoot.Access, testRoot.Secret, body)
			raw := readBody(t, resp)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, raw)
			}

			var out EvaluatePolicyResponse
			if err := json.Unmarshal([]byte(raw), &out); err != nil {
				t.Fatalf("unmarshal %s: %v", raw, err)
			}
			if len(out.Decisions) != 1 || len(out.Decisions[0]) != 1 || out.Decisions[0][0] != tt.want {
				t.Errorf("Decisions = %v, want [[%v]]", out.Decisions, tt.want)
			}
			if out.HasSessionPolicy != tt.wantHasSessionPo {
				t.Errorf("HasSessionPolicy = %v, want %v", out.HasSessionPolicy, tt.wantHasSessionPo)
			}
			if tt.wantHasSessionPo {
				if len(out.SessionDecisions) != 1 || len(out.SessionDecisions[0]) != 1 || out.SessionDecisions[0][0] != tt.wantSession {
					t.Errorf("SessionDecisions = %v, want [[%v]]", out.SessionDecisions, tt.wantSession)
				}
			} else if len(out.SessionDecisions) != 0 {
				t.Errorf("SessionDecisions = %v, want none when no session policy applies", out.SessionDecisions)
			}
			wantArn := iamutil.BuildAssumedRoleArn(iamutil.DefaultAccountID, role.RoleName, session.RoleSessionName)
			if out.PrincipalArn != wantArn {
				t.Errorf("PrincipalArn = %q, want %q", out.PrincipalArn, wantArn)
			}
		})
	}
}

// TestPrivateAPIEvaluatePolicyStripsCallerSuppliedIdentityKeys confirms the
// gateway cannot influence an identity-namespace condition key by sending
// one itself. Stripping rather than overriding matters for keys the service
// does not set at all: aws:PrincipalTag/team below has no value for an
// untagged user, and a policy that Allows on its *absence* must not be
// satisfiable by a value the caller supplied.
func TestPrivateAPIEvaluatePolicyStripsCallerSuppliedIdentityKeys(t *testing.T) {
	p, store := newTestServer(t)
	createTestUser(t, store, "alice", "AKIAALICE", "alicesecret",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*",`+
			`"Condition":{"StringEquals":{"aws:PrincipalTag/team":"admins"}}}]}`)

	body, _ := json.Marshal(EvaluatePolicyRequest{
		AccessKeyID: "AKIAALICE",
		Actions:     []string{"s3:GetObject"},
		Resources:   []string{"*"},
		Condition: map[string][]string{
			"aws:PrincipalTag/team": {"admins"},
			// Case-varied spellings must be stripped too: policy key lookup
			// is case-insensitive, so a case-sensitive filter would be no
			// filter at all.
			"AWS:PrincipalArn": {"arn:aws:iam::000000000000:user/somebodyelse"},
		},
	})

	resp := doPrivateRequest(t, p, http.MethodPost, EvaluatePath, testRoot.Access, testRoot.Secret, body)
	raw := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, raw)
	}

	var out EvaluatePolicyResponse
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("unmarshal %s: %v", raw, err)
	}
	if len(out.Decisions) != 1 || len(out.Decisions[0]) != 1 || out.Decisions[0][0] != DecisionNoMatch {
		t.Errorf("Decisions = %v, want [[%v]]: a caller-supplied aws:PrincipalTag must not satisfy the condition", out.Decisions, DecisionNoMatch)
	}
}

// TestPrivateAPIEvaluatePolicyUsesRequestConditionKeys is the counterpart to
// the test above: the request-derived keys the gateway *is* the authority
// for must reach the policy evaluator intact.
func TestPrivateAPIEvaluatePolicyUsesRequestConditionKeys(t *testing.T) {
	p, store := newTestServer(t)
	createTestUser(t, store, "alice", "AKIAALICE", "alicesecret",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*",`+
			`"Condition":{"IpAddress":{"aws:SourceIp":"10.1.2.0/24"}}}]}`)

	tests := []struct {
		name     string
		sourceIP string
		want     string
	}{
		{name: "matching source ip", sourceIP: "10.1.2.3", want: DecisionAllow},
		{name: "non-matching source ip", sourceIP: "10.9.9.9", want: DecisionNoMatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(EvaluatePolicyRequest{
				AccessKeyID: "AKIAALICE",
				Actions:     []string{"s3:GetObject"},
				Resources:   []string{"*"},
				Condition:   map[string][]string{"aws:SourceIp": {tt.sourceIP}},
			})

			resp := doPrivateRequest(t, p, http.MethodPost, EvaluatePath, testRoot.Access, testRoot.Secret, body)
			raw := readBody(t, resp)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, raw)
			}

			var out EvaluatePolicyResponse
			if err := json.Unmarshal([]byte(raw), &out); err != nil {
				t.Fatalf("unmarshal %s: %v", raw, err)
			}
			if len(out.Decisions) != 1 || len(out.Decisions[0]) != 1 || out.Decisions[0][0] != tt.want {
				t.Errorf("Decisions = %v, want [%v]", out.Decisions, tt.want)
			}
		})
	}
}

// TestPrivateAPIResolveIdentity covers the metadata-only endpoint: it must
// answer positionally for a whole batch, resolve a session with no token
// (the disclosure is harmless, since nothing it returns authenticates
// anyone), and label session versus user so the gateway can refuse to
// persist a reference to an ephemeral principal.
func TestPrivateAPIResolveIdentity(t *testing.T) {
	p, store := newTestServer(t)
	createTestUser(t, store, "alice", "AKIAALICE", "alicesecret", "")
	role := createTestRole(t, store, "testrole", "")
	session := createTestSessionForRole(t, store, role, "ASIASESSION", "sessionsecret", "tok", "")

	body, _ := json.Marshal(ResolveIdentityRequest{
		AccessKeyIDs: []string{"AKIAALICE", "AKIADOESNOTEXIST", session.AccessKeyId},
	})

	resp := doPrivateRequest(t, p, http.MethodPost, ResolveIdentityPath, testRoot.Access, testRoot.Secret, body)
	raw := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, raw)
	}

	var out ResolveIdentityResponse
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("unmarshal %s: %v", raw, err)
	}

	want := []ResolvedIdentity{
		{Found: true, Kind: KindUser, PrincipalArn: iamutil.BuildUserArn(iamutil.DefaultAccountID, "/", "alice")},
		{},
		{Found: true, Kind: KindSession, PrincipalArn: iamutil.BuildAssumedRoleArn(iamutil.DefaultAccountID, role.RoleName, session.RoleSessionName)},
	}
	if len(out.Identities) != len(want) {
		t.Fatalf("Identities = %+v, want %d entries", out.Identities, len(want))
	}
	for i := range want {
		if out.Identities[i] != want[i] {
			t.Errorf("Identities[%d] = %+v, want %+v", i, out.Identities[i], want[i])
		}
	}
}

func TestPrivateAPIEvaluatePolicy(t *testing.T) {
	p, store := newTestServer(t)
	createTestUser(t, store, "alice", "AKIAALICE", "alicesecret",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"},{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}`)
	wantArn := iamutil.BuildUserArn(iamutil.DefaultAccountID, "/", "alice")

	tests := []struct {
		name   string
		action string
		want   string
	}{
		{name: "allowed action", action: "s3:GetObject", want: DecisionAllow},
		{name: "action not granted", action: "s3:PutObject", want: DecisionNoMatch},
		{name: "explicitly denied action", action: "s3:DeleteObject", want: DecisionDeny},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(EvaluatePolicyRequest{
				AccessKeyID: "AKIAALICE",
				Actions:     []string{tt.action},
				Resources:   []string{"*"},
			})

			resp := doPrivateRequest(t, p, http.MethodPost, EvaluatePath, testRoot.Access, testRoot.Secret, body)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, body=%s", resp.StatusCode, readBody(t, resp))
			}

			var got EvaluatePolicyResponse
			if err := json.Unmarshal([]byte(readBody(t, resp)), &got); err != nil {
				t.Fatalf("unmarshal response: %v", err)
			}
			if len(got.Decisions) != 1 || len(got.Decisions[0]) != 1 || got.Decisions[0][0] != tt.want {
				t.Errorf("Decisions = %v, want [[%v]]", got.Decisions, tt.want)
			}
			if got.PrincipalArn != wantArn {
				t.Errorf("PrincipalArn = %q, want %q", got.PrincipalArn, wantArn)
			}
		})
	}
}

// TestPrivateAPIEvaluatePolicyBatchesMultipleActions confirms multiple
// actions supplied in one EvaluatePolicyRequest are each evaluated
// independently against the same resource, in a single request, with
// Decisions returned in the same order as Actions.
func TestPrivateAPIEvaluatePolicyBatchesMultipleActions(t *testing.T) {
	p, store := newTestServer(t)
	createTestUser(t, store, "alice", "AKIAALICE", "alicesecret",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"},{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}`)

	body, _ := json.Marshal(EvaluatePolicyRequest{
		AccessKeyID: "AKIAALICE",
		Actions:     []string{"s3:GetObject", "s3:PutObject", "s3:DeleteObject"},
		Resources:   []string{"*"},
	})

	resp := doPrivateRequest(t, p, http.MethodPost, EvaluatePath, testRoot.Access, testRoot.Secret, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}

	var got EvaluatePolicyResponse
	if err := json.Unmarshal([]byte(readBody(t, resp)), &got); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	want := []string{DecisionAllow, DecisionNoMatch, DecisionDeny}
	if len(got.Decisions) != 1 || len(got.Decisions[0]) != len(want) {
		t.Fatalf("Decisions = %v, want [%v]", got.Decisions, want)
	}
	for i := range want {
		if got.Decisions[0][i] != want[i] {
			t.Errorf("Decisions[0][%d] = %v, want %v", i, got.Decisions[0][i], want[i])
		}
	}
}

// TestPrivateAPIEvaluatePolicyBatchesMultipleResources confirms several
// resources are each evaluated against every action in one request — what
// keeps a 1000-key DeleteObjects a single round trip.
func TestPrivateAPIEvaluatePolicyBatchesMultipleResources(t *testing.T) {
	p, store := newTestServer(t)
	createTestUser(t, store, "alice", "AKIAALICE", "alicesecret",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::b/allowed/*"}]}`)

	body, _ := json.Marshal(EvaluatePolicyRequest{
		AccessKeyID: "AKIAALICE",
		Actions:     []string{"s3:DeleteObject"},
		Resources:   []string{"arn:aws:s3:::b/allowed/one", "arn:aws:s3:::b/denied/two", "arn:aws:s3:::b/allowed/three"},
	})

	resp := doPrivateRequest(t, p, http.MethodPost, EvaluatePath, testRoot.Access, testRoot.Secret, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, readBody(t, resp))
	}

	var got EvaluatePolicyResponse
	if err := json.Unmarshal([]byte(readBody(t, resp)), &got); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	want := []string{DecisionAllow, DecisionNoMatch, DecisionAllow}
	if len(got.Decisions) != len(want) {
		t.Fatalf("Decisions = %v, want %d resource entries", got.Decisions, len(want))
	}
	for i := range want {
		if len(got.Decisions[i]) != 1 || got.Decisions[i][0] != want[i] {
			t.Errorf("Decisions[%d] = %v, want [%v]", i, got.Decisions[i], want[i])
		}
	}
}

// TestPrivateAPIRejectsNonRootCredential confirms a validly-signed request
// from a real (non-root) IAM user's own credentials is rejected outright —
// only the S3 gateway's own root-equivalent identity may ever call these
// endpoints.
func TestPrivateAPIRejectsNonRootCredential(t *testing.T) {
	p, store := newTestServer(t)
	createTestUser(t, store, "alice", "AKIAALICE", "alicesecret", "")

	body, _ := json.Marshal(DeriveSigningKeyRequest{
		AccessKeyID: "AKIAALICE",
		Date:        time.Now().UTC().Format(sigv4auth.YYYYMMDD),
		Region:      "us-east-1",
		Service:     "s3",
	})

	// Signed with alice's own, otherwise-valid credentials — not root.
	resp := doPrivateRequest(t, p, http.MethodPost, DerivePath, "AKIAALICE", "alicesecret", body)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want %d; body=%s", resp.StatusCode, http.StatusForbidden, readBody(t, resp))
	}
}

func TestPrivateAPIRejectsMalformedBody(t *testing.T) {
	p, _ := newTestServer(t)

	resp := doPrivateRequest(t, p, http.MethodPost, DerivePath, testRoot.Access, testRoot.Secret, []byte("not json"))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d; body=%s", resp.StatusCode, http.StatusBadRequest, readBody(t, resp))
	}
}

func TestPrivateAPIRejectsUnsignedRequest(t *testing.T) {
	p, _ := newTestServer(t)

	body, _ := json.Marshal(DeriveSigningKeyRequest{AccessKeyID: "AKIAX", Date: "20260101", Region: "us-east-1", Service: "s3"})
	req := httptest.NewRequest(http.MethodPost, DerivePath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode == http.StatusOK {
		t.Errorf("expected an unsigned request to be rejected, got 200")
	}
}

func TestPrivateAPIVersion(t *testing.T) {
	store, err := storage.New(storage.Config{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	p, err := New(store, testRoot, WithPrivateServerVersion("v1.2.3"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	resp := doPrivateRequest(t, p, http.MethodPost, VersionPath, testRoot.Access, testRoot.Secret, []byte("{}"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, readBody(t, resp))
	}

	var got VersionResponse
	if err := json.Unmarshal([]byte(readBody(t, resp)), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Protocol != ProtocolVersion || got.MinClient != MinClientProtocol {
		t.Errorf("VersionResponse = %+v, want protocol %d minClient %d", got, ProtocolVersion, MinClientProtocol)
	}
	if got.ServerVersion != "v1.2.3" {
		t.Errorf("ServerVersion = %q, want %q", got.ServerVersion, "v1.2.3")
	}
}

// TestPrivateAPIVersionRequiresRootCredential confirms the version endpoint is
// authenticated like every other one here — that is what lets the gateway's
// startup probe verify its own credential in the same round trip.
func TestPrivateAPIVersionRequiresRootCredential(t *testing.T) {
	p, store := newTestServer(t)
	createTestUser(t, store, "alice", "AKIAALICE", "alicesecret", "")

	resp := doPrivateRequest(t, p, http.MethodPost, VersionPath, "AKIAALICE", "alicesecret", []byte("{}"))
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("version endpoint served a non-root credential: %s", readBody(t, resp))
	}
}

// TestPrivateAPIProtocolHeaderOnEveryResponse covers the success path, an
// application error, and an unknown route. The last two go through
// errorHandler, which must not drop the header — a mismatch response that
// carries no version is the one response an operator most needs it on.
func TestPrivateAPIProtocolHeaderOnEveryResponse(t *testing.T) {
	p, store := newTestServer(t)
	createTestUser(t, store, "alice", "AKIAALICE", "alicesecret", "")

	for _, tc := range []struct {
		name string
		path string
		body string
	}{
		{"success", ResolveIdentityPath, `{"accessKeyIds":["AKIAALICE"]}`},
		{"application error", DerivePath, "not json"},
		{"unknown route", "/private/nope", "{}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := doPrivateRequest(t, p, http.MethodPost, tc.path, testRoot.Access, testRoot.Secret, []byte(tc.body))
			if got := resp.Header.Get(ProtocolHeader); got != strconv.Itoa(ProtocolVersion) {
				t.Errorf("%s = %q, want %q", ProtocolHeader, got, strconv.Itoa(ProtocolVersion))
			}
		})
	}
}

// TestPrivateAPIRejectsIncompatibleClientProtocol covers every request-header
// value this build refuses. A gateway too old to be served safely, and one
// whose version cannot be read at all, are both refused with a code the
// gateway dispatches on — never served on an assumed version.
func TestPrivateAPIRejectsIncompatibleClientProtocol(t *testing.T) {
	p, store := newTestServer(t)
	createTestUser(t, store, "alice", "AKIAALICE", "alicesecret", "")

	for _, tc := range []struct {
		name     string
		protocol string
	}{
		{"absent", ""},
		{"empty", " "},
		{"not a number", "one"},
		{"signed", "+1"},
		{"zero", "0"},
		{"absurdly long", "11111111111111111111"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := doPrivateRequestWithProtocol(t, p, ResolveIdentityPath, tc.protocol, []byte(`{"accessKeyIds":["AKIAALICE"]}`))
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d; body = %s", resp.StatusCode, http.StatusBadRequest, readBody(t, resp))
			}
			body := readBody(t, resp)
			if !strings.Contains(body, CodeProtocolMismatch) {
				t.Errorf("body = %s, want code %s", body, CodeProtocolMismatch)
			}
			if got := resp.Header.Get(ProtocolHeader); got != strconv.Itoa(ProtocolVersion) {
				t.Errorf("%s = %q, want the refusing build's own version", ProtocolHeader, got)
			}
		})
	}
}

// TestPrivateAPIVersionExemptFromClientProtocolCheck confirms the version
// endpoint answers a gateway this build would otherwise refuse. Without it, a
// future service that raised MinClientProtocol could not tell an older gateway
// why it was being turned away.
func TestPrivateAPIVersionExemptFromClientProtocolCheck(t *testing.T) {
	p, _ := newTestServer(t)

	resp := doPrivateRequestWithProtocol(t, p, VersionPath, "", []byte("{}"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", resp.StatusCode, readBody(t, resp))
	}
	if got := resp.Header.Get(ProtocolHeader); got != strconv.Itoa(ProtocolVersion) {
		t.Errorf("%s = %q, want %q", ProtocolHeader, got, strconv.Itoa(ProtocolVersion))
	}
}

func TestParseProtocolVersion(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  int
	}{
		{"1", 1},
		{"2", 2},
		{"1000", 1000},
		{"", 0},
		{" 1", 0},
		{"1 ", 0},
		{"+1", 0},
		{"-1", 0},
		{"0", 0},
		{"1.0", 0},
		{"v1", 0},
		{"99999", 0},
	} {
		got, err := ParseProtocolVersion(tc.value)
		if tc.want == 0 {
			if err == nil {
				t.Errorf("ParseProtocolVersion(%q) = %d, want an error", tc.value, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseProtocolVersion(%q): %v", tc.value, err)
		}
		if got != tc.want {
			t.Errorf("ParseProtocolVersion(%q) = %d, want %d", tc.value, got, tc.want)
		}
	}
}

// createTestRole creates a role with an optional inline permission policy
// directly against store, the same way createTestUser bypasses the
// control-plane API. Arn and RoleID are set explicitly because
// storage.CreateRole doesn't populate them, and iamutil.ResolveSessionByToken
// re-checks both against the session before attaching the role's policies.
func createTestRole(t *testing.T, store storage.Storer, roleName, policyDocument string) *types.Role {
	t.Helper()
	ctx := context.Background()

	role, err := store.CreateRole(ctx, types.Role{
		RoleName:   roleName,
		Path:       "/",
		RoleID:     "AROA" + roleName,
		Arn:        iamutil.BuildRoleArn(iamutil.DefaultAccountID, "/", roleName),
		CreateDate: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}

	if policyDocument != "" {
		if err := store.PutRolePolicy(ctx, storage.PutRolePolicyInput{
			RoleName:       roleName,
			PolicyName:     "P",
			PolicyDocument: policyDocument,
		}); err != nil {
			t.Fatalf("PutRolePolicy: %v", err)
		}
	}
	return role
}

// createTestSessionForRole creates a session against role as
// AssumeRoleWithWebIdentity would, with an optional inline session policy.
// RoleID and RoleArn are copied from role so the session survives
// iamutil.ResolveSessionByToken's same-role re-check.
func createTestSessionForRole(t *testing.T, store storage.Storer, role *types.Role, accessKeyID, secret, token, sessionPolicy string) *types.Session {
	t.Helper()

	session, err := store.CreateSession(context.Background(), types.Session{
		AccessKeyId:     accessKeyID,
		SecretAccessKey: secret,
		SessionToken:    token,
		RoleArn:         role.Arn,
		RoleName:        role.RoleName,
		RoleID:          role.RoleID,
		RoleSessionName: "testsession",
		CreateDate:      time.Now().UTC(),
		Expiration:      time.Now().UTC().Add(time.Hour),
		Policy:          sessionPolicy,
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return session
}
