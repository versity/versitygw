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
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/versity/versitygw/iamapi"
	"github.com/versity/versitygw/iamapi/private"
	"github.com/versity/versitygw/iamapi/storage"
	"github.com/versity/versitygw/iamapi/types"
	"github.com/versity/versitygw/internal/netutil"
	"github.com/versity/versitygw/internal/sigv4auth"
	"github.com/versity/versitygw/s3err"
)

const standaloneTestRootAccess = "AKIDROOT"
const standaloneTestRootSecret = "ROOTSECRET"

// standaloneTestServer starts a real private.PrivateAPI on a unix socket in
// t.TempDir(), backed by a real file storage.Storer — an actual server, not
// a hand-rolled mock — so IAMServiceStandalone is exercised against exactly
// the same code path the smoke-tested `versitygw iam` binary runs.
func standaloneTestServer(t *testing.T) (store storage.Storer, sockPath string) {
	t.Helper()

	store, err := storage.New(storage.Config{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}

	p, err := private.New(store, iamapi.RootCredentials{
		Access: standaloneTestRootAccess,
		Secret: standaloneTestRootSecret,
	})
	if err != nil {
		t.Fatalf("private.New: %v", err)
	}

	// A unix socket path is limited to ~104 bytes on macOS (sockaddr_un),
	// which t.TempDir() alone can exceed once it embeds this test's full
	// name — os.MkdirTemp with a short, fixed prefix keeps it well under
	// that regardless of the test name.
	sockDir, err := os.MkdirTemp("", "vgw-priv")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	sockPath = filepath.Join(sockDir, "p.sock")

	errCh := make(chan error, 1)
	go func() {
		errCh <- p.ServeMultiPort([]string{sockPath}, netutil.TLSOptions{})
	}()

	waitForSocket(t, sockPath, errCh)

	t.Cleanup(func() {
		if err := p.Shutdown(); err != nil {
			t.Logf("shutdown private API: %v", err)
		}
	})

	return store, sockPath
}

func waitForSocket(t *testing.T, path string, errCh <-chan error) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			t.Fatalf("ServeMultiPort exited early: %v", err)
		default:
		}
		conn, err := net.Dial("unix", path)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("private API socket %s never became ready", path)
}

func createStandaloneTestUser(t *testing.T, store storage.Storer, userName, accessKeyID, secret, policyDocument string) {
	t.Helper()
	ctx := context.Background()

	if _, err := store.CreateUser(ctx, types.User{UserName: userName, Path: "/", CreateDate: time.Now().UTC()}); err != nil {
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

func TestIAMServiceStandaloneDeriveSigningKeyAndGetUserAccount(t *testing.T) {
	store, sock := standaloneTestServer(t)
	createStandaloneTestUser(t, store, "alice", "AKIAALICE", "alicesecret", "")

	rootAcc := Account{Access: standaloneTestRootAccess, Secret: standaloneTestRootSecret, Role: RoleAdmin}
	client, err := NewIAMServiceStandalone(rootAcc, IAMServiceStandaloneConfig{Endpoint: sock})
	if err != nil {
		t.Fatalf("NewIAMServiceStandalone: %v", err)
	}
	defer client.Shutdown()

	yyyymmdd := time.Now().UTC().Format(sigv4auth.YYYYMMDD)
	derivedKey, account, err := client.DeriveSigningKey("AKIAALICE", "", yyyymmdd, "us-east-1", "s3")
	if err != nil {
		t.Fatalf("DeriveSigningKey: %v", err)
	}

	want := sigv4auth.DeriveKey("alicesecret", yyyymmdd, "us-east-1", "s3")
	if string(derivedKey) != string(want) {
		t.Errorf("derived key = %x, want %x", derivedKey, want)
	}
	if account.Secret != "" {
		t.Errorf("account.Secret should never be populated by the standalone client, got %q", account.Secret)
	}
	if account.Role != RoleUser {
		t.Errorf("account.Role = %v, want %v", account.Role, RoleUser)
	}

	// GetUserAccount resolves via the metadata-only endpoint and must agree.
	got, err := client.GetUserAccount("AKIAALICE")
	if err != nil {
		t.Fatalf("GetUserAccount: %v", err)
	}
	if got.Access != "AKIAALICE" || got.Secret != "" {
		t.Errorf("GetUserAccount() = %+v", got)
	}
}

func TestIAMServiceStandaloneGetUserAccountUnknownReturnsErrNoSuchUser(t *testing.T) {
	store, sock := standaloneTestServer(t)
	_ = store

	rootAcc := Account{Access: standaloneTestRootAccess, Secret: standaloneTestRootSecret, Role: RoleAdmin}
	client, err := NewIAMServiceStandalone(rootAcc, IAMServiceStandaloneConfig{Endpoint: sock})
	if err != nil {
		t.Fatalf("NewIAMServiceStandalone: %v", err)
	}
	defer client.Shutdown()

	_, err = client.GetUserAccount("AKIADOESNOTEXIST")
	if !errors.Is(err, ErrNoSuchUser) {
		t.Errorf("GetUserAccount() error = %v, want ErrNoSuchUser", err)
	}
}

func TestIAMServiceStandaloneGetUserAccountRoot(t *testing.T) {
	_, sock := standaloneTestServer(t)

	rootAcc := Account{Access: standaloneTestRootAccess, Secret: standaloneTestRootSecret, Role: RoleAdmin}
	client, err := NewIAMServiceStandalone(rootAcc, IAMServiceStandaloneConfig{Endpoint: sock})
	if err != nil {
		t.Fatalf("NewIAMServiceStandalone: %v", err)
	}
	defer client.Shutdown()

	got, err := client.GetUserAccount(standaloneTestRootAccess)
	if err != nil {
		t.Fatalf("GetUserAccount(root): %v", err)
	}
	if got.Secret != standaloneTestRootSecret {
		t.Errorf("root account should resolve locally with its real secret, got %+v", got)
	}
}

func TestIAMServiceStandaloneEvaluatePolicy(t *testing.T) {
	store, sock := standaloneTestServer(t)
	createStandaloneTestUser(t, store, "bob", "AKIABOB", "bobsecret",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"},{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}`)

	rootAcc := Account{Access: standaloneTestRootAccess, Secret: standaloneTestRootSecret, Role: RoleAdmin}
	client, err := NewIAMServiceStandalone(rootAcc, IAMServiceStandaloneConfig{Endpoint: sock})
	if err != nil {
		t.Fatalf("NewIAMServiceStandalone: %v", err)
	}
	defer client.Shutdown()

	tests := []struct {
		name   string
		action Action
		want   policyDecision
	}{
		{name: "allowed action", action: Action("s3:GetObject"), want: policyDecisionAllow},
		{name: "action with no matching statement", action: Action("s3:PutObject"), want: policyDecisionNoMatch},
		{name: "explicitly denied action", action: Action("s3:DeleteObject"), want: policyDecisionDeny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eval, err := client.EvaluatePolicy("AKIABOB", "", []Action{tt.action}, []string{"*"}, nil)
			if err != nil {
				t.Fatalf("EvaluatePolicy: %v", err)
			}
			if len(eval.Decisions) != 1 || len(eval.Decisions[0]) != 1 || eval.Decisions[0][0] != tt.want {
				t.Errorf("Decisions = %v, want [[%v]]", eval.Decisions, tt.want)
			}
		})
	}
}

// TestIAMServiceStandaloneEvaluatePolicyBatchesMultipleActions confirms
// several actions are evaluated in a single request, with Decisions
// returned in the same order as the requested actions — the fix for
// identityPolicyDecision previously issuing one round trip per action.
func TestIAMServiceStandaloneEvaluatePolicyBatchesMultipleActions(t *testing.T) {
	store, sock := standaloneTestServer(t)
	createStandaloneTestUser(t, store, "bob", "AKIABOB", "bobsecret",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"},{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}`)

	rootAcc := Account{Access: standaloneTestRootAccess, Secret: standaloneTestRootSecret, Role: RoleAdmin}
	client, err := NewIAMServiceStandalone(rootAcc, IAMServiceStandaloneConfig{Endpoint: sock})
	if err != nil {
		t.Fatalf("NewIAMServiceStandalone: %v", err)
	}
	defer client.Shutdown()

	eval, err := client.EvaluatePolicy("AKIABOB", "", []Action{"s3:GetObject", "s3:PutObject", "s3:DeleteObject"}, []string{"*"}, nil)
	if err != nil {
		t.Fatalf("EvaluatePolicy: %v", err)
	}
	want := []policyDecision{policyDecisionAllow, policyDecisionNoMatch, policyDecisionDeny}
	if len(eval.Decisions) != 1 || len(eval.Decisions[0]) != len(want) {
		t.Fatalf("Decisions = %v, want [%v]", eval.Decisions, want)
	}
	for i := range want {
		if eval.Decisions[0][i] != want[i] {
			t.Errorf("Decisions[0][%d] = %v, want %v", i, eval.Decisions[0][i], want[i])
		}
	}
}

func TestIAMServiceStandaloneMutatingMethodsNotSupported(t *testing.T) {
	_, sock := standaloneTestServer(t)

	rootAcc := Account{Access: standaloneTestRootAccess, Secret: standaloneTestRootSecret, Role: RoleAdmin}
	client, err := NewIAMServiceStandalone(rootAcc, IAMServiceStandaloneConfig{Endpoint: sock})
	if err != nil {
		t.Fatalf("NewIAMServiceStandalone: %v", err)
	}
	defer client.Shutdown()

	notSupported := s3err.GetAPIError(s3err.ErrAdminMethodNotSupported)

	if err := client.CreateAccount(Account{}); !errors.Is(err, notSupported) {
		t.Errorf("CreateAccount() error = %v, want %v", err, notSupported)
	}
	if err := client.UpdateUserAccount("x", MutableProps{}); !errors.Is(err, notSupported) {
		t.Errorf("UpdateUserAccount() error = %v, want %v", err, notSupported)
	}
	if err := client.DeleteUserAccount("x"); !errors.Is(err, notSupported) {
		t.Errorf("DeleteUserAccount() error = %v, want %v", err, notSupported)
	}
	if _, err := client.ListUserAccounts(); !errors.Is(err, notSupported) {
		t.Errorf("ListUserAccounts() error = %v, want %v", err, notSupported)
	}
}

func TestNewIAMServiceStandaloneRequiresMTLSForTCPEndpoint(t *testing.T) {
	rootAcc := Account{Access: standaloneTestRootAccess, Secret: standaloneTestRootSecret}
	_, err := NewIAMServiceStandalone(rootAcc, IAMServiceStandaloneConfig{Endpoint: "127.0.0.1:9443"})
	if err == nil {
		t.Fatal("expected an error constructing a TCP-endpoint client without mTLS configured")
	}
}

// TestNewIAMServiceStandaloneDefaultsToRootCredentials confirms this
// client's own signing identity (the credential it signs its private
// requests with) falls back to the gateway's root account when
// Access/Secret aren't explicitly configured — so a deployment doesn't need
// to mint a dedicated IAM identity just for the gateway to talk to its own
// standalone IAM service.
func TestNewIAMServiceStandaloneDefaultsToRootCredentials(t *testing.T) {
	rootAcc := Account{Access: standaloneTestRootAccess, Secret: standaloneTestRootSecret}
	_, sock := standaloneTestServer(t)

	client, err := NewIAMServiceStandalone(rootAcc, IAMServiceStandaloneConfig{Endpoint: sock})
	if err != nil {
		t.Fatalf("NewIAMServiceStandalone: %v", err)
	}
	defer client.Shutdown()

	if client.access != rootAcc.Access {
		t.Errorf("access = %q, want root access %q", client.access, rootAcc.Access)
	}
	if client.secret != rootAcc.Secret {
		t.Errorf("secret = %q, want root secret %q", client.secret, rootAcc.Secret)
	}

	// Also confirm the client actually works end-to-end when signing with
	// the defaulted root identity, not just that the fields were set.
	if _, err := client.GetUserAccount(standaloneTestRootAccess); err != nil {
		t.Fatalf("GetUserAccount(root) with defaulted signing identity: %v", err)
	}
}

// TestNewIAMServiceStandaloneRespectsExplicitCredentials confirms an
// explicitly configured Access/Secret is used as-is, not overridden by the
// root account's credentials.
func TestNewIAMServiceStandaloneRespectsExplicitCredentials(t *testing.T) {
	rootAcc := Account{Access: standaloneTestRootAccess, Secret: standaloneTestRootSecret}
	_, sock := standaloneTestServer(t)

	client, err := NewIAMServiceStandalone(rootAcc, IAMServiceStandaloneConfig{
		Endpoint: sock,
		Access:   "AKIDCUSTOM",
		Secret:   "CUSTOMSECRET",
	})
	if err != nil {
		t.Fatalf("NewIAMServiceStandalone: %v", err)
	}
	defer client.Shutdown()

	if client.access != "AKIDCUSTOM" {
		t.Errorf("access = %q, want %q", client.access, "AKIDCUSTOM")
	}
	if client.secret != "CUSTOMSECRET" {
		t.Errorf("secret = %q, want %q", client.secret, "CUSTOMSECRET")
	}
}

// TestNewIAMServiceStandalonePartialCredentialsRejected covers a half
// configured signing identity: pairing one supplied key with the other half
// of the root credential would silently sign with a mismatched identity, so
// it must fail at construction instead.
func TestNewIAMServiceStandalonePartialCredentialsRejected(t *testing.T) {
	rootAcc := Account{Access: standaloneTestRootAccess, Secret: standaloneTestRootSecret}
	_, sock := standaloneTestServer(t)

	for _, tc := range []struct {
		name   string
		access string
		secret string
	}{
		{name: "access only", access: "AKIDCUSTOM"},
		{name: "secret only", secret: "CUSTOMSECRET"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewIAMServiceStandalone(rootAcc, IAMServiceStandaloneConfig{
				Endpoint: sock,
				Access:   tc.access,
				Secret:   tc.secret,
			})
			if err == nil {
				t.Fatal("expected an error when only one of access/secret is configured")
			}
		})
	}
}

// TestIAMServiceStandaloneRejectsIncompatibleService covers every response a
// peer can give that this gateway must not interpret: no protocol header at
// all (a pre-versioning build, or something else answering on the address),
// one it cannot read, and one older than the protocol this gateway speaks.
// None of them may yield a working client.
func TestIAMServiceStandaloneRejectsIncompatibleService(t *testing.T) {
	shortenProbeWindow(t)

	for _, tc := range []struct {
		name     string
		protocol string
	}{
		{"no header", ""},
		{"unreadable", "one"},
		{"older service", strconv.Itoa(private.ProtocolVersion - 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock := serveFakePrivate(t, tc.protocol, http.StatusOK, `{"protocol":0}`)

			rootAcc := Account{Access: standaloneTestRootAccess, Secret: standaloneTestRootSecret}
			_, err := NewIAMServiceStandalone(rootAcc, IAMServiceStandaloneConfig{Endpoint: sock})
			if err == nil {
				t.Fatal("expected the gateway to refuse to start against an incompatible IAM service")
			}
			var mismatch *protocolMismatchError
			if !errors.As(err, &mismatch) {
				t.Fatalf("error = %v, want a protocolMismatchError", err)
			}
		})
	}
}

// TestIAMServiceStandaloneAcceptsNewerService confirms the rule is
// "not older", not "equal": an IAM service upgraded ahead of its gateways is
// the supported deployment order, so it must keep serving them.
func TestIAMServiceStandaloneAcceptsNewerService(t *testing.T) {
	shortenProbeWindow(t)

	newer := strconv.Itoa(private.ProtocolVersion + 1)
	sock := serveFakePrivate(t, newer, http.StatusOK,
		`{"protocol":`+newer+`,"minClient":1,"serverVersion":"v9.9.9"}`)

	rootAcc := Account{Access: standaloneTestRootAccess, Secret: standaloneTestRootSecret}
	client, err := NewIAMServiceStandalone(rootAcc, IAMServiceStandaloneConfig{Endpoint: sock})
	if err != nil {
		t.Fatalf("NewIAMServiceStandalone against a newer IAM service: %v", err)
	}
	defer client.Shutdown()
}

// TestIAMServiceStandaloneRefusedByNewerService is the other direction of the
// same check: an IAM service that has raised its minimum turns this gateway
// away, and the gateway must recognise that as a version problem rather than
// as a generic server error.
func TestIAMServiceStandaloneRefusedByNewerService(t *testing.T) {
	shortenProbeWindow(t)

	sock := serveFakePrivate(t, strconv.Itoa(private.ProtocolVersion+1), http.StatusBadRequest,
		`{"error":"gateway speaks private protocol 1, this IAM service requires 2 or newer","code":"`+private.CodeProtocolMismatch+`"}`)

	rootAcc := Account{Access: standaloneTestRootAccess, Secret: standaloneTestRootSecret}
	_, err := NewIAMServiceStandalone(rootAcc, IAMServiceStandaloneConfig{Endpoint: sock})
	if err == nil {
		t.Fatal("expected the gateway to refuse to start when the IAM service refuses it")
	}
	var mismatch *protocolMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("error = %v, want a protocolMismatchError", err)
	}
}

// TestIAMServiceStandaloneRefusedByServiceMinimum covers the one direction a
// response header cannot express. The version endpoint is exempt from the
// service's own client-version check, so it answers 200 even to a gateway the
// service will not serve; the gateway has to reach that conclusion from the
// minimum the endpoint reports, or it would start cleanly and then fail every
// real request.
func TestIAMServiceStandaloneRefusedByServiceMinimum(t *testing.T) {
	shortenProbeWindow(t)

	current := strconv.Itoa(private.ProtocolVersion)
	sock := serveFakePrivate(t, current, http.StatusOK,
		`{"protocol":`+current+`,"minClient":`+strconv.Itoa(private.ProtocolVersion+1)+`}`)

	rootAcc := Account{Access: standaloneTestRootAccess, Secret: standaloneTestRootSecret}
	_, err := NewIAMServiceStandalone(rootAcc, IAMServiceStandaloneConfig{Endpoint: sock})
	if err == nil {
		t.Fatal("expected the gateway to refuse to start below the IAM service's minimum")
	}
	var mismatch *protocolMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("error = %v, want a protocolMismatchError", err)
	}
}

// TestIAMServiceStandaloneUnreachableIsNotFatal confirms an unreachable IAM
// service only warns. The two processes legitimately start in parallel, and
// every request checks the version anyway, so refusing to start here would
// invent an ordering dependency without buying any safety.
func TestIAMServiceStandaloneUnreachableIsNotFatal(t *testing.T) {
	shortenProbeWindow(t)

	sockDir, err := os.MkdirTemp("", "vgw-priv")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })

	rootAcc := Account{Access: standaloneTestRootAccess, Secret: standaloneTestRootSecret}
	client, err := NewIAMServiceStandalone(rootAcc, IAMServiceStandaloneConfig{
		Endpoint: filepath.Join(sockDir, "nothing-here.sock"),
	})
	if err != nil {
		t.Fatalf("an unreachable IAM service must not be fatal, got: %v", err)
	}
	defer client.Shutdown()
}

// TestIAMServiceStandaloneDoesNotRetryDefinitiveRejection confirms the probe's
// retry window applies only to failures that can resolve on their own. A
// rejected gateway credential is answered by a service that is up and
// compatible, so it must warn at once rather than hold startup for the full
// window. Deliberately run against the real, unshortened window.
func TestIAMServiceStandaloneDoesNotRetryDefinitiveRejection(t *testing.T) {
	sock := serveFakePrivate(t, strconv.Itoa(private.ProtocolVersion), http.StatusForbidden,
		`{"error":"The security token included in the request is invalid","code":"InvalidClientTokenId"}`)

	rootAcc := Account{Access: standaloneTestRootAccess, Secret: standaloneTestRootSecret}

	start := time.Now()
	client, err := NewIAMServiceStandalone(rootAcc, IAMServiceStandaloneConfig{Endpoint: sock})
	if err != nil {
		t.Fatalf("a rejected credential must warn, not fail startup: %v", err)
	}
	defer client.Shutdown()

	if elapsed := time.Since(start); elapsed > standaloneProbeInterval {
		t.Errorf("probe took %v; a definitive rejection must not be retried", elapsed)
	}
}

// TestIAMServiceStandaloneSendsProtocolHeader confirms the gateway advertises
// its own version, and that it does so inside the signature: the real server
// verifies the signature over that header, so an unsigned or absent one would
// fail before reaching a handler.
func TestIAMServiceStandaloneSendsProtocolHeader(t *testing.T) {
	store, sock := standaloneTestServer(t)
	createStandaloneTestUser(t, store, "alice", "AKIAALICE", "alicesecret", "")

	rootAcc := Account{Access: standaloneTestRootAccess, Secret: standaloneTestRootSecret}
	client, err := NewIAMServiceStandalone(rootAcc, IAMServiceStandaloneConfig{Endpoint: sock})
	if err != nil {
		t.Fatalf("NewIAMServiceStandalone: %v", err)
	}
	defer client.Shutdown()

	if _, err := client.GetUserAccount("AKIAALICE"); err != nil {
		t.Fatalf("GetUserAccount: %v", err)
	}
}

// TestIAMServiceStandaloneShapeChecksSurviveMatchingProtocol confirms the
// version header did not replace the response-shape checks. A peer can declare
// a compatible version and still send a matrix that disagrees — a forgotten
// bump, a locally patched build — and that must still fail closed.
func TestIAMServiceStandaloneShapeChecksSurviveMatchingProtocol(t *testing.T) {
	shortenProbeWindow(t)

	// Compatible on the wire version, but one action decision short of the two
	// actions asked for below.
	current := strconv.Itoa(private.ProtocolVersion)
	sock := serveFakePrivate(t, current, http.StatusOK,
		`{"protocol":`+current+`,"decisions":[["allow"]]}`)

	rootAcc := Account{Access: standaloneTestRootAccess, Secret: standaloneTestRootSecret}
	client, err := NewIAMServiceStandalone(rootAcc, IAMServiceStandaloneConfig{Endpoint: sock})
	if err != nil {
		t.Fatalf("NewIAMServiceStandalone: %v", err)
	}
	defer client.Shutdown()

	_, err = client.EvaluatePolicy("AKIAALICE", "", []Action{GetObjectAction, PutObjectAction}, []string{"arn:aws:s3:::b/o"}, nil)
	if err == nil {
		t.Fatal("expected a short decision row to fail closed even at a matching protocol version")
	}
}

// shortenProbeWindow collapses the startup probe's retry window for tests that
// deliberately point the client at an incompatible or absent service, which
// would otherwise sit through the full production window.
func shortenProbeWindow(t *testing.T) {
	t.Helper()

	window, interval := standaloneProbeWindow, standaloneProbeInterval
	standaloneProbeWindow, standaloneProbeInterval = 0, time.Millisecond
	t.Cleanup(func() { standaloneProbeWindow, standaloneProbeInterval = window, interval })
}

// serveFakePrivate serves a stand-in for the standalone IAM service on a unix
// socket, answering every request with the given protocol header (omitted when
// empty), status, and body. It exists because the cases worth testing — a
// build older or newer than this one, or one predating versioning altogether —
// cannot be produced by the real server, which only ever speaks its own
// version.
func serveFakePrivate(t *testing.T, protocol string, status int, body string) string {
	t.Helper()

	sockDir, err := os.MkdirTemp("", "vgw-priv")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	sockPath := filepath.Join(sockDir, "p.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if protocol != "" {
			w.Header().Set(private.ProtocolHeader, protocol)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	return sockPath
}
