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
	"net"
	"os"
	"path/filepath"
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
