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

package s3api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/backend/daos"
	"github.com/versity/versitygw/s3api/middlewares"
	"github.com/versity/versitygw/s3response"
)

func TestDaosPutObjectRouter(t *testing.T) {
	cases := []struct {
		name    string
		drop    string
		wantPut bool
	}{
		{name: "getters answer", wantPut: true},
		{name: "acl unsupported", drop: "acl"},
		{name: "policy unsupported", drop: "policy"},
		{name: "lock unsupported", drop: "lock"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			fs := daos.NewFake()
			if err := fs.Mkdir("bucket"); err != nil {
				t.Fatal(err)
			}
			gate := &putGate{inner: daos.NewWithFS(fs), drop: tt.drop}
			iam := allowUserIAM{user: auth.Account{
				Access: "user-access",
				Secret: "user-secret",
				Role:   auth.RoleUser,
			}}
			srv, err := New(gate,
				middlewares.RootUserConfig{Access: "root-access", Secret: "root-secret"},
				"us-east-1",
				&iam,
				nil, nil, nil, nil,
				WithQuiet(),
				WithConcurrencyLimiter(10, 10),
			)
			if err != nil {
				t.Fatal(err)
			}

			resp, err := srv.app.Test(signedUserPut(t, "/bucket/obj", []byte("hi")))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if tt.wantPut {
				if gate.puts != 1 {
					t.Fatalf("backend PutObject calls = %d, status %d, body %s", gate.puts, resp.StatusCode, body)
				}
				if iam.evals == 0 {
					t.Fatal("identity policy was not consulted")
				}
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("status %d, body %s", resp.StatusCode, body)
				}
				return
			}
			if gate.puts != 0 {
				t.Fatalf("backend PutObject calls = %d, want 0; status %d, body %s", gate.puts, resp.StatusCode, body)
			}
		})
	}
}

// putGate counts PutObject and can leave one read getter on BackendUnsupported.
type putGate struct {
	backend.BackendUnsupported
	inner *daos.Daos
	drop  string
	puts  int
}

func (g *putGate) PutObject(ctx context.Context, input s3response.PutObjectInput) (s3response.PutObjectOutput, error) {
	g.puts++
	return g.inner.PutObject(ctx, input)
}

func (g *putGate) GetBucketAcl(ctx context.Context, input *s3.GetBucketAclInput) ([]byte, error) {
	if g.drop == "acl" {
		return g.BackendUnsupported.GetBucketAcl(ctx, input)
	}
	return g.inner.GetBucketAcl(ctx, input)
}

func (g *putGate) GetBucketPolicy(ctx context.Context, bucket string) ([]byte, error) {
	if g.drop == "policy" {
		return g.BackendUnsupported.GetBucketPolicy(ctx, bucket)
	}
	return g.inner.GetBucketPolicy(ctx, bucket)
}

func (g *putGate) GetObjectLockConfiguration(ctx context.Context, bucket string) ([]byte, error) {
	if g.drop == "lock" {
		return g.BackendUnsupported.GetObjectLockConfiguration(ctx, bucket)
	}
	return g.inner.GetObjectLockConfiguration(ctx, bucket)
}

func (g *putGate) NormalizeObjectKey(bucket, object string) string {
	return g.inner.NormalizeObjectKey(bucket, object)
}

// allowUserIAM is a non-root, non-admin account whose identity policy allows
// the signed request. The allow matrix is filled by reflection because the
// decision type is not exported.
type allowUserIAM struct {
	user  auth.Account
	evals int
}

func (a allowUserIAM) CreateAccount(auth.Account) error { return auth.ErrUserExists }
func (a allowUserIAM) GetUserAccount(access string) (auth.Account, error) {
	if access == a.user.Access {
		return a.user, nil
	}
	return auth.Account{}, auth.ErrNoSuchUser
}
func (a allowUserIAM) ResolveAccounts(ids []string) ([]string, error) {
	var missing []string
	for _, id := range ids {
		if _, err := a.GetUserAccount(id); err != nil {
			missing = append(missing, id)
		}
	}
	return missing, nil
}
func (a allowUserIAM) UpdateUserAccount(string, auth.MutableProps) error {
	return auth.ErrNoSuchUser
}
func (a allowUserIAM) DeleteUserAccount(string) error { return auth.ErrNoSuchUser }
func (a allowUserIAM) ListUserAccounts() ([]auth.Account, error) {
	return []auth.Account{a.user}, nil
}
func (a allowUserIAM) Shutdown() error { return nil }

func (a *allowUserIAM) EvaluatePolicy(_, _ string, actions []auth.Action, resources []string, _ map[string][]string) (auth.PolicyEvaluation, error) {
	a.evals++
	return allowEvaluation(len(resources), len(actions)), nil
}

func allowEvaluation(resources, actions int) auth.PolicyEvaluation {
	var ev auth.PolicyEvaluation
	decisions := reflect.ValueOf(&ev).Elem().FieldByName("Decisions")
	rows := reflect.MakeSlice(decisions.Type(), resources, resources)
	for i := 0; i < resources; i++ {
		row := reflect.MakeSlice(decisions.Type().Elem(), actions, actions)
		for j := 0; j < actions; j++ {
			row.Index(j).SetInt(1)
		}
		rows.Index(i).Set(row)
	}
	decisions.Set(rows)
	return ev
}

func signedUserPut(t *testing.T, path string, body []byte) *http.Request {
	t.Helper()
	sum := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(sum[:])
	req := httptest.NewRequest(http.MethodPut, "http://localhost"+path, bytes.NewReader(body))
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	req.ContentLength = int64(len(body))
	creds := aws.Credentials{AccessKeyID: "user-access", SecretAccessKey: "user-secret"}
	if err := v4.NewSigner().SignHTTP(context.Background(), creds, req, payloadHash, "s3", "us-east-1", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	return req
}
