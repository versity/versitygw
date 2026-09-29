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

package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/versity/versitygw/internal/sigv4auth"
)

func TestIAMServiceSingleGetUserAccount(t *testing.T) {
	root := Account{Access: "root", Secret: "rootsecret", Role: RoleAdmin}
	iam := NewIAMServiceSingle(root)

	acc, err := iam.GetUserAccount("root")
	assert.NoError(t, err)
	assert.Equal(t, root, acc)

	_, err = iam.GetUserAccount("NOSUCHKEYID0000000")
	assert.Equal(t, ErrNoSuchUser, err)
}

// The S3 auth middlewares render InvalidAccessKeyId only when
// ResolveDerivedKey returns exactly ErrNoSuchUser.
func TestIAMServiceSingleResolveDerivedKeyUnknownAccess(t *testing.T) {
	root := Account{Access: "root", Secret: "rootsecret", Role: RoleAdmin}
	iam := NewIAMServiceSingle(root)

	_, _, err := ResolveDerivedKey(iam, root, "NOSUCHKEYID0000000", "", "20260928", "us-east-1", sigv4auth.ServiceS3)
	assert.Equal(t, ErrNoSuchUser, err)
}

func TestIAMServiceSingleResolveAccounts(t *testing.T) {
	iam := NewIAMServiceSingle(Account{Access: "root", Secret: "rootsecret", Role: RoleAdmin})

	missing, err := iam.ResolveAccounts([]string{"root", "user1", "user2"})
	assert.NoError(t, err)
	assert.Equal(t, []string{"user1", "user2"}, missing)
}
