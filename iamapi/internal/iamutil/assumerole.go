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

package iamutil

import (
	"regexp"
	"strings"
	"time"

	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/iamapi/types"
)

const (
	MinExternalIDLen = 2
	MaxExternalIDLen = 1224

	// MaxChainedDurationSeconds caps the session a role session may request
	// when it assumes another role, whatever that role's own
	// MaxSessionDuration allows.
	MaxChainedDurationSeconds = 3600

	// arnFieldCount is the number of colon-separated fields in an ARN:
	// arn:partition:service:region:account:resource.
	arnFieldCount = 6
)

var externalIDPattern = regexp.MustCompile(`^[\w+=,.@:/-]*$`)

// ValidateExternalID checks AssumeRole's ExternalId against STS's length and
// charset constraints.
func ValidateExternalID(externalID string) error {
	if len(externalID) < MinExternalIDLen {
		debuglogger.Logf("ExternalId too short: length=%d", len(externalID))
		return iamerr.ValueTooShort("externalId", MinExternalIDLen)
	}
	if len(externalID) > MaxExternalIDLen {
		debuglogger.Logf("ExternalId too long: length=%d", len(externalID))
		return iamerr.ValueTooLong("externalId", MaxExternalIDLen)
	}
	if !externalIDPattern.MatchString(externalID) {
		debuglogger.Logf("invalid ExternalId characters")
		return iamerr.InvalidExternalID(externalID)
	}
	return nil
}

// IsArnShaped reports whether value has an ARN's outline: the "arn" prefix
// and all six colon-separated fields. Whether it names anything is a
// separate question.
func IsArnShaped(value string) bool {
	fields := strings.SplitN(value, ":", arnFieldCount)
	return len(fields) == arnFieldCount && fields[0] == "arn"
}

// NewSession builds a session of role with freshly generated credentials,
// valid for durationSeconds from now. It is not stored.
func NewSession(role *types.Role, roleSessionName, sessionPolicy string, now time.Time, durationSeconds int32) (types.Session, error) {
	accessKeyID, err := GenerateTempAccessKeyID()
	if err != nil {
		return types.Session{}, err
	}
	secretAccessKey, err := GenerateSecretAccessKey()
	if err != nil {
		return types.Session{}, err
	}
	sessionToken, err := GenerateSessionToken()
	if err != nil {
		return types.Session{}, err
	}

	return types.Session{
		AccessKeyId:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		SessionToken:    sessionToken,
		RoleArn:         role.Arn,
		RoleName:        role.RoleName,
		RoleID:          role.RoleID,
		RoleSessionName: roleSessionName,
		CreateDate:      now,
		Expiration:      now.Add(time.Duration(durationSeconds) * time.Second),
		Policy:          sessionPolicy,
	}, nil
}

// SessionCredentials returns the credentials of session in the shape the
// AssumeRole and AssumeRoleWithWebIdentity responses carry.
func SessionCredentials(session types.Session) types.Credentials {
	return types.Credentials{
		AccessKeyId:     session.AccessKeyId,
		SecretAccessKey: session.SecretAccessKey,
		SessionToken:    session.SessionToken,
		Expiration:      session.Expiration,
	}
}
