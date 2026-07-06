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
	"crypto/rand"
	"encoding/base64"
	"regexp"

	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/iamapi/iamerr"
)

const (
	AccessKeyStatusActive   = "Active"
	AccessKeyStatusInactive = "Inactive"

	accessKeyIDPrefix    = "AKIA"
	accessKeyIDRandomLen = 17
	minAccessKeyIDLen    = 16
	maxAccessKeyIDLen    = 128
	secretAccessKeyBytes = 30
)

var accessKeyIDPattern = regexp.MustCompile(`^[\w]+$`)

// GenerateAccessKeyID returns a new cryptographically random IAM access key
// id in the AKIA… format.
func GenerateAccessKeyID() (string, error) {
	id, err := generateAWSID(accessKeyIDPrefix, accessKeyIDRandomLen)
	if err != nil {
		debuglogger.Logf("failed to generate IAM access key id: %v", err)
		return "", err
	}
	return id, nil
}

// GenerateSecretAccessKey returns a new cryptographically random 40 character
// secret access key.
func GenerateSecretAccessKey() (string, error) {
	b := make([]byte, secretAccessKeyBytes)
	if _, err := rand.Read(b); err != nil {
		debuglogger.Logf("failed to generate IAM secret access key: %v", err)
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// ValidateAccessKeyID checks that accessKeyID fits within the allowed length
// range and character set.
func ValidateAccessKeyID(accessKeyID string) error {
	if len(accessKeyID) < minAccessKeyIDLen {
		debuglogger.Logf("IAM access key id too short: value=%q", accessKeyID)
		return iamerr.AccessKeyIDTooShort(minAccessKeyIDLen)
	}
	if len(accessKeyID) > maxAccessKeyIDLen {
		debuglogger.Logf("IAM access key id too long: value=%q", accessKeyID)
		return iamerr.AccessKeyIDTooLong(maxAccessKeyIDLen)
	}
	if !accessKeyIDPattern.MatchString(accessKeyID) {
		debuglogger.Logf("invalid IAM access key id characters: value=%q", accessKeyID)
		return iamerr.GetAPIError(iamerr.ErrInvalidAccessKeyIDChars)
	}

	return nil
}

// ValidateAccessKeyStatus checks that status is either Active or Inactive.
func ValidateAccessKeyStatus(status string) error {
	if status != AccessKeyStatusActive && status != AccessKeyStatusInactive {
		debuglogger.Logf("invalid IAM access key status: %q", status)
		return iamerr.InvalidAccessKeyStatus(status)
	}

	return nil
}
