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
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/iamapi/types"
)

const (
	DefaultAccountID = "000000000000"
	DefaultUserPath  = "/"
	DefaultMaxItems  = 100
	MaxListItems     = 1000
	MaxUserNameLen   = 64
	MaxUserLookupLen = 128
	MaxPathLen       = 512
	userIDPrefix     = "AIDA"
	userIDRandomLen  = 17
	userIDAlphabet   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	maxTagKeyLen     = 128
	maxTagValLen     = 256
)

var (
	namePattern   = regexp.MustCompile(`^[A-Za-z0-9+=,.@_-]+$`)
	tagKeyPattern = regexp.MustCompile(`^[\p{L}\p{Z}\p{N}_.:/=+\-@]+$`)
	tagValPattern = regexp.MustCompile(`^[\p{L}\p{Z}\p{N}_.:/=+\-@]*$`)
)

// RequestParam looks up key first in URL query args, then in the POST body.
func RequestParam(ctx fiber.Ctx, key string) (string, bool) {
	queryArgs := ctx.Request().URI().QueryArgs()
	if queryArgs.Has(key) {
		return string(queryArgs.Peek(key)), true
	}

	postArgs := ctx.Request().PostArgs()
	if postArgs.Has(key) {
		return string(postArgs.Peek(key)), true
	}

	return "", false
}

// GetUserName resolves the UserName request parameter and validates it
// against maxLen, returning missingErr if the parameter is absent or empty.
// operation is included in the debug log on failure (e.g. "DeleteUser").
// missingErr lets callers match the exact AWS error their operation is
// verified against (e.g. iamerr.MissingValue vs iamerr.MissingParameter).
func GetUserName(ctx fiber.Ctx, operation string, maxLen int, missingErr error) (string, error) {
	userName, ok := RequestParam(ctx, "UserName")
	if !ok || userName == "" {
		debuglogger.Logf("missing required %s parameter: UserName", operation)
		return "", missingErr
	}
	if err := ValidateName("userName", userName, maxLen); err != nil {
		return "", err
	}

	return userName, nil
}

// ParseMaxItems reads the MaxItems request parameter, defaulting to
// DefaultMaxItems when absent. operation is included in the debug log on
// parse failure (e.g. "ListUsers", "ListAccessKeys").
func ParseMaxItems(ctx fiber.Ctx, operation string) (int32, error) {
	rawMaxItems, ok := RequestParam(ctx, "MaxItems")
	if !ok || rawMaxItems == "" {
		return int32(DefaultMaxItems), nil
	}

	parsed, err := strconv.ParseInt(rawMaxItems, 10, 32)
	if err != nil || parsed < 1 || parsed > MaxListItems {
		debuglogger.Logf("invalid %s MaxItems value %q: parse_error=%v", operation, rawMaxItems, err)
		return 0, iamerr.InvalidMaxItems(rawMaxItems)
	}

	return int32(parsed), nil
}

// ParseTags reads IAM tag members from the request (up to 50), validates each, and returns the list.
func ParseTags(ctx fiber.Ctx) ([]types.Tag, error) {
	var tags []types.Tag
	seen := map[string]struct{}{}

	for i := 1; ; i++ {
		keyName := fmt.Sprintf("Tags.member.%d.Key", i)
		valueName := fmt.Sprintf("Tags.member.%d.Value", i)

		key, hasKey := RequestParam(ctx, keyName)
		value, hasValue := RequestParam(ctx, valueName)
		if !hasKey && !hasValue {
			break
		}
		if len(tags) >= 50 {
			debuglogger.Logf("IAM user tag count exceeds maximum: max=%d", 50)
			return nil, iamerr.GetAPIError(iamerr.ErrTooManyTags)
		}
		if !hasKey {
			debuglogger.Logf("missing required IAM tag parameter: %s", keyName)
			return nil, iamerr.MissingParameter(keyName)
		}
		if !hasValue {
			debuglogger.Logf("missing required IAM tag parameter: %s", valueName)
			return nil, iamerr.MissingParameter(valueName)
		}
		if err := validateTag(i, key, value); err != nil {
			return nil, err
		}

		normalizedKey := strings.ToLower(key)
		if _, ok := seen[normalizedKey]; ok {
			debuglogger.Logf("duplicate IAM tag key: %q", key)
			return nil, iamerr.GetAPIError(iamerr.ErrDuplicateTagKeys)
		}
		seen[normalizedKey] = struct{}{}

		tags = append(tags, types.Tag{Key: key, Value: value})
	}

	return tags, nil
}

// ValidateName checks that name (an IAM identity or policy name, e.g.
// userName or policyName) is non-empty, matches the allowed character set,
// and fits within maxLength.
func ValidateName(field, name string, maxLength int) error {
	if len(name) > maxLength {
		debuglogger.Logf("IAM name exceeds maximum length: field=%s length=%d max=%d", field, len(name), maxLength)
		return iamerr.UserNameTooLong(field, maxLength)
	}
	if name == "" || !namePattern.MatchString(name) {
		debuglogger.Logf("invalid IAM name: field=%s value=%q", field, name)
		return iamerr.InvalidUserName(field)
	}

	return nil
}

// ValidatePath checks that path is a valid IAM path (must start and end with '/') within MaxPathLen.
func ValidatePath(field, path string) error {
	if len(path) > MaxPathLen {
		debuglogger.Logf("IAM path exceeds maximum length: field=%s length=%d max=%d", field, len(path), MaxPathLen)
		return iamerr.PathTooLong(field, MaxPathLen)
	}
	if !isValidIAMPath(path) {
		debuglogger.Logf("invalid IAM path: field=%s value=%q", field, path)
		return iamerr.InvalidPath(field)
	}

	return nil
}

// ValidatePathPrefix checks that pathPrefix is a non-empty printable ASCII string starting with '/'.
func ValidatePathPrefix(pathPrefix string) error {
	if pathPrefix == "" || len(pathPrefix) > MaxPathLen || pathPrefix[0] != '/' || !isPrintableASCII(pathPrefix[1:]) {
		debuglogger.Logf("invalid IAM path prefix: %q", pathPrefix)
		return iamerr.GetAPIError(iamerr.ErrInvalidPathPrefix)
	}

	return nil
}

// BuildUserArn constructs the ARN for an IAM user.
func BuildUserArn(accountID, path, userName string) string {
	return fmt.Sprintf("arn:aws:iam::%s:user%s%s", accountID, path, userName)
}

// GenerateUserID returns a new cryptographically random IAM user ID in the AIDA… format.
func GenerateUserID() (string, error) {
	id, err := generateAWSID(userIDPrefix, userIDRandomLen)
	if err != nil {
		debuglogger.Logf("failed to generate IAM user ID: %v", err)
		return "", err
	}
	return id, nil
}

// generateAWSID builds an AWS-style unique identifier: a fixed prefix
// followed by randomLen characters drawn from userIDAlphabet.
func generateAWSID(prefix string, randomLen int) (string, error) {
	var b strings.Builder
	b.Grow(len(prefix) + randomLen)
	b.WriteString(prefix)

	max := big.NewInt(int64(len(userIDAlphabet)))
	for range randomLen {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b.WriteByte(userIDAlphabet[n.Int64()])
	}

	return b.String(), nil
}

func validateTag(index int, key, value string) error {
	if len(key) > maxTagKeyLen {
		debuglogger.Logf("IAM tag key exceeds maximum length: index=%d length=%d max=%d", index, len(key), maxTagKeyLen)
		return iamerr.TagKeyTooLong(index)
	}
	if key == "" || !tagKeyPattern.MatchString(key) {
		debuglogger.Logf("invalid IAM tag key: index=%d value=%q", index, key)
		return iamerr.InvalidTagKey(index)
	}
	if len(value) > maxTagValLen {
		debuglogger.Logf("IAM tag value exceeds maximum length: index=%d length=%d max=%d", index, len(value), maxTagValLen)
		return iamerr.TagValueTooLong(index)
	}
	if !tagValPattern.MatchString(value) {
		debuglogger.Logf("invalid IAM tag value: index=%d value=%q", index, value)
		return iamerr.InvalidTagValue(index)
	}

	return nil
}

func isValidIAMPath(path string) bool {
	if path == "" || len(path) > MaxPathLen {
		return false
	}
	if path == "/" {
		return true
	}
	if path[0] != '/' || path[len(path)-1] != '/' {
		return false
	}

	return isPrintableASCII(path[1 : len(path)-1])
}

func isPrintableASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}
