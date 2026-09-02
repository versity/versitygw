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
	"github.com/versity/versitygw/internal/httpctx"
)

const (
	DefaultAccountID        = "000000000000"
	DefaultUserPath         = "/"
	DefaultMaxItems         = 100
	MaxListItems            = 1000
	MaxUserNameLen          = 64
	MaxUserLookupLen        = 128
	MaxPathLen              = 512
	userIDPrefix            = "AIDA"
	userIDRandomLen         = 17
	userIDAlphabet          = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	maxTagKeyLen            = 128
	maxTagValLen            = 256
	MaxTagMembersPerRequest = 50

	MaxRoleNameLen  = 64
	roleIDPrefix    = "AROA"
	roleIDRandomLen = 17

	MaxRoleDescriptionLen = 1000

	DefaultMaxSessionDuration = 3600
	MinMaxSessionDuration     = 3600
	MaxMaxSessionDuration     = 43200
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

// HasRequestParamPrefix reports whether any query or form parameter key
// (regardless of its value, including empty) starts with prefix. Unlike
// RequestParam, which probes one exact name, this scans every key actually
// present — needed to reject an AWS Query-protocol indexed-list parameter
// (e.g. "PolicyArns.member.N.arn") for every N a caller might supply,
// instead of only a fixed index like ".1.", which a caller could bypass
// entirely by supplying a different index, a gap, or several members.
func HasRequestParamPrefix(ctx fiber.Ctx, prefix string) bool {
	for key := range ctx.Request().URI().QueryArgs().All() {
		if strings.HasPrefix(string(key), prefix) {
			return true
		}
	}
	for key := range ctx.Request().PostArgs().All() {
		if strings.HasPrefix(string(key), prefix) {
			return true
		}
	}
	return false
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

// GetUserNameOrCaller resolves the UserName request parameter like
// GetUserName, except that an omitted parameter resolves to the calling
// user's own name instead of being an error — matching real IAM, which
// infers the user from the access key signing the request when UserName is
// left out.
//
// Only an entirely absent parameter is inferred. A UserName that is present
// but empty stays a ValidateName rejection, as on real IAM, so a client that
// sends the parameter with no value is told the value is invalid rather than
// silently acting on a different user than it named.
func GetUserNameOrCaller(ctx fiber.Ctx, operation string, maxLen int) (string, error) {
	userName, ok := RequestParam(ctx, "UserName")
	if !ok {
		identity, _ := httpctx.ContextKeyCallerIdentity.Get(ctx).(types.Identity)
		if identity.User == nil {
			debuglogger.Logf("%s omitted UserName with credentials that have no IAM user", operation)
			return "", iamerr.MustSpecifyUserName()
		}
		return identity.User.UserName, nil
	}
	if err := ValidateName("userName", userName, maxLen); err != nil {
		return "", err
	}

	return userName, nil
}

// GetRoleName resolves the RoleName request parameter and validates it
// against maxLen, returning missingErr if the parameter is absent or empty.
func GetRoleName(ctx fiber.Ctx, operation string, maxLen int, missingErr error) (string, error) {
	roleName, ok := RequestParam(ctx, "RoleName")
	if !ok || roleName == "" {
		debuglogger.Logf("missing required %s parameter: RoleName", operation)
		return "", missingErr
	}
	if err := ValidateName("roleName", roleName, maxLen); err != nil {
		return "", err
	}

	return roleName, nil
}

// ParseMaxSessionDuration reads the MaxSessionDuration request parameter,
// defaulting to DefaultMaxSessionDuration when absent, and validates it
// falls within [MinMaxSessionDuration, MaxMaxSessionDuration].
func ParseMaxSessionDuration(ctx fiber.Ctx) (int32, error) {
	raw, ok := RequestParam(ctx, "MaxSessionDuration")
	if !ok || raw == "" {
		return DefaultMaxSessionDuration, nil
	}

	parsed, err := strconv.ParseInt(raw, 10, 32)
	if err != nil {
		debuglogger.Logf("malformed MaxSessionDuration value %q", raw)
		return 0, iamerr.MalformedInput()
	}
	if parsed < MinMaxSessionDuration {
		debuglogger.Logf("invalid MaxSessionDuration value %q", raw)
		return 0, iamerr.MaxSessionDurationTooLow()
	}
	if parsed > MaxMaxSessionDuration {
		debuglogger.Logf("invalid MaxSessionDuration value %q", raw)
		return 0, iamerr.MaxSessionDurationTooHigh()
	}

	return int32(parsed), nil
}

// ValidateDescription checks that the IAM role "Description" fits
// within MaxRoleDescriptionLen and uses the allowed charset — printable
// Latin-1 (excluding 0x7F-0xA0) plus tab/LF/CR
func ValidateDescription(field, desc string) error {
	if len(desc) > MaxRoleDescriptionLen {
		debuglogger.Logf("IAM role description exceeds maximum length: field=%s length=%d max=%d", field, len(desc), MaxRoleDescriptionLen)
		return iamerr.ValueTooLong(field, MaxRoleDescriptionLen)
	}
	for _, r := range desc {
		switch r {
		case '\t', '\n', '\r':
			continue
		}
		if r < 0x20 || (r > 0x7E && r < 0xA1) || r > 0xFF {
			debuglogger.Logf("invalid IAM role description charset: field=%s", field)
			return iamerr.InvalidDescriptionCharset(field)
		}
	}
	return nil
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
	if err != nil {
		debuglogger.Logf("malformed %s MaxItems value %q: %v", operation, rawMaxItems, err)
		return 0, iamerr.MalformedInput()
	}
	if parsed < 1 {
		debuglogger.Logf("invalid %s MaxItems value %q", operation, rawMaxItems)
		return 0, iamerr.GetAPIError(iamerr.ErrMaxItemsTooLow)
	}
	if parsed > MaxListItems {
		debuglogger.Logf("invalid %s MaxItems value %q", operation, rawMaxItems)
		return 0, iamerr.GetAPIError(iamerr.ErrMaxItemsTooHigh)
	}

	return int32(parsed), nil
}

// TagKeyCase selects how a resource's tag keys are compared. IAM users and
// roles fold key case, so "env" and "ENV" name the same tag; OIDC providers
// compare keys exactly, so both can be carried at once.
type TagKeyCase int

const (
	TagKeysFolded TagKeyCase = iota
	TagKeysExact
)

// Equal reports whether a and b name the same tag key under c.
func (c TagKeyCase) Equal(a, b string) bool {
	if c == TagKeysExact {
		return a == b
	}
	return strings.EqualFold(a, b)
}

// normalize maps key to the form that identifies its tag under c, for use
// as a map key.
func (c TagKeyCase) normalize(key string) string {
	if c == TagKeysExact {
		return key
	}
	return strings.ToLower(key)
}

// duplicateErr is the error reported when one request supplies the same tag
// key twice under c.
func (c TagKeyCase) duplicateErr() iamerr.Error {
	if c == TagKeysExact {
		return iamerr.GetAPIError(iamerr.ErrDuplicateExactTagKeys)
	}
	return iamerr.GetAPIError(iamerr.ErrDuplicateTagKeys)
}

// ParseTags reads IAM tag members from the request (up to
// MaxTagMembersPerRequest), validates each, and returns the list.
// Duplicate keys are detected under keyCase, the tagged resource's own
// key-comparison rule.
func ParseTags(ctx fiber.Ctx, keyCase TagKeyCase) ([]types.Tag, error) {
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
		if len(tags) >= MaxTagMembersPerRequest {
			debuglogger.Logf("IAM tag count exceeds maximum: max=%d", MaxTagMembersPerRequest)
			return nil, iamerr.GetAPIError(iamerr.ErrTooManyTags)
		}
		if !hasKey {
			debuglogger.Logf("missing required IAM tag parameter: %s", keyName)
			return nil, iamerr.MissingTagKey(i)
		}
		if !hasValue {
			debuglogger.Logf("missing required IAM tag parameter: %s", valueName)
			return nil, iamerr.MissingTagValue(i)
		}
		if err := validateTag(i, key, value); err != nil {
			return nil, err
		}

		normalizedKey := keyCase.normalize(key)
		if _, ok := seen[normalizedKey]; ok {
			debuglogger.Logf("duplicate IAM tag key: %q", key)
			return nil, keyCase.duplicateErr()
		}
		seen[normalizedKey] = struct{}{}

		tags = append(tags, types.Tag{Key: key, Value: value})
	}

	return tags, nil
}

// ParseTagKeys reads the request's TagKeys members (up to
// MaxTagMembersPerRequest), validates each, and returns the list. Unlike
// ParseTags, duplicate keys are accepted: removing the same key twice is a
// no-op, so AWS has no reason to reject it.
func ParseTagKeys(ctx fiber.Ctx) ([]string, error) {
	var keys []string

	for i := 1; ; i++ {
		key, ok := RequestParam(ctx, fmt.Sprintf("TagKeys.member.%d", i))
		if !ok {
			break
		}
		if len(keys) >= MaxTagMembersPerRequest {
			debuglogger.Logf("IAM tag key count exceeds maximum: max=%d", MaxTagMembersPerRequest)
			return nil, iamerr.GetAPIError(iamerr.ErrTooManyTagKeys)
		}
		if key == "" || len(key) > maxTagKeyLen || !tagKeyPattern.MatchString(key) {
			debuglogger.Logf("invalid IAM tag key: index=%d value=%q", i, key)
			return nil, iamerr.GetAPIError(iamerr.ErrInvalidTagKeys)
		}

		keys = append(keys, key)
	}

	return keys, nil
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

// BuildRoleArn constructs the ARN for an IAM role.
func BuildRoleArn(accountID, path, roleName string) string {
	return fmt.Sprintf("arn:aws:iam::%s:role%s%s", accountID, path, roleName)
}

// GenerateRoleID returns a new cryptographically random IAM role ID in the AROA… format.
func GenerateRoleID() (string, error) {
	id, err := generateAWSID(roleIDPrefix, roleIDRandomLen)
	if err != nil {
		debuglogger.Logf("failed to generate IAM role ID: %v", err)
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
	if key == "" {
		debuglogger.Logf("empty IAM tag key: index=%d", index)
		return iamerr.TagKeyTooShort(index)
	}
	if !tagKeyPattern.MatchString(key) {
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
