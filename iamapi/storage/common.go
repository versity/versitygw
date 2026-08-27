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

package storage

import (
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/iamapi/internal/iamutil"
	"github.com/versity/versitygw/iamapi/types"
)

// MaxAccessKeysPerUser is the maximum number of access keys a single IAM
// user may hold at once, matching the AWS IAM quota.
const MaxAccessKeysPerUser = 2

// MaxTagsPerResource is the maximum number of tags a single IAM user, role
// or OIDC provider may carry at once, matching the AWS IAM quota.
const MaxTagsPerResource = 50

// MaxInlinePolicyBytesPerUser is the maximum aggregate size, in bytes, of
// all of a single IAM user's inline policy documents combined
const MaxInlinePolicyBytesPerUser = 2048

// MaxInlinePolicyBytesPerRole is the maximum aggregate size, in bytes, of
// all of a single IAM role's inline policy documents combined
const MaxInlinePolicyBytesPerRole = 10240

// MaxClientIDsPerOIDCProvider is the maximum number of client IDs a single
// OIDC provider may hold at once
const MaxClientIDsPerOIDCProvider = 100

// MaxOIDCProvidersPerAccount is the maximum number of OIDC providers a
// single account may hold
const MaxOIDCProvidersPerAccount = 100

// MaxActiveSessionsPerRole bounds how many currently-unexpired
// AssumeRoleWithWebIdentity sessions a single role may have at once.
// AWS manages and rate-limits STS as a hosted service with no
// customer-visible equivalent quota to match for fidelity; this exists
// purely as local resource protection, since without it a single valid
// federated token can be replayed indefinitely to grow the session
// store — every InternalStore rewrite, or Vault KV path/metadata entry —
// without bound. Chosen generously enough to not constrain any legitimate
// workload's concurrent session count.
//
// A var, not a const, so tests can temporarily lower it rather than paying
// the cost of actually creating 1000 sessions to exercise the cap.
var MaxActiveSessionsPerRole = 1000

var (
	ErrUserIDAlreadyExists      = errors.New("iamapi: user id already exists")
	ErrAccessKeyIDAlreadyExists = errors.New("iamapi: access key id already exists")
	ErrRoleIDAlreadyExists      = errors.New("iamapi: role id already exists")
	// ErrSessionNotFound is returned by GetSession when accessKeyID names no
	// session, or names one whose Expiration has already passed.
	ErrSessionNotFound = errors.New("iamapi: session not found")
)

type ListUsersInput struct {
	PathPrefix string
	Marker     string
	MaxItems   int32
}

type ListUsersOutput struct {
	Users       []types.User
	IsTruncated bool
	Marker      string
}

type ListUserTagsInput struct {
	UserName string
	Marker   string
	MaxItems int32
}

// ListTagsOutput is the paginated tag window ListUserTags and ListRoleTags
// both return.
type ListTagsOutput struct {
	Tags        []types.Tag
	IsTruncated bool
	Marker      string
}

type UpdateUserInput struct {
	UserName    string
	NewPath     string
	NewUserName string
	NewArn      string
}

type CreateAccessKeyInput struct {
	UserName        string
	AccessKeyID     string
	SecretAccessKey string
	Status          string
	CreateDate      time.Time
}

type UpdateAccessKeyInput struct {
	UserName    string
	AccessKeyID string
	Status      string
}

type ListAccessKeysInput struct {
	UserName string
	Marker   string
	MaxItems int32
}

type ListAccessKeysOutput struct {
	AccessKeys  []types.AccessKeyMetadata
	IsTruncated bool
	Marker      string
}

type GetAccessKeyLastUsedOutput struct {
	UserName     string
	LastUsedDate time.Time
	ServiceName  string
	Region       string
}

type PutUserPolicyInput struct {
	UserName       string
	PolicyName     string
	PolicyDocument string
}

type ListUserPoliciesInput struct {
	UserName string
	Marker   string
	MaxItems int32
}

type ListUserPoliciesOutput struct {
	PolicyNames []string
	IsTruncated bool
	Marker      string
}

type ListRolesInput struct {
	PathPrefix string
	Marker     string
	MaxItems   int32
}

type ListRolesOutput struct {
	Roles       []types.Role
	IsTruncated bool
	Marker      string
}

type UpdateAssumeRolePolicyInput struct {
	RoleName       string
	PolicyDocument string
}

type PutRolePolicyInput struct {
	RoleName       string
	PolicyName     string
	PolicyDocument string
}

type ListRolePoliciesInput struct {
	RoleName string
	Marker   string
	MaxItems int32
}

type ListRolePoliciesOutput struct {
	PolicyNames []string
	IsTruncated bool
	Marker      string
}

type ListRoleTagsInput struct {
	RoleName string
	Marker   string
	MaxItems int32
}

type ListOIDCProvidersOutput struct {
	Providers []types.OpenIDConnectProviderListEntry
}

type ListOIDCProviderTagsInput struct {
	Arn      string
	Marker   string
	MaxItems int32
}

// mergeTags applies the tag actions' merge semantics to existing: an
// incoming tag replaces the existing tag whose key matches under keyCase —
// taking over its position and its key's casing — and any remaining
// incoming tag is appended in the order supplied. AWS caps the merged
// total, not the request, so replacing a tag on a resource already at the
// cap is allowed.
func mergeTags(existing, incoming []types.Tag, keyCase iamutil.TagKeyCase) ([]types.Tag, error) {
	merged := slices.Clone(existing)
	for _, tag := range incoming {
		if idx := indexOfTagKey(merged, tag.Key, keyCase); idx >= 0 {
			merged[idx] = tag
			continue
		}
		if len(merged) >= MaxTagsPerResource {
			return nil, iamerr.GetAPIError(iamerr.ErrTagLimitExceeded)
		}
		merged = append(merged, tag)
	}
	return merged, nil
}

// removeTags applies the untag actions' removal semantics to existing:
// every tag whose key matches one of tagKeys under keyCase is dropped, and
// a key naming no existing tag is ignored rather than reported.
func removeTags(existing []types.Tag, tagKeys []string, keyCase iamutil.TagKeyCase) []types.Tag {
	return slices.DeleteFunc(slices.Clone(existing), func(tag types.Tag) bool {
		return slices.ContainsFunc(tagKeys, func(key string) bool {
			return keyCase.Equal(key, tag.Key)
		})
	})
}

func indexOfTagKey(tags []types.Tag, key string, keyCase iamutil.TagKeyCase) int {
	return slices.IndexFunc(tags, func(tag types.Tag) bool {
		return keyCase.Equal(tag.Key, key)
	})
}

// paginateTags sorts tags by key and applies the marker/maxItems window.
// AWS's own tag listings return tags in an unspecified order (its docs
// claim sorted by key; live responses are not), so this sorts by key: a
// stable order is what makes a Marker meaningful, and it's the order the
// documentation promises.
func paginateTags(tags []types.Tag, marker string, maxItems int32, keyCase iamutil.TagKeyCase) *ListTagsOutput {
	sorted := slices.Clone(tags)
	slices.SortFunc(sorted, func(a, b types.Tag) int {
		return strings.Compare(a.Key, b.Key)
	})

	if marker != "" {
		start := len(sorted)
		if idx := indexOfTagKey(sorted, marker, keyCase); idx >= 0 {
			start = idx + 1
		}
		sorted = sorted[start:]
	}

	limit := len(sorted)
	if maxItems > 0 && int(maxItems) < limit {
		limit = int(maxItems)
	}

	out := &ListTagsOutput{Tags: sorted[:limit]}
	if limit < len(sorted) {
		out.IsTruncated = true
		out.Marker = out.Tags[limit-1].Key
	}

	return out
}

func unwrapAPIError(err error) error {
	var apiErr iamerr.APIError
	if errors.As(err, &apiErr) {
		return apiErr
	}

	return err
}
