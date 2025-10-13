// Copyright 2023 Versity Software
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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/versity/versitygw/s3err"
)

var ErrAccessDenied = errors.New("access denied")

type policyErr string

func (p policyErr) Error() string {
	return string(p)
}

const (
	policyErrResourceMismatch     = policyErr("Action does not apply to any resource(s) in statement")
	policyErrInvalidResource      = policyErr("Policy has invalid resource")
	policyErrInvalidPrincipal     = policyErr("Invalid principal in policy")
	policyErrInvalidAction        = policyErr("Policy has invalid action")
	policyErrInvalidPolicy        = policyErr("This policy contains invalid Json")
	policyErrInvalidFirstChar     = policyErr("Policies must be valid JSON and the first byte must be '{'")
	policyErrEmptyStatement       = policyErr("Could not parse the policy: Statement is empty!")
	policyErrMissingStatmentField = policyErr("Missing required field Statement")
	policyErrInvalidVersion       = policyErr("The policy must contain a valid version string")
)

type BucketPolicy struct {
	Version   PolicyVersion      `json:"Version"`
	Statement []BucketPolicyItem `json:"Statement"`
}

func (bp *BucketPolicy) UnmarshalJSON(data []byte) error {
	var tmp struct {
		Version   *PolicyVersion
		Statement *[]BucketPolicyItem `json:"Statement"`
	}

	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}

	// If Statement is nil (not present in JSON), return an error
	if tmp.Statement == nil {
		return policyErrMissingStatmentField
	}

	if tmp.Version == nil {
		// bucket policy version should defualt to '2008-10-17'
		bp.Version = PolicyVersion2008
	} else {
		bp.Version = *tmp.Version
	}

	bp.Statement = *tmp.Statement
	return nil
}

func (bp *BucketPolicy) Validate(bucket string, iam IAMService) error {
	if !bp.Version.isValid() {
		return policyErrInvalidVersion
	}

	for _, statement := range bp.Statement {
		err := statement.Validate(bucket, iam)
		if err != nil {
			return err
		}
	}

	return nil
}

func (bp *BucketPolicy) isAllowed(principal string, action Action, resource string) bool {
	var isAllowed bool
	for _, statement := range bp.Statement {
		if statement.findMatch(principal, action, resource) {
			switch statement.Effect {
			case BucketPolicyAccessTypeAllow:
				isAllowed = true
			case BucketPolicyAccessTypeDeny:
				return false
			}
		}
	}

	return isAllowed
}

// IsPublicFor checks if the bucket policy statements contain
// an entity granting public access to the given resource and action
func (bp *BucketPolicy) isPublicFor(resource string, action Action) bool {
	var isAllowed bool
	for _, statement := range bp.Statement {
		if statement.isPublicFor(resource, action) {
			switch statement.Effect {
			case BucketPolicyAccessTypeAllow:
				isAllowed = true
			case BucketPolicyAccessTypeDeny:
				return false
			}
		}
	}

	return isAllowed
}

// IsPublic checks if one of bucket policy statments grant
// public access to ALL users
func (bp *BucketPolicy) IsPublic() bool {
	for _, statement := range bp.Statement {
		if statement.isPublic() {
			return true
		}
	}

	return false
}

type BucketPolicyItem struct {
	Effect     BucketPolicyAccessType `json:"Effect"`
	Principals Principals             `json:"Principal"`
	Actions    Actions                `json:"Action"`
	Resources  Resources              `json:"Resource"`
}

func (bpi *BucketPolicyItem) Validate(bucket string, iam IAMService) error {
	if err := bpi.Effect.Validate(); err != nil {
		return err
	}
	if err := bpi.Principals.Validate(iam); err != nil {
		return err
	}
	if err := bpi.Resources.Validate(bucket); err != nil {
		return err
	}

	containsObjectAction := bpi.Resources.ContainsObjectPattern()
	containsBucketAction := bpi.Resources.ContainsBucketPattern()

	for action := range bpi.Actions {
		isObjectAction := action.IsObjectAction()
		if isObjectAction == nil {
			break
		}
		if *isObjectAction && !containsObjectAction {
			return policyErrResourceMismatch
		}
		if !*isObjectAction && !containsBucketAction {
			return policyErrResourceMismatch
		}
	}

	return nil
}

func (bpi *BucketPolicyItem) findMatch(principal string, action Action, resource string) bool {
	if bpi.Principals.Contains(principal) && bpi.Actions.FindMatch(action) && bpi.Resources.FindMatch(resource) {
		return true
	}

	return false
}

// isPublicFor checks if the bucket policy statemant grants public access
// for given resource and action
func (bpi *BucketPolicyItem) isPublicFor(resource string, action Action) bool {
	return bpi.Principals.isPublic() && bpi.Actions.FindMatch(action) && bpi.Resources.FindMatch(resource)
}

// isPublic checks if the statement grants public access
// to ALL users
func (bpi *BucketPolicyItem) isPublic() bool {
	return bpi.Principals.isPublic()
}

func getMalformedPolicyError(err error) error {
	return s3err.APIError{
		Code:           "MalformedPolicy",
		Description:    err.Error(),
		HTTPStatusCode: http.StatusBadRequest,
	}
}

// ParsePolicyDocument parses raw bytes to 'BucketPolicy'
func ParsePolicyDocument(data []byte) (*BucketPolicy, error) {
	var policy BucketPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		var pe policyErr
		if errors.As(err, &pe) {
			return nil, getMalformedPolicyError(err)
		}
		return nil, getMalformedPolicyError(policyErrInvalidPolicy)
	}

	return &policy, nil
}

func ValidatePolicyDocument(policyBin []byte, bucket string, iam IAMService) error {
	if len(policyBin) == 0 || policyBin[0] != '{' {
		return getMalformedPolicyError(policyErrInvalidFirstChar)
	}
	policy, err := ParsePolicyDocument(policyBin)
	if err != nil {
		return err
	}

	if len(policy.Statement) == 0 {
		return getMalformedPolicyError(policyErrEmptyStatement)
	}

	if err := policy.Validate(bucket, iam); err != nil {
		return getMalformedPolicyError(err)
	}

	return nil
}

func VerifyBucketPolicy(policy []byte, access, bucket, object string, action Action) error {
	var bucketPolicy BucketPolicy
	if err := json.Unmarshal(policy, &bucketPolicy); err != nil {
		return fmt.Errorf("failed to parse the bucket policy: %w", err)
	}

	resource := bucket
	if object != "" {
		resource += "/" + object
	}

	if !bucketPolicy.isAllowed(access, action, resource) {
		return s3err.GetAPIError(s3err.ErrAccessDenied)
	}

	return nil
}

// Checks if the bucket policy grants public access
func VerifyPublicBucketPolicy(policy []byte, bucket, object string, action Action) error {
	var bucketPolicy BucketPolicy
	if err := json.Unmarshal(policy, &bucketPolicy); err != nil {
		return err
	}

	resource := bucket
	if object != "" {
		resource += "/" + object
	}

	if !bucketPolicy.isPublicFor(resource, action) {
		return ErrAccessDenied
	}

	return nil
}

// matchPattern checks if the input string matches the given pattern with wildcard(`*`) and any character(`?`).
// - `?` matches exactly one occurrence of any character.
// - `*` matches arbitrary many (including zero) occurrences of any character.
func matchPattern(pattern, input string) bool {
	pIdx, sIdx := 0, 0
	starIdx, matchIdx := -1, 0

	for sIdx < len(input) {
		if pIdx < len(pattern) && (pattern[pIdx] == '?' || pattern[pIdx] == input[sIdx]) {
			sIdx++
			pIdx++
		} else if pIdx < len(pattern) && pattern[pIdx] == '*' {
			starIdx = pIdx
			matchIdx = sIdx
			pIdx++
		} else if starIdx != -1 {
			pIdx = starIdx + 1
			matchIdx++
			sIdx = matchIdx
		} else {
			return false
		}
	}

	for pIdx < len(pattern) && pattern[pIdx] == '*' {
		pIdx++
	}

	return pIdx == len(pattern)
}
