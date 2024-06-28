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
	"net/http"

	"github.com/versity/versitygw/s3err"
)

var (
	errResourceMismatch = errors.New("Action does not apply to any resource(s) in statement")
	//lint:ignore ST1005 Reason: This error message is intended for end-user clarity and follows their expectations
	errInvalidResource = errors.New("Policy has invalid resource")
	//lint:ignore ST1005 Reason: This error message is intended for end-user clarity and follows their expectations
	errInvalidPrincipal = errors.New("Invalid principal in policy")
	//lint:ignore ST1005 Reason: This error message is intended for end-user clarity and follows their expectations
	errInvalidAction = errors.New("Policy has invalid action")
)

type BucketPolicy struct {
	Statement []BucketPolicyItem `json:"Statement"`
}

func (bp *BucketPolicy) Validate(bucket string, iam IAMService) error {
	for _, statement := range bp.Statement {
		err := statement.Validate(bucket, iam)
		if err != nil {
			return err
		}
	}

	return nil
}

func (bp *BucketPolicy) isAllowed(principal string, action Action, resource string) bool {
	for _, statement := range bp.Statement {
		if statement.findMatch(principal, action, resource) {
			switch statement.Effect {
			case BucketPolicyAccessTypeAllow:
				return true
			case BucketPolicyAccessTypeDeny:
				return false
			}
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
			return errResourceMismatch
		}
		if !*isObjectAction && !containsBucketAction {
			return errResourceMismatch
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

func getMalformedPolicyError(err error) error {
	return s3err.APIError{
		Code:           "MalformedPolicy",
		Description:    err.Error(),
		HTTPStatusCode: http.StatusBadRequest,
	}
}

func ValidatePolicyDocument(policyBin []byte, bucket string, iam IAMService) error {
	var policy BucketPolicy
	if err := json.Unmarshal(policyBin, &policy); err != nil {
		return getMalformedPolicyError(err)
	}

	if len(policy.Statement) == 0 {
		//lint:ignore ST1005 Reason: This error message is intended for end-user clarity and follows their expectations
		return getMalformedPolicyError(errors.New("Could not parse the policy: Statement is empty!"))
	}

	if err := policy.Validate(bucket, iam); err != nil {
		return getMalformedPolicyError(err)
	}

	return nil
}

func VerifyBucketPolicy(policy []byte, access, bucket, object string, action Action) error {
	var bucketPolicy BucketPolicy
	if err := json.Unmarshal(policy, &bucketPolicy); err != nil {
		return err
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
