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
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
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
		if statement.isAllowed(principal, action, resource) {
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
		if isObjectAction && !containsObjectAction {
			return fmt.Errorf("unsupported object action '%v' on the specified resources", action)
		}
		if !isObjectAction && !containsBucketAction {
			return fmt.Errorf("unsupported bucket action '%v' on the specified resources", action)
		}
	}

	return nil
}

func (bpi *BucketPolicyItem) isAllowed(principal string, action Action, resource string) bool {
	if bpi.Principals.Contains(principal) && bpi.Actions.FindMatch(action) && bpi.Resources.FindMatch(resource) {
		switch bpi.Effect {
		case BucketPolicyAccessTypeAllow:
			return true
		case BucketPolicyAccessTypeDeny:
			return false
		}
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

	if err := policy.Validate(bucket, iam); err != nil {
		return getMalformedPolicyError(err)
	}

	return nil
}

func verifyBucketPolicy(ctx context.Context, be backend.Backend, access, bucket, object string, action Action) error {
	policyDoc, err := be.GetBucketPolicy(ctx, bucket)
	if err != nil {
		return err
	}
	// If bucket policy is not set
	if len(policyDoc) == 0 {
		return nil
	}

	var bucketPolicy BucketPolicy
	if err := json.Unmarshal(policyDoc, &bucketPolicy); err != nil {
		return err
	}

	resource := bucket
	if object != "" {
		resource += "" + object
	}

	if !bucketPolicy.isAllowed(access, action, resource) {
		return s3err.GetAPIError(s3err.ErrAccessDenied)
	}

	return nil
}
