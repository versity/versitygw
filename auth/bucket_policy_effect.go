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

import "fmt"

type BucketPolicyAccessType string

const (
	BucketPolicyAccessTypeDeny  BucketPolicyAccessType = "Deny"
	BucketPolicyAccessTypeAllow BucketPolicyAccessType = "Allow"
)

// Checks policy statement Effect to be valid ("Deny", "Allow")
func (bpat BucketPolicyAccessType) Validate() error {
	switch bpat {
	case BucketPolicyAccessTypeAllow, BucketPolicyAccessTypeDeny:
		return nil
	}

	//lint:ignore ST1005 Reason: This error message is intended for end-user clarity and follows their expectations
	return fmt.Errorf("Invalid effect: %v", bpat)
}
