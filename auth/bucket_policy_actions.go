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
	"strings"
)

type Action string

const (
	GetBucketAclAction                     Action = "s3:GetBucketAcl"
	CreateBucketAction                     Action = "s3:CreateBucket"
	PutBucketAclAction                     Action = "s3:PutBucketAcl"
	DeleteBucketAction                     Action = "s3:DeleteBucket"
	PutBucketVersioningAction              Action = "s3:PutBucketVersioning"
	GetBucketVersioningAction              Action = "s3:GetBucketVersioning"
	PutBucketPolicyAction                  Action = "s3:PutBucketPolicy"
	GetBucketPolicyAction                  Action = "s3:GetBucketPolicy"
	DeleteBucketPolicyAction               Action = "s3:DeleteBucketPolicy"
	AbortMultipartUploadAction             Action = "s3:AbortMultipartUpload"
	ListMultipartUploadPartsAction         Action = "s3:ListMultipartUploadParts"
	ListBucketMultipartUploadsAction       Action = "s3:ListBucketMultipartUploads"
	PutObjectAction                        Action = "s3:PutObject"
	GetObjectAction                        Action = "s3:GetObject"
	GetObjectVersionAction                 Action = "s3:GetObjectVersion"
	DeleteObjectAction                     Action = "s3:DeleteObject"
	GetObjectAclAction                     Action = "s3:GetObjectAcl"
	GetObjectAttributesAction              Action = "s3:GetObjectAttributes"
	PutObjectAclAction                     Action = "s3:PutObjectAcl"
	RestoreObjectAction                    Action = "s3:RestoreObject"
	GetBucketTaggingAction                 Action = "s3:GetBucketTagging"
	PutBucketTaggingAction                 Action = "s3:PutBucketTagging"
	GetObjectTaggingAction                 Action = "s3:GetObjectTagging"
	PutObjectTaggingAction                 Action = "s3:PutObjectTagging"
	DeleteObjectTaggingAction              Action = "s3:DeleteObjectTagging"
	ListBucketVersionsAction               Action = "s3:ListBucketVersions"
	ListBucketAction                       Action = "s3:ListBucket"
	GetBucketObjectLockConfigurationAction Action = "s3:GetBucketObjectLockConfiguration"
	PutBucketObjectLockConfigurationAction Action = "s3:PutBucketObjectLockConfiguration"
	GetObjectLegalHoldAction               Action = "s3:GetObjectLegalHold"
	PutObjectLegalHoldAction               Action = "s3:PutObjectLegalHold"
	GetObjectRetentionAction               Action = "s3:GetObjectRetention"
	PutObjectRetentionAction               Action = "s3:PutObjectRetention"
	BypassGovernanceRetentionAction        Action = "s3:BypassGovernanceRetention"
	PutBucketOwnershipControlsAction       Action = "s3:PutBucketOwnershipControls"
	GetBucketOwnershipControlsAction       Action = "s3:GetBucketOwnershipControls"
	PutBucketCorsAction                    Action = "s3:PutBucketCORS"
	GetBucketCorsAction                    Action = "s3:GetBucketCORS"
	AllActions                             Action = "s3:*"
)

var supportedActionList = map[Action]struct{}{
	GetBucketAclAction:                     {},
	CreateBucketAction:                     {},
	PutBucketAclAction:                     {},
	DeleteBucketAction:                     {},
	PutBucketVersioningAction:              {},
	GetBucketVersioningAction:              {},
	PutBucketPolicyAction:                  {},
	GetBucketPolicyAction:                  {},
	DeleteBucketPolicyAction:               {},
	AbortMultipartUploadAction:             {},
	ListMultipartUploadPartsAction:         {},
	ListBucketMultipartUploadsAction:       {},
	PutObjectAction:                        {},
	GetObjectAction:                        {},
	GetObjectVersionAction:                 {},
	DeleteObjectAction:                     {},
	GetObjectAclAction:                     {},
	GetObjectAttributesAction:              {},
	PutObjectAclAction:                     {},
	RestoreObjectAction:                    {},
	GetBucketTaggingAction:                 {},
	PutBucketTaggingAction:                 {},
	GetObjectTaggingAction:                 {},
	PutObjectTaggingAction:                 {},
	DeleteObjectTaggingAction:              {},
	ListBucketVersionsAction:               {},
	ListBucketAction:                       {},
	GetBucketObjectLockConfigurationAction: {},
	PutBucketObjectLockConfigurationAction: {},
	GetObjectLegalHoldAction:               {},
	PutObjectLegalHoldAction:               {},
	GetObjectRetentionAction:               {},
	PutObjectRetentionAction:               {},
	BypassGovernanceRetentionAction:        {},
	PutBucketOwnershipControlsAction:       {},
	GetBucketOwnershipControlsAction:       {},
	PutBucketCorsAction:                    {},
	GetBucketCorsAction:                    {},
	AllActions:                             {},
}

var supportedObjectActionList = map[Action]struct{}{
	AbortMultipartUploadAction:      {},
	ListMultipartUploadPartsAction:  {},
	PutObjectAction:                 {},
	GetObjectAction:                 {},
	GetObjectVersionAction:          {},
	DeleteObjectAction:              {},
	GetObjectAclAction:              {},
	GetObjectAttributesAction:       {},
	PutObjectAclAction:              {},
	RestoreObjectAction:             {},
	GetObjectTaggingAction:          {},
	PutObjectTaggingAction:          {},
	DeleteObjectTaggingAction:       {},
	GetObjectLegalHoldAction:        {},
	PutObjectLegalHoldAction:        {},
	GetObjectRetentionAction:        {},
	PutObjectRetentionAction:        {},
	BypassGovernanceRetentionAction: {},
	AllActions:                      {},
}

// Validates Action: it should either wildcard match with supported actions list or be in it
func (a Action) IsValid() error {
	if !strings.HasPrefix(string(a), "s3:") {
		return policyErrInvalidAction
	}

	if a == AllActions {
		return nil
	}

	if a[len(a)-1] == '*' {
		pattern := strings.TrimSuffix(string(a), "*")
		for act := range supportedActionList {
			if strings.HasPrefix(string(act), pattern) {
				return nil
			}
		}

		return policyErrInvalidAction
	}

	_, found := supportedActionList[a]
	if !found {
		return policyErrInvalidAction
	}
	return nil
}

func getBoolPtr(bl bool) *bool {
	return &bl
}

// Checks if the action is object action
// nil points to 's3:*'
func (a Action) IsObjectAction() *bool {
	if a == AllActions {
		return nil
	}
	if a[len(a)-1] == '*' {
		pattern := strings.TrimSuffix(string(a), "*")
		for act := range supportedObjectActionList {
			if strings.HasPrefix(string(act), pattern) {
				return getBoolPtr(true)
			}
		}

		return getBoolPtr(false)
	}

	_, found := supportedObjectActionList[a]
	return &found
}

func (a Action) WildCardMatch(act Action) bool {
	if strings.HasSuffix(string(a), "*") {
		pattern := strings.TrimSuffix(string(a), "*")
		return strings.HasPrefix(string(act), pattern)
	}
	return false
}

type Actions map[Action]struct{}

// Override UnmarshalJSON method to decode both []string and string properties
func (a *Actions) UnmarshalJSON(data []byte) error {
	ss := []string{}
	var err error
	if err = json.Unmarshal(data, &ss); err == nil {
		if len(ss) == 0 {
			return policyErrInvalidAction
		}
		*a = make(Actions)
		for _, s := range ss {
			err = a.Add(s)
			if err != nil {
				return err
			}
		}
	} else {
		var s string
		if err = json.Unmarshal(data, &s); err == nil {
			if s == "" {
				return policyErrInvalidAction
			}
			*a = make(Actions)
			err = a.Add(s)
			if err != nil {
				return err
			}
		}
	}

	return err
}

// Validates and adds a new Action to Actions map
func (a Actions) Add(str string) error {
	action := Action(str)
	err := action.IsValid()
	if err != nil {
		return err
	}

	a[action] = struct{}{}
	return nil
}

func (a Actions) FindMatch(action Action) bool {
	_, ok := a[AllActions]
	if ok {
		return true
	}
	// First O(1) check for non wildcard actions
	_, found := a[action]
	if found {
		return true
	}

	for act := range a {
		if strings.HasSuffix(string(act), "*") && act.WildCardMatch(action) {
			return true
		}
	}

	return false
}
