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
	GetBucketAclAction                       Action = "s3:GetBucketAcl"
	CreateBucketAction                       Action = "s3:CreateBucket"
	PutBucketAclAction                       Action = "s3:PutBucketAcl"
	DeleteBucketAction                       Action = "s3:DeleteBucket"
	PutBucketVersioningAction                Action = "s3:PutBucketVersioning"
	GetBucketVersioningAction                Action = "s3:GetBucketVersioning"
	PutBucketPolicyAction                    Action = "s3:PutBucketPolicy"
	GetBucketPolicyAction                    Action = "s3:GetBucketPolicy"
	DeleteBucketPolicyAction                 Action = "s3:DeleteBucketPolicy"
	AbortMultipartUploadAction               Action = "s3:AbortMultipartUpload"
	ListMultipartUploadPartsAction           Action = "s3:ListMultipartUploadParts"
	ListBucketMultipartUploadsAction         Action = "s3:ListBucketMultipartUploads"
	PutObjectAction                          Action = "s3:PutObject"
	GetObjectAction                          Action = "s3:GetObject"
	GetObjectVersionAction                   Action = "s3:GetObjectVersion"
	DeleteObjectAction                       Action = "s3:DeleteObject"
	DeleteObjectVersionAction                Action = "s3:DeleteObjectVersion"
	GetObjectAclAction                       Action = "s3:GetObjectAcl"
	GetObjectAttributesAction                Action = "s3:GetObjectAttributes"
	GetObjectVersionAttributesAction         Action = "s3:GetObjectVersionAttributes"
	PutObjectAclAction                       Action = "s3:PutObjectAcl"
	RestoreObjectAction                      Action = "s3:RestoreObject"
	GetBucketTaggingAction                   Action = "s3:GetBucketTagging"
	PutBucketTaggingAction                   Action = "s3:PutBucketTagging"
	GetObjectTaggingAction                   Action = "s3:GetObjectTagging"
	GetObjectVersionTaggingAction            Action = "s3:GetObjectVersionTagging"
	PutObjectTaggingAction                   Action = "s3:PutObjectTagging"
	PutObjectVersionTaggingAction            Action = "s3:PutObjectVersionTagging"
	DeleteObjectTaggingAction                Action = "s3:DeleteObjectTagging"
	DeleteObjectVersionTaggingAction         Action = "s3:DeleteObjectVersionTagging"
	ListBucketVersionsAction                 Action = "s3:ListBucketVersions"
	ListBucketAction                         Action = "s3:ListBucket"
	GetBucketObjectLockConfigurationAction   Action = "s3:GetBucketObjectLockConfiguration"
	PutBucketObjectLockConfigurationAction   Action = "s3:PutBucketObjectLockConfiguration"
	GetObjectLegalHoldAction                 Action = "s3:GetObjectLegalHold"
	PutObjectLegalHoldAction                 Action = "s3:PutObjectLegalHold"
	GetObjectRetentionAction                 Action = "s3:GetObjectRetention"
	PutObjectRetentionAction                 Action = "s3:PutObjectRetention"
	BypassGovernanceRetentionAction          Action = "s3:BypassGovernanceRetention"
	PutBucketOwnershipControlsAction         Action = "s3:PutBucketOwnershipControls"
	GetBucketOwnershipControlsAction         Action = "s3:GetBucketOwnershipControls"
	PutBucketCorsAction                      Action = "s3:PutBucketCORS"
	GetBucketCorsAction                      Action = "s3:GetBucketCORS"
	PutAnalyticsConfigurationAction          Action = "s3:PutAnalyticsConfiguration"
	GetAnalyticsConfigurationAction          Action = "s3:GetAnalyticsConfiguration"
	PutEncryptionConfigurationAction         Action = "s3:PutEncryptionConfiguration"
	GetEncryptionConfigurationAction         Action = "s3:GetEncryptionConfiguration"
	PutIntelligentTieringConfigurationAction Action = "s3:PutIntelligentTieringConfiguration"
	GetIntelligentTieringConfigurationAction Action = "s3:GetIntelligentTieringConfiguration"
	PutInventoryConfigurationAction          Action = "s3:PutInventoryConfiguration"
	GetInventoryConfigurationAction          Action = "s3:GetInventoryConfiguration"
	PutLifecycleConfigurationAction          Action = "s3:PutLifecycleConfiguration"
	GetLifecycleConfigurationAction          Action = "s3:GetLifecycleConfiguration"
	PutBucketLoggingAction                   Action = "s3:PutBucketLogging"
	GetBucketLoggingAction                   Action = "s3:GetBucketLogging"
	PutBucketRequestPaymentAction            Action = "s3:PutBucketRequestPayment"
	GetBucketRequestPaymentAction            Action = "s3:GetBucketRequestPayment"
	PutMetricsConfigurationAction            Action = "s3:PutMetricsConfiguration"
	GetMetricsConfigurationAction            Action = "s3:GetMetricsConfiguration"
	PutReplicationConfigurationAction        Action = "s3:PutReplicationConfiguration"
	GetReplicationConfigurationAction        Action = "s3:GetReplicationConfiguration"
	PutBucketPublicAccessBlockAction         Action = "s3:PutBucketPublicAccessBlock"
	GetBucketPublicAccessBlockAction         Action = "s3:GetBucketPublicAccessBlock"
	PutBucketNotificationAction              Action = "s3:PutBucketNotification"
	GetBucketNotificationAction              Action = "s3:GetBucketNotification"
	PutAccelerateConfigurationAction         Action = "s3:PutAccelerateConfiguration"
	GetAccelerateConfigurationAction         Action = "s3:GetAccelerateConfiguration"
	PutBucketWebsiteAction                   Action = "s3:PutBucketWebsite"
	GetBucketWebsiteAction                   Action = "s3:GetBucketWebsite"
	GetBucketPolicyStatusAction              Action = "s3:GetBucketPolicyStatus"
	GetBucketLocationAction                  Action = "s3:GetBucketLocation"

	AllActions Action = "s3:*"
)

var supportedActionList = map[Action]struct{}{
	GetBucketAclAction:                       {},
	CreateBucketAction:                       {},
	PutBucketAclAction:                       {},
	DeleteBucketAction:                       {},
	PutBucketVersioningAction:                {},
	GetBucketVersioningAction:                {},
	PutBucketPolicyAction:                    {},
	GetBucketPolicyAction:                    {},
	DeleteBucketPolicyAction:                 {},
	AbortMultipartUploadAction:               {},
	ListMultipartUploadPartsAction:           {},
	ListBucketMultipartUploadsAction:         {},
	PutObjectAction:                          {},
	GetObjectAction:                          {},
	GetObjectVersionAction:                   {},
	DeleteObjectAction:                       {},
	DeleteObjectVersionAction:                {},
	GetObjectAclAction:                       {},
	GetObjectAttributesAction:                {},
	GetObjectVersionAttributesAction:         {},
	PutObjectAclAction:                       {},
	RestoreObjectAction:                      {},
	GetBucketTaggingAction:                   {},
	PutBucketTaggingAction:                   {},
	GetObjectTaggingAction:                   {},
	GetObjectVersionTaggingAction:            {},
	PutObjectTaggingAction:                   {},
	PutObjectVersionTaggingAction:            {},
	DeleteObjectTaggingAction:                {},
	DeleteObjectVersionTaggingAction:         {},
	ListBucketVersionsAction:                 {},
	ListBucketAction:                         {},
	GetBucketObjectLockConfigurationAction:   {},
	PutBucketObjectLockConfigurationAction:   {},
	GetObjectLegalHoldAction:                 {},
	PutObjectLegalHoldAction:                 {},
	GetObjectRetentionAction:                 {},
	PutObjectRetentionAction:                 {},
	BypassGovernanceRetentionAction:          {},
	PutBucketOwnershipControlsAction:         {},
	GetBucketOwnershipControlsAction:         {},
	PutBucketCorsAction:                      {},
	GetBucketCorsAction:                      {},
	PutAnalyticsConfigurationAction:          {},
	GetAnalyticsConfigurationAction:          {},
	PutEncryptionConfigurationAction:         {},
	GetEncryptionConfigurationAction:         {},
	PutIntelligentTieringConfigurationAction: {},
	GetIntelligentTieringConfigurationAction: {},
	PutInventoryConfigurationAction:          {},
	GetInventoryConfigurationAction:          {},
	PutLifecycleConfigurationAction:          {},
	GetLifecycleConfigurationAction:          {},
	PutBucketLoggingAction:                   {},
	GetBucketLoggingAction:                   {},
	PutBucketRequestPaymentAction:            {},
	GetBucketRequestPaymentAction:            {},
	PutMetricsConfigurationAction:            {},
	GetMetricsConfigurationAction:            {},
	PutReplicationConfigurationAction:        {},
	GetReplicationConfigurationAction:        {},
	PutBucketPublicAccessBlockAction:         {},
	GetBucketPublicAccessBlockAction:         {},
	PutBucketNotificationAction:              {},
	GetBucketNotificationAction:              {},
	PutAccelerateConfigurationAction:         {},
	GetAccelerateConfigurationAction:         {},
	PutBucketWebsiteAction:                   {},
	GetBucketWebsiteAction:                   {},
	GetBucketPolicyStatusAction:              {},
	GetBucketLocationAction:                  {},
	AllActions:                               {},
}

var supportedObjectActionList = map[Action]struct{}{
	AbortMultipartUploadAction:       {},
	ListMultipartUploadPartsAction:   {},
	PutObjectAction:                  {},
	GetObjectAction:                  {},
	GetObjectVersionAction:           {},
	DeleteObjectAction:               {},
	DeleteObjectVersionAction:        {},
	GetObjectAclAction:               {},
	GetObjectAttributesAction:        {},
	GetObjectVersionAttributesAction: {},
	PutObjectAclAction:               {},
	RestoreObjectAction:              {},
	GetObjectTaggingAction:           {},
	GetObjectVersionTaggingAction:    {},
	PutObjectTaggingAction:           {},
	PutObjectVersionTaggingAction:    {},
	DeleteObjectTaggingAction:        {},
	DeleteObjectVersionTaggingAction: {},
	GetObjectLegalHoldAction:         {},
	PutObjectLegalHoldAction:         {},
	GetObjectRetentionAction:         {},
	PutObjectRetentionAction:         {},
	BypassGovernanceRetentionAction:  {},
	AllActions:                       {},
}

// Validates Action: it should either wildcard match with supported actions list or be in it
func (a Action) IsValid() error {
	if !strings.HasPrefix(string(a), "s3:") {
		return policyErrInvalidAction
	}

	if a == AllActions {
		return nil
	}

	// first check for an exact match
	if _, ok := supportedActionList[a]; ok {
		return nil
	}

	// walk through the supported actions and try wildcard match
	for action := range supportedActionList {
		if action.Match(a) {
			return nil
		}
	}

	return policyErrInvalidAction
}

func getBoolPtr(bl bool) *bool {
	return &bl
}

// String converts the action to string
func (a Action) String() string {
	return string(a)
}

// Match wildcard matches the given pattern to the action
func (a Action) Match(pattern Action) bool {
	return matchPattern(pattern.String(), a.String())
}

// Checks if the action is object action
// nil points to 's3:*'
func (a Action) IsObjectAction() *bool {
	if a == AllActions {
		return nil
	}

	// first find an exact match
	if _, ok := supportedObjectActionList[a]; ok {
		return &ok
	}

	for action := range supportedObjectActionList {
		if action.Match(a) {
			return getBoolPtr(true)
		}
	}

	return getBoolPtr(false)
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

// FindMatch tries to match the given action to the actions list
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

	// search for a wildcard match
	for act := range a {
		if action.Match(act) {
			return true
		}
	}

	return false
}
