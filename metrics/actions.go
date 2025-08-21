// Copyright 2024 Versity Software
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

package metrics

type Action struct {
	Name    string
	Service string
}

var (
	ActionMap map[string]Action
)

var (
	ActionUndetected                                  = "ActionUnDetected"
	ActionAbortMultipartUpload                        = "s3_AbortMultipartUpload"
	ActionCompleteMultipartUpload                     = "s3_CompleteMultipartUpload"
	ActionCopyObject                                  = "s3_CopyObject"
	ActionCreateBucket                                = "s3_CreateBucket"
	ActionCreateMultipartUpload                       = "s3_CreateMultipartUpload"
	ActionDeleteBucket                                = "s3_DeleteBucket"
	ActionDeleteBucketPolicy                          = "s3_DeleteBucketPolicy"
	ActionDeleteBucketTagging                         = "s3_DeleteBucketTagging"
	ActionDeleteObject                                = "s3_DeleteObject"
	ActionDeleteObjectTagging                         = "s3_DeleteObjectTagging"
	ActionDeleteObjects                               = "s3_DeleteObjects"
	ActionGetBucketAcl                                = "s3_GetBucketAcl"
	ActionGetBucketPolicy                             = "s3_GetBucketPolicy"
	ActionGetBucketTagging                            = "s3_GetBucketTagging"
	ActionGetBucketVersioning                         = "s3_GetBucketVersioning"
	ActionGetObject                                   = "s3_GetObject"
	ActionGetObjectAcl                                = "s3_GetObjectAcl"
	ActionGetObjectAttributes                         = "s3_GetObjectAttributes"
	ActionGetObjectLegalHold                          = "s3_GetObjectLegalHold"
	ActionGetObjectLockConfiguration                  = "s3_GetObjectLockConfiguration"
	ActionGetObjectRetention                          = "s3_GetObjectRetention"
	ActionGetObjectTagging                            = "s3_GetObjectTagging"
	ActionHeadBucket                                  = "s3_HeadBucket"
	ActionHeadObject                                  = "s3_HeadObject"
	ActionListAllMyBuckets                            = "s3_ListAllMyBuckets"
	ActionListMultipartUploads                        = "s3_ListMultipartUploads"
	ActionListObjectVersions                          = "s3_ListObjectVersions"
	ActionListObjects                                 = "s3_ListObjects"
	ActionListObjectsV2                               = "s3_ListObjectsV2"
	ActionListParts                                   = "s3_ListParts"
	ActionPutBucketAcl                                = "s3_PutBucketAcl"
	ActionPutBucketPolicy                             = "s3_PutBucketPolicy"
	ActionPutBucketTagging                            = "s3_PutBucketTagging"
	ActionPutBucketVersioning                         = "s3_PutBucketVersioning"
	ActionPutObject                                   = "s3_PutObject"
	ActionPutObjectAcl                                = "s3_PutObjectAcl"
	ActionPutObjectLegalHold                          = "s3_PutObjectLegalHold"
	ActionPutObjectLockConfiguration                  = "s3_PutObjectLockConfiguration"
	ActionPutObjectRetention                          = "s3_PutObjectRetention"
	ActionPutObjectTagging                            = "s3_PutObjectTagging"
	ActionRestoreObject                               = "s3_RestoreObject"
	ActionSelectObjectContent                         = "s3_SelectObjectContent"
	ActionUploadPart                                  = "s3_UploadPart"
	ActionUploadPartCopy                              = "s3_UploadPartCopy"
	ActionPutBucketOwnershipControls                  = "s3_PutBucketOwnershipControls"
	ActionGetBucketOwnershipControls                  = "s3_GetBucketOwnershipControls"
	ActionDeleteBucketOwnershipControls               = "s3_DeleteBucketOwnershipControls"
	ActionPutBucketCors                               = "s3_PutBucketCors"
	ActionGetBucketCors                               = "s3_GetBucketCors"
	ActionDeleteBucketCors                            = "s3_DeleteBucketCors"
	ActionOptions                                     = "s3_Options"
	ActionPutBucketAnalyticsConfiguration             = "s3_PutBucketAnalyticsConfiguration"
	ActionGetBucketAnalyticsConfiguration             = "s3_GetBucketAnalyticsConfiguration"
	ActionListBucketAnalyticsConfigurations           = "s3_ListBucketAnalyticsConfigurations"
	ActionDeleteBucketAnalyticsConfiguration          = "s3_DeleteBucketAnalyticsConfiguration"
	ActionPutBucketEncryption                         = "s3_PutBucketEncryption"
	ActionGetBucketEncryption                         = "s3_GetBucketEncryption"
	ActionDeleteBucketEncryption                      = "s3_DeleteBucketEncryption"
	ActionPutBucketIntelligentTieringConfiguration    = "s3_PutBucketIntelligentTieringConfiguration"
	ActionGetBucketIntelligentTieringConfiguration    = "s3_GetBucketIntelligentTieringConfiguration"
	ActionListBucketIntelligentTieringConfigurations  = "s3_ListBucketIntelligentTieringConfigurations"
	ActionDeleteBucketIntelligentTieringConfiguration = "s3_DeleteBucketIntelligentTieringConfiguration"
	ActionPutBucketInventoryConfiguration             = "s3_PutBucketInventoryConfiguration"
	ActionGetBucketInventoryConfiguration             = "s3_GetBucketInventoryConfiguration"
	ActionListBucketInventoryConfigurations           = "s3_ListBucketInventoryConfigurations"
	ActionDeleteBucketInventoryConfiguration          = "s3_DeleteBucketInventoryConfiguration"
	ActionPutBucketLifecycleConfiguration             = "s3_PutBucketLifecycleConfiguration"
	ActionGetBucketLifecycleConfiguration             = "s3_GetBucketLifecycleConfiguration"
	ActionDeleteBucketLifecycle                       = "s3_DeleteBucketLifecycle"
	ActionPutBucketLogging                            = "s3_PutBucketLogging"
	ActionGetBucketLogging                            = "s3_GetBucketLogging"
	ActionPutBucketRequestPayment                     = "s3_PutBucketRequestPayment"
	ActionGetBucketRequestPayment                     = "s3_GetBucketRequestPayment"
	ActionPutBucketMetricsConfiguration               = "s3_PutBucketMetricsConfiguration"
	ActionGetBucketMetricsConfiguration               = "s3_GetBucketMetricsConfiguration"
	ActionListBucketMetricsConfigurations             = "s3_ListBucketMetricsConfigurations"
	ActionDeleteBucketMetricsConfiguration            = "s3_DeleteBucketMetricsConfiguration"
	ActionPutBucketReplication                        = "s3_PutBucketReplication"
	ActionGetBucketReplication                        = "s3_GetBucketReplication"
	ActionDeleteBucketReplication                     = "s3_DeleteBucketReplication"
	ActionPutPublicAccessBlock                        = "s3_PutPublicAccessBlock"
	ActionGetPublicAccessBlock                        = "s3_GetPublicAccessBlock"
	ActionDeletePublicAccessBlock                     = "s3_DeletePublicAccessBlock"
	ActionPutBucketNotificationConfiguration          = "s3_PutBucketNotificationConfiguration"
	ActionGetBucketNotificationConfiguration          = "s3_GetBucketNotificationConfiguration"
	ActionPutBucketAccelerateConfiguration            = "s3_PutBucketAccelerateConfiguration"
	ActionGetBucketAccelerateConfiguration            = "s3_GetBucketAccelerateConfiguration"
	ActionPutBucketWebsite                            = "s3_PutBucketWebsite"
	ActionGetBucketWebsite                            = "s3_GetBucketWebsite"
	ActionDeleteBucketWebsite                         = "s3_DeleteBucketWebsite"

	// Admin actions
	ActionAdminCreateUser        = "admin_CreateUser"
	ActionAdminUpdateUser        = "admin_UpdateUser"
	ActionAdminDeleteUser        = "admin_DeleteUser"
	ActionAdminChangeBucketOwner = "admin_ChangeBucketOwner"
	ActionAdminListUsers         = "admin_ListUsers"
	ActionAdminListBuckets       = "admin_ListBuckets"
)

func init() {
	ActionMap = make(map[string]Action)

	ActionMap[ActionUndetected] = Action{
		Name:    "ActionUnDetected",
		Service: "unknown",
	}

	ActionMap[ActionAbortMultipartUpload] = Action{
		Name:    "AbortMultipartUpload",
		Service: "s3",
	}
	ActionMap[ActionCompleteMultipartUpload] = Action{
		Name:    "CompleteMultipartUpload",
		Service: "s3",
	}
	ActionMap[ActionCopyObject] = Action{
		Name:    "CopyObject",
		Service: "s3",
	}
	ActionMap[ActionCreateBucket] = Action{
		Name:    "CreateBucket",
		Service: "s3",
	}
	ActionMap[ActionCreateMultipartUpload] = Action{
		Name:    "CreateMultipartUpload",
		Service: "s3",
	}
	ActionMap[ActionDeleteBucket] = Action{
		Name:    "DeleteBucket",
		Service: "s3",
	}
	ActionMap[ActionDeleteBucketPolicy] = Action{
		Name:    "DeleteBucketPolicy",
		Service: "s3",
	}
	ActionMap[ActionDeleteBucketTagging] = Action{
		Name:    "DeleteBucketTagging",
		Service: "s3",
	}
	ActionMap[ActionDeleteObject] = Action{
		Name:    "DeleteObject",
		Service: "s3",
	}
	ActionMap[ActionDeleteObjectTagging] = Action{
		Name:    "DeleteObjectTagging",
		Service: "s3",
	}
	ActionMap[ActionDeleteObjects] = Action{
		Name:    "DeleteObjects",
		Service: "s3",
	}
	ActionMap[ActionGetBucketAcl] = Action{
		Name:    "GetBucketAcl",
		Service: "s3",
	}
	ActionMap[ActionGetBucketPolicy] = Action{
		Name:    "GetBucketPolicy",
		Service: "s3",
	}
	ActionMap[ActionGetBucketTagging] = Action{
		Name:    "GetBucketTagging",
		Service: "s3",
	}
	ActionMap[ActionGetBucketVersioning] = Action{
		Name:    "GetBucketVersioning",
		Service: "s3",
	}
	ActionMap[ActionGetObject] = Action{
		Name:    "GetObject",
		Service: "s3",
	}
	ActionMap[ActionGetObjectAcl] = Action{
		Name:    "GetObjectAcl",
		Service: "s3",
	}
	ActionMap[ActionGetObjectAttributes] = Action{
		Name:    "GetObjectAttributes",
		Service: "s3",
	}
	ActionMap[ActionGetObjectLegalHold] = Action{
		Name:    "GetObjectLegalHold",
		Service: "s3",
	}
	ActionMap[ActionGetObjectLockConfiguration] = Action{
		Name:    "GetObjectLockConfiguration",
		Service: "s3",
	}
	ActionMap[ActionGetObjectRetention] = Action{
		Name:    "GetObjectRetention",
		Service: "s3",
	}
	ActionMap[ActionGetObjectTagging] = Action{
		Name:    "GetObjectTagging",
		Service: "s3",
	}
	ActionMap[ActionHeadBucket] = Action{
		Name:    "HeadBucket",
		Service: "s3",
	}
	ActionMap[ActionHeadObject] = Action{
		Name:    "HeadObject",
		Service: "s3",
	}
	ActionMap[ActionListAllMyBuckets] = Action{
		Name:    "ListAllMyBuckets",
		Service: "s3",
	}
	ActionMap[ActionListMultipartUploads] = Action{
		Name:    "ListMultipartUploads",
		Service: "s3",
	}
	ActionMap[ActionListObjectVersions] = Action{
		Name:    "ListObjectVersions",
		Service: "s3",
	}
	ActionMap[ActionListObjects] = Action{
		Name:    "ListObjects",
		Service: "s3",
	}
	ActionMap[ActionListObjectsV2] = Action{
		Name:    "ListObjectsV2",
		Service: "s3",
	}
	ActionMap[ActionListParts] = Action{
		Name:    "ListParts",
		Service: "s3",
	}
	ActionMap[ActionPutBucketAcl] = Action{
		Name:    "PutBucketAcl",
		Service: "s3",
	}
	ActionMap[ActionPutBucketPolicy] = Action{
		Name:    "PutBucketPolicy",
		Service: "s3",
	}
	ActionMap[ActionPutBucketTagging] = Action{
		Name:    "PutBucketTagging",
		Service: "s3",
	}
	ActionMap[ActionPutBucketVersioning] = Action{
		Name:    "PutBucketVersioning",
		Service: "s3",
	}
	ActionMap[ActionPutObject] = Action{
		Name:    "PutObject",
		Service: "s3",
	}
	ActionMap[ActionPutObjectAcl] = Action{
		Name:    "PutObjectAcl",
		Service: "s3",
	}
	ActionMap[ActionPutObjectLegalHold] = Action{
		Name:    "PutObjectLegalHold",
		Service: "s3",
	}
	ActionMap[ActionPutObjectLockConfiguration] = Action{
		Name:    "PutObjectLockConfiguration",
		Service: "s3",
	}
	ActionMap[ActionPutObjectRetention] = Action{
		Name:    "PutObjectRetention",
		Service: "s3",
	}
	ActionMap[ActionPutObjectTagging] = Action{
		Name:    "PutObjectTagging",
		Service: "s3",
	}
	ActionMap[ActionRestoreObject] = Action{
		Name:    "RestoreObject",
		Service: "s3",
	}
	ActionMap[ActionSelectObjectContent] = Action{
		Name:    "SelectObjectContent",
		Service: "s3",
	}
	ActionMap[ActionUploadPart] = Action{
		Name:    "UploadPart",
		Service: "s3",
	}
	ActionMap[ActionUploadPartCopy] = Action{
		Name:    "UploadPartCopy",
		Service: "s3",
	}
	ActionMap[ActionPutBucketCors] = Action{
		Name:    "PutBucketCors",
		Service: "s3",
	}
	ActionMap[ActionGetBucketCors] = Action{
		Name:    "GetBucketCors",
		Service: "s3",
	}
	ActionMap[ActionDeleteBucketCors] = Action{
		Name:    "DeleteBucketCors",
		Service: "s3",
	}
	ActionMap[ActionPutBucketOwnershipControls] = Action{
		Name:    "PutBucketOwnershipControls",
		Service: "s3",
	}
	ActionMap[ActionGetBucketOwnershipControls] = Action{
		Name:    "GetBucketOwnershipControls",
		Service: "s3",
	}
	ActionMap[ActionDeleteBucketOwnershipControls] = Action{
		Name:    "DeleteBucketOwnershipControls",
		Service: "s3",
	}
	ActionMap[ActionOptions] = Action{
		Name:    "Options",
		Service: "s3",
	}
	ActionMap[ActionPutBucketAnalyticsConfiguration] = Action{
		Name:    "PutBucketAnalyticsConfiguration",
		Service: "s3",
	}
	ActionMap[ActionGetBucketAnalyticsConfiguration] = Action{
		Name:    "GetBucketAnalyticsConfiguration",
		Service: "s3",
	}
	ActionMap[ActionListBucketAnalyticsConfigurations] = Action{
		Name:    "ListBucketAnalyticsConfigurations",
		Service: "s3",
	}
	ActionMap[ActionDeleteBucketAnalyticsConfiguration] = Action{
		Name:    "DeleteBucketAnalyticsConfiguration",
		Service: "s3",
	}
	ActionMap[ActionPutBucketEncryption] = Action{
		Name:    "PutBucketEncryption",
		Service: "s3",
	}
	ActionMap[ActionGetBucketEncryption] = Action{
		Name:    "GetBucketEncryption",
		Service: "s3",
	}
	ActionMap[ActionDeleteBucketEncryption] = Action{
		Name:    "DeleteBucketEncryption",
		Service: "s3",
	}
	ActionMap[ActionPutBucketIntelligentTieringConfiguration] = Action{
		Name:    "PutBucketIntelligentTieringConfiguration",
		Service: "s3",
	}
	ActionMap[ActionGetBucketIntelligentTieringConfiguration] = Action{
		Name:    "GetBucketIntelligentTieringConfiguration",
		Service: "s3",
	}
	ActionMap[ActionListBucketIntelligentTieringConfigurations] = Action{
		Name:    "ListBucketIntelligentTieringConfigurations",
		Service: "s3",
	}
	ActionMap[ActionDeleteBucketIntelligentTieringConfiguration] = Action{
		Name:    "DeleteBucketIntelligentTieringConfiguration",
		Service: "s3",
	}
	ActionMap[ActionPutBucketInventoryConfiguration] = Action{
		Name:    "PutBucketInventoryConfiguration",
		Service: "s3",
	}
	ActionMap[ActionGetBucketInventoryConfiguration] = Action{
		Name:    "GetBucketInventoryConfiguration",
		Service: "s3",
	}
	ActionMap[ActionListBucketInventoryConfigurations] = Action{
		Name:    "ListBucketInventoryConfigurations",
		Service: "s3",
	}
	ActionMap[ActionDeleteBucketInventoryConfiguration] = Action{
		Name:    "DeleteBucketInventoryConfiguration",
		Service: "s3",
	}
	ActionMap[ActionPutBucketLifecycleConfiguration] = Action{
		Name:    "PutBucketLifecycleConfiguration",
		Service: "s3",
	}
	ActionMap[ActionGetBucketLifecycleConfiguration] = Action{
		Name:    "GetBucketLifecycleConfiguration",
		Service: "s3",
	}
	ActionMap[ActionDeleteBucketLifecycle] = Action{
		Name:    "DeleteBucketLifecycle",
		Service: "s3",
	}
	ActionMap[ActionPutBucketLogging] = Action{
		Name:    "PutBucketLogging",
		Service: "s3",
	}
	ActionMap[ActionGetBucketLogging] = Action{
		Name:    "GetBucketLogging",
		Service: "s3",
	}
	ActionMap[ActionPutBucketRequestPayment] = Action{
		Name:    "PutBucketRequestPayment",
		Service: "s3",
	}
	ActionMap[ActionGetBucketRequestPayment] = Action{
		Name:    "GetBucketRequestPayment",
		Service: "s3",
	}
	ActionMap[ActionPutBucketMetricsConfiguration] = Action{
		Name:    "PutBucketMetricsConfiguration",
		Service: "s3",
	}
	ActionMap[ActionGetBucketMetricsConfiguration] = Action{
		Name:    "GetBucketMetricsConfiguration",
		Service: "s3",
	}
	ActionMap[ActionListBucketMetricsConfigurations] = Action{
		Name:    "ListBucketMetricsConfigurations",
		Service: "s3",
	}
	ActionMap[ActionDeleteBucketMetricsConfiguration] = Action{
		Name:    "DeleteBucketMetricsConfiguration",
		Service: "s3",
	}
	ActionMap[ActionPutBucketReplication] = Action{
		Name:    "PutBucketReplication",
		Service: "s3",
	}
	ActionMap[ActionGetBucketReplication] = Action{
		Name:    "GetBucketReplication",
		Service: "s3",
	}
	ActionMap[ActionDeleteBucketReplication] = Action{
		Name:    "DeleteBucketReplication",
		Service: "s3",
	}
	ActionMap[ActionPutPublicAccessBlock] = Action{
		Name:    "PutPublicAccessBlock",
		Service: "s3",
	}
	ActionMap[ActionGetPublicAccessBlock] = Action{
		Name:    "GetPublicAccessBlock",
		Service: "s3",
	}
	ActionMap[ActionDeletePublicAccessBlock] = Action{
		Name:    "DeletePublicAccessBlock",
		Service: "s3",
	}
	ActionMap[ActionPutBucketNotificationConfiguration] = Action{
		Name:    "PutBucketNotificationConfiguration",
		Service: "s3",
	}
	ActionMap[ActionGetBucketNotificationConfiguration] = Action{
		Name:    "GetBucketNotificationConfiguration",
		Service: "s3",
	}
	ActionMap[ActionPutBucketAccelerateConfiguration] = Action{
		Name:    "PutBucketAccelerateConfiguration",
		Service: "s3",
	}
	ActionMap[ActionGetBucketAccelerateConfiguration] = Action{
		Name:    "GetBucketAccelerateConfiguration",
		Service: "s3",
	}
	ActionMap[ActionPutBucketWebsite] = Action{
		Name:    "PutBucketWebsite",
		Service: "s3",
	}
	ActionMap[ActionGetBucketWebsite] = Action{
		Name:    "GetBucketWebsite",
		Service: "s3",
	}
	ActionMap[ActionDeleteBucketWebsite] = Action{
		Name:    "DeleteBucketWebsite",
		Service: "s3",
	}
}
