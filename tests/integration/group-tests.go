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

package integration

func TestAuthentication(s *S3Conf) {
	Authentication_empty_auth_header(s)
	Authentication_invalid_auth_header(s)
	Authentication_unsupported_signature_version(s)
	Authentication_malformed_credentials(s)
	Authentication_malformed_credentials_invalid_parts(s)
	Authentication_credentials_terminated_string(s)
	Authentication_credentials_incorrect_service(s)
	Authentication_credentials_incorrect_region(s)
	Authentication_credentials_invalid_date(s)
	Authentication_credentials_future_date(s)
	Authentication_credentials_past_date(s)
	Authentication_credentials_non_existing_access_key(s)
	Authentication_invalid_signed_headers(s)
	Authentication_missing_date_header(s)
	Authentication_invalid_date_header(s)
	Authentication_date_mismatch(s)
	Authentication_incorrect_payload_hash(s)
	Authentication_incorrect_md5(s)
	Authentication_signature_error_incorrect_secret_key(s)
}

func TestPresignedAuthentication(s *S3Conf) {
	PresignedAuth_missing_algo_query_param(s)
	PresignedAuth_unsupported_algorithm(s)
	PresignedAuth_missing_credentials_query_param(s)
	PresignedAuth_malformed_creds_invalid_parts(s)
	PresignedAuth_malformed_creds_invalid_parts(s)
	PresignedAuth_creds_incorrect_service(s)
	PresignedAuth_creds_incorrect_region(s)
	PresignedAuth_creds_invalid_date(s)
	PresignedAuth_missing_date_query(s)
	PresignedAuth_dates_mismatch(s)
	PresignedAuth_non_existing_access_key_id(s)
	PresignedAuth_missing_signed_headers_query_param(s)
	PresignedAuth_missing_expiration_query_param(s)
	PresignedAuth_invalid_expiration_query_param(s)
	PresignedAuth_negative_expiration_query_param(s)
	PresignedAuth_exceeding_expiration_query_param(s)
	PresignedAuth_expired_request(s)
	PresignedAuth_incorrect_secret_key(s)
	PresignedAuth_PutObject_success(s)
	PresignedAuth_Put_GetObject_with_data(s)
	PresignedAuth_Put_GetObject_with_UTF8_chars(s)
	PresignedAuth_UploadPart(s)
}

func TestCreateBucket(s *S3Conf) {
	CreateBucket_invalid_bucket_name(s)
	CreateBucket_existing_bucket(s)
	CreateBucket_owned_by_you(s)
	CreateBucket_as_user(s)
	CreateBucket_default_acl(s)
	CreateBucket_non_default_acl(s)
	CreateDeleteBucket_success(s)
	CreateBucket_default_object_lock(s)
}

func TestHeadBucket(s *S3Conf) {
	HeadBucket_non_existing_bucket(s)
	HeadBucket_success(s)
}

func TestListBuckets(s *S3Conf) {
	ListBuckets_as_user(s)
	ListBuckets_as_admin(s)
	ListBuckets_success(s)
}

func TestDeleteBucket(s *S3Conf) {
	DeleteBucket_non_existing_bucket(s)
	DeleteBucket_non_empty_bucket(s)
	DeleteBucket_success_status_code(s)
}

func TestPutBucketTagging(s *S3Conf) {
	PutBucketTagging_non_existing_bucket(s)
	PutBucketTagging_long_tags(s)
	PutBucketTagging_success(s)
}

func TestGetBucketTagging(s *S3Conf) {
	GetBucketTagging_non_existing_bucket(s)
	GetBucketTagging_unset_tags(s)
	GetBucketTagging_success(s)
}

func TestDeleteBucketTagging(s *S3Conf) {
	DeleteBucketTagging_non_existing_object(s)
	DeleteBucketTagging_success_status(s)
	DeleteBucketTagging_success(s)
}

func TestPutObject(s *S3Conf) {
	PutObject_non_existing_bucket(s)
	PutObject_special_chars(s)
	PutObject_invalid_long_tags(s)
	PutObject_missing_object_lock_retention_config(s)
	PutObject_with_object_lock(s)
	PutObject_success(s)
	PutObject_invalid_credentials(s)
}

func TestHeadObject(s *S3Conf) {
	HeadObject_non_existing_object(s)
	HeadObject_invalid_part_number(s)
	HeadObject_non_existing_mp(s)
	HeadObject_mp_success(s)
	HeadObject_success(s)
}

func TestGetObjectAttributes(s *S3Conf) {
	GetObjectAttributes_non_existing_bucket(s)
	GetObjectAttributes_non_existing_object(s)
	GetObjectAttributes_existing_object(s)
	GetObjectAttributes_multipart_upload(s)
	GetObjectAttributes_multipart_upload_truncated(s)
}

func TestGetObject(s *S3Conf) {
	GetObject_non_existing_key(s)
	GetObject_invalid_ranges(s)
	GetObject_with_meta(s)
	GetObject_success(s)
	GetObject_by_range_success(s)
	GetObject_by_range_resp_status(s)
}

func TestListObjects(s *S3Conf) {
	ListObjects_non_existing_bucket(s)
	ListObjects_with_prefix(s)
	ListObject_truncated(s)
	ListObjects_invalid_max_keys(s)
	ListObjects_max_keys_0(s)
	ListObjects_delimiter(s)
	ListObjects_max_keys_none(s)
	ListObjects_marker_not_from_obj_list(s)
}

func TestListObjectsV2(s *S3Conf) {
	ListObjectsV2_start_after(s)
	ListObjectsV2_both_start_after_and_continuation_token(s)
	ListObjectsV2_start_after_not_in_list(s)
	ListObjectsV2_start_after_empty_result(s)
}

func TestDeleteObject(s *S3Conf) {
	DeleteObject_non_existing_object(s)
	DeleteObject_success(s)
	DeleteObject_success_status_code(s)
}

func TestDeleteObjects(s *S3Conf) {
	DeleteObjects_empty_input(s)
	DeleteObjects_non_existing_objects(s)
	DeleteObjects_success(s)
}

func TestCopyObject(s *S3Conf) {
	CopyObject_non_existing_dst_bucket(s)
	CopyObject_not_owned_source_bucket(s)
	CopyObject_copy_to_itself(s)
	CopyObject_to_itself_with_new_metadata(s)
	CopyObject_success(s)
}

func TestPutObjectTagging(s *S3Conf) {
	PutObjectTagging_non_existing_object(s)
	PutObjectTagging_long_tags(s)
	PutObjectTagging_success(s)
}

func TestGetObjectTagging(s *S3Conf) {
	GetObjectTagging_non_existing_object(s)
	GetObjectTagging_unset_tags(s)
	GetObjectTagging_success(s)
}

func TestDeleteObjectTagging(s *S3Conf) {
	DeleteObjectTagging_non_existing_object(s)
	DeleteObjectTagging_success_status(s)
	DeleteObjectTagging_success(s)
}

func TestCreateMultipartUpload(s *S3Conf) {
	CreateMultipartUpload_non_existing_bucket(s)
	CreateMultipartUpload_success(s)
}

func TestUploadPart(s *S3Conf) {
	UploadPart_non_existing_bucket(s)
	UploadPart_invalid_part_number(s)
	UploadPart_non_existing_key(s)
	UploadPart_non_existing_mp_upload(s)
	UploadPart_success(s)
}

func TestUploadPartCopy(s *S3Conf) {
	UploadPartCopy_non_existing_bucket(s)
	UploadPartCopy_incorrect_uploadId(s)
	UploadPartCopy_incorrect_object_key(s)
	UploadPartCopy_invalid_part_number(s)
	UploadPartCopy_invalid_copy_source(s)
	UploadPartCopy_non_existing_source_bucket(s)
	UploadPartCopy_non_existing_source_object_key(s)
	UploadPartCopy_success(s)
	UploadPartCopy_by_range_invalid_range(s)
	UploadPartCopy_greater_range_than_obj_size(s)
	UploadPartCopy_by_range_success(s)
}

func TestListParts(s *S3Conf) {
	ListParts_incorrect_uploadId(s)
	ListParts_incorrect_object_key(s)
	ListParts_success(s)
}

func TestListMultipartUploads(s *S3Conf) {
	ListMultipartUploads_non_existing_bucket(s)
	ListMultipartUploads_empty_result(s)
	ListMultipartUploads_invalid_max_uploads(s)
	ListMultipartUploads_max_uploads(s)
	ListMultipartUploads_incorrect_next_key_marker(s)
	ListMultipartUploads_ignore_upload_id_marker(s)
	ListMultipartUploads_success(s)
}

func TestAbortMultipartUpload(s *S3Conf) {
	AbortMultipartUpload_non_existing_bucket(s)
	AbortMultipartUpload_incorrect_uploadId(s)
	AbortMultipartUpload_incorrect_object_key(s)
	AbortMultipartUpload_success(s)
	AbortMultipartUpload_success_status_code(s)
}

func TestCompleteMultipartUpload(s *S3Conf) {
	CompletedMultipartUpload_non_existing_bucket(s)
	CompleteMultipartUpload_invalid_part_number(s)
	CompleteMultipartUpload_invalid_ETag(s)
	CompleteMultipartUpload_success(s)
}

func TestPutBucketAcl(s *S3Conf) {
	PutBucketAcl_non_existing_bucket(s)
	PutBucketAcl_invalid_acl_canned_and_acp(s)
	PutBucketAcl_invalid_acl_canned_and_grants(s)
	PutBucketAcl_invalid_acl_acp_and_grants(s)
	PutBucketAcl_invalid_owner(s)
	PutBucketAcl_success_access_denied(s)
	PutBucketAcl_success_grants(s)
	PutBucketAcl_success_canned_acl(s)
	PutBucketAcl_success_acp(s)
}

func TestGetBucketAcl(s *S3Conf) {
	GetBucketAcl_non_existing_bucket(s)
	GetBucketAcl_access_denied(s)
	GetBucketAcl_success(s)
}

func TestPutBucketPolicy(s *S3Conf) {
	PutBucketPolicy_non_existing_bucket(s)
	PutBucketPolicy_invalid_effect(s)
	PutBucketPolicy_empty_actions_string(s)
	PutBucketPolicy_empty_actions_array(s)
	PutBucketPolicy_invalid_action(s)
	PutBucketPolicy_unsupported_action(s)
	PutBucketPolicy_incorrect_action_wildcard_usage(s)
	PutBucketPolicy_empty_principals_string(s)
	PutBucketPolicy_empty_principals_array(s)
	PutBucketPolicy_principals_aws_struct_empty_string(s)
	PutBucketPolicy_principals_aws_struct_empty_string_slice(s)
	PutBucketPolicy_principals_incorrect_wildcard_usage(s)
	PutBucketPolicy_non_existing_principals(s)
	PutBucketPolicy_empty_resources_string(s)
	PutBucketPolicy_empty_resources_array(s)
	PutBucketPolicy_invalid_resource_prefix(s)
	PutBucketPolicy_invalid_resource_with_starting_slash(s)
	PutBucketPolicy_duplicate_resource(s)
	PutBucketPolicy_incorrect_bucket_name(s)
	PutBucketPolicy_object_action_on_bucket_resource(s)
	PutBucketPolicy_bucket_action_on_object_resource(s)
	PutBucketPolicy_success(s)
}

func TestGetBucketPolicy(s *S3Conf) {
	GetBucketPolicy_non_existing_bucket(s)
	GetBucketPolicy_not_set(s)
	GetBucketPolicy_success(s)
}

func TestDeleteBucketPolicy(s *S3Conf) {
	DeleteBucketPolicy_non_existing_bucket(s)
	DeleteBucketPolicy_remove_before_setting(s)
	DeleteBucketPolicy_success(s)
}

func TestPutObjectLockConfiguration(s *S3Conf) {
	PutObjectLockConfiguration_non_existing_bucket(s)
	PutObjectLockConfiguration_empty_config(s)
	PutObjectLockConfiguration_not_enabled_on_bucket_creation(s)
	PutObjectLockConfiguration_invalid_status(s)
	PutObjectLockConfiguration_invalid_mode(s)
	PutObjectLockConfiguration_both_years_and_days(s)
	PutObjectLockConfiguration_invalid_years_days(s)
	PutObjectLockConfiguration_success(s)
}

func TestGetObjectLockConfiguration(s *S3Conf) {
	GetObjectLockConfiguration_non_existing_bucket(s)
	GetObjectLockConfiguration_unset_config(s)
	GetObjectLockConfiguration_success(s)
}

func TestPutObjectRetention(s *S3Conf) {
	PutObjectRetention_non_existing_bucket(s)
	PutObjectRetention_non_existing_object(s)
	PutObjectRetention_unset_bucket_object_lock_config(s)
	PutObjectRetention_disabled_bucket_object_lock_config(s)
	PutObjectRetention_expired_retain_until_date(s)
	PutObjectRetention_invalid_mode(s)
	PutObjectRetention_success(s)
}

func TestGetObjectRetention(s *S3Conf) {
	GetObjectRetention_non_existing_bucket(s)
	GetObjectRetention_non_existing_object(s)
	GetObjectRetention_unset_config(s)
	GetObjectRetention_success(s)
}

func TestPutObjectLegalHold(s *S3Conf) {
	PutObjectLegalHold_non_existing_bucket(s)
	PutObjectLegalHold_non_existing_object(s)
	PutObjectLegalHold_invalid_body(s)
	PutObjectLegalHold_invalid_status(s)
	PutObjectLegalHold_unset_bucket_object_lock_config(s)
	PutObjectLegalHold_disabled_bucket_object_lock_config(s)
	PutObjectLegalHold_success(s)
}

func TestGetObjectLegalHold(s *S3Conf) {
	GetObjectLegalHold_non_existing_bucket(s)
	GetObjectLegalHold_non_existing_object(s)
	GetObjectLegalHold_unset_config(s)
	GetObjectLegalHold_success(s)
}

func TestWORMProtection(s *S3Conf) {
	WORMProtection_bucket_object_lock_configuration_compliance_mode(s)
	WORMProtection_bucket_object_lock_governance_root_overwrite(s)
	WORMProtection_object_lock_retention_compliance_root_access_denied(s)
	WORMProtection_object_lock_retention_governance_root_overwrite(s)
	WORMProtection_object_lock_retention_governance_user_access_denied(s)
	WORMProtection_object_lock_legal_hold_user_access_denied(s)
	WORMProtection_object_lock_legal_hold_root_overwrite(s)
}

func TestFullFlow(s *S3Conf) {
	TestAuthentication(s)
	TestPresignedAuthentication(s)
	TestCreateBucket(s)
	TestHeadBucket(s)
	TestListBuckets(s)
	TestDeleteBucket(s)
	TestPutBucketTagging(s)
	TestGetBucketTagging(s)
	TestDeleteBucketTagging(s)
	TestPutObject(s)
	TestHeadObject(s)
	TestGetObjectAttributes(s)
	TestGetObject(s)
	TestListObjects(s)
	TestListObjectsV2(s)
	TestDeleteObject(s)
	TestDeleteObjects(s)
	TestCopyObject(s)
	TestPutObjectTagging(s)
	TestDeleteObjectTagging(s)
	TestCreateMultipartUpload(s)
	TestUploadPart(s)
	TestUploadPartCopy(s)
	TestListParts(s)
	TestListMultipartUploads(s)
	TestAbortMultipartUpload(s)
	TestCompleteMultipartUpload(s)
	TestPutBucketAcl(s)
	TestGetBucketAcl(s)
	TestPutBucketPolicy(s)
	TestGetBucketPolicy(s)
	TestDeleteBucketPolicy(s)
	TestPutObjectLockConfiguration(s)
	TestGetObjectLockConfiguration(s)
	TestPutObjectRetention(s)
	TestGetObjectRetention(s)
	TestPutObjectLegalHold(s)
	TestGetObjectLegalHold(s)
	TestWORMProtection(s)
	TestAccessControl(s)
}

func TestPosix(s *S3Conf) {
	PutObject_overwrite_dir_obj(s)
	PutObject_overwrite_file_obj(s)
	PutObject_dir_obj_with_data(s)
	CreateMultipartUpload_dir_obj(s)
}

func TestIAM(s *S3Conf) {
	IAM_user_access_denied(s)
	IAM_userplus_access_denied(s)
	IAM_userplus_CreateBucket(s)
	IAM_admin_ChangeBucketOwner(s)
}

func TestAccessControl(s *S3Conf) {
	AccessControl_default_ACL_user_access_denied(s)
	AccessControl_default_ACL_userplus_access_denied(s)
	AccessControl_default_ACL_admin_successful_access(s)
	AccessControl_bucket_resource_single_action(s)
	AccessControl_bucket_resource_all_action(s)
	AccessControl_single_object_resource_actions(s)
	AccessControl_multi_statement_policy(s)
}

type IntTests map[string]func(s *S3Conf) error

func GetIntTests() IntTests {
	return IntTests{
		"Authentication_empty_auth_header":                                   Authentication_empty_auth_header,
		"Authentication_invalid_auth_header":                                 Authentication_invalid_auth_header,
		"Authentication_unsupported_signature_version":                       Authentication_unsupported_signature_version,
		"Authentication_malformed_credentials":                               Authentication_malformed_credentials,
		"Authentication_malformed_credentials_invalid_parts":                 Authentication_malformed_credentials_invalid_parts,
		"Authentication_credentials_terminated_string":                       Authentication_credentials_terminated_string,
		"Authentication_credentials_incorrect_service":                       Authentication_credentials_incorrect_service,
		"Authentication_credentials_incorrect_region":                        Authentication_credentials_incorrect_region,
		"Authentication_credentials_invalid_date":                            Authentication_credentials_invalid_date,
		"Authentication_credentials_future_date":                             Authentication_credentials_future_date,
		"Authentication_credentials_past_date":                               Authentication_credentials_past_date,
		"Authentication_credentials_non_existing_access_key":                 Authentication_credentials_non_existing_access_key,
		"Authentication_invalid_signed_headers":                              Authentication_invalid_signed_headers,
		"Authentication_missing_date_header":                                 Authentication_missing_date_header,
		"Authentication_invalid_date_header":                                 Authentication_invalid_date_header,
		"Authentication_date_mismatch":                                       Authentication_date_mismatch,
		"Authentication_incorrect_payload_hash":                              Authentication_incorrect_payload_hash,
		"Authentication_incorrect_md5":                                       Authentication_incorrect_md5,
		"Authentication_signature_error_incorrect_secret_key":                Authentication_signature_error_incorrect_secret_key,
		"PresignedAuth_missing_algo_query_param":                             PresignedAuth_missing_algo_query_param,
		"PresignedAuth_unsupported_algorithm":                                PresignedAuth_unsupported_algorithm,
		"PresignedAuth_missing_credentials_query_param":                      PresignedAuth_missing_credentials_query_param,
		"PresignedAuth_malformed_creds_invalid_parts":                        PresignedAuth_malformed_creds_invalid_parts,
		"PresignedAuth_creds_invalid_terminator":                             PresignedAuth_creds_invalid_terminator,
		"PresignedAuth_creds_incorrect_service":                              PresignedAuth_creds_incorrect_service,
		"PresignedAuth_creds_incorrect_region":                               PresignedAuth_creds_incorrect_region,
		"PresignedAuth_creds_invalid_date":                                   PresignedAuth_creds_invalid_date,
		"PresignedAuth_missing_date_query":                                   PresignedAuth_missing_date_query,
		"PresignedAuth_dates_mismatch":                                       PresignedAuth_dates_mismatch,
		"PresignedAuth_non_existing_access_key_id":                           PresignedAuth_non_existing_access_key_id,
		"PresignedAuth_missing_signed_headers_query_param":                   PresignedAuth_missing_signed_headers_query_param,
		"PresignedAuth_missing_expiration_query_param":                       PresignedAuth_missing_expiration_query_param,
		"PresignedAuth_invalid_expiration_query_param":                       PresignedAuth_invalid_expiration_query_param,
		"PresignedAuth_negative_expiration_query_param":                      PresignedAuth_negative_expiration_query_param,
		"PresignedAuth_exceeding_expiration_query_param":                     PresignedAuth_exceeding_expiration_query_param,
		"PresignedAuth_expired_request":                                      PresignedAuth_expired_request,
		"PresignedAuth_incorrect_secret_key":                                 PresignedAuth_incorrect_secret_key,
		"PresignedAuth_PutObject_success":                                    PresignedAuth_PutObject_success,
		"PutObject_missing_object_lock_retention_config":                     PutObject_missing_object_lock_retention_config,
		"PutObject_with_object_lock":                                         PutObject_with_object_lock,
		"PresignedAuth_Put_GetObject_with_data":                              PresignedAuth_Put_GetObject_with_data,
		"PresignedAuth_Put_GetObject_with_UTF8_chars":                        PresignedAuth_Put_GetObject_with_UTF8_chars,
		"PresignedAuth_UploadPart":                                           PresignedAuth_UploadPart,
		"CreateBucket_invalid_bucket_name":                                   CreateBucket_invalid_bucket_name,
		"CreateBucket_existing_bucket":                                       CreateBucket_existing_bucket,
		"CreateBucket_owned_by_you":                                          CreateBucket_owned_by_you,
		"CreateBucket_as_user":                                               CreateBucket_as_user,
		"CreateDeleteBucket_success":                                         CreateDeleteBucket_success,
		"CreateBucket_default_acl":                                           CreateBucket_default_acl,
		"CreateBucket_non_default_acl":                                       CreateBucket_non_default_acl,
		"CreateBucket_default_object_lock":                                   CreateBucket_default_object_lock,
		"HeadBucket_non_existing_bucket":                                     HeadBucket_non_existing_bucket,
		"HeadBucket_success":                                                 HeadBucket_success,
		"ListBuckets_as_user":                                                ListBuckets_as_user,
		"ListBuckets_as_admin":                                               ListBuckets_as_admin,
		"ListBuckets_success":                                                ListBuckets_success,
		"DeleteBucket_non_existing_bucket":                                   DeleteBucket_non_existing_bucket,
		"DeleteBucket_non_empty_bucket":                                      DeleteBucket_non_empty_bucket,
		"DeleteBucket_success_status_code":                                   DeleteBucket_success_status_code,
		"PutBucketTagging_non_existing_bucket":                               PutBucketTagging_non_existing_bucket,
		"PutBucketTagging_long_tags":                                         PutBucketTagging_long_tags,
		"PutBucketTagging_success":                                           PutBucketTagging_success,
		"GetBucketTagging_non_existing_bucket":                               GetBucketTagging_non_existing_bucket,
		"GetBucketTagging_unset_tags":                                        GetBucketTagging_unset_tags,
		"GetBucketTagging_success":                                           GetBucketTagging_success,
		"DeleteBucketTagging_non_existing_object":                            DeleteBucketTagging_non_existing_object,
		"DeleteBucketTagging_success_status":                                 DeleteBucketTagging_success_status,
		"DeleteBucketTagging_success":                                        DeleteBucketTagging_success,
		"PutObject_non_existing_bucket":                                      PutObject_non_existing_bucket,
		"PutObject_special_chars":                                            PutObject_special_chars,
		"PutObject_invalid_long_tags":                                        PutObject_invalid_long_tags,
		"PutObject_success":                                                  PutObject_success,
		"HeadObject_non_existing_object":                                     HeadObject_non_existing_object,
		"HeadObject_invalid_part_number":                                     HeadObject_invalid_part_number,
		"HeadObject_non_existing_mp":                                         HeadObject_non_existing_mp,
		"HeadObject_mp_success":                                              HeadObject_mp_success,
		"HeadObject_success":                                                 HeadObject_success,
		"GetObjectAttributes_non_existing_bucket":                            GetObjectAttributes_non_existing_bucket,
		"GetObjectAttributes_non_existing_object":                            GetObjectAttributes_non_existing_object,
		"GetObjectAttributes_existing_object":                                GetObjectAttributes_existing_object,
		"GetObjectAttributes_multipart_upload":                               GetObjectAttributes_multipart_upload,
		"GetObjectAttributes_multipart_upload_truncated":                     GetObjectAttributes_multipart_upload_truncated,
		"GetObject_non_existing_key":                                         GetObject_non_existing_key,
		"GetObject_invalid_ranges":                                           GetObject_invalid_ranges,
		"GetObject_with_meta":                                                GetObject_with_meta,
		"GetObject_success":                                                  GetObject_success,
		"GetObject_by_range_success":                                         GetObject_by_range_success,
		"GetObject_by_range_resp_status":                                     GetObject_by_range_resp_status,
		"ListObjects_non_existing_bucket":                                    ListObjects_non_existing_bucket,
		"ListObjects_with_prefix":                                            ListObjects_with_prefix,
		"ListObject_truncated":                                               ListObject_truncated,
		"ListObjects_invalid_max_keys":                                       ListObjects_invalid_max_keys,
		"ListObjects_max_keys_0":                                             ListObjects_max_keys_0,
		"ListObjects_delimiter":                                              ListObjects_delimiter,
		"ListObjects_max_keys_none":                                          ListObjects_max_keys_none,
		"ListObjects_marker_not_from_obj_list":                               ListObjects_marker_not_from_obj_list,
		"ListObjectsV2_start_after":                                          ListObjectsV2_start_after,
		"ListObjectsV2_both_start_after_and_continuation_token":              ListObjectsV2_both_start_after_and_continuation_token,
		"ListObjectsV2_start_after_not_in_list":                              ListObjectsV2_start_after_not_in_list,
		"ListObjectsV2_start_after_empty_result":                             ListObjectsV2_start_after_empty_result,
		"DeleteObject_non_existing_object":                                   DeleteObject_non_existing_object,
		"DeleteObject_success":                                               DeleteObject_success,
		"DeleteObject_success_status_code":                                   DeleteObject_success_status_code,
		"DeleteObjects_empty_input":                                          DeleteObjects_empty_input,
		"DeleteObjects_non_existing_objects":                                 DeleteObjects_non_existing_objects,
		"DeleteObjects_success":                                              DeleteObjects_success,
		"CopyObject_non_existing_dst_bucket":                                 CopyObject_non_existing_dst_bucket,
		"CopyObject_not_owned_source_bucket":                                 CopyObject_not_owned_source_bucket,
		"CopyObject_copy_to_itself":                                          CopyObject_copy_to_itself,
		"CopyObject_to_itself_with_new_metadata":                             CopyObject_to_itself_with_new_metadata,
		"CopyObject_success":                                                 CopyObject_success,
		"PutObjectTagging_non_existing_object":                               PutObjectTagging_non_existing_object,
		"PutObjectTagging_long_tags":                                         PutObjectTagging_long_tags,
		"PutObjectTagging_success":                                           PutObjectTagging_success,
		"GetObjectTagging_non_existing_object":                               GetObjectTagging_non_existing_object,
		"GetObjectTagging_unset_tags":                                        GetObjectTagging_unset_tags,
		"GetObjectTagging_success":                                           GetObjectTagging_success,
		"DeleteObjectTagging_non_existing_object":                            DeleteObjectTagging_non_existing_object,
		"DeleteObjectTagging_success_status":                                 DeleteObjectTagging_success_status,
		"DeleteObjectTagging_success":                                        DeleteObjectTagging_success,
		"CreateMultipartUpload_non_existing_bucket":                          CreateMultipartUpload_non_existing_bucket,
		"CreateMultipartUpload_success":                                      CreateMultipartUpload_success,
		"UploadPart_non_existing_bucket":                                     UploadPart_non_existing_bucket,
		"UploadPart_invalid_part_number":                                     UploadPart_invalid_part_number,
		"UploadPart_non_existing_key":                                        UploadPart_non_existing_key,
		"UploadPart_non_existing_mp_upload":                                  UploadPart_non_existing_mp_upload,
		"UploadPart_success":                                                 UploadPart_success,
		"UploadPartCopy_non_existing_bucket":                                 UploadPartCopy_non_existing_bucket,
		"UploadPartCopy_incorrect_uploadId":                                  UploadPartCopy_incorrect_uploadId,
		"UploadPartCopy_incorrect_object_key":                                UploadPartCopy_incorrect_object_key,
		"UploadPartCopy_invalid_part_number":                                 UploadPartCopy_invalid_part_number,
		"UploadPartCopy_invalid_copy_source":                                 UploadPartCopy_invalid_copy_source,
		"UploadPartCopy_non_existing_source_bucket":                          UploadPartCopy_non_existing_source_bucket,
		"UploadPartCopy_non_existing_source_object_key":                      UploadPartCopy_non_existing_source_object_key,
		"UploadPartCopy_success":                                             UploadPartCopy_success,
		"UploadPartCopy_by_range_invalid_range":                              UploadPartCopy_by_range_invalid_range,
		"UploadPartCopy_greater_range_than_obj_size":                         UploadPartCopy_greater_range_than_obj_size,
		"UploadPartCopy_by_range_success":                                    UploadPartCopy_by_range_success,
		"ListParts_incorrect_uploadId":                                       ListParts_incorrect_uploadId,
		"ListParts_incorrect_object_key":                                     ListParts_incorrect_object_key,
		"ListParts_success":                                                  ListParts_success,
		"ListMultipartUploads_non_existing_bucket":                           ListMultipartUploads_non_existing_bucket,
		"ListMultipartUploads_empty_result":                                  ListMultipartUploads_empty_result,
		"ListMultipartUploads_invalid_max_uploads":                           ListMultipartUploads_invalid_max_uploads,
		"ListMultipartUploads_max_uploads":                                   ListMultipartUploads_max_uploads,
		"ListMultipartUploads_incorrect_next_key_marker":                     ListMultipartUploads_incorrect_next_key_marker,
		"ListMultipartUploads_ignore_upload_id_marker":                       ListMultipartUploads_ignore_upload_id_marker,
		"ListMultipartUploads_success":                                       ListMultipartUploads_success,
		"AbortMultipartUpload_non_existing_bucket":                           AbortMultipartUpload_non_existing_bucket,
		"AbortMultipartUpload_incorrect_uploadId":                            AbortMultipartUpload_incorrect_uploadId,
		"AbortMultipartUpload_incorrect_object_key":                          AbortMultipartUpload_incorrect_object_key,
		"AbortMultipartUpload_success":                                       AbortMultipartUpload_success,
		"AbortMultipartUpload_success_status_code":                           AbortMultipartUpload_success_status_code,
		"CompletedMultipartUpload_non_existing_bucket":                       CompletedMultipartUpload_non_existing_bucket,
		"CompleteMultipartUpload_invalid_part_number":                        CompleteMultipartUpload_invalid_part_number,
		"CompleteMultipartUpload_invalid_ETag":                               CompleteMultipartUpload_invalid_ETag,
		"CompleteMultipartUpload_success":                                    CompleteMultipartUpload_success,
		"PutBucketAcl_non_existing_bucket":                                   PutBucketAcl_non_existing_bucket,
		"PutBucketAcl_invalid_acl_canned_and_acp":                            PutBucketAcl_invalid_acl_canned_and_acp,
		"PutBucketAcl_invalid_acl_canned_and_grants":                         PutBucketAcl_invalid_acl_canned_and_grants,
		"PutBucketAcl_invalid_acl_acp_and_grants":                            PutBucketAcl_invalid_acl_acp_and_grants,
		"PutBucketAcl_invalid_owner":                                         PutBucketAcl_invalid_owner,
		"PutBucketAcl_success_access_denied":                                 PutBucketAcl_success_access_denied,
		"PutBucketAcl_success_grants":                                        PutBucketAcl_success_grants,
		"PutBucketAcl_success_canned_acl":                                    PutBucketAcl_success_canned_acl,
		"PutBucketAcl_success_acp":                                           PutBucketAcl_success_acp,
		"GetBucketAcl_non_existing_bucket":                                   GetBucketAcl_non_existing_bucket,
		"GetBucketAcl_access_denied":                                         GetBucketAcl_access_denied,
		"GetBucketAcl_success":                                               GetBucketAcl_success,
		"PutBucketPolicy_non_existing_bucket":                                PutBucketPolicy_non_existing_bucket,
		"PutBucketPolicy_invalid_effect":                                     PutBucketPolicy_invalid_effect,
		"PutBucketPolicy_empty_actions_string":                               PutBucketPolicy_empty_actions_string,
		"PutBucketPolicy_empty_actions_array":                                PutBucketPolicy_empty_actions_array,
		"PutBucketPolicy_invalid_action":                                     PutBucketPolicy_invalid_action,
		"PutBucketPolicy_unsupported_action":                                 PutBucketPolicy_unsupported_action,
		"PutBucketPolicy_incorrect_action_wildcard_usage":                    PutBucketPolicy_incorrect_action_wildcard_usage,
		"PutBucketPolicy_empty_principals_string":                            PutBucketPolicy_empty_principals_string,
		"PutBucketPolicy_empty_principals_array":                             PutBucketPolicy_empty_principals_array,
		"PutBucketPolicy_principals_aws_struct_empty_string":                 PutBucketPolicy_principals_aws_struct_empty_string,
		"PutBucketPolicy_principals_aws_struct_empty_string_slice":           PutBucketPolicy_principals_aws_struct_empty_string_slice,
		"PutBucketPolicy_principals_incorrect_wildcard_usage":                PutBucketPolicy_principals_incorrect_wildcard_usage,
		"PutBucketPolicy_non_existing_principals":                            PutBucketPolicy_non_existing_principals,
		"PutBucketPolicy_empty_resources_string":                             PutBucketPolicy_empty_resources_string,
		"PutBucketPolicy_empty_resources_array":                              PutBucketPolicy_empty_resources_array,
		"PutBucketPolicy_invalid_resource_prefix":                            PutBucketPolicy_invalid_resource_prefix,
		"PutBucketPolicy_invalid_resource_with_starting_slash":               PutBucketPolicy_invalid_resource_with_starting_slash,
		"PutBucketPolicy_duplicate_resource":                                 PutBucketPolicy_duplicate_resource,
		"PutBucketPolicy_incorrect_bucket_name":                              PutBucketPolicy_incorrect_bucket_name,
		"PutBucketPolicy_object_action_on_bucket_resource":                   PutBucketPolicy_object_action_on_bucket_resource,
		"PutBucketPolicy_bucket_action_on_object_resource":                   PutBucketPolicy_bucket_action_on_object_resource,
		"PutBucketPolicy_success":                                            PutBucketPolicy_success,
		"GetBucketPolicy_non_existing_bucket":                                GetBucketPolicy_non_existing_bucket,
		"GetBucketPolicy_not_set":                                            GetBucketPolicy_not_set,
		"GetBucketPolicy_success":                                            GetBucketPolicy_success,
		"DeleteBucketPolicy_non_existing_bucket":                             DeleteBucketPolicy_non_existing_bucket,
		"DeleteBucketPolicy_remove_before_setting":                           DeleteBucketPolicy_remove_before_setting,
		"DeleteBucketPolicy_success":                                         DeleteBucketPolicy_success,
		"PutObjectLockConfiguration_non_existing_bucket":                     PutObjectLockConfiguration_non_existing_bucket,
		"PutObjectLockConfiguration_empty_config":                            PutObjectLockConfiguration_empty_config,
		"PutObjectLockConfiguration_not_enabled_on_bucket_creation":          PutObjectLockConfiguration_not_enabled_on_bucket_creation,
		"PutObjectLockConfiguration_invalid_status":                          PutObjectLockConfiguration_invalid_status,
		"PutObjectLockConfiguration_invalid_mode":                            PutObjectLockConfiguration_invalid_mode,
		"PutObjectLockConfiguration_both_years_and_days":                     PutObjectLockConfiguration_both_years_and_days,
		"PutObjectLockConfiguration_invalid_years_days":                      PutObjectLockConfiguration_invalid_years_days,
		"PutObjectLockConfiguration_success":                                 PutObjectLockConfiguration_success,
		"GetObjectLockConfiguration_non_existing_bucket":                     GetObjectLockConfiguration_non_existing_bucket,
		"GetObjectLockConfiguration_unset_config":                            GetObjectLockConfiguration_unset_config,
		"GetObjectLockConfiguration_success":                                 GetObjectLockConfiguration_success,
		"PutObjectRetention_non_existing_bucket":                             PutObjectRetention_non_existing_bucket,
		"PutObjectRetention_non_existing_object":                             PutObjectRetention_non_existing_object,
		"PutObjectRetention_unset_bucket_object_lock_config":                 PutObjectRetention_unset_bucket_object_lock_config,
		"PutObjectRetention_disabled_bucket_object_lock_config":              PutObjectRetention_disabled_bucket_object_lock_config,
		"PutObjectRetention_expired_retain_until_date":                       PutObjectRetention_expired_retain_until_date,
		"PutObjectRetention_invalid_mode":                                    PutObjectRetention_invalid_mode,
		"PutObjectRetention_success":                                         PutObjectRetention_success,
		"GetObjectRetention_non_existing_bucket":                             GetObjectRetention_non_existing_bucket,
		"GetObjectRetention_non_existing_object":                             GetObjectRetention_non_existing_object,
		"GetObjectRetention_unset_config":                                    GetObjectRetention_unset_config,
		"GetObjectRetention_success":                                         GetObjectRetention_success,
		"PutObjectLegalHold_non_existing_bucket":                             PutObjectLegalHold_non_existing_bucket,
		"PutObjectLegalHold_non_existing_object":                             PutObjectLegalHold_non_existing_object,
		"PutObjectLegalHold_invalid_body":                                    PutObjectLegalHold_invalid_body,
		"PutObjectLegalHold_invalid_status":                                  PutObjectLegalHold_invalid_status,
		"PutObjectLegalHold_unset_bucket_object_lock_config":                 PutObjectLegalHold_unset_bucket_object_lock_config,
		"PutObjectLegalHold_disabled_bucket_object_lock_config":              PutObjectLegalHold_disabled_bucket_object_lock_config,
		"PutObjectLegalHold_success":                                         PutObjectLegalHold_success,
		"GetObjectLegalHold_non_existing_bucket":                             GetObjectLegalHold_non_existing_bucket,
		"GetObjectLegalHold_non_existing_object":                             GetObjectLegalHold_non_existing_object,
		"GetObjectLegalHold_unset_config":                                    GetObjectLegalHold_unset_config,
		"GetObjectLegalHold_success":                                         GetObjectLegalHold_success,
		"WORMProtection_bucket_object_lock_configuration_compliance_mode":    WORMProtection_bucket_object_lock_configuration_compliance_mode,
		"WORMProtection_bucket_object_lock_governance_root_overwrite":        WORMProtection_bucket_object_lock_governance_root_overwrite,
		"WORMProtection_object_lock_retention_compliance_root_access_denied": WORMProtection_object_lock_retention_compliance_root_access_denied,
		"WORMProtection_object_lock_retention_governance_root_overwrite":     WORMProtection_object_lock_retention_governance_root_overwrite,
		"WORMProtection_object_lock_retention_governance_user_access_denied": WORMProtection_object_lock_retention_governance_user_access_denied,
		"WORMProtection_object_lock_legal_hold_user_access_denied":           WORMProtection_object_lock_legal_hold_user_access_denied,
		"WORMProtection_object_lock_legal_hold_root_overwrite":               WORMProtection_object_lock_legal_hold_root_overwrite,
		"PutObject_overwrite_dir_obj":                                        PutObject_overwrite_dir_obj,
		"PutObject_overwrite_file_obj":                                       PutObject_overwrite_file_obj,
		"PutObject_dir_obj_with_data":                                        PutObject_dir_obj_with_data,
		"CreateMultipartUpload_dir_obj":                                      CreateMultipartUpload_dir_obj,
		"IAM_user_access_denied":                                             IAM_user_access_denied,
		"IAM_userplus_access_denied":                                         IAM_userplus_access_denied,
		"IAM_userplus_CreateBucket":                                          IAM_userplus_CreateBucket,
		"IAM_admin_ChangeBucketOwner":                                        IAM_admin_ChangeBucketOwner,
	}
}
