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
	if !s.azureTests {
		PresignedAuth_Put_GetObject_with_UTF8_chars(s)
	}
	PresignedAuth_UploadPart(s)
}

func TestCreateBucket(s *S3Conf) {
	CreateBucket_invalid_bucket_name(s)
	CreateBucket_existing_bucket(s)
	CreateBucket_owned_by_you(s)
	CreateBucket_invalid_ownership(s)
	CreateBucket_ownership_with_acl(s)
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
	ListBuckets_with_prefix(s)
	ListBuckets_invalid_max_buckets(s)
	ListBuckets_truncated(s)
	ListBuckets_success(s)
	ListBuckets_empty_success(s)
}

func TestDeleteBucket(s *S3Conf) {
	DeleteBucket_non_existing_bucket(s)
	DeleteBucket_non_empty_bucket(s)
	DeleteBucket_success_status_code(s)
}

func TestPutBucketOwnershipControls(s *S3Conf) {
	PutBucketOwnershipControls_non_existing_bucket(s)
	PutBucketOwnershipControls_multiple_rules(s)
	PutBucketOwnershipControls_invalid_ownership(s)
	PutBucketOwnershipControls_success(s)
}

func TestGetBucketOwnershipControls(s *S3Conf) {
	GetBucketOwnershipControls_non_existing_bucket(s)
	GetBucketOwnershipControls_default_ownership(s)
	GetBucketOwnershipControls_success(s)
}

func TestDeleteBucketOwnershipControls(s *S3Conf) {
	DeleteBucketOwnershipControls_non_existing_bucket(s)
	DeleteBucketOwnershipControls_success(s)
}

func TestPutBucketTagging(s *S3Conf) {
	PutBucketTagging_non_existing_bucket(s)
	PutBucketTagging_long_tags(s)
	PutBucketTagging_duplicate_keys(s)
	PutBucketTagging_tag_count_limit(s)
	PutBucketTagging_success(s)
	PutBucketTagging_success_status(s)
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
	PutObject_tagging(s)
	PutObject_missing_object_lock_retention_config(s)
	PutObject_with_object_lock(s)
	PutObject_invalid_legal_hold(s)
	PutObject_invalid_object_lock_mode(s)
	//TODO: remove the condition after implementing checksums in azure
	if !s.azureTests {
		PutObject_checksum_algorithm_and_header_mismatch(s)
		PutObject_multiple_checksum_headers(s)
		PutObject_invalid_checksum_header(s)
		PutObject_incorrect_checksums(s)
		PutObject_default_checksum(s)
		PutObject_checksums_success(s)
		// azure applies some encoding mechanisms.
		PutObject_false_negative_object_names(s)
	}
	PutObject_success(s)
	if !s.versioningEnabled {
		PutObject_racey_success(s)
	}
	PutObject_invalid_credentials(s)
	PutObject_invalid_object_names(s)
}

func TestHeadObject(s *S3Conf) {
	HeadObject_non_existing_object(s)
	HeadObject_invalid_part_number(s)
	HeadObject_non_existing_mp(s)
	HeadObject_mp_success(s)
	HeadObject_directory_object_noslash(s)
	HeadObject_non_existing_dir_object(s)
	HeadObject_invalid_parent_dir(s)
	HeadObject_with_range(s)
	//TODO: remove the condition after implementing checksums in azure
	if !s.azureTests {
		HeadObject_not_enabled_checksum_mode(s)
		HeadObject_checksums(s)
	}
	HeadObject_success(s)
}

func TestGetObjectAttributes(s *S3Conf) {
	GetObjectAttributes_non_existing_bucket(s)
	GetObjectAttributes_non_existing_object(s)
	GetObjectAttributes_invalid_attrs(s)
	GetObjectAttributes_invalid_parent(s)
	GetObjectAttributes_invalid_single_attribute(s)
	GetObjectAttributes_empty_attrs(s)
	GetObjectAttributes_existing_object(s)
	//TODO: remove the condition after implementing checksums in azure
	if !s.azureTests {
		GetObjectAttributes_checksums(s)
	}
}

func TestGetObject(s *S3Conf) {
	GetObject_non_existing_key(s)
	GetObject_directory_object_noslash(s)
	GetObject_with_range(s)
	GetObject_invalid_parent(s)
	GetObject_large_object(s)
	//TODO: remove the condition after implementing checksums in azure
	if !s.azureTests {
		GetObject_checksums(s)
	}
	GetObject_success(s)
	GetObject_directory_success(s)
	GetObject_by_range_resp_status(s)
	GetObject_non_existing_dir_object(s)
}

func TestListObjects(s *S3Conf) {
	ListObjects_non_existing_bucket(s)
	ListObjects_with_prefix(s)
	ListObjects_truncated(s)
	ListObjects_paginated(s)
	ListObjects_invalid_max_keys(s)
	ListObjects_max_keys_0(s)
	ListObjects_exceeding_max_keys(s)
	ListObjects_delimiter(s)
	ListObjects_max_keys_none(s)
	ListObjects_marker_not_from_obj_list(s)
	ListObjects_list_all_objs(s)
	ListObjects_nested_dir_file_objs(s)
	ListObjects_check_owner(s)
	ListObjects_non_truncated_common_prefixes(s)
	//TODO: remove the condition after implementing checksums in azure
	if !s.azureTests {
		ListObjects_with_checksum(s)
	}
}

func TestListObjectsV2(s *S3Conf) {
	ListObjectsV2_start_after(s)
	ListObjectsV2_both_start_after_and_continuation_token(s)
	ListObjectsV2_start_after_not_in_list(s)
	ListObjectsV2_start_after_empty_result(s)
	ListObjectsV2_both_delimiter_and_prefix(s)
	ListObjectsV2_single_dir_object_with_delim_and_prefix(s)
	ListObjectsV2_truncated_common_prefixes(s)
	ListObjectsV2_all_objs_max_keys(s)
	ListObjectsV2_exceeding_max_keys(s)
	ListObjectsV2_list_all_objs(s)
	ListObjectsV2_with_owner(s)
	//TODO: remove the condition after implementing checksums in azure
	if !s.azureTests {
		ListObjectsV2_with_checksum(s)
	}
	ListObjectsV2_invalid_parent_prefix(s)
}

// VD stands for Versioning Disabled
func TestListObjectVersions_VD(s *S3Conf) {
	ListObjectVersions_VD_success(s)
}

func TestDeleteObject(s *S3Conf) {
	DeleteObject_non_existing_object(s)
	DeleteObject_directory_object_noslash(s)
	DeleteObject_non_existing_dir_object(s)
	DeleteObject_directory_object(s)
	DeleteObject_non_empty_dir_obj(s)
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
	CopyObject_copy_to_itself_invalid_directive(s)
	CopyObject_should_replace_tagging(s)
	CopyObject_should_copy_tagging(s)
	CopyObject_invalid_tagging_directive(s)
	CopyObject_to_itself_with_new_metadata(s)
	CopyObject_CopySource_starting_with_slash(s)
	CopyObject_non_existing_dir_object(s)
	CopyObject_should_copy_meta_props(s)
	CopyObject_should_replace_meta_props(s)
	CopyObject_invalid_legal_hold(s)
	CopyObject_invalid_object_lock_mode(s)
	CopyObject_with_legal_hold(s)
	CopyObject_with_retention_lock(s)
	//TODO: remove the condition after implementing checksums in azure
	if !s.azureTests {
		CopyObject_invalid_checksum_algorithm(s)
		CopyObject_create_checksum_on_copy(s)
		CopyObject_should_copy_the_existing_checksum(s)
		CopyObject_should_replace_the_existing_checksum(s)
		CopyObject_to_itself_by_replacing_the_checksum(s)
	}
	CopyObject_success(s)
}

func TestPutObjectTagging(s *S3Conf) {
	PutObjectTagging_non_existing_object(s)
	PutObjectTagging_long_tags(s)
	PutObjectTagging_duplicate_keys(s)
	PutObjectTagging_tag_count_limit(s)
	PutObjectTagging_success(s)
}

func TestGetObjectTagging(s *S3Conf) {
	GetObjectTagging_non_existing_object(s)
	GetObjectTagging_unset_tags(s)
	GetObjectTagging_invalid_parent(s)
	GetObjectTagging_success(s)
}

func TestDeleteObjectTagging(s *S3Conf) {
	DeleteObjectTagging_non_existing_object(s)
	DeleteObjectTagging_success_status(s)
	DeleteObjectTagging_success(s)
}

func TestCreateMultipartUpload(s *S3Conf) {
	CreateMultipartUpload_non_existing_bucket(s)
	CreateMultipartUpload_with_metadata(s)
	CreateMultipartUpload_with_tagging(s)
	CreateMultipartUpload_with_object_lock(s)
	CreateMultipartUpload_with_object_lock_not_enabled(s)
	CreateMultipartUpload_with_object_lock_invalid_retention(s)
	CreateMultipartUpload_past_retain_until_date(s)
	CreateMultipartUpload_invalid_legal_hold(s)
	CreateMultipartUpload_invalid_object_lock_mode(s)
	//TODO: remove the condition after implementing checksums in azure
	if !s.azureTests {
		CreateMultipartUpload_invalid_checksum_algorithm(s)
		CreateMultipartUpload_empty_checksum_algorithm_with_checksum_type(s)
		CreateMultipartUpload_invalid_checksum_type(s)
		CreateMultipartUpload_valid_checksum_algorithm(s)
	}
	CreateMultipartUpload_success(s)
}

func TestUploadPart(s *S3Conf) {
	UploadPart_non_existing_bucket(s)
	UploadPart_invalid_part_number(s)
	UploadPart_non_existing_key(s)
	UploadPart_non_existing_mp_upload(s)
	//TODO: remove the condition after implementing checksums in azure
	if !s.azureTests {
		UploadPart_checksum_algorithm_and_header_mismatch(s)
		UploadPart_multiple_checksum_headers(s)
		UploadPart_invalid_checksum_header(s)
		UploadPart_checksum_algorithm_mistmatch_on_initialization(s)
		UploadPart_checksum_algorithm_mistmatch_on_initialization_with_value(s)
		UploadPart_incorrect_checksums(s)
		UploadPart_with_checksums_success(s)
	}
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
	UploadPartCopy_by_range_invalid_ranges(s)
	UploadPartCopy_exceeding_copy_source_range(s)
	UploadPartCopy_greater_range_than_obj_size(s)
	UploadPartCopy_by_range_success(s)
	//TODO: remove the condition after implementing checksums in azure
	if !s.azureTests {
		UploadPartCopy_should_copy_the_checksum(s)
		UploadPartCopy_should_not_copy_the_checksum(s)
		UploadPartCopy_should_calculate_the_checksum(s)
	}
}

func TestListParts(s *S3Conf) {
	ListParts_incorrect_uploadId(s)
	ListParts_incorrect_object_key(s)
	ListParts_invalid_max_parts(s)
	ListParts_default_max_parts(s)
	ListParts_exceeding_max_parts(s)
	ListParts_truncated(s)
	//TODO: remove the condition after implementing checksums in azure
	if !s.azureTests {
		ListParts_with_checksums(s)
		ListParts_null_checksums(s)
	}
	ListParts_success(s)
}

func TestListMultipartUploads(s *S3Conf) {
	ListMultipartUploads_non_existing_bucket(s)
	ListMultipartUploads_empty_result(s)
	ListMultipartUploads_invalid_max_uploads(s)
	ListMultipartUploads_max_uploads(s)
	ListMultipartUploads_exceeding_max_uploads(s)
	ListMultipartUploads_incorrect_next_key_marker(s)
	ListMultipartUploads_ignore_upload_id_marker(s)
	//TODO: remove the condition after implementing checksums in azure
	if !s.azureTests {
		ListMultipartUploads_with_checksums(s)
	}
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
	CompleteMultipartUpload_incorrect_part_number(s)
	CompleteMultipartUpload_invalid_part_number(s)
	CompleteMultipartUpload_invalid_ETag(s)
	CompleteMultipartUpload_small_upload_size(s)
	CompleteMultipartUpload_empty_parts(s)
	CompleteMultipartUpload_incorrect_parts_order(s)
	CompleteMultipartUpload_mpu_object_size(s)
	//TODO: remove the condition after implementing checksums in azure
	if !s.azureTests {
		CompleteMultipartUpload_invalid_checksum_type(s)
		CompleteMultipartUpload_invalid_checksum_part(s)
		CompleteMultipartUpload_multiple_checksum_part(s)
		CompleteMultipartUpload_incorrect_checksum_part(s)
		CompleteMultipartUpload_different_checksum_part(s)
		CompleteMultipartUpload_missing_part_checksum(s)
		CompleteMultipartUpload_multiple_final_checksums(s)
		CompleteMultipartUpload_invalid_final_checksums(s)
		CompleteMultipartUpload_incorrect_final_checksums(s)
		CompleteMultipartUpload_should_calculate_the_final_checksum_full_object(s)
		CompleteMultipartUpload_should_verify_the_final_checksum(s)
		CompleteMultipartUpload_checksum_type_mismatch(s)
		CompleteMultipartUpload_should_ignore_the_final_checksum(s)
		CompleteMultipartUpload_should_succeed_without_final_checksum_type(s)
	}
	CompleteMultipartUpload_success(s)
	if !s.azureTests {
		CompleteMultipartUpload_racey_success(s)
	}
}

func TestPutBucketAcl(s *S3Conf) {
	PutBucketAcl_non_existing_bucket(s)
	PutBucketAcl_disabled(s)
	PutBucketAcl_none_of_the_options_specified(s)
	PutBucketAcl_invalid_acl_canned_and_acp(s)
	PutBucketAcl_invalid_acl_canned_and_grants(s)
	PutBucketAcl_invalid_acl_acp_and_grants(s)
	PutBucketAcl_invalid_owner(s)
	PutBucketAcl_invalid_owner_not_in_body(s)
	PutBucketAcl_invalid_empty_owner_id_in_body(s)
	PutBucketAcl_invalid_permission_in_body(s)
	PutBucketAcl_invalid_grantee_type_in_body(s)
	PutBucketAcl_empty_grantee_ID_in_body(s)
	PutBucketAcl_success_access_denied(s)
	PutBucketAcl_success_grants(s)
	PutBucketAcl_success_canned_acl(s)
	PutBucketAcl_success_acp(s)
}

func TestGetBucketAcl(s *S3Conf) {
	GetBucketAcl_non_existing_bucket(s)
	GetBucketAcl_translation_canned_public_read(s)
	GetBucketAcl_translation_canned_public_read_write(s)
	GetBucketAcl_translation_canned_private(s)
	GetBucketAcl_access_denied(s)
	GetBucketAcl_success(s)
}

func TestPutBucketPolicy(s *S3Conf) {
	PutBucketPolicy_non_existing_bucket(s)
	PutBucketPolicy_invalid_json(s)
	PutBucketPolicy_statement_not_provided(s)
	PutBucketPolicy_empty_statement(s)
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
	PutBucketPolicy_explicit_deny(s)
	PutBucketPolicy_multi_wildcard_resource(s)
	PutBucketPolicy_any_char_match(s)
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
	PutObjectRetention_overwrite_compliance_mode(s)
	PutObjectRetention_overwrite_governance_without_bypass_specified(s)
	PutObjectRetention_overwrite_governance_with_permission(s)
	PutObjectRetention_success(s)
}

func TestGetObjectRetention(s *S3Conf) {
	GetObjectRetention_non_existing_bucket(s)
	GetObjectRetention_non_existing_object(s)
	GetObjectRetention_disabled_lock(s)
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
	GetObjectLegalHold_disabled_lock(s)
	GetObjectLegalHold_unset_config(s)
	GetObjectLegalHold_success(s)
}

func TestWORMProtection(s *S3Conf) {
	WORMProtection_bucket_object_lock_configuration_compliance_mode(s)
	WORMProtection_bucket_object_lock_configuration_governance_mode(s)
	WORMProtection_bucket_object_lock_governance_bypass_delete(s)
	WORMProtection_bucket_object_lock_governance_bypass_delete_multiple(s)
	WORMProtection_object_lock_retention_compliance_locked(s)
	WORMProtection_object_lock_retention_governance_locked(s)
	WORMProtection_object_lock_retention_governance_bypass_overwrite(s)
	WORMProtection_object_lock_retention_governance_bypass_delete(s)
	WORMProtection_object_lock_retention_governance_bypass_delete_mul(s)
	WORMProtection_object_lock_legal_hold_locked(s)
	WORMProtection_root_bypass_governance_retention_delete_object(s)
}

func TestFullFlow(s *S3Conf) {
	TestAuthentication(s)
	TestPresignedAuthentication(s)
	TestCreateBucket(s)
	TestHeadBucket(s)
	TestListBuckets(s)
	TestDeleteBucket(s)
	TestPutBucketOwnershipControls(s)
	TestGetBucketOwnershipControls(s)
	TestDeleteBucketOwnershipControls(s)
	TestPutBucketTagging(s)
	TestGetBucketTagging(s)
	TestDeleteBucketTagging(s)
	TestPutObject(s)
	TestHeadObject(s)
	TestGetObjectAttributes(s)
	TestGetObject(s)
	TestListObjects(s)
	TestListObjectsV2(s)
	if !s.versioningEnabled && !s.azureTests {
		TestListObjectVersions_VD(s)
	}
	TestDeleteObject(s)
	TestDeleteObjects(s)
	TestCopyObject(s)
	TestPutObjectTagging(s)
	TestDeleteObjectTagging(s)
	TestCreateMultipartUpload(s)
	TestUploadPart(s)
	if !s.azureTests {
		TestUploadPartCopy(s)
	}
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
	// FIXME: The tests should pass for azure as well
	// but this issue should be fixed with https://github.com/versity/versitygw/issues/1336
	if !s.azureTests {
		TestPublicBuckets(s)
	}
	if s.versioningEnabled {
		TestVersioning(s)
	}
}

func TestPosix(s *S3Conf) {
	PutObject_overwrite_dir_obj(s)
	PutObject_overwrite_file_obj(s)
	PutObject_overwrite_file_obj_with_nested_obj(s)
	PutObject_dir_obj_with_data(s)
	CreateMultipartUpload_dir_obj(s)
	PutObject_name_too_long(s)
	HeadObject_name_too_long(s)
	DeleteObject_name_too_long(s)
	CopyObject_overwrite_same_dir_object(s)
	CopyObject_overwrite_same_file_object(s)
	DeleteObject_directory_not_empty(s)
	// posix specific versioning tests
	if !s.versioningEnabled {
		TestVersioningDisabled(s)
	}
}

func TestScoutfs(s *S3Conf) {
	TestAuthentication(s)
	TestPresignedAuthentication(s)
	TestCreateBucket(s)
	TestHeadBucket(s)
	TestListBuckets(s)
	TestDeleteBucket(s)
	TestPutBucketOwnershipControls(s)
	TestGetBucketOwnershipControls(s)
	TestDeleteBucketOwnershipControls(s)
	TestPutBucketTagging(s)
	TestGetBucketTagging(s)
	TestDeleteBucketTagging(s)
	TestPutObject(s)
	TestHeadObject(s)
	TestGetObjectAttributes(s)
	TestGetObject(s)
	TestListObjects(s)
	TestListObjectsV2(s)
	TestListObjectVersions_VD(s)
	TestDeleteObject(s)
	TestDeleteObjects(s)
	TestCopyObject(s)
	TestPutObjectTagging(s)
	TestDeleteObjectTagging(s)
	TestUploadPart(s)
	TestUploadPartCopy(s)
	TestListParts(s)
	TestListMultipartUploads(s)
	TestAbortMultipartUpload(s)
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

	CreateMultipartUpload_non_existing_bucket(s)
	CreateMultipartUpload_with_tagging(s)
	CreateMultipartUpload_with_object_lock(s)
	CreateMultipartUpload_with_object_lock_not_enabled(s)
	CreateMultipartUpload_with_object_lock_invalid_retention(s)
	CreateMultipartUpload_past_retain_until_date(s)
	CreateMultipartUpload_invalid_legal_hold(s)
	CreateMultipartUpload_invalid_object_lock_mode(s)
	CreateMultipartUpload_invalid_checksum_algorithm(s)
	CreateMultipartUpload_empty_checksum_algorithm_with_checksum_type(s)
	CreateMultipartUpload_invalid_checksum_type(s)
	CreateMultipartUpload_valid_checksum_algorithm(s)
	CreateMultipartUpload_success(s)

	CompletedMultipartUpload_non_existing_bucket(s)
	CompleteMultipartUpload_incorrect_part_number(s)
	CompleteMultipartUpload_invalid_part_number(s)
	CompleteMultipartUpload_invalid_ETag(s)
	CompleteMultipartUpload_small_upload_size(s)
	CompleteMultipartUpload_empty_parts(s)
	CompleteMultipartUpload_incorrect_parts_order(s)
	CompleteMultipartUpload_mpu_object_size(s)
	CompleteMultipartUpload_invalid_checksum_type(s)
	CompleteMultipartUpload_invalid_checksum_part(s)
	CompleteMultipartUpload_multiple_checksum_part(s)
	CompleteMultipartUpload_incorrect_checksum_part(s)
	CompleteMultipartUpload_different_checksum_part(s)
	CompleteMultipartUpload_missing_part_checksum(s)
	CompleteMultipartUpload_multiple_final_checksums(s)
	CompleteMultipartUpload_invalid_final_checksums(s)
	CompleteMultipartUpload_checksum_type_mismatch(s)
	CompleteMultipartUpload_should_ignore_the_final_checksum(s)
	CompleteMultipartUpload_success(s)
	CompleteMultipartUpload_racey_success(s)

	// posix/scoutfs specific tests
	PutObject_overwrite_dir_obj(s)
	PutObject_overwrite_file_obj(s)
	PutObject_overwrite_file_obj_with_nested_obj(s)
	PutObject_dir_obj_with_data(s)
	CreateMultipartUpload_dir_obj(s)
	PutObject_name_too_long(s)
	HeadObject_name_too_long(s)
	DeleteObject_name_too_long(s)
	CopyObject_overwrite_same_dir_object(s)
	CopyObject_overwrite_same_file_object(s)
	DeleteObject_directory_not_empty(s)
}

func TestIAM(s *S3Conf) {
	IAM_user_access_denied(s)
	IAM_userplus_access_denied(s)
	IAM_userplus_CreateBucket(s)
	IAM_admin_ChangeBucketOwner(s)
	IAM_ChangeBucketOwner_back_to_root(s)
	IAM_ListBuckets(s)
}

func TestAccessControl(s *S3Conf) {
	AccessControl_default_ACL_user_access_denied(s)
	AccessControl_default_ACL_userplus_access_denied(s)
	AccessControl_default_ACL_admin_successful_access(s)
	AccessControl_bucket_resource_single_action(s)
	AccessControl_bucket_resource_all_action(s)
	AccessControl_single_object_resource_actions(s)
	AccessControl_multi_statement_policy(s)
	AccessControl_bucket_ownership_to_user(s)
	AccessControl_root_PutBucketAcl(s)
	AccessControl_user_PutBucketAcl_with_policy_access(s)
	AccessControl_copy_object_with_starting_slash_for_user(s)
}

func TestPublicBuckets(s *S3Conf) {
	PublicBucket_default_privet_bucket(s)
	PublicBucket_public_bucket_policy(s)
	PublicBucket_public_object_policy(s)
	PublicBucket_public_acl(s)
}

func TestVersioning(s *S3Conf) {
	// PutBucketVersioning action
	PutBucketVersioning_non_existing_bucket(s)
	PutBucketVersioning_invalid_status(s)
	PutBucketVersioning_success_enabled(s)
	PutBucketVersioning_success_suspended(s)
	// GetBucketVersioning action
	GetBucketVersioning_non_existing_bucket(s)
	GetBucketVersioning_empty_response(s)
	GetBucketVersioning_success(s)
	// DeleteBucket action
	Versioning_DeleteBucket_not_empty(s)
	// PutObject action
	Versioning_PutObject_suspended_null_versionId_obj(s)
	Versioning_PutObject_null_versionId_obj(s)
	Versioning_PutObject_overwrite_null_versionId_obj(s)
	Versioning_PutObject_success(s)
	// CopyObject action
	Versioning_CopyObject_success(s)
	Versioning_CopyObject_non_existing_version_id(s)
	Versioning_CopyObject_from_an_object_version(s)
	Versioning_CopyObject_special_chars(s)
	// HeadObject action
	Versioning_HeadObject_invalid_versionId(s)
	Versioning_HeadObject_invalid_parent(s)
	Versioning_HeadObject_success(s)
	Versioning_HeadObject_without_versionId(s)
	Versioning_HeadObject_delete_marker(s)
	// GetObject action
	Versioning_GetObject_invalid_versionId(s)
	Versioning_GetObject_success(s)
	Versioning_GetObject_delete_marker_without_versionId(s)
	Versioning_GetObject_delete_marker(s)
	Versioning_GetObject_null_versionId_obj(s)
	// GetObjectAttributes action
	Versioning_GetObjectAttributes_object_version(s)
	Versioning_GetObjectAttributes_delete_marker(s)
	// DeleteObject(s) actions
	Versioning_DeleteObject_delete_object_version(s)
	Versioning_DeleteObject_non_existing_object(s)
	Versioning_DeleteObject_delete_a_delete_marker(s)
	Versioning_Delete_null_versionId_object(s)
	Versioning_DeleteObject_nested_dir_object(s)
	Versioning_DeleteObject_suspended(s)
	Versioning_DeleteObjects_success(s)
	Versioning_DeleteObjects_delete_deleteMarkers(s)
	// ListObjectVersions
	ListObjectVersions_non_existing_bucket(s)
	ListObjectVersions_list_single_object_versions(s)
	ListObjectVersions_list_multiple_object_versions(s)
	ListObjectVersions_multiple_object_versions_truncated(s)
	ListObjectVersions_with_delete_markers(s)
	ListObjectVersions_containing_null_versionId_obj(s)
	ListObjectVersions_single_null_versionId_object(s)
	ListObjectVersions_checksum(s)
	// Multipart upload
	Versioning_Multipart_Upload_success(s)
	Versioning_Multipart_Upload_overwrite_an_object(s)
	Versioning_UploadPartCopy_non_existing_versionId(s)
	Versioning_UploadPartCopy_from_an_object_version(s)
	// Object lock configuration
	Versioning_Enable_object_lock(s)
	Versioning_status_switch_to_suspended_with_object_lock(s)
	// Object-Lock Retention
	Versioning_PutObjectRetention_invalid_versionId(s)
	Versioning_GetObjectRetention_invalid_versionId(s)
	Versioning_Put_GetObjectRetention_success(s)
	// Object-Lock Legal hold
	Versioning_PutObjectLegalHold_invalid_versionId(s)
	Versioning_GetObjectLegalHold_invalid_versionId(s)
	Versioning_Put_GetObjectLegalHold_success(s)
	// WORM protection
	Versioning_WORM_obj_version_locked_with_legal_hold(s)
	Versioning_WORM_obj_version_locked_with_governance_retention(s)
	Versioning_WORM_obj_version_locked_with_compliance_retention(s)
	// Concurrent requests
	//Versioninig_concurrent_upload_object(s)
}

func TestVersioningDisabled(s *S3Conf) {
	VersioningDisabled_GetBucketVersioning_not_configured(s)
	VersioningDisabled_PutBucketVersioning_not_configured(s)
}

type IntTests map[string]func(s *S3Conf) error

func GetIntTests() IntTests {
	return IntTests{
		"Authentication_invalid_auth_header":                                      Authentication_invalid_auth_header,
		"Authentication_unsupported_signature_version":                            Authentication_unsupported_signature_version,
		"Authentication_malformed_credentials":                                    Authentication_malformed_credentials,
		"Authentication_malformed_credentials_invalid_parts":                      Authentication_malformed_credentials_invalid_parts,
		"Authentication_credentials_terminated_string":                            Authentication_credentials_terminated_string,
		"Authentication_credentials_incorrect_service":                            Authentication_credentials_incorrect_service,
		"Authentication_credentials_incorrect_region":                             Authentication_credentials_incorrect_region,
		"Authentication_credentials_invalid_date":                                 Authentication_credentials_invalid_date,
		"Authentication_credentials_future_date":                                  Authentication_credentials_future_date,
		"Authentication_credentials_past_date":                                    Authentication_credentials_past_date,
		"Authentication_credentials_non_existing_access_key":                      Authentication_credentials_non_existing_access_key,
		"Authentication_invalid_signed_headers":                                   Authentication_invalid_signed_headers,
		"Authentication_missing_date_header":                                      Authentication_missing_date_header,
		"Authentication_invalid_date_header":                                      Authentication_invalid_date_header,
		"Authentication_date_mismatch":                                            Authentication_date_mismatch,
		"Authentication_incorrect_payload_hash":                                   Authentication_incorrect_payload_hash,
		"Authentication_incorrect_md5":                                            Authentication_incorrect_md5,
		"Authentication_signature_error_incorrect_secret_key":                     Authentication_signature_error_incorrect_secret_key,
		"PresignedAuth_unsupported_algorithm":                                     PresignedAuth_unsupported_algorithm,
		"PresignedAuth_missing_credentials_query_param":                           PresignedAuth_missing_credentials_query_param,
		"PresignedAuth_malformed_creds_invalid_parts":                             PresignedAuth_malformed_creds_invalid_parts,
		"PresignedAuth_creds_invalid_terminator":                                  PresignedAuth_creds_invalid_terminator,
		"PresignedAuth_creds_incorrect_service":                                   PresignedAuth_creds_incorrect_service,
		"PresignedAuth_creds_incorrect_region":                                    PresignedAuth_creds_incorrect_region,
		"PresignedAuth_creds_invalid_date":                                        PresignedAuth_creds_invalid_date,
		"PresignedAuth_missing_date_query":                                        PresignedAuth_missing_date_query,
		"PresignedAuth_dates_mismatch":                                            PresignedAuth_dates_mismatch,
		"PresignedAuth_non_existing_access_key_id":                                PresignedAuth_non_existing_access_key_id,
		"PresignedAuth_missing_signed_headers_query_param":                        PresignedAuth_missing_signed_headers_query_param,
		"PresignedAuth_missing_expiration_query_param":                            PresignedAuth_missing_expiration_query_param,
		"PresignedAuth_invalid_expiration_query_param":                            PresignedAuth_invalid_expiration_query_param,
		"PresignedAuth_negative_expiration_query_param":                           PresignedAuth_negative_expiration_query_param,
		"PresignedAuth_exceeding_expiration_query_param":                          PresignedAuth_exceeding_expiration_query_param,
		"PresignedAuth_expired_request":                                           PresignedAuth_expired_request,
		"PresignedAuth_incorrect_secret_key":                                      PresignedAuth_incorrect_secret_key,
		"PresignedAuth_PutObject_success":                                         PresignedAuth_PutObject_success,
		"PutObject_missing_object_lock_retention_config":                          PutObject_missing_object_lock_retention_config,
		"PutObject_name_too_long":                                                 PutObject_name_too_long,
		"PutObject_with_object_lock":                                              PutObject_with_object_lock,
		"PutObject_invalid_legal_hold":                                            PutObject_invalid_legal_hold,
		"PutObject_invalid_object_lock_mode":                                      PutObject_invalid_object_lock_mode,
		"PutObject_checksum_algorithm_and_header_mismatch":                        PutObject_checksum_algorithm_and_header_mismatch,
		"PutObject_multiple_checksum_headers":                                     PutObject_multiple_checksum_headers,
		"PutObject_invalid_checksum_header":                                       PutObject_invalid_checksum_header,
		"PutObject_incorrect_checksums":                                           PutObject_incorrect_checksums,
		"PutObject_default_checksum":                                              PutObject_default_checksum,
		"PutObject_checksums_success":                                             PutObject_checksums_success,
		"PresignedAuth_Put_GetObject_with_data":                                   PresignedAuth_Put_GetObject_with_data,
		"PresignedAuth_Put_GetObject_with_UTF8_chars":                             PresignedAuth_Put_GetObject_with_UTF8_chars,
		"PresignedAuth_UploadPart":                                                PresignedAuth_UploadPart,
		"CreateBucket_invalid_bucket_name":                                        CreateBucket_invalid_bucket_name,
		"CreateBucket_existing_bucket":                                            CreateBucket_existing_bucket,
		"CreateBucket_owned_by_you":                                               CreateBucket_owned_by_you,
		"CreateBucket_invalid_ownership":                                          CreateBucket_invalid_ownership,
		"CreateBucket_ownership_with_acl":                                         CreateBucket_ownership_with_acl,
		"CreateBucket_as_user":                                                    CreateBucket_as_user,
		"CreateDeleteBucket_success":                                              CreateDeleteBucket_success,
		"CreateBucket_default_acl":                                                CreateBucket_default_acl,
		"CreateBucket_non_default_acl":                                            CreateBucket_non_default_acl,
		"CreateBucket_default_object_lock":                                        CreateBucket_default_object_lock,
		"HeadBucket_non_existing_bucket":                                          HeadBucket_non_existing_bucket,
		"HeadBucket_success":                                                      HeadBucket_success,
		"ListBuckets_as_user":                                                     ListBuckets_as_user,
		"ListBuckets_as_admin":                                                    ListBuckets_as_admin,
		"ListBuckets_with_prefix":                                                 ListBuckets_with_prefix,
		"ListBuckets_invalid_max_buckets":                                         ListBuckets_invalid_max_buckets,
		"ListBuckets_truncated":                                                   ListBuckets_truncated,
		"ListBuckets_success":                                                     ListBuckets_success,
		"DeleteBucket_non_existing_bucket":                                        DeleteBucket_non_existing_bucket,
		"DeleteBucket_non_empty_bucket":                                           DeleteBucket_non_empty_bucket,
		"DeleteBucket_success_status_code":                                        DeleteBucket_success_status_code,
		"PutBucketOwnershipControls_non_existing_bucket":                          PutBucketOwnershipControls_non_existing_bucket,
		"PutBucketOwnershipControls_multiple_rules":                               PutBucketOwnershipControls_multiple_rules,
		"PutBucketOwnershipControls_invalid_ownership":                            PutBucketOwnershipControls_invalid_ownership,
		"PutBucketOwnershipControls_success":                                      PutBucketOwnershipControls_success,
		"GetBucketOwnershipControls_non_existing_bucket":                          GetBucketOwnershipControls_non_existing_bucket,
		"GetBucketOwnershipControls_default_ownership":                            GetBucketOwnershipControls_default_ownership,
		"GetBucketOwnershipControls_success":                                      GetBucketOwnershipControls_success,
		"DeleteBucketOwnershipControls_non_existing_bucket":                       DeleteBucketOwnershipControls_non_existing_bucket,
		"DeleteBucketOwnershipControls_success":                                   DeleteBucketOwnershipControls_success,
		"PutBucketTagging_non_existing_bucket":                                    PutBucketTagging_non_existing_bucket,
		"PutBucketTagging_long_tags":                                              PutBucketTagging_long_tags,
		"PutBucketTagging_duplicate_keys":                                         PutBucketTagging_duplicate_keys,
		"PutBucketTagging_tag_count_limit":                                        PutBucketTagging_tag_count_limit,
		"PutBucketTagging_success":                                                PutBucketTagging_success,
		"PutBucketTagging_success_status":                                         PutBucketTagging_success_status,
		"GetBucketTagging_non_existing_bucket":                                    GetBucketTagging_non_existing_bucket,
		"GetBucketTagging_unset_tags":                                             GetBucketTagging_unset_tags,
		"GetBucketTagging_success":                                                GetBucketTagging_success,
		"DeleteBucketTagging_non_existing_object":                                 DeleteBucketTagging_non_existing_object,
		"DeleteBucketTagging_success_status":                                      DeleteBucketTagging_success_status,
		"DeleteBucketTagging_success":                                             DeleteBucketTagging_success,
		"PutObject_non_existing_bucket":                                           PutObject_non_existing_bucket,
		"PutObject_special_chars":                                                 PutObject_special_chars,
		"PutObject_tagging":                                                       PutObject_tagging,
		"PutObject_success":                                                       PutObject_success,
		"PutObject_invalid_object_names":                                          PutObject_invalid_object_names,
		"PutObject_false_negative_object_names":                                   PutObject_false_negative_object_names,
		"PutObject_racey_success":                                                 PutObject_racey_success,
		"HeadObject_non_existing_object":                                          HeadObject_non_existing_object,
		"HeadObject_invalid_part_number":                                          HeadObject_invalid_part_number,
		"HeadObject_non_existing_mp":                                              HeadObject_non_existing_mp,
		"HeadObject_mp_success":                                                   HeadObject_mp_success,
		"HeadObject_directory_object_noslash":                                     HeadObject_directory_object_noslash,
		"HeadObject_non_existing_dir_object":                                      HeadObject_non_existing_dir_object,
		"HeadObject_name_too_long":                                                HeadObject_name_too_long,
		"HeadObject_invalid_parent_dir":                                           HeadObject_invalid_parent_dir,
		"HeadObject_with_range":                                                   HeadObject_with_range,
		"HeadObject_not_enabled_checksum_mode":                                    HeadObject_not_enabled_checksum_mode,
		"HeadObject_checksums":                                                    HeadObject_checksums,
		"HeadObject_success":                                                      HeadObject_success,
		"GetObjectAttributes_non_existing_bucket":                                 GetObjectAttributes_non_existing_bucket,
		"GetObjectAttributes_non_existing_object":                                 GetObjectAttributes_non_existing_object,
		"GetObjectAttributes_invalid_attrs":                                       GetObjectAttributes_invalid_attrs,
		"GetObjectAttributes_invalid_parent":                                      GetObjectAttributes_invalid_parent,
		"GetObjectAttributes_invalid_single_attribute":                            GetObjectAttributes_invalid_single_attribute,
		"GetObjectAttributes_empty_attrs":                                         GetObjectAttributes_empty_attrs,
		"GetObjectAttributes_existing_object":                                     GetObjectAttributes_existing_object,
		"GetObjectAttributes_checksums":                                           GetObjectAttributes_checksums,
		"GetObject_non_existing_key":                                              GetObject_non_existing_key,
		"GetObject_directory_object_noslash":                                      GetObject_directory_object_noslash,
		"GetObject_with_range":                                                    GetObject_with_range,
		"GetObject_invalid_parent":                                                GetObject_invalid_parent,
		"GetObject_large_object":                                                  GetObject_large_object,
		"GetObject_checksums":                                                     GetObject_checksums,
		"GetObject_success":                                                       GetObject_success,
		"GetObject_directory_success":                                             GetObject_directory_success,
		"GetObject_by_range_resp_status":                                          GetObject_by_range_resp_status,
		"GetObject_non_existing_dir_object":                                       GetObject_non_existing_dir_object,
		"ListObjects_non_existing_bucket":                                         ListObjects_non_existing_bucket,
		"ListObjects_with_prefix":                                                 ListObjects_with_prefix,
		"ListObjects_truncated":                                                   ListObjects_truncated,
		"ListObjects_paginated":                                                   ListObjects_paginated,
		"ListObjects_invalid_max_keys":                                            ListObjects_invalid_max_keys,
		"ListObjects_max_keys_0":                                                  ListObjects_max_keys_0,
		"ListObjects_delimiter":                                                   ListObjects_delimiter,
		"ListObjects_max_keys_none":                                               ListObjects_max_keys_none,
		"ListObjects_marker_not_from_obj_list":                                    ListObjects_marker_not_from_obj_list,
		"ListObjects_list_all_objs":                                               ListObjects_list_all_objs,
		"ListObjects_nested_dir_file_objs":                                        ListObjects_nested_dir_file_objs,
		"ListObjects_check_owner":                                                 ListObjects_check_owner,
		"ListObjects_non_truncated_common_prefixes":                               ListObjects_non_truncated_common_prefixes,
		"ListObjects_with_checksum":                                               ListObjects_with_checksum,
		"ListObjectsV2_start_after":                                               ListObjectsV2_start_after,
		"ListObjectsV2_both_start_after_and_continuation_token":                   ListObjectsV2_both_start_after_and_continuation_token,
		"ListObjectsV2_start_after_not_in_list":                                   ListObjectsV2_start_after_not_in_list,
		"ListObjectsV2_start_after_empty_result":                                  ListObjectsV2_start_after_empty_result,
		"ListObjectsV2_both_delimiter_and_prefix":                                 ListObjectsV2_both_delimiter_and_prefix,
		"ListObjectsV2_single_dir_object_with_delim_and_prefix":                   ListObjectsV2_single_dir_object_with_delim_and_prefix,
		"ListObjectsV2_truncated_common_prefixes":                                 ListObjectsV2_truncated_common_prefixes,
		"ListObjectsV2_all_objs_max_keys":                                         ListObjectsV2_all_objs_max_keys,
		"ListObjectsV2_list_all_objs":                                             ListObjectsV2_list_all_objs,
		"ListObjectsV2_with_owner":                                                ListObjectsV2_with_owner,
		"ListObjectsV2_with_checksum":                                             ListObjectsV2_with_checksum,
		"ListObjectVersions_VD_success":                                           ListObjectVersions_VD_success,
		"DeleteObject_non_existing_object":                                        DeleteObject_non_existing_object,
		"DeleteObject_directory_object_noslash":                                   DeleteObject_directory_object_noslash,
		"DeleteObject_non_empty_dir_obj":                                          DeleteObject_non_empty_dir_obj,
		"DeleteObject_name_too_long":                                              DeleteObject_name_too_long,
		"CopyObject_overwrite_same_dir_object":                                    CopyObject_overwrite_same_dir_object,
		"CopyObject_overwrite_same_file_object":                                   CopyObject_overwrite_same_file_object,
		"DeleteObject_non_existing_dir_object":                                    DeleteObject_non_existing_dir_object,
		"DeleteObject_directory_object":                                           DeleteObject_directory_object,
		"DeleteObject_success":                                                    DeleteObject_success,
		"DeleteObject_success_status_code":                                        DeleteObject_success_status_code,
		"DeleteObjects_empty_input":                                               DeleteObjects_empty_input,
		"DeleteObjects_non_existing_objects":                                      DeleteObjects_non_existing_objects,
		"DeleteObjects_success":                                                   DeleteObjects_success,
		"CopyObject_non_existing_dst_bucket":                                      CopyObject_non_existing_dst_bucket,
		"CopyObject_not_owned_source_bucket":                                      CopyObject_not_owned_source_bucket,
		"CopyObject_copy_to_itself":                                               CopyObject_copy_to_itself,
		"CopyObject_copy_to_itself_invalid_directive":                             CopyObject_copy_to_itself_invalid_directive,
		"CopyObject_should_replace_tagging":                                       CopyObject_should_replace_tagging,
		"CopyObject_should_copy_tagging":                                          CopyObject_should_copy_tagging,
		"CopyObject_invalid_tagging_directive":                                    CopyObject_invalid_tagging_directive,
		"CopyObject_to_itself_with_new_metadata":                                  CopyObject_to_itself_with_new_metadata,
		"CopyObject_CopySource_starting_with_slash":                               CopyObject_CopySource_starting_with_slash,
		"CopyObject_non_existing_dir_object":                                      CopyObject_non_existing_dir_object,
		"CopyObject_should_copy_meta_props":                                       CopyObject_should_copy_meta_props,
		"CopyObject_should_replace_meta_props":                                    CopyObject_should_replace_meta_props,
		"CopyObject_invalid_legal_hold":                                           CopyObject_invalid_legal_hold,
		"CopyObject_invalid_object_lock_mode":                                     CopyObject_invalid_object_lock_mode,
		"CopyObject_with_legal_hold":                                              CopyObject_with_legal_hold,
		"CopyObject_with_retention_lock":                                          CopyObject_with_retention_lock,
		"CopyObject_invalid_checksum_algorithm":                                   CopyObject_invalid_checksum_algorithm,
		"CopyObject_create_checksum_on_copy":                                      CopyObject_create_checksum_on_copy,
		"CopyObject_should_copy_the_existing_checksum":                            CopyObject_should_copy_the_existing_checksum,
		"CopyObject_should_replace_the_existing_checksum":                         CopyObject_should_replace_the_existing_checksum,
		"CopyObject_to_itself_by_replacing_the_checksum":                          CopyObject_to_itself_by_replacing_the_checksum,
		"CopyObject_success":                                                      CopyObject_success,
		"PutObjectTagging_non_existing_object":                                    PutObjectTagging_non_existing_object,
		"PutObjectTagging_long_tags":                                              PutObjectTagging_long_tags,
		"PutObjectTagging_duplicate_keys":                                         PutObjectTagging_duplicate_keys,
		"PutObjectTagging_tag_count_limit":                                        PutObjectTagging_tag_count_limit,
		"PutObjectTagging_success":                                                PutObjectTagging_success,
		"GetObjectTagging_non_existing_object":                                    GetObjectTagging_non_existing_object,
		"GetObjectTagging_unset_tags":                                             GetObjectTagging_unset_tags,
		"GetObjectTagging_invalid_parent":                                         GetObjectTagging_invalid_parent,
		"GetObjectTagging_success":                                                GetObjectTagging_success,
		"DeleteObjectTagging_non_existing_object":                                 DeleteObjectTagging_non_existing_object,
		"DeleteObjectTagging_success_status":                                      DeleteObjectTagging_success_status,
		"DeleteObjectTagging_success":                                             DeleteObjectTagging_success,
		"CreateMultipartUpload_non_existing_bucket":                               CreateMultipartUpload_non_existing_bucket,
		"CreateMultipartUpload_with_metadata":                                     CreateMultipartUpload_with_metadata,
		"CreateMultipartUpload_with_tagging":                                      CreateMultipartUpload_with_tagging,
		"CreateMultipartUpload_with_object_lock":                                  CreateMultipartUpload_with_object_lock,
		"CreateMultipartUpload_with_object_lock_not_enabled":                      CreateMultipartUpload_with_object_lock_not_enabled,
		"CreateMultipartUpload_with_object_lock_invalid_retention":                CreateMultipartUpload_with_object_lock_invalid_retention,
		"CreateMultipartUpload_past_retain_until_date":                            CreateMultipartUpload_past_retain_until_date,
		"CreateMultipartUpload_invalid_legal_hold":                                CreateMultipartUpload_invalid_legal_hold,
		"CreateMultipartUpload_invalid_object_lock_mode":                          CreateMultipartUpload_invalid_object_lock_mode,
		"CreateMultipartUpload_invalid_checksum_algorithm":                        CreateMultipartUpload_invalid_checksum_algorithm,
		"CreateMultipartUpload_empty_checksum_algorithm_with_checksum_type":       CreateMultipartUpload_empty_checksum_algorithm_with_checksum_type,
		"CreateMultipartUpload_invalid_checksum_type":                             CreateMultipartUpload_invalid_checksum_type,
		"CreateMultipartUpload_valid_checksum_algorithm":                          CreateMultipartUpload_valid_checksum_algorithm,
		"CreateMultipartUpload_success":                                           CreateMultipartUpload_success,
		"UploadPart_non_existing_bucket":                                          UploadPart_non_existing_bucket,
		"UploadPart_invalid_part_number":                                          UploadPart_invalid_part_number,
		"UploadPart_non_existing_key":                                             UploadPart_non_existing_key,
		"UploadPart_non_existing_mp_upload":                                       UploadPart_non_existing_mp_upload,
		"UploadPart_checksum_algorithm_and_header_mismatch":                       UploadPart_checksum_algorithm_and_header_mismatch,
		"UploadPart_multiple_checksum_headers":                                    UploadPart_multiple_checksum_headers,
		"UploadPart_invalid_checksum_header":                                      UploadPart_invalid_checksum_header,
		"UploadPart_checksum_algorithm_mistmatch_on_initialization":               UploadPart_checksum_algorithm_mistmatch_on_initialization,
		"UploadPart_checksum_algorithm_mistmatch_on_initialization_with_value":    UploadPart_checksum_algorithm_mistmatch_on_initialization_with_value,
		"UploadPart_incorrect_checksums":                                          UploadPart_incorrect_checksums,
		"UploadPart_with_checksums_success":                                       UploadPart_with_checksums_success,
		"UploadPart_success":                                                      UploadPart_success,
		"UploadPartCopy_non_existing_bucket":                                      UploadPartCopy_non_existing_bucket,
		"UploadPartCopy_incorrect_uploadId":                                       UploadPartCopy_incorrect_uploadId,
		"UploadPartCopy_incorrect_object_key":                                     UploadPartCopy_incorrect_object_key,
		"UploadPartCopy_invalid_part_number":                                      UploadPartCopy_invalid_part_number,
		"UploadPartCopy_invalid_copy_source":                                      UploadPartCopy_invalid_copy_source,
		"UploadPartCopy_non_existing_source_bucket":                               UploadPartCopy_non_existing_source_bucket,
		"UploadPartCopy_non_existing_source_object_key":                           UploadPartCopy_non_existing_source_object_key,
		"UploadPartCopy_success":                                                  UploadPartCopy_success,
		"UploadPartCopy_by_range_invalid_ranges":                                  UploadPartCopy_by_range_invalid_ranges,
		"UploadPartCopy_exceeding_copy_source_range":                              UploadPartCopy_exceeding_copy_source_range,
		"UploadPartCopy_greater_range_than_obj_size":                              UploadPartCopy_greater_range_than_obj_size,
		"UploadPartCopy_by_range_success":                                         UploadPartCopy_by_range_success,
		"UploadPartCopy_should_copy_the_checksum":                                 UploadPartCopy_should_copy_the_checksum,
		"UploadPartCopy_should_not_copy_the_checksum":                             UploadPartCopy_should_not_copy_the_checksum,
		"UploadPartCopy_should_calculate_the_checksum":                            UploadPartCopy_should_calculate_the_checksum,
		"ListParts_incorrect_uploadId":                                            ListParts_incorrect_uploadId,
		"ListParts_incorrect_object_key":                                          ListParts_incorrect_object_key,
		"ListParts_invalid_max_parts":                                             ListParts_invalid_max_parts,
		"ListParts_default_max_parts":                                             ListParts_default_max_parts,
		"ListParts_truncated":                                                     ListParts_truncated,
		"ListParts_with_checksums":                                                ListParts_with_checksums,
		"ListParts_null_checksums":                                                ListParts_null_checksums,
		"ListParts_success":                                                       ListParts_success,
		"ListMultipartUploads_non_existing_bucket":                                ListMultipartUploads_non_existing_bucket,
		"ListMultipartUploads_empty_result":                                       ListMultipartUploads_empty_result,
		"ListMultipartUploads_invalid_max_uploads":                                ListMultipartUploads_invalid_max_uploads,
		"ListMultipartUploads_max_uploads":                                        ListMultipartUploads_max_uploads,
		"ListMultipartUploads_exceeding_max_uploads":                              ListMultipartUploads_exceeding_max_uploads,
		"ListMultipartUploads_incorrect_next_key_marker":                          ListMultipartUploads_incorrect_next_key_marker,
		"ListMultipartUploads_ignore_upload_id_marker":                            ListMultipartUploads_ignore_upload_id_marker,
		"ListMultipartUploads_with_checksums":                                     ListMultipartUploads_with_checksums,
		"ListMultipartUploads_success":                                            ListMultipartUploads_success,
		"AbortMultipartUpload_non_existing_bucket":                                AbortMultipartUpload_non_existing_bucket,
		"AbortMultipartUpload_incorrect_uploadId":                                 AbortMultipartUpload_incorrect_uploadId,
		"AbortMultipartUpload_incorrect_object_key":                               AbortMultipartUpload_incorrect_object_key,
		"AbortMultipartUpload_success":                                            AbortMultipartUpload_success,
		"AbortMultipartUpload_success_status_code":                                AbortMultipartUpload_success_status_code,
		"CompletedMultipartUpload_non_existing_bucket":                            CompletedMultipartUpload_non_existing_bucket,
		"CompleteMultipartUpload_invalid_part_number":                             CompleteMultipartUpload_invalid_part_number,
		"CompleteMultipartUpload_invalid_ETag":                                    CompleteMultipartUpload_invalid_ETag,
		"CompleteMultipartUpload_small_upload_size":                               CompleteMultipartUpload_small_upload_size,
		"CompleteMultipartUpload_empty_parts":                                     CompleteMultipartUpload_empty_parts,
		"CompleteMultipartUpload_incorrect_parts_order":                           CompleteMultipartUpload_incorrect_parts_order,
		"CompleteMultipartUpload_mpu_object_size":                                 CompleteMultipartUpload_mpu_object_size,
		"CompleteMultipartUpload_invalid_checksum_type":                           CompleteMultipartUpload_invalid_checksum_type,
		"CompleteMultipartUpload_invalid_checksum_part":                           CompleteMultipartUpload_invalid_checksum_part,
		"CompleteMultipartUpload_multiple_checksum_part":                          CompleteMultipartUpload_multiple_checksum_part,
		"CompleteMultipartUpload_incorrect_checksum_part":                         CompleteMultipartUpload_incorrect_checksum_part,
		"CompleteMultipartUpload_different_checksum_part":                         CompleteMultipartUpload_different_checksum_part,
		"CompleteMultipartUpload_missing_part_checksum":                           CompleteMultipartUpload_missing_part_checksum,
		"CompleteMultipartUpload_multiple_final_checksums":                        CompleteMultipartUpload_multiple_final_checksums,
		"CompleteMultipartUpload_invalid_final_checksums":                         CompleteMultipartUpload_invalid_final_checksums,
		"CompleteMultipartUpload_incorrect_final_checksums":                       CompleteMultipartUpload_incorrect_final_checksums,
		"CompleteMultipartUpload_should_calculate_the_final_checksum_full_object": CompleteMultipartUpload_should_calculate_the_final_checksum_full_object,
		"CompleteMultipartUpload_should_verify_the_final_checksum":                CompleteMultipartUpload_should_verify_the_final_checksum,
		"CompleteMultipartUpload_checksum_type_mismatch":                          CompleteMultipartUpload_checksum_type_mismatch,
		"CompleteMultipartUpload_should_ignore_the_final_checksum":                CompleteMultipartUpload_should_ignore_the_final_checksum,
		"CompleteMultipartUpload_should_succeed_without_final_checksum_type":      CompleteMultipartUpload_should_succeed_without_final_checksum_type,
		"CompleteMultipartUpload_success":                                         CompleteMultipartUpload_success,
		"CompleteMultipartUpload_racey_success":                                   CompleteMultipartUpload_racey_success,
		"PutBucketAcl_non_existing_bucket":                                        PutBucketAcl_non_existing_bucket,
		"PutBucketAcl_disabled":                                                   PutBucketAcl_disabled,
		"PutBucketAcl_none_of_the_options_specified":                              PutBucketAcl_none_of_the_options_specified,
		"PutBucketAcl_invalid_acl_canned_and_acp":                                 PutBucketAcl_invalid_acl_canned_and_acp,
		"PutBucketAcl_invalid_acl_canned_and_grants":                              PutBucketAcl_invalid_acl_canned_and_grants,
		"PutBucketAcl_invalid_acl_acp_and_grants":                                 PutBucketAcl_invalid_acl_acp_and_grants,
		"PutBucketAcl_invalid_owner":                                              PutBucketAcl_invalid_owner,
		"PutBucketAcl_invalid_owner_not_in_body":                                  PutBucketAcl_invalid_owner_not_in_body,
		"PutBucketAcl_invalid_empty_owner_id_in_body":                             PutBucketAcl_invalid_empty_owner_id_in_body,
		"PutBucketAcl_invalid_permission_in_body":                                 PutBucketAcl_invalid_permission_in_body,
		"PutBucketAcl_invalid_grantee_type_in_body":                               PutBucketAcl_invalid_grantee_type_in_body,
		"PutBucketAcl_empty_grantee_ID_in_body":                                   PutBucketAcl_empty_grantee_ID_in_body,
		"PutBucketAcl_success_access_denied":                                      PutBucketAcl_success_access_denied,
		"PutBucketAcl_success_grants":                                             PutBucketAcl_success_grants,
		"PutBucketAcl_success_canned_acl":                                         PutBucketAcl_success_canned_acl,
		"PutBucketAcl_success_acp":                                                PutBucketAcl_success_acp,
		"GetBucketAcl_non_existing_bucket":                                        GetBucketAcl_non_existing_bucket,
		"GetBucketAcl_translation_canned_public_read":                             GetBucketAcl_translation_canned_public_read,
		"GetBucketAcl_translation_canned_public_read_write":                       GetBucketAcl_translation_canned_public_read_write,
		"GetBucketAcl_translation_canned_private":                                 GetBucketAcl_translation_canned_private,
		"GetBucketAcl_access_denied":                                              GetBucketAcl_access_denied,
		"GetBucketAcl_success":                                                    GetBucketAcl_success,
		"PutBucketPolicy_non_existing_bucket":                                     PutBucketPolicy_non_existing_bucket,
		"PutBucketPolicy_invalid_json":                                            PutBucketPolicy_invalid_json,
		"PutBucketPolicy_statement_not_provided":                                  PutBucketPolicy_statement_not_provided,
		"PutBucketPolicy_empty_statement":                                         PutBucketPolicy_empty_statement,
		"PutBucketPolicy_invalid_effect":                                          PutBucketPolicy_invalid_effect,
		"PutBucketPolicy_empty_actions_string":                                    PutBucketPolicy_empty_actions_string,
		"PutBucketPolicy_empty_actions_array":                                     PutBucketPolicy_empty_actions_array,
		"PutBucketPolicy_invalid_action":                                          PutBucketPolicy_invalid_action,
		"PutBucketPolicy_unsupported_action":                                      PutBucketPolicy_unsupported_action,
		"PutBucketPolicy_incorrect_action_wildcard_usage":                         PutBucketPolicy_incorrect_action_wildcard_usage,
		"PutBucketPolicy_empty_principals_string":                                 PutBucketPolicy_empty_principals_string,
		"PutBucketPolicy_empty_principals_array":                                  PutBucketPolicy_empty_principals_array,
		"PutBucketPolicy_principals_aws_struct_empty_string":                      PutBucketPolicy_principals_aws_struct_empty_string,
		"PutBucketPolicy_principals_aws_struct_empty_string_slice":                PutBucketPolicy_principals_aws_struct_empty_string_slice,
		"PutBucketPolicy_principals_incorrect_wildcard_usage":                     PutBucketPolicy_principals_incorrect_wildcard_usage,
		"PutBucketPolicy_non_existing_principals":                                 PutBucketPolicy_non_existing_principals,
		"PutBucketPolicy_empty_resources_string":                                  PutBucketPolicy_empty_resources_string,
		"PutBucketPolicy_empty_resources_array":                                   PutBucketPolicy_empty_resources_array,
		"PutBucketPolicy_invalid_resource_prefix":                                 PutBucketPolicy_invalid_resource_prefix,
		"PutBucketPolicy_invalid_resource_with_starting_slash":                    PutBucketPolicy_invalid_resource_with_starting_slash,
		"PutBucketPolicy_duplicate_resource":                                      PutBucketPolicy_duplicate_resource,
		"PutBucketPolicy_incorrect_bucket_name":                                   PutBucketPolicy_incorrect_bucket_name,
		"PutBucketPolicy_object_action_on_bucket_resource":                        PutBucketPolicy_object_action_on_bucket_resource,
		"PutBucketPolicy_explicit_deny":                                           PutBucketPolicy_explicit_deny,
		"PutBucketPolicy_bucket_action_on_object_resource":                        PutBucketPolicy_bucket_action_on_object_resource,
		"PutBucketPolicy_multi_wildcard_resource":                                 PutBucketPolicy_multi_wildcard_resource,
		"PutBucketPolicy_any_char_match":                                          PutBucketPolicy_any_char_match,
		"PutBucketPolicy_success":                                                 PutBucketPolicy_success,
		"GetBucketPolicy_non_existing_bucket":                                     GetBucketPolicy_non_existing_bucket,
		"GetBucketPolicy_not_set":                                                 GetBucketPolicy_not_set,
		"GetBucketPolicy_success":                                                 GetBucketPolicy_success,
		"DeleteBucketPolicy_non_existing_bucket":                                  DeleteBucketPolicy_non_existing_bucket,
		"DeleteBucketPolicy_remove_before_setting":                                DeleteBucketPolicy_remove_before_setting,
		"DeleteBucketPolicy_success":                                              DeleteBucketPolicy_success,
		"PutObjectLockConfiguration_non_existing_bucket":                          PutObjectLockConfiguration_non_existing_bucket,
		"PutObjectLockConfiguration_empty_config":                                 PutObjectLockConfiguration_empty_config,
		"PutObjectLockConfiguration_not_enabled_on_bucket_creation":               PutObjectLockConfiguration_not_enabled_on_bucket_creation,
		"PutObjectLockConfiguration_invalid_status":                               PutObjectLockConfiguration_invalid_status,
		"PutObjectLockConfiguration_invalid_mode":                                 PutObjectLockConfiguration_invalid_mode,
		"PutObjectLockConfiguration_both_years_and_days":                          PutObjectLockConfiguration_both_years_and_days,
		"PutObjectLockConfiguration_invalid_years_days":                           PutObjectLockConfiguration_invalid_years_days,
		"PutObjectLockConfiguration_success":                                      PutObjectLockConfiguration_success,
		"GetObjectLockConfiguration_non_existing_bucket":                          GetObjectLockConfiguration_non_existing_bucket,
		"GetObjectLockConfiguration_unset_config":                                 GetObjectLockConfiguration_unset_config,
		"GetObjectLockConfiguration_success":                                      GetObjectLockConfiguration_success,
		"PutObjectRetention_non_existing_bucket":                                  PutObjectRetention_non_existing_bucket,
		"PutObjectRetention_non_existing_object":                                  PutObjectRetention_non_existing_object,
		"PutObjectRetention_unset_bucket_object_lock_config":                      PutObjectRetention_unset_bucket_object_lock_config,
		"PutObjectRetention_disabled_bucket_object_lock_config":                   PutObjectRetention_disabled_bucket_object_lock_config,
		"PutObjectRetention_expired_retain_until_date":                            PutObjectRetention_expired_retain_until_date,
		"PutObjectRetention_invalid_mode":                                         PutObjectRetention_invalid_mode,
		"PutObjectRetention_overwrite_compliance_mode":                            PutObjectRetention_overwrite_compliance_mode,
		"PutObjectRetention_overwrite_governance_without_bypass_specified":        PutObjectRetention_overwrite_governance_without_bypass_specified,
		"PutObjectRetention_overwrite_governance_with_permission":                 PutObjectRetention_overwrite_governance_with_permission,
		"PutObjectRetention_success":                                              PutObjectRetention_success,
		"GetObjectRetention_non_existing_bucket":                                  GetObjectRetention_non_existing_bucket,
		"GetObjectRetention_non_existing_object":                                  GetObjectRetention_non_existing_object,
		"GetObjectRetention_disabled_lock":                                        GetObjectRetention_disabled_lock,
		"GetObjectRetention_unset_config":                                         GetObjectRetention_unset_config,
		"GetObjectRetention_success":                                              GetObjectRetention_success,
		"PutObjectLegalHold_non_existing_bucket":                                  PutObjectLegalHold_non_existing_bucket,
		"PutObjectLegalHold_non_existing_object":                                  PutObjectLegalHold_non_existing_object,
		"PutObjectLegalHold_invalid_body":                                         PutObjectLegalHold_invalid_body,
		"PutObjectLegalHold_invalid_status":                                       PutObjectLegalHold_invalid_status,
		"PutObjectLegalHold_unset_bucket_object_lock_config":                      PutObjectLegalHold_unset_bucket_object_lock_config,
		"PutObjectLegalHold_disabled_bucket_object_lock_config":                   PutObjectLegalHold_disabled_bucket_object_lock_config,
		"PutObjectLegalHold_success":                                              PutObjectLegalHold_success,
		"GetObjectLegalHold_non_existing_bucket":                                  GetObjectLegalHold_non_existing_bucket,
		"GetObjectLegalHold_non_existing_object":                                  GetObjectLegalHold_non_existing_object,
		"GetObjectLegalHold_disabled_lock":                                        GetObjectLegalHold_disabled_lock,
		"GetObjectLegalHold_unset_config":                                         GetObjectLegalHold_unset_config,
		"GetObjectLegalHold_success":                                              GetObjectLegalHold_success,
		"WORMProtection_bucket_object_lock_configuration_compliance_mode":         WORMProtection_bucket_object_lock_configuration_compliance_mode,
		"WORMProtection_bucket_object_lock_configuration_governance_mode":         WORMProtection_bucket_object_lock_configuration_governance_mode,
		"WORMProtection_bucket_object_lock_governance_bypass_delete":              WORMProtection_bucket_object_lock_governance_bypass_delete,
		"WORMProtection_bucket_object_lock_governance_bypass_delete_multiple":     WORMProtection_bucket_object_lock_governance_bypass_delete_multiple,
		"WORMProtection_object_lock_retention_compliance_locked":                  WORMProtection_object_lock_retention_compliance_locked,
		"WORMProtection_object_lock_retention_governance_locked":                  WORMProtection_object_lock_retention_governance_locked,
		"WORMProtection_object_lock_retention_governance_bypass_overwrite":        WORMProtection_object_lock_retention_governance_bypass_overwrite,
		"WORMProtection_object_lock_retention_governance_bypass_delete":           WORMProtection_object_lock_retention_governance_bypass_delete,
		"WORMProtection_object_lock_retention_governance_bypass_delete_mul":       WORMProtection_object_lock_retention_governance_bypass_delete_mul,
		"WORMProtection_object_lock_legal_hold_locked":                            WORMProtection_object_lock_legal_hold_locked,
		"WORMProtection_root_bypass_governance_retention_delete_object":           WORMProtection_root_bypass_governance_retention_delete_object,
		"PutObject_overwrite_dir_obj":                                             PutObject_overwrite_dir_obj,
		"PutObject_overwrite_file_obj":                                            PutObject_overwrite_file_obj,
		"PutObject_overwrite_file_obj_with_nested_obj":                            PutObject_overwrite_file_obj_with_nested_obj,
		"PutObject_dir_obj_with_data":                                             PutObject_dir_obj_with_data,
		"CreateMultipartUpload_dir_obj":                                           CreateMultipartUpload_dir_obj,
		"IAM_user_access_denied":                                                  IAM_user_access_denied,
		"IAM_userplus_access_denied":                                              IAM_userplus_access_denied,
		"IAM_userplus_CreateBucket":                                               IAM_userplus_CreateBucket,
		"IAM_admin_ChangeBucketOwner":                                             IAM_admin_ChangeBucketOwner,
		"IAM_ChangeBucketOwner_back_to_root":                                      IAM_ChangeBucketOwner_back_to_root,
		"AccessControl_default_ACL_user_access_denied":                            AccessControl_default_ACL_user_access_denied,
		"AccessControl_default_ACL_userplus_access_denied":                        AccessControl_default_ACL_userplus_access_denied,
		"AccessControl_default_ACL_admin_successful_access":                       AccessControl_default_ACL_admin_successful_access,
		"AccessControl_bucket_resource_single_action":                             AccessControl_bucket_resource_single_action,
		"AccessControl_bucket_resource_all_action":                                AccessControl_bucket_resource_all_action,
		"AccessControl_single_object_resource_actions":                            AccessControl_single_object_resource_actions,
		"AccessControl_multi_statement_policy":                                    AccessControl_multi_statement_policy,
		"AccessControl_bucket_ownership_to_user":                                  AccessControl_bucket_ownership_to_user,
		"AccessControl_root_PutBucketAcl":                                         AccessControl_root_PutBucketAcl,
		"AccessControl_user_PutBucketAcl_with_policy_access":                      AccessControl_user_PutBucketAcl_with_policy_access,
		"AccessControl_copy_object_with_starting_slash_for_user":                  AccessControl_copy_object_with_starting_slash_for_user,
		"PublicBucket_default_privet_bucket":                                      PublicBucket_default_privet_bucket,
		"PublicBucket_public_bucket_policy":                                       PublicBucket_public_bucket_policy,
		"PublicBucket_public_object_policy":                                       PublicBucket_public_object_policy,
		"PublicBucket_public_acl":                                                 PublicBucket_public_acl,
		"PutBucketVersioning_non_existing_bucket":                                 PutBucketVersioning_non_existing_bucket,
		"PutBucketVersioning_invalid_status":                                      PutBucketVersioning_invalid_status,
		"PutBucketVersioning_success_enabled":                                     PutBucketVersioning_success_enabled,
		"PutBucketVersioning_success_suspended":                                   PutBucketVersioning_success_suspended,
		"GetBucketVersioning_non_existing_bucket":                                 GetBucketVersioning_non_existing_bucket,
		"GetBucketVersioning_empty_response":                                      GetBucketVersioning_empty_response,
		"GetBucketVersioning_success":                                             GetBucketVersioning_success,
		"Versioning_DeleteBucket_not_empty":                                       Versioning_DeleteBucket_not_empty,
		"Versioning_PutObject_suspended_null_versionId_obj":                       Versioning_PutObject_suspended_null_versionId_obj,
		"Versioning_PutObject_null_versionId_obj":                                 Versioning_PutObject_null_versionId_obj,
		"Versioning_PutObject_overwrite_null_versionId_obj":                       Versioning_PutObject_overwrite_null_versionId_obj,
		"Versioning_PutObject_success":                                            Versioning_PutObject_success,
		"Versioning_CopyObject_success":                                           Versioning_CopyObject_success,
		"Versioning_CopyObject_non_existing_version_id":                           Versioning_CopyObject_non_existing_version_id,
		"Versioning_CopyObject_from_an_object_version":                            Versioning_CopyObject_from_an_object_version,
		"Versioning_CopyObject_special_chars":                                     Versioning_CopyObject_special_chars,
		"Versioning_HeadObject_invalid_versionId":                                 Versioning_HeadObject_invalid_versionId,
		"Versioning_HeadObject_invalid_parent":                                    Versioning_HeadObject_invalid_parent,
		"Versioning_HeadObject_success":                                           Versioning_HeadObject_success,
		"Versioning_HeadObject_without_versionId":                                 Versioning_HeadObject_without_versionId,
		"Versioning_HeadObject_delete_marker":                                     Versioning_HeadObject_delete_marker,
		"Versioning_GetObject_invalid_versionId":                                  Versioning_GetObject_invalid_versionId,
		"Versioning_GetObject_success":                                            Versioning_GetObject_success,
		"Versioning_GetObject_delete_marker_without_versionId":                    Versioning_GetObject_delete_marker_without_versionId,
		"Versioning_GetObject_delete_marker":                                      Versioning_GetObject_delete_marker,
		"Versioning_GetObject_null_versionId_obj":                                 Versioning_GetObject_null_versionId_obj,
		"Versioning_GetObjectAttributes_object_version":                           Versioning_GetObjectAttributes_object_version,
		"Versioning_GetObjectAttributes_delete_marker":                            Versioning_GetObjectAttributes_delete_marker,
		"Versioning_DeleteObject_delete_object_version":                           Versioning_DeleteObject_delete_object_version,
		"Versioning_DeleteObject_non_existing_object":                             Versioning_DeleteObject_non_existing_object,
		"Versioning_DeleteObject_delete_a_delete_marker":                          Versioning_DeleteObject_delete_a_delete_marker,
		"Versioning_Delete_null_versionId_object":                                 Versioning_Delete_null_versionId_object,
		"Versioning_DeleteObject_nested_dir_object":                               Versioning_DeleteObject_nested_dir_object,
		"Versioning_DeleteObject_suspended":                                       Versioning_DeleteObject_suspended,
		"Versioning_DeleteObjects_success":                                        Versioning_DeleteObjects_success,
		"Versioning_DeleteObjects_delete_deleteMarkers":                           Versioning_DeleteObjects_delete_deleteMarkers,
		"ListObjectVersions_non_existing_bucket":                                  ListObjectVersions_non_existing_bucket,
		"ListObjectVersions_list_single_object_versions":                          ListObjectVersions_list_single_object_versions,
		"ListObjectVersions_list_multiple_object_versions":                        ListObjectVersions_list_multiple_object_versions,
		"ListObjectVersions_multiple_object_versions_truncated":                   ListObjectVersions_multiple_object_versions_truncated,
		"ListObjectVersions_with_delete_markers":                                  ListObjectVersions_with_delete_markers,
		"ListObjectVersions_containing_null_versionId_obj":                        ListObjectVersions_containing_null_versionId_obj,
		"ListObjectVersions_single_null_versionId_object":                         ListObjectVersions_single_null_versionId_object,
		"ListObjectVersions_checksum":                                             ListObjectVersions_checksum,
		"Versioning_Multipart_Upload_success":                                     Versioning_Multipart_Upload_success,
		"Versioning_Multipart_Upload_overwrite_an_object":                         Versioning_Multipart_Upload_overwrite_an_object,
		"Versioning_UploadPartCopy_non_existing_versionId":                        Versioning_UploadPartCopy_non_existing_versionId,
		"Versioning_UploadPartCopy_from_an_object_version":                        Versioning_UploadPartCopy_from_an_object_version,
		"Versioning_Enable_object_lock":                                           Versioning_Enable_object_lock,
		"Versioning_status_switch_to_suspended_with_object_lock":                  Versioning_status_switch_to_suspended_with_object_lock,
		"Versioning_PutObjectRetention_invalid_versionId":                         Versioning_PutObjectRetention_invalid_versionId,
		"Versioning_GetObjectRetention_invalid_versionId":                         Versioning_GetObjectRetention_invalid_versionId,
		"Versioning_Put_GetObjectRetention_success":                               Versioning_Put_GetObjectRetention_success,
		"Versioning_PutObjectLegalHold_invalid_versionId":                         Versioning_PutObjectLegalHold_invalid_versionId,
		"Versioning_GetObjectLegalHold_invalid_versionId":                         Versioning_GetObjectLegalHold_invalid_versionId,
		"Versioning_Put_GetObjectLegalHold_success":                               Versioning_Put_GetObjectLegalHold_success,
		"Versioning_WORM_obj_version_locked_with_legal_hold":                      Versioning_WORM_obj_version_locked_with_legal_hold,
		"Versioning_WORM_obj_version_locked_with_governance_retention":            Versioning_WORM_obj_version_locked_with_governance_retention,
		"Versioning_WORM_obj_version_locked_with_compliance_retention":            Versioning_WORM_obj_version_locked_with_compliance_retention,
		"Versioning_concurrent_upload_object":                                     Versioning_concurrent_upload_object,
	}
}
