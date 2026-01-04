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

func TestAuthentication(ts *TestState) {
	ts.Run(Authentication_invalid_auth_header)
	ts.Run(Authentication_unsupported_signature_version)
	ts.Run(Authentication_missing_components)
	ts.Run(Authentication_malformed_component)
	ts.Run(Authentication_missing_credentials)
	ts.Run(Authentication_missing_signedheaders)
	ts.Run(Authentication_missing_signature)
	ts.Run(Authentication_malformed_credential)
	ts.Run(Authentication_credentials_invalid_terminal)
	ts.Run(Authentication_credentials_incorrect_service)
	ts.Run(Authentication_credentials_incorrect_region)
	ts.Run(Authentication_credentials_invalid_date)
	ts.Run(Authentication_credentials_future_date)
	ts.Run(Authentication_credentials_past_date)
	ts.Run(Authentication_credentials_non_existing_access_key)
	//TODO: handle the case with signed headers
	ts.Run(Authentication_missing_date_header)
	ts.Run(Authentication_invalid_date_header)
	ts.Run(Authentication_date_mismatch)
	ts.Run(Authentication_incorrect_payload_hash)
	ts.Run(Authentication_invalid_sha256_payload_hash)
	ts.Run(Authentication_md5)
	ts.Run(Authentication_signature_error_incorrect_secret_key)
	ts.Run(Authentication_with_expect_header)
}

func TestPresignedAuthentication(ts *TestState) {
	ts.Run(PresignedAuth_security_token_not_supported)
	ts.Run(PresignedAuth_unsupported_algorithm)
	ts.Run(PresignedAuth_ECDSA_not_supported)
	ts.Run(PresignedAuth_missing_signature_query_param)
	ts.Run(PresignedAuth_missing_credentials_query_param)
	ts.Run(PresignedAuth_malformed_creds_invalid_parts)
	ts.Run(PresignedAuth_creds_invalid_terminal)
	ts.Run(PresignedAuth_creds_incorrect_service)
	ts.Run(PresignedAuth_creds_incorrect_region)
	ts.Run(PresignedAuth_creds_invalid_date)
	ts.Run(PresignedAuth_missing_date_query)
	ts.Run(PresignedAuth_dates_mismatch)
	ts.Run(PresignedAuth_non_existing_access_key_id)
	ts.Run(PresignedAuth_missing_signed_headers_query_param)
	ts.Run(PresignedAuth_missing_expiration_query_param)
	ts.Run(PresignedAuth_invalid_expiration_query_param)
	ts.Run(PresignedAuth_negative_expiration_query_param)
	ts.Run(PresignedAuth_exceeding_expiration_query_param)
	ts.Run(PresignedAuth_expired_request)
	ts.Run(PresignedAuth_incorrect_secret_key)
	ts.Run(PresignedAuth_PutObject_success)
	ts.Run(PresignedAuth_Put_GetObject_with_data)
	if !ts.conf.azureTests {
		ts.Run(PresignedAuth_Put_GetObject_with_UTF8_chars)
	}
	ts.Run(PresignedAuth_UploadPart)
}

func TestCreateBucket(ts *TestState) {
	ts.Run(CreateBucket_invalid_bucket_name)
	ts.Run(CreateBucket_existing_bucket)
	ts.Run(CreateBucket_owned_by_you)
	ts.Run(CreateBucket_invalid_ownership)
	ts.Run(CreateBucket_ownership_with_acl)
	ts.Run(CreateBucket_as_user)
	ts.Run(CreateBucket_default_acl)
	ts.Run(CreateBucket_non_default_acl)
	ts.Run(CreateDeleteBucket_success)
	ts.Run(CreateBucket_default_object_lock)
	ts.Run(CreateBucket_invalid_location_constraint)
	ts.Run(CreateBucket_long_tags)
	ts.Run(CreateBucket_invalid_tags)
	ts.Run(CreateBucket_duplicate_keys)
	ts.Run(CreateBucket_tag_count_limit)
	ts.Run(CreateBucket_invalid_canned_acl)
}

func TestHeadBucket(ts *TestState) {
	ts.Run(HeadBucket_non_existing_bucket)
	ts.Run(HeadBucket_success)
}

func TestListBuckets(ts *TestState) {
	ts.Sync(ListBuckets_as_user)
	ts.Sync(ListBuckets_as_admin)
	ts.Sync(ListBuckets_with_prefix)
	ts.Sync(ListBuckets_invalid_max_buckets)
	ts.Sync(ListBuckets_truncated)
	ts.Sync(ListBuckets_success)
	ts.Sync(ListBuckets_empty_success)
}

func TestDeleteBucket(ts *TestState) {
	ts.Run(DeleteBucket_non_existing_bucket)
	ts.Run(DeleteBucket_non_empty_bucket)
	ts.Run(DeleteBucket_success_status_code)
	ts.Run(DeleteBucket_incorrect_expected_bucket_owner)
}

func TestPutBucketOwnershipControls(ts *TestState) {
	ts.Run(PutBucketOwnershipControls_non_existing_bucket)
	ts.Run(PutBucketOwnershipControls_multiple_rules)
	ts.Run(PutBucketOwnershipControls_invalid_ownership)
	ts.Run(PutBucketOwnershipControls_success)
}

func TestGetBucketOwnershipControls(ts *TestState) {
	ts.Run(GetBucketOwnershipControls_non_existing_bucket)
	ts.Run(GetBucketOwnershipControls_default_ownership)
	ts.Run(GetBucketOwnershipControls_success)
}

func TestDeleteBucketOwnershipControls(ts *TestState) {
	ts.Run(DeleteBucketOwnershipControls_non_existing_bucket)
	ts.Run(DeleteBucketOwnershipControls_success)
}

func TestPutBucketTagging(ts *TestState) {
	ts.Run(PutBucketTagging_non_existing_bucket)
	ts.Run(PutBucketTagging_long_tags)
	ts.Run(PutBucketTagging_invalid_tags)
	ts.Run(PutBucketTagging_duplicate_keys)
	ts.Run(PutBucketTagging_tag_count_limit)
	ts.Run(PutBucketTagging_success)
	ts.Run(PutBucketTagging_success_status)
}

func TestGetBucketTagging(ts *TestState) {
	ts.Run(GetBucketTagging_non_existing_bucket)
	ts.Run(GetBucketTagging_unset_tags)
	ts.Run(GetBucketTagging_success)
}

func TestDeleteBucketTagging(ts *TestState) {
	ts.Run(DeleteBucketTagging_non_existing_object)
	ts.Run(DeleteBucketTagging_success_status)
	ts.Run(DeleteBucketTagging_success)
}

func TestGetBucketLocation(ts *TestState) {
	ts.Run(GetBucketLocation_success)
	ts.Run(GetBucketLocation_non_exist)
	ts.Run(GetBucketLocation_no_access)
}

func TestPutObject(ts *TestState) {
	ts.Run(PutObject_non_existing_bucket)
	ts.Run(PutObject_special_chars)
	ts.Run(PutObject_tagging)
	ts.Run(PutObject_missing_object_lock_retention_config)
	ts.Run(PutObject_with_object_lock)
	ts.Run(PutObject_invalid_legal_hold)
	ts.Run(PutObject_invalid_object_lock_mode)
	ts.Run(PutObject_conditional_writes)
	//TODO: remove the condition after implementing checksums in azure
	if !ts.conf.azureTests {
		ts.Run(PutObject_checksum_algorithm_and_header_mismatch)
		ts.Run(PutObject_multiple_checksum_headers)
		ts.Run(PutObject_invalid_checksum_header)
		ts.Run(PutObject_incorrect_checksums)
		ts.Run(PutObject_default_checksum)
		ts.Run(PutObject_checksums_success)
		// azure applies some encoding mechanisms.
		ts.Run(PutObject_false_negative_object_names)
		// azure doesn't support these metadata characters
		ts.Run(PutObject_with_metadata)
	}
	ts.Run(PutObject_success)
	if !ts.conf.versioningEnabled {
		ts.Run(PutObject_racey_success)
	}
	ts.Run(PutObject_invalid_credentials)
	ts.Run(PutObject_invalid_object_names)
}

func TestHeadObject(ts *TestState) {
	ts.Run(HeadObject_non_existing_object)
	ts.Run(HeadObject_invalid_part_number)
	ts.Run(HeadObject_part_number_not_supported)
	ts.Run(HeadObject_directory_object_noslash)
	ts.Run(HeadObject_non_existing_dir_object)
	ts.Run(HeadObject_invalid_parent_dir)
	ts.Run(HeadObject_with_range)
	ts.Run(HeadObject_zero_len_with_range)
	ts.Run(HeadObject_dir_with_range)
	ts.Run(HeadObject_conditional_reads)
	//TODO: remove the condition after implementing checksums in azure
	if !ts.conf.azureTests {
		ts.Run(HeadObject_not_enabled_checksum_mode)
		ts.Run(HeadObject_checksums)
	}
	ts.Run(HeadObject_success)
}

func TestGetObjectAttributes(ts *TestState) {
	ts.Run(GetObjectAttributes_non_existing_bucket)
	ts.Run(GetObjectAttributes_non_existing_object)
	ts.Run(GetObjectAttributes_invalid_attrs)
	ts.Run(GetObjectAttributes_invalid_parent)
	ts.Run(GetObjectAttributes_invalid_single_attribute)
	ts.Run(GetObjectAttributes_empty_attrs)
	ts.Run(GetObjectAttributes_existing_object)
	//TODO: remove the condition after implementing checksums in azure
	if !ts.conf.azureTests {
		ts.Run(GetObjectAttributes_checksums)
	}
}

func TestGetObject(ts *TestState) {
	ts.Run(GetObject_non_existing_key)
	ts.Run(GetObject_directory_object_noslash)
	ts.Run(GetObject_with_range)
	ts.Run(GetObject_zero_len_with_range)
	ts.Run(GetObject_dir_with_range)
	ts.Run(GetObject_invalid_parent)
	ts.Sync(GetObject_large_object)
	ts.Run(GetObject_conditional_reads)
	//TODO: remove the condition after implementing checksums in azure
	if !ts.conf.azureTests {
		ts.Run(GetObject_checksums)
	}
	ts.Run(GetObject_success)
	ts.Run(GetObject_directory_success)
	ts.Run(GetObject_by_range_resp_status)
	ts.Run(GetObject_non_existing_dir_object)
	ts.Run(GetObject_overrides_success)
	ts.Run(GetObject_overrides_presign_success)
	ts.Run(GetObject_overrides_fail_public)
	ts.Run(GetObject_invalid_part_number)
	ts.Run(GetObject_part_number_not_supported)
}

func TestListObjects(ts *TestState) {
	ts.Run(ListObjects_non_existing_bucket)
	ts.Run(ListObjects_with_prefix)
	ts.Run(ListObjects_truncated)
	ts.Run(ListObjects_paginated)
	ts.Run(ListObjects_invalid_max_keys)
	ts.Run(ListObjects_max_keys_0)
	ts.Run(ListObjects_exceeding_max_keys)
	ts.Run(ListObjects_delimiter)
	ts.Run(ListObjects_max_keys_none)
	ts.Run(ListObjects_marker_not_from_obj_list)
	ts.Run(ListObjects_list_all_objs)
	ts.Run(ListObjects_nested_dir_file_objs)
	ts.Run(ListObjects_check_owner)
	ts.Run(ListObjects_non_truncated_common_prefixes)
	//TODO: remove the condition after implementing checksums in azure
	if !ts.conf.azureTests {
		ts.Run(ListObjects_with_checksum)
	}
}

func TestListObjectsV2(ts *TestState) {
	ts.Run(ListObjectsV2_start_after)
	// posix continuation token not compatible with azure
	if !ts.conf.azureTests {
		ts.Run(ListObjectsV2_both_start_after_and_continuation_token)
	}
	ts.Run(ListObjectsV2_start_after_not_in_list)
	ts.Run(ListObjectsV2_start_after_empty_result)
	ts.Run(ListObjectsV2_both_delimiter_and_prefix)
	ts.Run(ListObjectsV2_single_dir_object_with_delim_and_prefix)
	ts.Run(ListObjectsV2_truncated_common_prefixes)
	ts.Run(ListObjectsV2_all_objs_max_keys)
	ts.Run(ListObjectsV2_exceeding_max_keys)
	ts.Run(ListObjectsV2_list_all_objs)
	ts.Run(ListObjectsV2_with_owner)
	ts.Run(ListObjectsV2_non_truncated_common_prefixes)
	//TODO: remove the condition after implementing checksums in azure
	if !ts.conf.azureTests {
		ts.Run(ListObjectsV2_with_checksum)
	}
	ts.Run(ListObjectsV2_invalid_parent_prefix)
}

// VD stands for Versioning Disabled
func TestListObjectVersions_VD(ts *TestState) {
	ts.Run(ListObjectVersions_VD_success)
}

func TestDeleteObject(ts *TestState) {
	ts.Run(DeleteObject_non_existing_object)
	ts.Run(DeleteObject_directory_object_noslash)
	ts.Run(DeleteObject_non_existing_dir_object)
	ts.Run(DeleteObject_directory_object)
	ts.Run(DeleteObject_non_empty_dir_obj)
	ts.Run(DeleteObject_conditional_writes)
	ts.Run(DeleteObject_success)
	ts.Run(DeleteObject_success_status_code)
	ts.Run(DeleteObject_incorrect_expected_bucket_owner)
	ts.Run(DeleteObject_expected_bucket_owner)
}

func TestDeleteObjects(ts *TestState) {
	ts.Run(DeleteObjects_empty_input)
	ts.Run(DeleteObjects_non_existing_objects)
	ts.Run(DeleteObjects_success)
}

func TestCopyObject(ts *TestState) {
	ts.Run(CopyObject_non_existing_dst_bucket)
	ts.Run(CopyObject_not_owned_source_bucket)
	ts.Run(CopyObject_copy_to_itself)
	ts.Run(CopyObject_copy_to_itself_invalid_directive)
	ts.Run(CopyObject_should_replace_tagging)
	ts.Run(CopyObject_should_copy_tagging)
	ts.Run(CopyObject_invalid_tagging_directive)
	ts.Run(CopyObject_to_itself_with_new_metadata)
	ts.Run(CopyObject_copy_source_starting_with_slash)
	ts.Run(CopyObject_invalid_copy_source)
	ts.Run(CopyObject_non_existing_dir_object)
	ts.Run(CopyObject_should_copy_meta_props)
	ts.Run(CopyObject_should_replace_meta_props)
	ts.Run(CopyObject_invalid_legal_hold)
	ts.Run(CopyObject_invalid_object_lock_mode)
	ts.Run(CopyObject_with_legal_hold)
	ts.Run(CopyObject_with_retention_lock)
	ts.Run(CopyObject_conditional_reads)
	//TODO: remove the condition after implementing checksums in azure
	if !ts.conf.azureTests {
		ts.Run(CopyObject_invalid_checksum_algorithm)
		ts.Run(CopyObject_create_checksum_on_copy)
		ts.Run(CopyObject_should_copy_the_existing_checksum)
		ts.Run(CopyObject_should_replace_the_existing_checksum)
		ts.Run(CopyObject_to_itself_by_replacing_the_checksum)
		// azure doesn't support these metadata characters
		ts.Run(CopyObject_with_metadata)
	}
	ts.Run(CopyObject_success)
}

func TestPutObjectTagging(ts *TestState) {
	ts.Run(PutObjectTagging_non_existing_object)
	ts.Run(PutObjectTagging_long_tags)
	ts.Run(PutObjectTagging_duplicate_keys)
	ts.Run(PutObjectTagging_tag_count_limit)
	ts.Run(PutObjectTagging_invalid_tags)
	ts.Run(PutObjectTagging_success)
}

func TestGetObjectTagging(ts *TestState) {
	ts.Run(GetObjectTagging_non_existing_object)
	ts.Run(GetObjectTagging_unset_tags)
	ts.Run(GetObjectTagging_invalid_parent)
	ts.Run(GetObjectTagging_success)
}

func TestDeleteObjectTagging(ts *TestState) {
	ts.Run(DeleteObjectTagging_non_existing_object)
	ts.Run(DeleteObjectTagging_success_status)
	ts.Run(DeleteObjectTagging_success)
	ts.Run(DeleteObjectTagging_expected_bucket_owner)
}

func TestCreateMultipartUpload(ts *TestState) {
	ts.Run(CreateMultipartUpload_non_existing_bucket)
	ts.Run(CreateMultipartUpload_with_metadata)
	ts.Run(CreateMultipartUpload_with_tagging)
	ts.Run(CreateMultipartUpload_with_object_lock)
	ts.Run(CreateMultipartUpload_with_object_lock_not_enabled)
	ts.Run(CreateMultipartUpload_with_object_lock_invalid_retention)
	ts.Run(CreateMultipartUpload_past_retain_until_date)
	ts.Run(CreateMultipartUpload_invalid_legal_hold)
	ts.Run(CreateMultipartUpload_invalid_object_lock_mode)
	//TODO: remove the condition after implementing checksums in azure
	if !ts.conf.azureTests {
		ts.Run(CreateMultipartUpload_invalid_checksum_algorithm)
		ts.Run(CreateMultipartUpload_empty_checksum_algorithm_with_checksum_type)
		ts.Run(CreateMultipartUpload_type_algo_mismatch)
		ts.Run(CreateMultipartUpload_invalid_checksum_type)
		ts.Run(CreateMultipartUpload_valid_algo_type)
	}
	ts.Run(CreateMultipartUpload_success)
}

func TestUploadPart(ts *TestState) {
	ts.Run(UploadPart_non_existing_bucket)
	ts.Run(UploadPart_invalid_part_number)
	ts.Run(UploadPart_non_existing_key)
	ts.Run(UploadPart_non_existing_mp_upload)
	//TODO: remove the condition after implementing checksums in azure
	if !ts.conf.azureTests {
		ts.Run(UploadPart_multiple_checksum_headers)
		ts.Run(UploadPart_invalid_checksum_header)
		ts.Run(UploadPart_checksum_header_and_algo_mismatch)
		ts.Run(UploadPart_checksum_algorithm_mistmatch_on_initialization)
		ts.Run(UploadPart_checksum_algorithm_mistmatch_on_initialization_with_value)
		ts.Run(UploadPart_incorrect_checksums)
		ts.Run(UploadPart_no_checksum_with_full_object_checksum_type)
		ts.Run(UploadPart_no_checksum_with_composite_checksum_type)
		ts.Run(UploadPart_should_calculate_checksum_if_only_algorithm_is_provided)
		ts.Run(UploadPart_with_checksums_success)
	}
	ts.Run(UploadPart_success)
}

func TestUploadPartCopy(ts *TestState) {
	ts.Run(UploadPartCopy_non_existing_bucket)
	ts.Run(UploadPartCopy_incorrect_uploadId)
	ts.Run(UploadPartCopy_incorrect_object_key)
	ts.Run(UploadPartCopy_invalid_part_number)
	ts.Run(UploadPartCopy_invalid_copy_source)
	ts.Run(UploadPartCopy_non_existing_source_bucket)
	ts.Run(UploadPartCopy_non_existing_source_object_key)
	ts.Run(UploadPartCopy_success)
	ts.Run(UploadPartCopy_by_range_invalid_ranges)
	ts.Run(UploadPartCopy_exceeding_copy_source_range)
	ts.Run(UploadPartCopy_greater_range_than_obj_size)
	ts.Run(UploadPartCopy_by_range_success)
	//TODO: remove the condition after implementing checksums in azure
	if !ts.conf.azureTests {
		ts.Run(UploadPartCopy_should_copy_the_checksum)
		ts.Run(UploadPartCopy_should_not_copy_the_checksum)
		ts.Run(UploadPartCopy_should_calculate_the_checksum)
		ts.Run(UploadPartCopy_conditional_reads)
	}
}

func TestListParts(ts *TestState) {
	ts.Run(ListParts_incorrect_uploadId)
	ts.Run(ListParts_incorrect_object_key)
	ts.Run(ListParts_invalid_max_parts)
	ts.Run(ListParts_default_max_parts)
	ts.Run(ListParts_exceeding_max_parts)
	ts.Run(ListParts_truncated)
	//TODO: remove the condition after implementing checksums in azure
	if !ts.conf.azureTests {
		ts.Run(ListParts_with_checksums)
		ts.Run(ListParts_null_checksums)
	}
	ts.Run(ListParts_success)
}

func TestListMultipartUploads(ts *TestState) {
	ts.Run(ListMultipartUploads_non_existing_bucket)
	ts.Run(ListMultipartUploads_empty_result)
	ts.Run(ListMultipartUploads_invalid_max_uploads)
	ts.Run(ListMultipartUploads_max_uploads)
	ts.Run(ListMultipartUploads_exceeding_max_uploads)
	ts.Run(ListMultipartUploads_incorrect_next_key_marker)
	ts.Run(ListMultipartUploads_ignore_upload_id_marker)
	//TODO: remove the condition after implementing checksums in azure
	if !ts.conf.azureTests {
		ts.Run(ListMultipartUploads_with_checksums)
	}
	ts.Run(ListMultipartUploads_success)
}

func TestAbortMultipartUpload(ts *TestState) {
	ts.Run(AbortMultipartUpload_non_existing_bucket)
	ts.Run(AbortMultipartUpload_incorrect_uploadId)
	ts.Run(AbortMultipartUpload_incorrect_object_key)
	ts.Run(AbortMultipartUpload_success)
	ts.Run(AbortMultipartUpload_success_status_code)
	ts.Run(AbortMultipartUpload_if_match_initiated_time)
}

func TestCompleteMultipartUpload(ts *TestState) {
	ts.Run(CompletedMultipartUpload_non_existing_bucket)
	ts.Run(CompleteMultipartUpload_incorrect_part_number)
	ts.Run(CompleteMultipartUpload_invalid_part_number)
	ts.Run(CompleteMultipartUpload_invalid_ETag)
	ts.Run(CompleteMultipartUpload_small_upload_size)
	ts.Run(CompleteMultipartUpload_empty_parts)
	ts.Run(CompleteMultipartUpload_incorrect_parts_order)
	ts.Run(CompleteMultipartUpload_mpu_object_size)
	ts.Run(CompleteMultipartUpload_conditional_writes)
	//TODO: remove the condition after implementing checksums in azure
	if !ts.conf.azureTests {
		ts.Run(CompleteMultipartUpload_invalid_checksum_type)
		ts.Run(CompleteMultipartUpload_invalid_checksum_part)
		ts.Run(CompleteMultipartUpload_multiple_checksum_part)
		ts.Run(CompleteMultipartUpload_incorrect_checksum_part)
		ts.Run(CompleteMultipartUpload_different_checksum_part)
		ts.Run(CompleteMultipartUpload_missing_part_checksum)
		ts.Run(CompleteMultipartUpload_multiple_final_checksums)
		ts.Run(CompleteMultipartUpload_invalid_final_checksums)
		ts.Run(CompleteMultipartUpload_incorrect_final_checksums)
		ts.Run(CompleteMultipartUpload_should_calculate_the_final_checksum_full_object)
		ts.Run(CompleteMultipartUpload_should_verify_the_final_checksum)
		ts.Run(CompleteMultipartUpload_should_verify_final_composite_checksum)
		ts.Run(CompleteMultipartUpload_invalid_final_composite_checksum)
		ts.Run(CompleteMultipartUpload_checksum_type_mismatch)
		ts.Run(CompleteMultipartUpload_should_ignore_the_final_checksum)
		ts.Run(CompleteMultipartUpload_should_succeed_without_final_checksum_type)
		// azure doesn't support these metadata characters
		ts.Run(CompleteMultipartUpload_with_metadata)
	}
	ts.Run(CompleteMultipartUpload_success)
	if !ts.conf.azureTests {
		ts.Run(CompleteMultipartUpload_racey_success)
	}
}

func TestPutBucketAcl(ts *TestState) {
	ts.Run(PutBucketAcl_non_existing_bucket)
	ts.Run(PutBucketAcl_disabled)
	ts.Run(PutBucketAcl_none_of_the_options_specified)
	ts.Run(PutBucketAcl_invalid_canned_acl)
	ts.Run(PutBucketAcl_invalid_acl_canned_and_acp)
	ts.Run(PutBucketAcl_invalid_acl_canned_and_grants)
	ts.Run(PutBucketAcl_invalid_acl_acp_and_grants)
	ts.Run(PutBucketAcl_invalid_owner)
	ts.Run(PutBucketAcl_invalid_owner_not_in_body)
	ts.Run(PutBucketAcl_invalid_empty_owner_id_in_body)
	ts.Run(PutBucketAcl_invalid_permission_in_body)
	ts.Run(PutBucketAcl_invalid_grantee_type_in_body)
	ts.Run(PutBucketAcl_empty_grantee_ID_in_body)
	ts.Run(PutBucketAcl_success_access_denied)
	ts.Run(PutBucketAcl_success_grants)
	ts.Run(PutBucketAcl_success_canned_acl)
	ts.Run(PutBucketAcl_success_acp)
}

func TestGetBucketAcl(ts *TestState) {
	ts.Run(GetBucketAcl_non_existing_bucket)
	ts.Run(GetBucketAcl_translation_canned_public_read)
	ts.Run(GetBucketAcl_translation_canned_public_read_write)
	ts.Run(GetBucketAcl_translation_canned_private)
	ts.Run(GetBucketAcl_access_denied)
	ts.Run(GetBucketAcl_success)
}

func TestPutBucketPolicy(ts *TestState) {
	ts.Run(PutBucketPolicy_non_existing_bucket)
	ts.Run(PutBucketPolicy_invalid_json)
	ts.Run(PutBucketPolicy_statement_not_provided)
	ts.Run(PutBucketPolicy_empty_statement)
	ts.Run(PutBucketPolicy_invalid_effect)
	ts.Run(PutBucketPolicy_invalid_action)
	ts.Run(PutBucketPolicy_empty_principals_string)
	ts.Run(PutBucketPolicy_empty_principals_array)
	ts.Run(PutBucketPolicy_principals_aws_struct_empty_string)
	ts.Run(PutBucketPolicy_principals_aws_struct_empty_string_slice)
	ts.Run(PutBucketPolicy_principals_incorrect_wildcard_usage)
	ts.Run(PutBucketPolicy_non_existing_principals)
	ts.Run(PutBucketPolicy_empty_resources_string)
	ts.Run(PutBucketPolicy_empty_resources_array)
	ts.Run(PutBucketPolicy_invalid_resource_prefix)
	ts.Run(PutBucketPolicy_invalid_resource_with_starting_slash)
	ts.Run(PutBucketPolicy_duplicate_resource)
	ts.Run(PutBucketPolicy_incorrect_bucket_name)
	ts.Run(PutBucketPolicy_action_resource_mismatch)
	ts.Run(PutBucketPolicy_explicit_deny)
	ts.Run(PutBucketPolicy_multi_wildcard_resource)
	ts.Run(PutBucketPolicy_any_char_match)
	ts.Run(PutBucketPolicy_version)
	ts.Run(PutBucketPolicy_success)
	ts.Run(PutBucketPolicy_status)
}

func TestGetBucketPolicy(ts *TestState) {
	ts.Run(GetBucketPolicy_non_existing_bucket)
	ts.Run(GetBucketPolicy_not_set)
	ts.Run(GetBucketPolicy_success)
}

func TestGetBucketPolicyStatus(ts *TestState) {
	ts.Run(GetBucketPolicyStatus_non_existing_bucket)
	ts.Run(GetBucketPolicyStatus_no_such_bucket_policy)
	ts.Run(GetBucketPolicyStatus_success)
}

func TestDeleteBucketPolicy(ts *TestState) {
	ts.Run(DeleteBucketPolicy_non_existing_bucket)
	ts.Run(DeleteBucketPolicy_remove_before_setting)
	ts.Run(DeleteBucketPolicy_success)
}

func TestPutBucketCors(ts *TestState) {
	ts.Run(PutBucketCors_non_existing_bucket)
	ts.Run(PutBucketCors_empty_cors_rules)
	ts.Run(PutBucketCors_invalid_method)
	ts.Run(PutBucketCors_invalid_header)
	ts.Run(PutBucketCors_md5)
	ts.Run(PutBucketCors_success)
}

func TestGetBucketCors(ts *TestState) {
	ts.Run(GetBucketCors_non_existing_bucket)
	ts.Run(GetBucketCors_no_such_bucket_cors)
	ts.Run(GetBucketCors_success)
}

func TestDeleteBucketCors(ts *TestState) {
	ts.Run(DeleteBucketCors_non_existing_bucket)
	ts.Run(DeleteBucketCors_success)
}

func TestPreflightOPTIONSEndpoint(ts *TestState) {
	ts.Run(PreflightOPTIONS_non_existing_bucket)
	ts.Run(PreflightOPTIONS_missing_origin)
	ts.Run(PreflightOPTIONS_invalid_request_method)
	ts.Run(PreflightOPTIONS_invalid_request_headers)
	ts.Run(PreflightOPTIONS_unset_bucket_cors)
	ts.Run(PreflightOPTIONS_access_forbidden)
	ts.Run(PreflightOPTIONS_access_granted)
}

func TestCORSMiddleware(ts *TestState) {
	ts.Run(CORSMiddleware_invalid_method)
	ts.Run(CORSMiddleware_invalid_headers)
	ts.Run(CORSMiddleware_access_forbidden)
	ts.Run(CORSMiddleware_access_granted)
}

func TestPutObjectLockConfiguration(ts *TestState) {
	ts.Run(PutObjectLockConfiguration_non_existing_bucket)
	ts.Run(PutObjectLockConfiguration_empty_request_body)
	ts.Run(PutObjectLockConfiguration_malformed_body)
	if !ts.conf.versioningEnabled {
		ts.Run(PutObjectLockConfiguration_not_enabled_on_bucket_creation)
	}
	ts.Run(PutObjectLockConfiguration_invalid_status)
	ts.Run(PutObjectLockConfiguration_invalid_mode)
	ts.Run(PutObjectLockConfiguration_both_years_and_days)
	ts.Run(PutObjectLockConfiguration_invalid_years_days)
	ts.Run(PutObjectLockConfiguration_success)
}

func TestGetObjectLockConfiguration(ts *TestState) {
	ts.Run(GetObjectLockConfiguration_non_existing_bucket)
	ts.Run(GetObjectLockConfiguration_unset_config)
	ts.Run(GetObjectLockConfiguration_success)
}

func TestPutObjectRetention(ts *TestState) {
	ts.Run(PutObjectRetention_non_existing_bucket)
	ts.Run(PutObjectRetention_non_existing_object)
	ts.Run(PutObjectRetention_unset_bucket_object_lock_config)
	ts.Run(PutObjectRetention_expired_retain_until_date)
	ts.Run(PutObjectRetention_invalid_mode)
	ts.Run(PutObjectRetention_overwrite_compliance_mode)
	ts.Run(PutObjectRetention_overwrite_compliance_with_compliance)
	ts.Run(PutObjectRetention_overwrite_governance_with_governance)
	ts.Run(PutObjectRetention_overwrite_governance_without_bypass_specified)
	ts.Run(PutObjectRetention_overwrite_governance_with_permission)
	ts.Run(PutObjectRetention_success)
}

func TestGetObjectRetention(ts *TestState) {
	ts.Run(GetObjectRetention_non_existing_bucket)
	ts.Run(GetObjectRetention_non_existing_object)
	ts.Run(GetObjectRetention_disabled_lock)
	ts.Run(GetObjectRetention_unset_config)
	ts.Run(GetObjectRetention_success)
}

func TestPutObjectLegalHold(ts *TestState) {
	ts.Run(PutObjectLegalHold_non_existing_bucket)
	ts.Run(PutObjectLegalHold_non_existing_object)
	ts.Run(PutObjectLegalHold_invalid_body)
	ts.Run(PutObjectLegalHold_invalid_status)
	ts.Run(PutObjectLegalHold_unset_bucket_object_lock_config)
	ts.Run(PutObjectLegalHold_success)
}

func TestGetObjectLegalHold(ts *TestState) {
	ts.Run(GetObjectLegalHold_non_existing_bucket)
	ts.Run(GetObjectLegalHold_non_existing_object)
	ts.Run(GetObjectLegalHold_disabled_lock)
	ts.Run(GetObjectLegalHold_unset_config)
	ts.Run(GetObjectLegalHold_success)
}

func TestNotImplementedActions(ts *TestState) {
	// bucket analytics actions
	ts.Run(PutBucketAnalyticsConfiguration_not_implemented)
	ts.Run(GetBucketAnalyticsConfiguration_not_implemented)
	ts.Run(ListBucketAnalyticsConfiguration_not_implemented)
	ts.Run(DeleteBucketAnalyticsConfiguration_not_implemented)
	// bucket encryption actions
	ts.Run(PutBucketEncryption_not_implemented)
	ts.Run(GetBucketEncryption_not_implemented)
	ts.Run(DeleteBucketEncryption_not_implemented)
	// bucket intelligent tierieng actions
	ts.Run(PutBucketIntelligentTieringConfiguration_not_implemented)
	ts.Run(GetBucketIntelligentTieringConfiguration_not_implemented)
	ts.Run(ListBucketIntelligentTieringConfiguration_not_implemented)
	ts.Run(DeleteBucketIntelligentTieringConfiguration_not_implemented)
	// bucket inventory configuration actions
	ts.Run(PutBucketInventoryConfiguration_not_implemented)
	ts.Run(GetBucketInventoryConfiguration_not_implemented)
	ts.Run(ListBucketInventoryConfiguration_not_implemented)
	ts.Run(DeleteBucketInventoryConfiguration_not_implemented)
	// bucket lifecycle configuration actions
	ts.Run(PutBucketLifecycleConfiguration_not_implemented)
	ts.Run(GetBucketLifecycleConfiguration_not_implemented)
	ts.Run(DeleteBucketLifecycle_not_implemented)
	// bucket logging actions
	ts.Run(PutBucketLogging_not_implemented)
	ts.Run(GetBucketLogging_not_implemented)
	// bucket request payment actions
	ts.Run(PutBucketRequestPayment_not_implemented)
	ts.Run(GetBucketRequestPayment_not_implemented)
	// bucket metrics configuration actions
	ts.Run(PutBucketMetricsConfiguration_not_implemented)
	ts.Run(GetBucketMetricsConfiguration_not_implemented)
	ts.Run(ListBucketMetricsConfigurations_not_implemented)
	ts.Run(DeleteBucketMetricsConfiguration_not_implemented)
	// bucket replication actions
	ts.Run(PutBucketReplication_not_implemented)
	ts.Run(GetBucketReplication_not_implemented)
	ts.Run(DeleteBucketReplication_not_implemented)
	// bucket public access block actions
	ts.Run(PutPublicAccessBlock_not_implemented)
	ts.Run(GetPublicAccessBlock_not_implemented)
	ts.Run(DeletePublicAccessBlock_not_implemented)
	// bucket notification actions
	ts.Run(PutBucketNotificationConfiguratio_not_implemented)
	ts.Run(GetBucketNotificationConfiguratio_not_implemented)
	// bucket acceleration actions
	ts.Run(PutBucketAccelerateConfiguration_not_implemented)
	ts.Run(GetBucketAccelerateConfiguration_not_implemented)
	// bucket website actions
	ts.Run(PutBucketWebsite_not_implemented)
	ts.Run(GetBucketWebsite_not_implemented)
	ts.Run(DeleteBucketWebsite_not_implemented)
}

func TestWORMProtection(ts *TestState) {
	ts.Run(WORMProtection_bucket_object_lock_configuration_compliance_mode)
	ts.Run(WORMProtection_bucket_object_lock_configuration_governance_mode)
	ts.Run(WORMProtection_bucket_object_lock_governance_bypass_delete)
	ts.Run(WORMProtection_bucket_object_lock_governance_bypass_delete_multiple)
	ts.Run(WORMProtection_object_lock_retention_compliance_locked)
	ts.Run(WORMProtection_object_lock_retention_governance_locked)
	ts.Run(WORMProtection_object_lock_retention_governance_bypass_overwrite_put)
	ts.Run(WORMProtection_object_lock_retention_governance_bypass_overwrite_copy)
	ts.Run(WORMProtection_object_lock_retention_governance_bypass_overwrite_mp)
	ts.Run(WORMProtection_unable_to_overwrite_locked_object_put)
	ts.Run(WORMProtection_unable_to_overwrite_locked_object_copy)
	ts.Run(WORMProtection_unable_to_overwrite_locked_object_mp)
	ts.Run(WORMProtection_object_lock_retention_governance_bypass_delete)
	ts.Run(WORMProtection_object_lock_retention_governance_bypass_delete_mul)
	ts.Run(WORMProtection_object_lock_legal_hold_locked)
	ts.Run(WORMProtection_root_bypass_governance_retention_delete_object)
}

func TestFullFlow(ts *TestState) {
	TestAuthentication(ts)
	TestPresignedAuthentication(ts)
	TestCreateBucket(ts)
	TestHeadBucket(ts)
	TestListBuckets(ts)
	TestDeleteBucket(ts)
	TestPutBucketOwnershipControls(ts)
	TestGetBucketOwnershipControls(ts)
	TestDeleteBucketOwnershipControls(ts)
	TestPutBucketTagging(ts)
	TestGetBucketTagging(ts)
	TestDeleteBucketTagging(ts)
	TestGetBucketLocation(ts)
	TestPutObject(ts)
	TestHeadObject(ts)
	TestGetObjectAttributes(ts)
	TestGetObject(ts)
	TestListObjects(ts)
	TestListObjectsV2(ts)
	if !ts.conf.versioningEnabled && !ts.conf.azureTests {
		TestListObjectVersions_VD(ts)
	}
	TestDeleteObject(ts)
	TestDeleteObjects(ts)
	TestCopyObject(ts)
	TestPutObjectTagging(ts)
	TestDeleteObjectTagging(ts)
	TestCreateMultipartUpload(ts)
	TestUploadPart(ts)
	if !ts.conf.azureTests {
		TestUploadPartCopy(ts)
	}
	TestListParts(ts)
	TestListMultipartUploads(ts)
	TestAbortMultipartUpload(ts)
	TestCompleteMultipartUpload(ts)
	TestPutBucketAcl(ts)
	TestGetBucketAcl(ts)
	TestPutBucketPolicy(ts)
	TestGetBucketPolicy(ts)
	TestDeleteBucketPolicy(ts)
	TestPutBucketCors(ts)
	TestGetBucketCors(ts)
	TestDeleteBucketCors(ts)
	TestPreflightOPTIONSEndpoint(ts)
	TestPutObjectLockConfiguration(ts)
	TestGetObjectLockConfiguration(ts)
	TestPutObjectRetention(ts)
	TestGetObjectRetention(ts)
	TestPutObjectLegalHold(ts)
	TestGetObjectLegalHold(ts)
	if !ts.conf.versioningEnabled {
		TestWORMProtection(ts)
	}
	TestAccessControl(ts)
	TestRouter(ts)
	TestUnsignedStreaminPayloadTrailer(ts)
	TestSignedStreaminPayload(ts)
	TestSignedStreaminPayloadTrailer(ts)
	// FIXME: The tests should pass for azure as well
	// but this issue should be fixed with https://github.com/versity/versitygw/issues/1336
	if !ts.conf.azureTests {
		TestPublicBuckets(ts)
	}
	if ts.conf.versioningEnabled {
		TestVersioning(ts)
	}
}

func TestPosix(ts *TestState) {
	ts.Run(PutObject_overwrite_dir_obj)
	ts.Run(PutObject_overwrite_file_obj)
	ts.Run(PutObject_overwrite_file_obj_with_nested_obj)
	ts.Run(PutObject_dir_obj_with_data)
	ts.Run(PutObject_with_slashes)
	ts.Run(CreateMultipartUpload_dir_obj)
	ts.Run(PutObject_name_too_long)
	ts.Run(HeadObject_name_too_long)
	ts.Run(DeleteObject_name_too_long)
	ts.Run(CopyObject_overwrite_same_dir_object)
	ts.Run(CopyObject_overwrite_same_file_object)
	ts.Run(DeleteObject_directory_not_empty)
	// posix specific versioning tests
	if !ts.conf.versioningEnabled {
		TestVersioningDisabled(ts)
	}
}

func TestScoutfs(ts *TestState) {
	TestAuthentication(ts)
	TestPresignedAuthentication(ts)
	TestCreateBucket(ts)
	TestHeadBucket(ts)
	TestListBuckets(ts)
	TestDeleteBucket(ts)
	TestPutBucketOwnershipControls(ts)
	TestGetBucketOwnershipControls(ts)
	TestDeleteBucketOwnershipControls(ts)
	TestPutBucketTagging(ts)
	TestGetBucketTagging(ts)
	TestDeleteBucketTagging(ts)
	TestGetBucketLocation(ts)
	TestPutObject(ts)
	TestHeadObject(ts)
	TestGetObjectAttributes(ts)
	TestGetObject(ts)
	TestListObjects(ts)
	TestListObjectsV2(ts)
	TestListObjectVersions_VD(ts)
	TestDeleteObject(ts)
	TestDeleteObjects(ts)
	TestCopyObject(ts)
	TestPutObjectTagging(ts)
	TestDeleteObjectTagging(ts)
	TestUploadPart(ts)
	TestUploadPartCopy(ts)
	TestListParts(ts)
	TestListMultipartUploads(ts)
	TestAbortMultipartUpload(ts)
	TestPutBucketAcl(ts)
	TestGetBucketAcl(ts)
	TestPutBucketPolicy(ts)
	TestGetBucketPolicy(ts)
	TestDeleteBucketPolicy(ts)
	TestPutObjectLockConfiguration(ts)
	TestGetObjectLockConfiguration(ts)
	TestPutObjectRetention(ts)
	TestGetObjectRetention(ts)
	TestPutObjectLegalHold(ts)
	TestGetObjectLegalHold(ts)
	TestWORMProtection(ts)
	TestAccessControl(ts)

	ts.Run(CreateMultipartUpload_non_existing_bucket)
	ts.Run(CreateMultipartUpload_with_tagging)
	ts.Run(CreateMultipartUpload_with_object_lock)
	ts.Run(CreateMultipartUpload_with_object_lock_not_enabled)
	ts.Run(CreateMultipartUpload_with_object_lock_invalid_retention)
	ts.Run(CreateMultipartUpload_past_retain_until_date)
	ts.Run(CreateMultipartUpload_invalid_legal_hold)
	ts.Run(CreateMultipartUpload_invalid_object_lock_mode)
	ts.Run(CreateMultipartUpload_invalid_checksum_algorithm)
	ts.Run(CreateMultipartUpload_empty_checksum_algorithm_with_checksum_type)
	ts.Run(CreateMultipartUpload_invalid_checksum_type)
	ts.Run(CreateMultipartUpload_valid_algo_type)
	ts.Run(CreateMultipartUpload_success)

	ts.Run(CompletedMultipartUpload_non_existing_bucket)
	ts.Run(CompleteMultipartUpload_incorrect_part_number)
	ts.Run(CompleteMultipartUpload_invalid_part_number)
	ts.Run(CompleteMultipartUpload_invalid_ETag)
	ts.Run(CompleteMultipartUpload_small_upload_size)
	ts.Run(CompleteMultipartUpload_empty_parts)
	ts.Run(CompleteMultipartUpload_incorrect_parts_order)
	ts.Run(CompleteMultipartUpload_mpu_object_size)
	ts.Run(CompleteMultipartUpload_invalid_checksum_type)
	ts.Run(CompleteMultipartUpload_invalid_checksum_part)
	ts.Run(CompleteMultipartUpload_multiple_checksum_part)
	ts.Run(CompleteMultipartUpload_incorrect_checksum_part)
	ts.Run(CompleteMultipartUpload_different_checksum_part)
	ts.Run(CompleteMultipartUpload_missing_part_checksum)
	ts.Run(CompleteMultipartUpload_multiple_final_checksums)
	ts.Run(CompleteMultipartUpload_invalid_final_checksums)
	ts.Run(CompleteMultipartUpload_checksum_type_mismatch)
	ts.Run(CompleteMultipartUpload_should_ignore_the_final_checksum)
	ts.Run(CompleteMultipartUpload_success)
	ts.Run(CompleteMultipartUpload_racey_success)

	// posix/scoutfs specific tests
	ts.Run(PutObject_overwrite_dir_obj)
	ts.Run(PutObject_overwrite_file_obj)
	ts.Run(PutObject_overwrite_file_obj_with_nested_obj)
	ts.Run(PutObject_dir_obj_with_data)
	ts.Run(PutObject_with_slashes)
	ts.Run(CreateMultipartUpload_dir_obj)
	ts.Run(PutObject_name_too_long)
	ts.Run(HeadObject_name_too_long)
	ts.Run(DeleteObject_name_too_long)
	ts.Run(CopyObject_overwrite_same_dir_object)
	ts.Run(CopyObject_overwrite_same_file_object)
	ts.Run(DeleteObject_directory_not_empty)
}

func TestIAM(ts *TestState) {
	ts.Run(IAM_user_access_denied)
	ts.Run(IAM_userplus_access_denied)
	ts.Run(IAM_userplus_CreateBucket)
	ts.Run(IAM_admin_ChangeBucketOwner)
	ts.Run(IAM_ChangeBucketOwner_back_to_root)
	ts.Run(IAM_ListBuckets)
}

func TestAccessControl(ts *TestState) {
	ts.Run(AccessControl_default_ACL_user_access_denied)
	ts.Run(AccessControl_default_ACL_userplus_access_denied)
	ts.Run(AccessControl_default_ACL_admin_successful_access)
	ts.Run(AccessControl_bucket_resource_single_action)
	ts.Run(AccessControl_bucket_resource_all_action)
	ts.Run(AccessControl_single_object_resource_actions)
	ts.Run(AccessControl_multi_statement_policy)
	ts.Run(AccessControl_bucket_ownership_to_user)
	ts.Run(AccessControl_root_PutBucketAcl)
	ts.Run(AccessControl_user_PutBucketAcl_with_policy_access)
	ts.Run(AccessControl_copy_object_with_starting_slash_for_user)
}

func TestPublicBuckets(ts *TestState) {
	ts.Run(PublicBucket_default_private_bucket)
	ts.Run(PublicBucket_public_bucket_policy)
	if !ts.conf.versioningEnabled {
		// This test targets gateway actions when bucket grants
		// public access to object operations: no specific
		// bucket versioning operations. As object version cleanup
		// is hard to perform, run the test only on the versioning-disabled
		// gateway instance
		ts.Run(PublicBucket_public_object_policy)
	}
	ts.Run(PublicBucket_public_acl)
	ts.Run(PublicBucket_signed_streaming_payload)
	ts.Run(PublicBucket_incorrect_sha256_hash)
}

func TestVersioning(ts *TestState) {
	// PutBucketVersioning action
	ts.Run(PutBucketVersioning_non_existing_bucket)
	ts.Run(PutBucketVersioning_invalid_status)
	ts.Run(PutBucketVersioning_success_enabled)
	ts.Run(PutBucketVersioning_success_suspended)
	// GetBucketVersioning action
	ts.Run(GetBucketVersioning_non_existing_bucket)
	ts.Run(GetBucketVersioning_empty_response)
	ts.Run(GetBucketVersioning_success)
	// DeleteBucket action
	ts.Run(Versioning_DeleteBucket_not_empty)
	// PutObject action
	ts.Run(Versioning_PutObject_suspended_null_versionId_obj)
	ts.Run(Versioning_PutObject_null_versionId_obj)
	ts.Run(Versioning_PutObject_overwrite_null_versionId_obj)
	ts.Run(Versioning_PutObject_success)
	// CopyObject action
	ts.Run(Versioning_CopyObject_invalid_versionId)
	ts.Run(Versioning_CopyObject_success)
	ts.Run(Versioning_CopyObject_non_existing_version_id)
	ts.Run(Versioning_CopyObject_from_an_object_version)
	ts.Run(Versioning_CopyObject_special_chars)
	// HeadObject action
	ts.Run(Versioning_HeadObject_invalid_versionId)
	ts.Run(Versioning_HeadObject_non_existing_object_version)
	ts.Run(Versioning_HeadObject_invalid_parent)
	ts.Run(Versioning_HeadObject_success)
	ts.Run(Versioning_HeadObject_without_versionId)
	ts.Run(Versioning_HeadObject_delete_marker)
	// GetObject action
	ts.Run(Versioning_GetObject_invalid_versionId)
	ts.Run(Versioning_GetObject_non_existing_object_version)
	ts.Run(Versioning_GetObject_success)
	ts.Run(Versioning_GetObject_delete_marker_without_versionId)
	ts.Run(Versioning_GetObject_delete_marker)
	ts.Run(Versioning_GetObject_null_versionId_obj)
	// object tagging actions
	ts.Run(Versioning_PutObjectTagging_invalid_versionId)
	ts.Run(Versioning_PutObjectTagging_non_existing_object_version)
	ts.Run(Versioning_GetObjectTagging_invalid_versionId)
	ts.Run(Versioning_GetObjectTagging_non_existing_object_version)
	ts.Run(Versioning_DeleteObjectTagging_invalid_versionId)
	ts.Run(Versioning_DeleteObjectTagging_non_existing_object_version)
	ts.Run(Versioning_PutGetDeleteObjectTagging_success)
	// GetObjectAttributes action
	ts.Run(Versioning_GetObjectAttributes_invalid_versionId)
	ts.Run(Versioning_GetObjectAttributes_object_version)
	ts.Run(Versioning_GetObjectAttributes_delete_marker)
	// DeleteObject actions
	ts.Run(Versioning_DeleteObject_invalid_versionId)
	ts.Run(Versioning_DeleteObject_delete_object_version)
	ts.Run(Versioning_DeleteObject_non_existing_object)
	ts.Run(Versioning_DeleteObject_delete_a_delete_marker)
	ts.Run(Versioning_Delete_null_versionId_object)
	ts.Run(Versioning_DeleteObject_nested_dir_object)
	ts.Run(Versioning_DeleteObject_suspended)
	ts.Run(Versioning_DeleteObjects_success)
	ts.Run(Versioning_DeleteObjects_delete_deleteMarkers)
	// ListObjectVersions
	ts.Run(ListObjectVersions_non_existing_bucket)
	ts.Run(ListObjectVersions_list_single_object_versions)
	ts.Run(ListObjectVersions_list_multiple_object_versions)
	ts.Run(ListObjectVersions_multiple_object_versions_truncated)
	ts.Run(ListObjectVersions_with_delete_markers)
	ts.Run(ListObjectVersions_containing_null_versionId_obj)
	ts.Run(ListObjectVersions_single_null_versionId_object)
	ts.Run(ListObjectVersions_checksum)
	// Multipart upload
	ts.Run(Versioning_Multipart_Upload_success)
	ts.Run(Versioning_Multipart_Upload_overwrite_an_object)
	ts.Run(Versioning_UploadPartCopy_invalid_versionId)
	ts.Run(Versioning_UploadPartCopy_non_existing_versionId)
	ts.Run(Versioning_UploadPartCopy_from_an_object_version)
	// Object lock configuration
	ts.Run(Versioning_object_lock_not_enabled_on_bucket_creation)
	ts.Run(Versioning_Enable_object_lock)
	ts.Run(Versioning_status_switch_to_suspended_with_object_lock)
	// Object-Lock Retention
	ts.Run(Versioning_PutObjectRetention_invalid_versionId)
	ts.Run(Versioning_PutObjectRetention_non_existing_object_version)
	ts.Run(Versioning_GetObjectRetention_invalid_versionId)
	ts.Run(Versioning_GetObjectRetention_non_existing_object_version)
	ts.Run(Versioning_Put_GetObjectRetention_success)
	// Object-Lock Legal hold
	ts.Run(Versioning_PutObjectLegalHold_invalid_versionId)
	ts.Run(Versioning_PutObjectLegalHold_non_existing_object_version)
	ts.Run(Versioning_GetObjectLegalHold_invalid_versionId)
	ts.Run(Versioning_GetObjectLegalHold_non_existing_object_version)
	ts.Run(Versioning_Put_GetObjectLegalHold_success)
	// WORM protection
	ts.Run(Versioning_WORM_obj_version_locked_with_legal_hold)
	ts.Run(Versioning_WORM_obj_version_locked_with_governance_retention)
	ts.Run(Versioning_WORM_obj_version_locked_with_compliance_retention)
	ts.Run(Versioning_WORM_PutObject_overwrite_locked_object)
	ts.Run(Versioning_WORM_CopyObject_overwrite_locked_object)
	ts.Run(Versioning_WORM_CompleteMultipartUpload_overwrite_locked_object)
	// Concurrent requests
	// Versioninig_concurrent_upload_object
	ts.Run(Versioning_AccessControl_GetObjectVersion)
	ts.Run(Versioning_AccessControl_HeadObjectVersion)
	ts.Run(Versioning_AccessControl_object_tagging_policy)
	ts.Run(Versioning_AccessControl_DeleteObject_policy)
	ts.Run(Versioning_AccessControl_GetObjectAttributes_policy)
}

func TestVersioningDisabled(ts *TestState) {
	ts.Run(VersioningDisabled_GetBucketVersioning_not_configured)
	ts.Run(VersioningDisabled_PutBucketVersioning_not_configured)
}

func TestRouter(ts *TestState) {
	ts.Run(RouterPutPartNumberWithoutUploadId)
	ts.Run(RouterPostRoot)
	ts.Run(RouterPostObjectWithoutQuery)
	ts.Run(RouterPUTObjectOnlyUploadId)
	ts.Run(RouterGetUploadsWithKey)
	ts.Run(RouterCopySourceNotAllowed)
}

func TestUnsignedStreaminPayloadTrailer(ts *TestState) {
	// azure doesn't support checksums
	if !ts.conf.azureTests {
		ts.Run(UnsignedStreaminPayloadTrailer_malformed_trailer)
		ts.Run(UnsignedStreamingPayloadTrailer_missing_invalid_dec_content_length)
		ts.Run(UnsignedStreamingPayloadTrailer_invalid_trailing_checksum)
		ts.Run(UnsignedStreamingPayloadTrailer_incorrect_trailing_checksum)
		ts.Run(UnsignedStreamingPayloadTrailer_multiple_checksum_headers)
		ts.Run(UnsignedStreamingPayloadTrailer_sdk_algo_and_trailer_mismatch)
		ts.Run(UnsignedStreamingPayloadTrailer_incomplete_body)
		ts.Run(UnsignedStreamingPayloadTrailer_invalid_chunk_size)
		ts.Run(UnsignedStreamingPayloadTrailer_content_length_payload_size_mismatch)
		ts.Run(UnsignedStreamingPayloadTrailer_no_trailer_should_calculate_crc64nvme)
		ts.Run(UnsignedStreamingPayloadTrailer_no_payload_trailer_only_headers)
		ts.Run(UnsignedStreamingPayloadTrailer_success_both_sdk_algo_and_trailer)
		ts.Run(UnsignedStreamingPayloadTrailer_UploadPart_no_trailer_composite_checksum)
		ts.Run(UnsignedStreamingPayloadTrailer_UploadPart_no_trailer_full_object)
		ts.Run(UnsignedStreamingPayloadTrailer_UploadPart_trailer_and_mp_algo_mismatch)
		ts.Run(UnsignedStreamingPayloadTrailer_UploadPart_success_with_trailer)
		ts.Run(UnsignedStreamingPayloadTrailer_not_allowed)
	}
}

func TestSignedStreaminPayload(ts *TestState) {
	if !ts.conf.azureTests {
		ts.Run(SignedStreamingPayload_invalid_encoding)
		ts.Run(SignedStreamingPayload_invalid_chunk_size)
		ts.Run(SignedStreamingPayload_decoded_content_length_mismatch)
	}
}

func TestSignedStreaminPayloadTrailer(ts *TestState) {
	if !ts.conf.azureTests {
		ts.Run(SignedStreamingPayloadTrailer_malformed_trailer)
		ts.Run(SignedStreamingPayloadTrailer_incomplete_body)
		ts.Run(SignedStreamingPayloadTrailer_missing_x_amz_trailer_header)
		ts.Run(SignedStreamingPayloadTrailer_invalid_checksum)
		ts.Run(SignedStreamingPayloadTrailer_bad_digest)
		ts.Run(SignedStreamingPayloadTrailer_success)
	}
}

type IntTest func(s3 *S3Conf) error

type IntTests map[string]IntTest

func GetIntTests() IntTests {
	return IntTests{
		"Authentication_invalid_auth_header":                                       Authentication_invalid_auth_header,
		"Authentication_unsupported_signature_version":                             Authentication_unsupported_signature_version,
		"Authentication_missing_components":                                        Authentication_missing_components,
		"Authentication_malformed_component":                                       Authentication_malformed_component,
		"Authentication_missing_credentials":                                       Authentication_missing_credentials,
		"Authentication_missing_signedheaders":                                     Authentication_missing_signedheaders,
		"Authentication_missing_signature":                                         Authentication_missing_signature,
		"Authentication_malformed_credential":                                      Authentication_malformed_credential,
		"Authentication_credentials_invalid_terminal":                              Authentication_credentials_invalid_terminal,
		"Authentication_credentials_incorrect_service":                             Authentication_credentials_incorrect_service,
		"Authentication_credentials_incorrect_region":                              Authentication_credentials_incorrect_region,
		"Authentication_credentials_invalid_date":                                  Authentication_credentials_invalid_date,
		"Authentication_credentials_future_date":                                   Authentication_credentials_future_date,
		"Authentication_credentials_past_date":                                     Authentication_credentials_past_date,
		"Authentication_credentials_non_existing_access_key":                       Authentication_credentials_non_existing_access_key,
		"Authentication_missing_date_header":                                       Authentication_missing_date_header,
		"Authentication_invalid_date_header":                                       Authentication_invalid_date_header,
		"Authentication_date_mismatch":                                             Authentication_date_mismatch,
		"Authentication_incorrect_payload_hash":                                    Authentication_incorrect_payload_hash,
		"Authentication_invalid_sha256_payload_hash":                               Authentication_invalid_sha256_payload_hash,
		"Authentication_md5":                                                       Authentication_md5,
		"Authentication_signature_error_incorrect_secret_key":                      Authentication_signature_error_incorrect_secret_key,
		"Authentication_with_expect_header":                                        Authentication_with_expect_header,
		"PresignedAuth_security_token_not_supported":                               PresignedAuth_security_token_not_supported,
		"PresignedAuth_unsupported_algorithm":                                      PresignedAuth_unsupported_algorithm,
		"PresignedAuth_ECDSA_not_supported":                                        PresignedAuth_ECDSA_not_supported,
		"PresignedAuth_missing_signature_query_param":                              PresignedAuth_missing_signature_query_param,
		"PresignedAuth_missing_credentials_query_param":                            PresignedAuth_missing_credentials_query_param,
		"PresignedAuth_malformed_creds_invalid_parts":                              PresignedAuth_malformed_creds_invalid_parts,
		"PresignedAuth_creds_invalid_terminal":                                     PresignedAuth_creds_invalid_terminal,
		"PresignedAuth_creds_incorrect_service":                                    PresignedAuth_creds_incorrect_service,
		"PresignedAuth_creds_incorrect_region":                                     PresignedAuth_creds_incorrect_region,
		"PresignedAuth_creds_invalid_date":                                         PresignedAuth_creds_invalid_date,
		"PresignedAuth_missing_date_query":                                         PresignedAuth_missing_date_query,
		"PresignedAuth_dates_mismatch":                                             PresignedAuth_dates_mismatch,
		"PresignedAuth_non_existing_access_key_id":                                 PresignedAuth_non_existing_access_key_id,
		"PresignedAuth_missing_signed_headers_query_param":                         PresignedAuth_missing_signed_headers_query_param,
		"PresignedAuth_missing_expiration_query_param":                             PresignedAuth_missing_expiration_query_param,
		"PresignedAuth_invalid_expiration_query_param":                             PresignedAuth_invalid_expiration_query_param,
		"PresignedAuth_negative_expiration_query_param":                            PresignedAuth_negative_expiration_query_param,
		"PresignedAuth_exceeding_expiration_query_param":                           PresignedAuth_exceeding_expiration_query_param,
		"PresignedAuth_expired_request":                                            PresignedAuth_expired_request,
		"PresignedAuth_incorrect_secret_key":                                       PresignedAuth_incorrect_secret_key,
		"PresignedAuth_PutObject_success":                                          PresignedAuth_PutObject_success,
		"PutObject_missing_object_lock_retention_config":                           PutObject_missing_object_lock_retention_config,
		"PutObject_name_too_long":                                                  PutObject_name_too_long,
		"PutObject_with_object_lock":                                               PutObject_with_object_lock,
		"PutObject_invalid_legal_hold":                                             PutObject_invalid_legal_hold,
		"PutObject_invalid_object_lock_mode":                                       PutObject_invalid_object_lock_mode,
		"PutObject_conditional_writes":                                             PutObject_conditional_writes,
		"PutObject_with_metadata":                                                  PutObject_with_metadata,
		"PutObject_invalid_credentials":                                            PutObject_invalid_credentials,
		"PutObject_checksum_algorithm_and_header_mismatch":                         PutObject_checksum_algorithm_and_header_mismatch,
		"PutObject_multiple_checksum_headers":                                      PutObject_multiple_checksum_headers,
		"PutObject_invalid_checksum_header":                                        PutObject_invalid_checksum_header,
		"PutObject_incorrect_checksums":                                            PutObject_incorrect_checksums,
		"PutObject_default_checksum":                                               PutObject_default_checksum,
		"PutObject_checksums_success":                                              PutObject_checksums_success,
		"PresignedAuth_Put_GetObject_with_data":                                    PresignedAuth_Put_GetObject_with_data,
		"PresignedAuth_Put_GetObject_with_UTF8_chars":                              PresignedAuth_Put_GetObject_with_UTF8_chars,
		"PresignedAuth_UploadPart":                                                 PresignedAuth_UploadPart,
		"CreateBucket_invalid_bucket_name":                                         CreateBucket_invalid_bucket_name,
		"CreateBucket_existing_bucket":                                             CreateBucket_existing_bucket,
		"CreateBucket_owned_by_you":                                                CreateBucket_owned_by_you,
		"CreateBucket_invalid_ownership":                                           CreateBucket_invalid_ownership,
		"CreateBucket_ownership_with_acl":                                          CreateBucket_ownership_with_acl,
		"CreateBucket_as_user":                                                     CreateBucket_as_user,
		"CreateDeleteBucket_success":                                               CreateDeleteBucket_success,
		"CreateBucket_default_acl":                                                 CreateBucket_default_acl,
		"CreateBucket_non_default_acl":                                             CreateBucket_non_default_acl,
		"CreateBucket_default_object_lock":                                         CreateBucket_default_object_lock,
		"CreateBucket_invalid_location_constraint":                                 CreateBucket_invalid_location_constraint,
		"CreateBucket_long_tags":                                                   CreateBucket_long_tags,
		"CreateBucket_invalid_tags":                                                CreateBucket_invalid_tags,
		"CreateBucket_duplicate_keys":                                              CreateBucket_duplicate_keys,
		"CreateBucket_tag_count_limit":                                             CreateBucket_tag_count_limit,
		"CreateBucket_invalid_canned_acl":                                          CreateBucket_invalid_canned_acl,
		"HeadBucket_non_existing_bucket":                                           HeadBucket_non_existing_bucket,
		"HeadBucket_success":                                                       HeadBucket_success,
		"ListBuckets_as_user":                                                      ListBuckets_as_user,
		"ListBuckets_as_admin":                                                     ListBuckets_as_admin,
		"ListBuckets_with_prefix":                                                  ListBuckets_with_prefix,
		"ListBuckets_invalid_max_buckets":                                          ListBuckets_invalid_max_buckets,
		"ListBuckets_truncated":                                                    ListBuckets_truncated,
		"ListBuckets_success":                                                      ListBuckets_success,
		"DeleteBucket_non_existing_bucket":                                         DeleteBucket_non_existing_bucket,
		"DeleteBucket_non_empty_bucket":                                            DeleteBucket_non_empty_bucket,
		"DeleteBucket_incorrect_expected_bucket_owner":                             DeleteBucket_incorrect_expected_bucket_owner,
		"DeleteBucket_success_status_code":                                         DeleteBucket_success_status_code,
		"PutBucketOwnershipControls_non_existing_bucket":                           PutBucketOwnershipControls_non_existing_bucket,
		"PutBucketOwnershipControls_multiple_rules":                                PutBucketOwnershipControls_multiple_rules,
		"PutBucketOwnershipControls_invalid_ownership":                             PutBucketOwnershipControls_invalid_ownership,
		"PutBucketOwnershipControls_success":                                       PutBucketOwnershipControls_success,
		"GetBucketOwnershipControls_non_existing_bucket":                           GetBucketOwnershipControls_non_existing_bucket,
		"GetBucketOwnershipControls_default_ownership":                             GetBucketOwnershipControls_default_ownership,
		"GetBucketOwnershipControls_success":                                       GetBucketOwnershipControls_success,
		"DeleteBucketOwnershipControls_non_existing_bucket":                        DeleteBucketOwnershipControls_non_existing_bucket,
		"DeleteBucketOwnershipControls_success":                                    DeleteBucketOwnershipControls_success,
		"PutBucketTagging_non_existing_bucket":                                     PutBucketTagging_non_existing_bucket,
		"PutBucketTagging_long_tags":                                               PutBucketTagging_long_tags,
		"PutBucketTagging_invalid_tags":                                            PutBucketTagging_invalid_tags,
		"PutBucketTagging_duplicate_keys":                                          PutBucketTagging_duplicate_keys,
		"PutBucketTagging_tag_count_limit":                                         PutBucketTagging_tag_count_limit,
		"PutBucketTagging_success":                                                 PutBucketTagging_success,
		"PutBucketTagging_success_status":                                          PutBucketTagging_success_status,
		"GetBucketTagging_non_existing_bucket":                                     GetBucketTagging_non_existing_bucket,
		"GetBucketTagging_unset_tags":                                              GetBucketTagging_unset_tags,
		"GetBucketTagging_success":                                                 GetBucketTagging_success,
		"DeleteBucketTagging_non_existing_object":                                  DeleteBucketTagging_non_existing_object,
		"DeleteBucketTagging_success_status":                                       DeleteBucketTagging_success_status,
		"DeleteBucketTagging_success":                                              DeleteBucketTagging_success,
		"GetBucketLocation_success":                                                GetBucketLocation_success,
		"GetBucketLocation_non_exist":                                              GetBucketLocation_non_exist,
		"GetBucketLocation_no_access":                                              GetBucketLocation_no_access,
		"PutObject_non_existing_bucket":                                            PutObject_non_existing_bucket,
		"PutObject_special_chars":                                                  PutObject_special_chars,
		"PutObject_tagging":                                                        PutObject_tagging,
		"PutObject_success":                                                        PutObject_success,
		"PutObject_invalid_object_names":                                           PutObject_invalid_object_names,
		"PutObject_false_negative_object_names":                                    PutObject_false_negative_object_names,
		"PutObject_racey_success":                                                  PutObject_racey_success,
		"HeadObject_non_existing_object":                                           HeadObject_non_existing_object,
		"HeadObject_invalid_part_number":                                           HeadObject_invalid_part_number,
		"HeadObject_part_number_not_supported":                                     HeadObject_part_number_not_supported,
		"HeadObject_directory_object_noslash":                                      HeadObject_directory_object_noslash,
		"HeadObject_non_existing_dir_object":                                       HeadObject_non_existing_dir_object,
		"HeadObject_name_too_long":                                                 HeadObject_name_too_long,
		"HeadObject_invalid_parent_dir":                                            HeadObject_invalid_parent_dir,
		"HeadObject_with_range":                                                    HeadObject_with_range,
		"HeadObject_zero_len_with_range":                                           HeadObject_zero_len_with_range,
		"HeadObject_dir_with_range":                                                HeadObject_dir_with_range,
		"HeadObject_conditional_reads":                                             HeadObject_conditional_reads,
		"HeadObject_not_enabled_checksum_mode":                                     HeadObject_not_enabled_checksum_mode,
		"HeadObject_checksums":                                                     HeadObject_checksums,
		"HeadObject_success":                                                       HeadObject_success,
		"GetObjectAttributes_non_existing_bucket":                                  GetObjectAttributes_non_existing_bucket,
		"GetObjectAttributes_non_existing_object":                                  GetObjectAttributes_non_existing_object,
		"GetObjectAttributes_invalid_attrs":                                        GetObjectAttributes_invalid_attrs,
		"GetObjectAttributes_invalid_parent":                                       GetObjectAttributes_invalid_parent,
		"GetObjectAttributes_invalid_single_attribute":                             GetObjectAttributes_invalid_single_attribute,
		"GetObjectAttributes_empty_attrs":                                          GetObjectAttributes_empty_attrs,
		"GetObjectAttributes_existing_object":                                      GetObjectAttributes_existing_object,
		"GetObjectAttributes_checksums":                                            GetObjectAttributes_checksums,
		"GetObject_non_existing_key":                                               GetObject_non_existing_key,
		"GetObject_directory_object_noslash":                                       GetObject_directory_object_noslash,
		"GetObject_with_range":                                                     GetObject_with_range,
		"GetObject_zero_len_with_range":                                            GetObject_zero_len_with_range,
		"GetObject_dir_with_range":                                                 GetObject_dir_with_range,
		"GetObject_invalid_parent":                                                 GetObject_invalid_parent,
		"GetObject_large_object":                                                   GetObject_large_object,
		"GetObject_conditional_reads":                                              GetObject_conditional_reads,
		"GetObject_checksums":                                                      GetObject_checksums,
		"GetObject_success":                                                        GetObject_success,
		"GetObject_directory_success":                                              GetObject_directory_success,
		"GetObject_by_range_resp_status":                                           GetObject_by_range_resp_status,
		"GetObject_non_existing_dir_object":                                        GetObject_non_existing_dir_object,
		"GetObject_overrides_success":                                              GetObject_overrides_success,
		"GetObject_overrides_presign_success":                                      GetObject_overrides_presign_success,
		"GetObject_overrides_fail_public":                                          GetObject_overrides_fail_public,
		"GetObject_invalid_part_number":                                            GetObject_invalid_part_number,
		"GetObject_part_number_not_supported":                                      GetObject_part_number_not_supported,
		"ListObjects_non_existing_bucket":                                          ListObjects_non_existing_bucket,
		"ListObjects_with_prefix":                                                  ListObjects_with_prefix,
		"ListObjects_truncated":                                                    ListObjects_truncated,
		"ListObjects_paginated":                                                    ListObjects_paginated,
		"ListObjects_invalid_max_keys":                                             ListObjects_invalid_max_keys,
		"ListObjects_max_keys_0":                                                   ListObjects_max_keys_0,
		"ListObjects_delimiter":                                                    ListObjects_delimiter,
		"ListObjects_max_keys_none":                                                ListObjects_max_keys_none,
		"ListObjects_marker_not_from_obj_list":                                     ListObjects_marker_not_from_obj_list,
		"ListObjects_list_all_objs":                                                ListObjects_list_all_objs,
		"ListObjects_nested_dir_file_objs":                                         ListObjects_nested_dir_file_objs,
		"ListObjects_check_owner":                                                  ListObjects_check_owner,
		"ListObjects_non_truncated_common_prefixes":                                ListObjects_non_truncated_common_prefixes,
		"ListObjectsV2_non_truncated_common_prefixes":                              ListObjectsV2_non_truncated_common_prefixes,
		"ListObjects_with_checksum":                                                ListObjects_with_checksum,
		"ListObjectsV2_start_after":                                                ListObjectsV2_start_after,
		"ListObjectsV2_both_start_after_and_continuation_token":                    ListObjectsV2_both_start_after_and_continuation_token,
		"ListObjectsV2_start_after_not_in_list":                                    ListObjectsV2_start_after_not_in_list,
		"ListObjectsV2_start_after_empty_result":                                   ListObjectsV2_start_after_empty_result,
		"ListObjectsV2_both_delimiter_and_prefix":                                  ListObjectsV2_both_delimiter_and_prefix,
		"ListObjectsV2_single_dir_object_with_delim_and_prefix":                    ListObjectsV2_single_dir_object_with_delim_and_prefix,
		"ListObjectsV2_truncated_common_prefixes":                                  ListObjectsV2_truncated_common_prefixes,
		"ListObjectsV2_all_objs_max_keys":                                          ListObjectsV2_all_objs_max_keys,
		"ListObjectsV2_list_all_objs":                                              ListObjectsV2_list_all_objs,
		"ListObjectsV2_with_owner":                                                 ListObjectsV2_with_owner,
		"ListObjectsV2_with_checksum":                                              ListObjectsV2_with_checksum,
		"ListObjectVersions_VD_success":                                            ListObjectVersions_VD_success,
		"DeleteObject_non_existing_object":                                         DeleteObject_non_existing_object,
		"DeleteObject_directory_object_noslash":                                    DeleteObject_directory_object_noslash,
		"DeleteObject_non_empty_dir_obj":                                           DeleteObject_non_empty_dir_obj,
		"DeleteObject_conditional_writes":                                          DeleteObject_conditional_writes,
		"DeleteObject_name_too_long":                                               DeleteObject_name_too_long,
		"CopyObject_overwrite_same_dir_object":                                     CopyObject_overwrite_same_dir_object,
		"CopyObject_overwrite_same_file_object":                                    CopyObject_overwrite_same_file_object,
		"DeleteObject_non_existing_dir_object":                                     DeleteObject_non_existing_dir_object,
		"DeleteObject_directory_object":                                            DeleteObject_directory_object,
		"DeleteObject_success":                                                     DeleteObject_success,
		"DeleteObject_success_status_code":                                         DeleteObject_success_status_code,
		"DeleteObject_incorrect_expected_bucket_owner":                             DeleteObject_incorrect_expected_bucket_owner,
		"DeleteObject_expected_bucket_owner":                                       DeleteObject_expected_bucket_owner,
		"DeleteObjects_empty_input":                                                DeleteObjects_empty_input,
		"DeleteObjects_non_existing_objects":                                       DeleteObjects_non_existing_objects,
		"DeleteObjects_success":                                                    DeleteObjects_success,
		"CopyObject_non_existing_dst_bucket":                                       CopyObject_non_existing_dst_bucket,
		"CopyObject_not_owned_source_bucket":                                       CopyObject_not_owned_source_bucket,
		"CopyObject_copy_to_itself":                                                CopyObject_copy_to_itself,
		"CopyObject_copy_to_itself_invalid_directive":                              CopyObject_copy_to_itself_invalid_directive,
		"CopyObject_should_replace_tagging":                                        CopyObject_should_replace_tagging,
		"CopyObject_should_copy_tagging":                                           CopyObject_should_copy_tagging,
		"CopyObject_invalid_tagging_directive":                                     CopyObject_invalid_tagging_directive,
		"CopyObject_to_itself_with_new_metadata":                                   CopyObject_to_itself_with_new_metadata,
		"CopyObject_copy_source_starting_with_slash":                               CopyObject_copy_source_starting_with_slash,
		"CopyObject_invalid_copy_source":                                           CopyObject_invalid_copy_source,
		"CopyObject_non_existing_dir_object":                                       CopyObject_non_existing_dir_object,
		"CopyObject_should_copy_meta_props":                                        CopyObject_should_copy_meta_props,
		"CopyObject_should_replace_meta_props":                                     CopyObject_should_replace_meta_props,
		"CopyObject_invalid_legal_hold":                                            CopyObject_invalid_legal_hold,
		"CopyObject_invalid_object_lock_mode":                                      CopyObject_invalid_object_lock_mode,
		"CopyObject_with_legal_hold":                                               CopyObject_with_legal_hold,
		"CopyObject_with_retention_lock":                                           CopyObject_with_retention_lock,
		"CopyObject_conditional_reads":                                             CopyObject_conditional_reads,
		"CopyObject_with_metadata":                                                 CopyObject_with_metadata,
		"CopyObject_invalid_checksum_algorithm":                                    CopyObject_invalid_checksum_algorithm,
		"CopyObject_create_checksum_on_copy":                                       CopyObject_create_checksum_on_copy,
		"CopyObject_should_copy_the_existing_checksum":                             CopyObject_should_copy_the_existing_checksum,
		"CopyObject_should_replace_the_existing_checksum":                          CopyObject_should_replace_the_existing_checksum,
		"CopyObject_to_itself_by_replacing_the_checksum":                           CopyObject_to_itself_by_replacing_the_checksum,
		"CopyObject_success":                                                       CopyObject_success,
		"PutObjectTagging_non_existing_object":                                     PutObjectTagging_non_existing_object,
		"PutObjectTagging_long_tags":                                               PutObjectTagging_long_tags,
		"PutObjectTagging_duplicate_keys":                                          PutObjectTagging_duplicate_keys,
		"PutObjectTagging_tag_count_limit":                                         PutObjectTagging_tag_count_limit,
		"PutObjectTagging_invalid_tags":                                            PutObjectTagging_invalid_tags,
		"PutObjectTagging_success":                                                 PutObjectTagging_success,
		"GetObjectTagging_non_existing_object":                                     GetObjectTagging_non_existing_object,
		"GetObjectTagging_unset_tags":                                              GetObjectTagging_unset_tags,
		"GetObjectTagging_invalid_parent":                                          GetObjectTagging_invalid_parent,
		"GetObjectTagging_success":                                                 GetObjectTagging_success,
		"DeleteObjectTagging_non_existing_object":                                  DeleteObjectTagging_non_existing_object,
		"DeleteObjectTagging_success_status":                                       DeleteObjectTagging_success_status,
		"DeleteObjectTagging_success":                                              DeleteObjectTagging_success,
		"DeleteObjectTagging_expected_bucket_owner":                                DeleteObjectTagging_expected_bucket_owner,
		"CreateMultipartUpload_non_existing_bucket":                                CreateMultipartUpload_non_existing_bucket,
		"CreateMultipartUpload_with_metadata":                                      CreateMultipartUpload_with_metadata,
		"CreateMultipartUpload_with_tagging":                                       CreateMultipartUpload_with_tagging,
		"CreateMultipartUpload_with_object_lock":                                   CreateMultipartUpload_with_object_lock,
		"CreateMultipartUpload_with_object_lock_not_enabled":                       CreateMultipartUpload_with_object_lock_not_enabled,
		"CreateMultipartUpload_with_object_lock_invalid_retention":                 CreateMultipartUpload_with_object_lock_invalid_retention,
		"CreateMultipartUpload_past_retain_until_date":                             CreateMultipartUpload_past_retain_until_date,
		"CreateMultipartUpload_invalid_legal_hold":                                 CreateMultipartUpload_invalid_legal_hold,
		"CreateMultipartUpload_invalid_object_lock_mode":                           CreateMultipartUpload_invalid_object_lock_mode,
		"CreateMultipartUpload_invalid_checksum_algorithm":                         CreateMultipartUpload_invalid_checksum_algorithm,
		"CreateMultipartUpload_empty_checksum_algorithm_with_checksum_type":        CreateMultipartUpload_empty_checksum_algorithm_with_checksum_type,
		"CreateMultipartUpload_type_algo_mismatch":                                 CreateMultipartUpload_type_algo_mismatch,
		"CreateMultipartUpload_invalid_checksum_type":                              CreateMultipartUpload_invalid_checksum_type,
		"CreateMultipartUpload_valid_algo_type":                                    CreateMultipartUpload_valid_algo_type,
		"CreateMultipartUpload_success":                                            CreateMultipartUpload_success,
		"UploadPart_non_existing_bucket":                                           UploadPart_non_existing_bucket,
		"UploadPart_invalid_part_number":                                           UploadPart_invalid_part_number,
		"UploadPart_non_existing_key":                                              UploadPart_non_existing_key,
		"UploadPart_non_existing_mp_upload":                                        UploadPart_non_existing_mp_upload,
		"UploadPart_multiple_checksum_headers":                                     UploadPart_multiple_checksum_headers,
		"UploadPart_invalid_checksum_header":                                       UploadPart_invalid_checksum_header,
		"UploadPart_checksum_header_and_algo_mismatch":                             UploadPart_checksum_header_and_algo_mismatch,
		"UploadPart_checksum_algorithm_mistmatch_on_initialization":                UploadPart_checksum_algorithm_mistmatch_on_initialization,
		"UploadPart_checksum_algorithm_mistmatch_on_initialization_with_value":     UploadPart_checksum_algorithm_mistmatch_on_initialization_with_value,
		"UploadPart_incorrect_checksums":                                           UploadPart_incorrect_checksums,
		"UploadPart_no_checksum_with_full_object_checksum_type":                    UploadPart_no_checksum_with_full_object_checksum_type,
		"UploadPart_no_checksum_with_composite_checksum_type":                      UploadPart_no_checksum_with_composite_checksum_type,
		"UploadPart_should_calculate_checksum_if_only_algorithm_is_provided":       UploadPart_should_calculate_checksum_if_only_algorithm_is_provided,
		"UploadPart_with_checksums_success":                                        UploadPart_with_checksums_success,
		"UploadPart_success":                                                       UploadPart_success,
		"UploadPartCopy_non_existing_bucket":                                       UploadPartCopy_non_existing_bucket,
		"UploadPartCopy_incorrect_uploadId":                                        UploadPartCopy_incorrect_uploadId,
		"UploadPartCopy_incorrect_object_key":                                      UploadPartCopy_incorrect_object_key,
		"UploadPartCopy_invalid_part_number":                                       UploadPartCopy_invalid_part_number,
		"UploadPartCopy_invalid_copy_source":                                       UploadPartCopy_invalid_copy_source,
		"UploadPartCopy_non_existing_source_bucket":                                UploadPartCopy_non_existing_source_bucket,
		"UploadPartCopy_non_existing_source_object_key":                            UploadPartCopy_non_existing_source_object_key,
		"UploadPartCopy_success":                                                   UploadPartCopy_success,
		"UploadPartCopy_by_range_invalid_ranges":                                   UploadPartCopy_by_range_invalid_ranges,
		"UploadPartCopy_exceeding_copy_source_range":                               UploadPartCopy_exceeding_copy_source_range,
		"UploadPartCopy_greater_range_than_obj_size":                               UploadPartCopy_greater_range_than_obj_size,
		"UploadPartCopy_by_range_success":                                          UploadPartCopy_by_range_success,
		"UploadPartCopy_conditional_reads":                                         UploadPartCopy_conditional_reads,
		"UploadPartCopy_should_copy_the_checksum":                                  UploadPartCopy_should_copy_the_checksum,
		"UploadPartCopy_should_not_copy_the_checksum":                              UploadPartCopy_should_not_copy_the_checksum,
		"UploadPartCopy_should_calculate_the_checksum":                             UploadPartCopy_should_calculate_the_checksum,
		"ListParts_incorrect_uploadId":                                             ListParts_incorrect_uploadId,
		"ListParts_incorrect_object_key":                                           ListParts_incorrect_object_key,
		"ListParts_invalid_max_parts":                                              ListParts_invalid_max_parts,
		"ListParts_default_max_parts":                                              ListParts_default_max_parts,
		"ListParts_truncated":                                                      ListParts_truncated,
		"ListParts_with_checksums":                                                 ListParts_with_checksums,
		"ListParts_null_checksums":                                                 ListParts_null_checksums,
		"ListParts_success":                                                        ListParts_success,
		"ListMultipartUploads_non_existing_bucket":                                 ListMultipartUploads_non_existing_bucket,
		"ListMultipartUploads_empty_result":                                        ListMultipartUploads_empty_result,
		"ListMultipartUploads_invalid_max_uploads":                                 ListMultipartUploads_invalid_max_uploads,
		"ListMultipartUploads_max_uploads":                                         ListMultipartUploads_max_uploads,
		"ListMultipartUploads_exceeding_max_uploads":                               ListMultipartUploads_exceeding_max_uploads,
		"ListMultipartUploads_incorrect_next_key_marker":                           ListMultipartUploads_incorrect_next_key_marker,
		"ListMultipartUploads_ignore_upload_id_marker":                             ListMultipartUploads_ignore_upload_id_marker,
		"ListMultipartUploads_with_checksums":                                      ListMultipartUploads_with_checksums,
		"ListMultipartUploads_success":                                             ListMultipartUploads_success,
		"AbortMultipartUpload_non_existing_bucket":                                 AbortMultipartUpload_non_existing_bucket,
		"AbortMultipartUpload_incorrect_uploadId":                                  AbortMultipartUpload_incorrect_uploadId,
		"AbortMultipartUpload_incorrect_object_key":                                AbortMultipartUpload_incorrect_object_key,
		"AbortMultipartUpload_success":                                             AbortMultipartUpload_success,
		"AbortMultipartUpload_success_status_code":                                 AbortMultipartUpload_success_status_code,
		"AbortMultipartUpload_if_match_initiated_time":                             AbortMultipartUpload_if_match_initiated_time,
		"CompletedMultipartUpload_non_existing_bucket":                             CompletedMultipartUpload_non_existing_bucket,
		"CompleteMultipartUpload_invalid_part_number":                              CompleteMultipartUpload_invalid_part_number,
		"CompleteMultipartUpload_invalid_ETag":                                     CompleteMultipartUpload_invalid_ETag,
		"CompleteMultipartUpload_small_upload_size":                                CompleteMultipartUpload_small_upload_size,
		"CompleteMultipartUpload_empty_parts":                                      CompleteMultipartUpload_empty_parts,
		"CompleteMultipartUpload_incorrect_parts_order":                            CompleteMultipartUpload_incorrect_parts_order,
		"CompleteMultipartUpload_mpu_object_size":                                  CompleteMultipartUpload_mpu_object_size,
		"CompleteMultipartUpload_conditional_writes":                               CompleteMultipartUpload_conditional_writes,
		"CompleteMultipartUpload_with_metadata":                                    CompleteMultipartUpload_with_metadata,
		"CompleteMultipartUpload_invalid_checksum_type":                            CompleteMultipartUpload_invalid_checksum_type,
		"CompleteMultipartUpload_invalid_checksum_part":                            CompleteMultipartUpload_invalid_checksum_part,
		"CompleteMultipartUpload_multiple_checksum_part":                           CompleteMultipartUpload_multiple_checksum_part,
		"CompleteMultipartUpload_incorrect_checksum_part":                          CompleteMultipartUpload_incorrect_checksum_part,
		"CompleteMultipartUpload_different_checksum_part":                          CompleteMultipartUpload_different_checksum_part,
		"CompleteMultipartUpload_missing_part_checksum":                            CompleteMultipartUpload_missing_part_checksum,
		"CompleteMultipartUpload_multiple_final_checksums":                         CompleteMultipartUpload_multiple_final_checksums,
		"CompleteMultipartUpload_invalid_final_checksums":                          CompleteMultipartUpload_invalid_final_checksums,
		"CompleteMultipartUpload_incorrect_final_checksums":                        CompleteMultipartUpload_incorrect_final_checksums,
		"CompleteMultipartUpload_should_calculate_the_final_checksum_full_object":  CompleteMultipartUpload_should_calculate_the_final_checksum_full_object,
		"CompleteMultipartUpload_should_verify_the_final_checksum":                 CompleteMultipartUpload_should_verify_the_final_checksum,
		"CompleteMultipartUpload_should_verify_final_composite_checksum":           CompleteMultipartUpload_should_verify_final_composite_checksum,
		"CompleteMultipartUpload_invalid_final_composite_checksum":                 CompleteMultipartUpload_invalid_final_composite_checksum,
		"CompleteMultipartUpload_checksum_type_mismatch":                           CompleteMultipartUpload_checksum_type_mismatch,
		"CompleteMultipartUpload_should_ignore_the_final_checksum":                 CompleteMultipartUpload_should_ignore_the_final_checksum,
		"CompleteMultipartUpload_should_succeed_without_final_checksum_type":       CompleteMultipartUpload_should_succeed_without_final_checksum_type,
		"CompleteMultipartUpload_success":                                          CompleteMultipartUpload_success,
		"CompleteMultipartUpload_racey_success":                                    CompleteMultipartUpload_racey_success,
		"PutBucketAcl_non_existing_bucket":                                         PutBucketAcl_non_existing_bucket,
		"PutBucketAcl_disabled":                                                    PutBucketAcl_disabled,
		"PutBucketAcl_none_of_the_options_specified":                               PutBucketAcl_none_of_the_options_specified,
		"PutBucketAcl_invalid_canned_acl":                                          PutBucketAcl_invalid_canned_acl,
		"PutBucketAcl_invalid_acl_canned_and_acp":                                  PutBucketAcl_invalid_acl_canned_and_acp,
		"PutBucketAcl_invalid_acl_canned_and_grants":                               PutBucketAcl_invalid_acl_canned_and_grants,
		"PutBucketAcl_invalid_acl_acp_and_grants":                                  PutBucketAcl_invalid_acl_acp_and_grants,
		"PutBucketAcl_invalid_owner":                                               PutBucketAcl_invalid_owner,
		"PutBucketAcl_invalid_owner_not_in_body":                                   PutBucketAcl_invalid_owner_not_in_body,
		"PutBucketAcl_invalid_empty_owner_id_in_body":                              PutBucketAcl_invalid_empty_owner_id_in_body,
		"PutBucketAcl_invalid_permission_in_body":                                  PutBucketAcl_invalid_permission_in_body,
		"PutBucketAcl_invalid_grantee_type_in_body":                                PutBucketAcl_invalid_grantee_type_in_body,
		"PutBucketAcl_empty_grantee_ID_in_body":                                    PutBucketAcl_empty_grantee_ID_in_body,
		"PutBucketAcl_success_access_denied":                                       PutBucketAcl_success_access_denied,
		"PutBucketAcl_success_grants":                                              PutBucketAcl_success_grants,
		"PutBucketAcl_success_canned_acl":                                          PutBucketAcl_success_canned_acl,
		"PutBucketAcl_success_acp":                                                 PutBucketAcl_success_acp,
		"GetBucketAcl_non_existing_bucket":                                         GetBucketAcl_non_existing_bucket,
		"GetBucketAcl_translation_canned_public_read":                              GetBucketAcl_translation_canned_public_read,
		"GetBucketAcl_translation_canned_public_read_write":                        GetBucketAcl_translation_canned_public_read_write,
		"GetBucketAcl_translation_canned_private":                                  GetBucketAcl_translation_canned_private,
		"GetBucketAcl_access_denied":                                               GetBucketAcl_access_denied,
		"GetBucketAcl_success":                                                     GetBucketAcl_success,
		"PutBucketPolicy_non_existing_bucket":                                      PutBucketPolicy_non_existing_bucket,
		"PutBucketPolicy_invalid_json":                                             PutBucketPolicy_invalid_json,
		"PutBucketPolicy_statement_not_provided":                                   PutBucketPolicy_statement_not_provided,
		"PutBucketPolicy_empty_statement":                                          PutBucketPolicy_empty_statement,
		"PutBucketPolicy_invalid_effect":                                           PutBucketPolicy_invalid_effect,
		"PutBucketPolicy_invalid_action":                                           PutBucketPolicy_invalid_action,
		"PutBucketPolicy_empty_principals_string":                                  PutBucketPolicy_empty_principals_string,
		"PutBucketPolicy_empty_principals_array":                                   PutBucketPolicy_empty_principals_array,
		"PutBucketPolicy_principals_aws_struct_empty_string":                       PutBucketPolicy_principals_aws_struct_empty_string,
		"PutBucketPolicy_principals_aws_struct_empty_string_slice":                 PutBucketPolicy_principals_aws_struct_empty_string_slice,
		"PutBucketPolicy_principals_incorrect_wildcard_usage":                      PutBucketPolicy_principals_incorrect_wildcard_usage,
		"PutBucketPolicy_non_existing_principals":                                  PutBucketPolicy_non_existing_principals,
		"PutBucketPolicy_empty_resources_string":                                   PutBucketPolicy_empty_resources_string,
		"PutBucketPolicy_empty_resources_array":                                    PutBucketPolicy_empty_resources_array,
		"PutBucketPolicy_invalid_resource_prefix":                                  PutBucketPolicy_invalid_resource_prefix,
		"PutBucketPolicy_invalid_resource_with_starting_slash":                     PutBucketPolicy_invalid_resource_with_starting_slash,
		"PutBucketPolicy_duplicate_resource":                                       PutBucketPolicy_duplicate_resource,
		"PutBucketPolicy_incorrect_bucket_name":                                    PutBucketPolicy_incorrect_bucket_name,
		"PutBucketPolicy_action_resource_mismatch":                                 PutBucketPolicy_action_resource_mismatch,
		"PutBucketPolicy_explicit_deny":                                            PutBucketPolicy_explicit_deny,
		"PutBucketPolicy_multi_wildcard_resource":                                  PutBucketPolicy_multi_wildcard_resource,
		"PutBucketPolicy_any_char_match":                                           PutBucketPolicy_any_char_match,
		"PutBucketPolicy_version":                                                  PutBucketPolicy_version,
		"PutBucketPolicy_success":                                                  PutBucketPolicy_success,
		"PutBucketPolicy_status":                                                   PutBucketPolicy_status,
		"GetBucketPolicy_non_existing_bucket":                                      GetBucketPolicy_non_existing_bucket,
		"GetBucketPolicy_not_set":                                                  GetBucketPolicy_not_set,
		"GetBucketPolicy_success":                                                  GetBucketPolicy_success,
		"GetBucketPolicyStatus_non_existing_bucket":                                GetBucketPolicyStatus_non_existing_bucket,
		"GetBucketPolicyStatus_no_such_bucket_policy":                              GetBucketPolicyStatus_no_such_bucket_policy,
		"GetBucketPolicyStatus_success":                                            GetBucketPolicyStatus_success,
		"DeleteBucketPolicy_non_existing_bucket":                                   DeleteBucketPolicy_non_existing_bucket,
		"DeleteBucketPolicy_remove_before_setting":                                 DeleteBucketPolicy_remove_before_setting,
		"DeleteBucketPolicy_success":                                               DeleteBucketPolicy_success,
		"PutBucketCors_non_existing_bucket":                                        PutBucketCors_non_existing_bucket,
		"PutBucketCors_empty_cors_rules":                                           PutBucketCors_empty_cors_rules,
		"PutBucketCors_invalid_method":                                             PutBucketCors_invalid_method,
		"PutBucketCors_invalid_header":                                             PutBucketCors_invalid_header,
		"PutBucketCors_md5":                                                        PutBucketCors_md5,
		"GetBucketCors_non_existing_bucket":                                        GetBucketCors_non_existing_bucket,
		"GetBucketCors_no_such_bucket_cors":                                        GetBucketCors_no_such_bucket_cors,
		"GetBucketCors_success":                                                    GetBucketCors_success,
		"DeleteBucketCors_non_existing_bucket":                                     DeleteBucketCors_non_existing_bucket,
		"DeleteBucketCors_success":                                                 DeleteBucketCors_success,
		"PutBucketCors_success":                                                    PutBucketCors_success,
		"PreflightOPTIONS_non_existing_bucket":                                     PreflightOPTIONS_non_existing_bucket,
		"PreflightOPTIONS_missing_origin":                                          PreflightOPTIONS_missing_origin,
		"PreflightOPTIONS_invalid_request_method":                                  PreflightOPTIONS_invalid_request_method,
		"PreflightOPTIONS_invalid_request_headers":                                 PreflightOPTIONS_invalid_request_headers,
		"PreflightOPTIONS_unset_bucket_cors":                                       PreflightOPTIONS_unset_bucket_cors,
		"PreflightOPTIONS_access_forbidden":                                        PreflightOPTIONS_access_forbidden,
		"PreflightOPTIONS_access_granted":                                          PreflightOPTIONS_access_granted,
		"CORSMiddleware_invalid_method":                                            CORSMiddleware_invalid_method,
		"CORSMiddleware_invalid_headers":                                           CORSMiddleware_invalid_headers,
		"CORSMiddleware_access_forbidden":                                          CORSMiddleware_access_forbidden,
		"CORSMiddleware_access_granted":                                            CORSMiddleware_access_granted,
		"PutObjectLockConfiguration_non_existing_bucket":                           PutObjectLockConfiguration_non_existing_bucket,
		"PutObjectLockConfiguration_empty_request_body":                            PutObjectLockConfiguration_empty_request_body,
		"PutObjectLockConfiguration_malformed_body":                                PutObjectLockConfiguration_malformed_body,
		"PutObjectLockConfiguration_not_enabled_on_bucket_creation":                PutObjectLockConfiguration_not_enabled_on_bucket_creation,
		"PutObjectLockConfiguration_invalid_status":                                PutObjectLockConfiguration_invalid_status,
		"PutObjectLockConfiguration_invalid_mode":                                  PutObjectLockConfiguration_invalid_mode,
		"PutObjectLockConfiguration_both_years_and_days":                           PutObjectLockConfiguration_both_years_and_days,
		"PutObjectLockConfiguration_invalid_years_days":                            PutObjectLockConfiguration_invalid_years_days,
		"PutObjectLockConfiguration_success":                                       PutObjectLockConfiguration_success,
		"GetObjectLockConfiguration_non_existing_bucket":                           GetObjectLockConfiguration_non_existing_bucket,
		"GetObjectLockConfiguration_unset_config":                                  GetObjectLockConfiguration_unset_config,
		"GetObjectLockConfiguration_success":                                       GetObjectLockConfiguration_success,
		"PutObjectRetention_non_existing_bucket":                                   PutObjectRetention_non_existing_bucket,
		"PutObjectRetention_non_existing_object":                                   PutObjectRetention_non_existing_object,
		"PutObjectRetention_unset_bucket_object_lock_config":                       PutObjectRetention_unset_bucket_object_lock_config,
		"PutObjectRetention_expired_retain_until_date":                             PutObjectRetention_expired_retain_until_date,
		"PutObjectRetention_invalid_mode":                                          PutObjectRetention_invalid_mode,
		"PutObjectRetention_overwrite_compliance_mode":                             PutObjectRetention_overwrite_compliance_mode,
		"PutObjectRetention_overwrite_compliance_with_compliance":                  PutObjectRetention_overwrite_compliance_with_compliance,
		"PutObjectRetention_overwrite_governance_with_governance":                  PutObjectRetention_overwrite_governance_with_governance,
		"PutObjectRetention_overwrite_governance_without_bypass_specified":         PutObjectRetention_overwrite_governance_without_bypass_specified,
		"PutObjectRetention_overwrite_governance_with_permission":                  PutObjectRetention_overwrite_governance_with_permission,
		"PutObjectRetention_success":                                               PutObjectRetention_success,
		"GetObjectRetention_non_existing_bucket":                                   GetObjectRetention_non_existing_bucket,
		"GetObjectRetention_non_existing_object":                                   GetObjectRetention_non_existing_object,
		"GetObjectRetention_disabled_lock":                                         GetObjectRetention_disabled_lock,
		"GetObjectRetention_unset_config":                                          GetObjectRetention_unset_config,
		"GetObjectRetention_success":                                               GetObjectRetention_success,
		"PutObjectLegalHold_non_existing_bucket":                                   PutObjectLegalHold_non_existing_bucket,
		"PutObjectLegalHold_non_existing_object":                                   PutObjectLegalHold_non_existing_object,
		"PutObjectLegalHold_invalid_body":                                          PutObjectLegalHold_invalid_body,
		"PutObjectLegalHold_invalid_status":                                        PutObjectLegalHold_invalid_status,
		"PutObjectLegalHold_unset_bucket_object_lock_config":                       PutObjectLegalHold_unset_bucket_object_lock_config,
		"PutObjectLegalHold_success":                                               PutObjectLegalHold_success,
		"GetObjectLegalHold_non_existing_bucket":                                   GetObjectLegalHold_non_existing_bucket,
		"GetObjectLegalHold_non_existing_object":                                   GetObjectLegalHold_non_existing_object,
		"GetObjectLegalHold_disabled_lock":                                         GetObjectLegalHold_disabled_lock,
		"GetObjectLegalHold_unset_config":                                          GetObjectLegalHold_unset_config,
		"GetObjectLegalHold_success":                                               GetObjectLegalHold_success,
		"PutBucketAnalyticsConfiguration_not_implemented":                          PutBucketAnalyticsConfiguration_not_implemented,
		"GetBucketAnalyticsConfiguration_not_implemented":                          GetBucketAnalyticsConfiguration_not_implemented,
		"ListBucketAnalyticsConfiguration_not_implemented":                         ListBucketAnalyticsConfiguration_not_implemented,
		"DeleteBucketAnalyticsConfiguration_not_implemented":                       DeleteBucketAnalyticsConfiguration_not_implemented,
		"PutBucketEncryption_not_implemented":                                      PutBucketEncryption_not_implemented,
		"GetBucketEncryption_not_implemented":                                      GetBucketEncryption_not_implemented,
		"DeleteBucketEncryption_not_implemented":                                   DeleteBucketEncryption_not_implemented,
		"PutBucketIntelligentTieringConfiguration_not_implemented":                 PutBucketIntelligentTieringConfiguration_not_implemented,
		"GetBucketIntelligentTieringConfiguration_not_implemented":                 GetBucketIntelligentTieringConfiguration_not_implemented,
		"ListBucketIntelligentTieringConfiguration_not_implemented":                ListBucketIntelligentTieringConfiguration_not_implemented,
		"DeleteBucketIntelligentTieringConfiguration_not_implemented":              DeleteBucketIntelligentTieringConfiguration_not_implemented,
		"PutBucketInventoryConfiguration_not_implemented":                          PutBucketInventoryConfiguration_not_implemented,
		"GetBucketInventoryConfiguration_not_implemented":                          GetBucketInventoryConfiguration_not_implemented,
		"ListBucketInventoryConfiguration_not_implemented":                         ListBucketInventoryConfiguration_not_implemented,
		"DeleteBucketInventoryConfiguration_not_implemented":                       DeleteBucketInventoryConfiguration_not_implemented,
		"PutBucketLifecycleConfiguration_not_implemented":                          PutBucketLifecycleConfiguration_not_implemented,
		"GetBucketLifecycleConfiguration_not_implemented":                          GetBucketLifecycleConfiguration_not_implemented,
		"DeleteBucketLifecycle_not_implemented":                                    DeleteBucketLifecycle_not_implemented,
		"PutBucketLogging_not_implemented":                                         PutBucketLogging_not_implemented,
		"GetBucketLogging_not_implemented":                                         GetBucketLogging_not_implemented,
		"PutBucketRequestPayment_not_implemented":                                  PutBucketRequestPayment_not_implemented,
		"GetBucketRequestPayment_not_implemented":                                  GetBucketRequestPayment_not_implemented,
		"PutBucketMetricsConfiguration_not_implemented":                            PutBucketMetricsConfiguration_not_implemented,
		"GetBucketMetricsConfiguration_not_implemented":                            GetBucketMetricsConfiguration_not_implemented,
		"ListBucketMetricsConfigurations_not_implemented":                          ListBucketMetricsConfigurations_not_implemented,
		"DeleteBucketMetricsConfiguration_not_implemented":                         DeleteBucketMetricsConfiguration_not_implemented,
		"PutBucketReplication_not_implemented":                                     PutBucketReplication_not_implemented,
		"GetBucketReplication_not_implemented":                                     GetBucketReplication_not_implemented,
		"DeleteBucketReplication_not_implemented":                                  DeleteBucketReplication_not_implemented,
		"PutPublicAccessBlock_not_implemented":                                     PutPublicAccessBlock_not_implemented,
		"GetPublicAccessBlock_not_implemented":                                     GetPublicAccessBlock_not_implemented,
		"DeletePublicAccessBlock_not_implemented":                                  DeletePublicAccessBlock_not_implemented,
		"PutBucketNotificationConfiguratio_not_implemented":                        PutBucketNotificationConfiguratio_not_implemented,
		"GetBucketNotificationConfiguratio_not_implemented":                        GetBucketNotificationConfiguratio_not_implemented,
		"PutBucketAccelerateConfiguration_not_implemented":                         PutBucketAccelerateConfiguration_not_implemented,
		"GetBucketAccelerateConfiguration_not_implemented":                         GetBucketAccelerateConfiguration_not_implemented,
		"PutBucketWebsite_not_implemented":                                         PutBucketWebsite_not_implemented,
		"GetBucketWebsite_not_implemented":                                         GetBucketWebsite_not_implemented,
		"DeleteBucketWebsite_not_implemented":                                      DeleteBucketWebsite_not_implemented,
		"WORMProtection_bucket_object_lock_configuration_compliance_mode":          WORMProtection_bucket_object_lock_configuration_compliance_mode,
		"WORMProtection_bucket_object_lock_configuration_governance_mode":          WORMProtection_bucket_object_lock_configuration_governance_mode,
		"WORMProtection_bucket_object_lock_governance_bypass_delete":               WORMProtection_bucket_object_lock_governance_bypass_delete,
		"WORMProtection_bucket_object_lock_governance_bypass_delete_multiple":      WORMProtection_bucket_object_lock_governance_bypass_delete_multiple,
		"WORMProtection_object_lock_retention_compliance_locked":                   WORMProtection_object_lock_retention_compliance_locked,
		"WORMProtection_object_lock_retention_governance_locked":                   WORMProtection_object_lock_retention_governance_locked,
		"WORMProtection_object_lock_retention_governance_bypass_overwrite_put":     WORMProtection_object_lock_retention_governance_bypass_overwrite_put,
		"WORMProtection_object_lock_retention_governance_bypass_overwrite_copy":    WORMProtection_object_lock_retention_governance_bypass_overwrite_copy,
		"WORMProtection_object_lock_retention_governance_bypass_overwrite_mp":      WORMProtection_object_lock_retention_governance_bypass_overwrite_mp,
		"WORMProtection_unable_to_overwrite_locked_object_put":                     WORMProtection_unable_to_overwrite_locked_object_put,
		"WORMProtection_unable_to_overwrite_locked_object_copy":                    WORMProtection_unable_to_overwrite_locked_object_copy,
		"WORMProtection_unable_to_overwrite_locked_object_mp":                      WORMProtection_unable_to_overwrite_locked_object_mp,
		"WORMProtection_object_lock_retention_governance_bypass_delete":            WORMProtection_object_lock_retention_governance_bypass_delete,
		"WORMProtection_object_lock_retention_governance_bypass_delete_mul":        WORMProtection_object_lock_retention_governance_bypass_delete_mul,
		"WORMProtection_object_lock_legal_hold_locked":                             WORMProtection_object_lock_legal_hold_locked,
		"WORMProtection_root_bypass_governance_retention_delete_object":            WORMProtection_root_bypass_governance_retention_delete_object,
		"PutObject_overwrite_dir_obj":                                              PutObject_overwrite_dir_obj,
		"PutObject_overwrite_file_obj":                                             PutObject_overwrite_file_obj,
		"PutObject_overwrite_file_obj_with_nested_obj":                             PutObject_overwrite_file_obj_with_nested_obj,
		"PutObject_dir_obj_with_data":                                              PutObject_dir_obj_with_data,
		"PutObject_with_slashes":                                                   PutObject_with_slashes,
		"CreateMultipartUpload_dir_obj":                                            CreateMultipartUpload_dir_obj,
		"IAM_user_access_denied":                                                   IAM_user_access_denied,
		"IAM_userplus_access_denied":                                               IAM_userplus_access_denied,
		"IAM_userplus_CreateBucket":                                                IAM_userplus_CreateBucket,
		"IAM_admin_ChangeBucketOwner":                                              IAM_admin_ChangeBucketOwner,
		"IAM_ChangeBucketOwner_back_to_root":                                       IAM_ChangeBucketOwner_back_to_root,
		"AccessControl_default_ACL_user_access_denied":                             AccessControl_default_ACL_user_access_denied,
		"AccessControl_default_ACL_userplus_access_denied":                         AccessControl_default_ACL_userplus_access_denied,
		"AccessControl_default_ACL_admin_successful_access":                        AccessControl_default_ACL_admin_successful_access,
		"AccessControl_bucket_resource_single_action":                              AccessControl_bucket_resource_single_action,
		"AccessControl_bucket_resource_all_action":                                 AccessControl_bucket_resource_all_action,
		"AccessControl_single_object_resource_actions":                             AccessControl_single_object_resource_actions,
		"AccessControl_multi_statement_policy":                                     AccessControl_multi_statement_policy,
		"AccessControl_bucket_ownership_to_user":                                   AccessControl_bucket_ownership_to_user,
		"AccessControl_root_PutBucketAcl":                                          AccessControl_root_PutBucketAcl,
		"AccessControl_user_PutBucketAcl_with_policy_access":                       AccessControl_user_PutBucketAcl_with_policy_access,
		"AccessControl_copy_object_with_starting_slash_for_user":                   AccessControl_copy_object_with_starting_slash_for_user,
		"PublicBucket_default_private_bucket":                                      PublicBucket_default_private_bucket,
		"PublicBucket_public_bucket_policy":                                        PublicBucket_public_bucket_policy,
		"PublicBucket_public_object_policy":                                        PublicBucket_public_object_policy,
		"PublicBucket_public_acl":                                                  PublicBucket_public_acl,
		"PublicBucket_signed_streaming_payload":                                    PublicBucket_signed_streaming_payload,
		"PublicBucket_incorrect_sha256_hash":                                       PublicBucket_incorrect_sha256_hash,
		"PutBucketVersioning_non_existing_bucket":                                  PutBucketVersioning_non_existing_bucket,
		"PutBucketVersioning_invalid_status":                                       PutBucketVersioning_invalid_status,
		"PutBucketVersioning_success_enabled":                                      PutBucketVersioning_success_enabled,
		"PutBucketVersioning_success_suspended":                                    PutBucketVersioning_success_suspended,
		"GetBucketVersioning_non_existing_bucket":                                  GetBucketVersioning_non_existing_bucket,
		"GetBucketVersioning_empty_response":                                       GetBucketVersioning_empty_response,
		"GetBucketVersioning_success":                                              GetBucketVersioning_success,
		"Versioning_DeleteBucket_not_empty":                                        Versioning_DeleteBucket_not_empty,
		"Versioning_PutObject_suspended_null_versionId_obj":                        Versioning_PutObject_suspended_null_versionId_obj,
		"Versioning_PutObject_null_versionId_obj":                                  Versioning_PutObject_null_versionId_obj,
		"Versioning_PutObject_overwrite_null_versionId_obj":                        Versioning_PutObject_overwrite_null_versionId_obj,
		"Versioning_PutObject_success":                                             Versioning_PutObject_success,
		"Versioning_CopyObject_invalid_versionId":                                  Versioning_CopyObject_invalid_versionId,
		"Versioning_CopyObject_success":                                            Versioning_CopyObject_success,
		"Versioning_CopyObject_non_existing_version_id":                            Versioning_CopyObject_non_existing_version_id,
		"Versioning_CopyObject_from_an_object_version":                             Versioning_CopyObject_from_an_object_version,
		"Versioning_CopyObject_special_chars":                                      Versioning_CopyObject_special_chars,
		"Versioning_HeadObject_invalid_versionId":                                  Versioning_HeadObject_invalid_versionId,
		"Versioning_HeadObject_non_existing_object_version":                        Versioning_HeadObject_non_existing_object_version,
		"Versioning_HeadObject_invalid_parent":                                     Versioning_HeadObject_invalid_parent,
		"Versioning_HeadObject_success":                                            Versioning_HeadObject_success,
		"Versioning_HeadObject_without_versionId":                                  Versioning_HeadObject_without_versionId,
		"Versioning_HeadObject_delete_marker":                                      Versioning_HeadObject_delete_marker,
		"Versioning_GetObject_invalid_versionId":                                   Versioning_GetObject_invalid_versionId,
		"Versioning_GetObject_non_existing_object_version":                         Versioning_GetObject_non_existing_object_version,
		"Versioning_GetObject_success":                                             Versioning_GetObject_success,
		"Versioning_GetObject_delete_marker_without_versionId":                     Versioning_GetObject_delete_marker_without_versionId,
		"Versioning_GetObject_delete_marker":                                       Versioning_GetObject_delete_marker,
		"Versioning_GetObject_null_versionId_obj":                                  Versioning_GetObject_null_versionId_obj,
		"Versioning_PutObjectTagging_invalid_versionId":                            Versioning_PutObjectTagging_invalid_versionId,
		"Versioning_PutObjectTagging_non_existing_object_version":                  Versioning_PutObjectTagging_non_existing_object_version,
		"Versioning_GetObjectTagging_invalid_versionId":                            Versioning_GetObjectTagging_invalid_versionId,
		"Versioning_GetObjectTagging_non_existing_object_version":                  Versioning_GetObjectTagging_non_existing_object_version,
		"Versioning_DeleteObjectTagging_invalid_versionId":                         Versioning_DeleteObjectTagging_invalid_versionId,
		"Versioning_DeleteObjectTagging_non_existing_object_version":               Versioning_DeleteObjectTagging_non_existing_object_version,
		"Versioning_PutGetDeleteObjectTagging_success":                             Versioning_PutGetDeleteObjectTagging_success,
		"Versioning_GetObjectAttributes_invalid_versionId":                         Versioning_GetObjectAttributes_invalid_versionId,
		"Versioning_GetObjectAttributes_object_version":                            Versioning_GetObjectAttributes_object_version,
		"Versioning_GetObjectAttributes_delete_marker":                             Versioning_GetObjectAttributes_delete_marker,
		"Versioning_DeleteObject_invalid_versionId":                                Versioning_DeleteObject_invalid_versionId,
		"Versioning_DeleteObject_delete_object_version":                            Versioning_DeleteObject_delete_object_version,
		"Versioning_DeleteObject_non_existing_object":                              Versioning_DeleteObject_non_existing_object,
		"Versioning_DeleteObject_delete_a_delete_marker":                           Versioning_DeleteObject_delete_a_delete_marker,
		"Versioning_Delete_null_versionId_object":                                  Versioning_Delete_null_versionId_object,
		"Versioning_DeleteObject_nested_dir_object":                                Versioning_DeleteObject_nested_dir_object,
		"Versioning_DeleteObject_suspended":                                        Versioning_DeleteObject_suspended,
		"Versioning_DeleteObjects_success":                                         Versioning_DeleteObjects_success,
		"Versioning_DeleteObjects_delete_deleteMarkers":                            Versioning_DeleteObjects_delete_deleteMarkers,
		"ListObjectVersions_non_existing_bucket":                                   ListObjectVersions_non_existing_bucket,
		"ListObjectVersions_list_single_object_versions":                           ListObjectVersions_list_single_object_versions,
		"ListObjectVersions_list_multiple_object_versions":                         ListObjectVersions_list_multiple_object_versions,
		"ListObjectVersions_multiple_object_versions_truncated":                    ListObjectVersions_multiple_object_versions_truncated,
		"ListObjectVersions_with_delete_markers":                                   ListObjectVersions_with_delete_markers,
		"ListObjectVersions_containing_null_versionId_obj":                         ListObjectVersions_containing_null_versionId_obj,
		"ListObjectVersions_single_null_versionId_object":                          ListObjectVersions_single_null_versionId_object,
		"ListObjectVersions_checksum":                                              ListObjectVersions_checksum,
		"Versioning_Multipart_Upload_success":                                      Versioning_Multipart_Upload_success,
		"Versioning_Multipart_Upload_overwrite_an_object":                          Versioning_Multipart_Upload_overwrite_an_object,
		"Versioning_UploadPartCopy_invalid_versionId":                              Versioning_UploadPartCopy_invalid_versionId,
		"Versioning_UploadPartCopy_non_existing_versionId":                         Versioning_UploadPartCopy_non_existing_versionId,
		"Versioning_UploadPartCopy_from_an_object_version":                         Versioning_UploadPartCopy_from_an_object_version,
		"Versioning_object_lock_not_enabled_on_bucket_creation":                    Versioning_object_lock_not_enabled_on_bucket_creation,
		"Versioning_Enable_object_lock":                                            Versioning_Enable_object_lock,
		"Versioning_status_switch_to_suspended_with_object_lock":                   Versioning_status_switch_to_suspended_with_object_lock,
		"Versioning_PutObjectRetention_invalid_versionId":                          Versioning_PutObjectRetention_invalid_versionId,
		"Versioning_PutObjectRetention_non_existing_object_version":                Versioning_PutObjectRetention_non_existing_object_version,
		"Versioning_GetObjectRetention_invalid_versionId":                          Versioning_GetObjectRetention_invalid_versionId,
		"Versioning_GetObjectRetention_non_existing_object_version":                Versioning_GetObjectRetention_non_existing_object_version,
		"Versioning_Put_GetObjectRetention_success":                                Versioning_Put_GetObjectRetention_success,
		"Versioning_PutObjectLegalHold_invalid_versionId":                          Versioning_PutObjectLegalHold_invalid_versionId,
		"Versioning_PutObjectLegalHold_non_existing_object_version":                Versioning_PutObjectLegalHold_non_existing_object_version,
		"Versioning_GetObjectLegalHold_invalid_versionId":                          Versioning_GetObjectLegalHold_invalid_versionId,
		"Versioning_GetObjectLegalHold_non_existing_object_version":                Versioning_GetObjectLegalHold_non_existing_object_version,
		"Versioning_Put_GetObjectLegalHold_success":                                Versioning_Put_GetObjectLegalHold_success,
		"Versioning_WORM_obj_version_locked_with_legal_hold":                       Versioning_WORM_obj_version_locked_with_legal_hold,
		"Versioning_WORM_obj_version_locked_with_governance_retention":             Versioning_WORM_obj_version_locked_with_governance_retention,
		"Versioning_WORM_obj_version_locked_with_compliance_retention":             Versioning_WORM_obj_version_locked_with_compliance_retention,
		"Versioning_WORM_PutObject_overwrite_locked_object":                        Versioning_WORM_PutObject_overwrite_locked_object,
		"Versioning_WORM_CopyObject_overwrite_locked_object":                       Versioning_WORM_CopyObject_overwrite_locked_object,
		"Versioning_WORM_CompleteMultipartUpload_overwrite_locked_object":          Versioning_WORM_CompleteMultipartUpload_overwrite_locked_object,
		"Versioning_AccessControl_GetObjectVersion":                                Versioning_AccessControl_GetObjectVersion,
		"Versioning_AccessControl_HeadObjectVersion":                               Versioning_AccessControl_HeadObjectVersion,
		"Versioning_AccessControl_object_tagging_policy":                           Versioning_AccessControl_object_tagging_policy,
		"Versioning_AccessControl_DeleteObject_policy":                             Versioning_AccessControl_DeleteObject_policy,
		"Versioning_AccessControl_GetObjectAttributes_policy":                      Versioning_AccessControl_GetObjectAttributes_policy,
		"Versioning_concurrent_upload_object":                                      Versioning_concurrent_upload_object,
		"RouterPutPartNumberWithoutUploadId":                                       RouterPutPartNumberWithoutUploadId,
		"RouterPostRoot":                                                           RouterPostRoot,
		"RouterPostObjectWithoutQuery":                                             RouterPostObjectWithoutQuery,
		"RouterPUTObjectOnlyUploadId":                                              RouterPUTObjectOnlyUploadId,
		"RouterGetUploadsWithKey":                                                  RouterGetUploadsWithKey,
		"RouterCopySourceNotAllowed":                                               RouterCopySourceNotAllowed,
		"UnsignedStreaminPayloadTrailer_malformed_trailer":                         UnsignedStreaminPayloadTrailer_malformed_trailer,
		"UnsignedStreamingPayloadTrailer_missing_invalid_dec_content_length":       UnsignedStreamingPayloadTrailer_missing_invalid_dec_content_length,
		"UnsignedStreamingPayloadTrailer_invalid_trailing_checksum":                UnsignedStreamingPayloadTrailer_invalid_trailing_checksum,
		"UnsignedStreamingPayloadTrailer_incorrect_trailing_checksum":              UnsignedStreamingPayloadTrailer_incorrect_trailing_checksum,
		"UnsignedStreamingPayloadTrailer_multiple_checksum_headers":                UnsignedStreamingPayloadTrailer_multiple_checksum_headers,
		"UnsignedStreamingPayloadTrailer_sdk_algo_and_trailer_mismatch":            UnsignedStreamingPayloadTrailer_sdk_algo_and_trailer_mismatch,
		"UnsignedStreamingPayloadTrailer_incomplete_body":                          UnsignedStreamingPayloadTrailer_incomplete_body,
		"UnsignedStreamingPayloadTrailer_invalid_chunk_size":                       UnsignedStreamingPayloadTrailer_invalid_chunk_size,
		"UnsignedStreamingPayloadTrailer_content_length_payload_size_mismatch":     UnsignedStreamingPayloadTrailer_content_length_payload_size_mismatch,
		"UnsignedStreamingPayloadTrailer_no_trailer_should_calculate_crc64nvme":    UnsignedStreamingPayloadTrailer_no_trailer_should_calculate_crc64nvme,
		"UnsignedStreamingPayloadTrailer_no_payload_trailer_only_headers":          UnsignedStreamingPayloadTrailer_no_payload_trailer_only_headers,
		"UnsignedStreamingPayloadTrailer_success_both_sdk_algo_and_trailer":        UnsignedStreamingPayloadTrailer_success_both_sdk_algo_and_trailer,
		"UnsignedStreamingPayloadTrailer_UploadPart_no_trailer_composite_checksum": UnsignedStreamingPayloadTrailer_UploadPart_no_trailer_composite_checksum,
		"UnsignedStreamingPayloadTrailer_UploadPart_no_trailer_full_object":        UnsignedStreamingPayloadTrailer_UploadPart_no_trailer_full_object,
		"UnsignedStreamingPayloadTrailer_UploadPart_trailer_and_mp_algo_mismatch":  UnsignedStreamingPayloadTrailer_UploadPart_trailer_and_mp_algo_mismatch,
		"UnsignedStreamingPayloadTrailer_UploadPart_success_with_trailer":          UnsignedStreamingPayloadTrailer_UploadPart_success_with_trailer,
		"UnsignedStreamingPayloadTrailer_not_allowed":                              UnsignedStreamingPayloadTrailer_not_allowed,
		"SignedStreamingPayload_invalid_encoding":                                  SignedStreamingPayload_invalid_encoding,
		"SignedStreamingPayload_invalid_chunk_size":                                SignedStreamingPayload_invalid_chunk_size,
		"SignedStreamingPayload_decoded_content_length_mismatch":                   SignedStreamingPayload_decoded_content_length_mismatch,
		"SignedStreamingPayloadTrailer_malformed_trailer":                          SignedStreamingPayloadTrailer_malformed_trailer,
		"SignedStreamingPayloadTrailer_incomplete_body":                            SignedStreamingPayloadTrailer_incomplete_body,
		"SignedStreamingPayloadTrailer_missing_x_amz_trailer_header":               SignedStreamingPayloadTrailer_missing_x_amz_trailer_header,
		"SignedStreamingPayloadTrailer_invalid_checksum":                           SignedStreamingPayloadTrailer_invalid_checksum,
		"SignedStreamingPayloadTrailer_bad_digest":                                 SignedStreamingPayloadTrailer_bad_digest,
		"SignedStreamingPayloadTrailer_success":                                    SignedStreamingPayloadTrailer_success,
	}
}
