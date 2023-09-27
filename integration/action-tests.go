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

func TestCreateBucket(s *S3Conf) {
	CreateBucket_invalid_bucket_name(s)
	CreateBucket_existing_bucket(s)
	CreateBucket_as_user(s)
	CreateDeleteBucket_success(s)
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

func TestPutObject(s *S3Conf) {
	PutObject_non_existing_bucket(s)
	PutObject_special_chars(s)
	PutObject_existing_dir_obj(s)
	PutObject_obj_parent_is_file(s)
	PutObject_invalid_long_tags(s)
	PutObject_success(s)
}

func TestHeadObject(s *S3Conf) {
	HeadObject_non_existing_object(s)
	HeadObject_success(s)
}

func TestGetObject(s *S3Conf) {
	GetObject_non_existing_key(s)
	GetObject_invalid_ranges(s)
	GetObject_with_meta(s)
	GetObject_success(s)
	GetObject_by_range_success(s)
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

func TestFullFlow(s *S3Conf) {
	TestAuthentication(s)
	TestCreateBucket(s)
	TestHeadBucket(s)
	TestListBuckets(s)
	TestDeleteBucket(s)
	TestPutObject(s)
	TestHeadObject(s)
	TestGetObject(s)
	TestListObjects(s)
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
}
