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
	PutObject_invalid_long_tags(s)
	PutObject_success(s)
	PutObject_invalid_credentials(s)
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

func TestPosix(s *S3Conf) {
	PutObject_overwrite_dir_obj(s)
	PutObject_overwrite_file_obj(s)
	PutObject_dir_obj_with_data(s)
	CreateMultipartUpload_dir_obj(s)
}

type IntTests map[string]func(s *S3Conf) error

func GetIntTests() IntTests {
	return IntTests{
		"Authentication_empty_auth_header":                    Authentication_empty_auth_header,
		"Authentication_invalid_auth_header":                  Authentication_invalid_auth_header,
		"Authentication_unsupported_signature_version":        Authentication_unsupported_signature_version,
		"Authentication_malformed_credentials":                Authentication_malformed_credentials,
		"Authentication_malformed_credentials_invalid_parts":  Authentication_malformed_credentials_invalid_parts,
		"Authentication_credentials_terminated_string":        Authentication_credentials_terminated_string,
		"Authentication_credentials_incorrect_service":        Authentication_credentials_incorrect_service,
		"Authentication_credentials_incorrect_region":         Authentication_credentials_incorrect_region,
		"Authentication_credentials_invalid_date":             Authentication_credentials_invalid_date,
		"Authentication_credentials_future_date":              Authentication_credentials_future_date,
		"Authentication_credentials_past_date":                Authentication_credentials_past_date,
		"Authentication_credentials_non_existing_access_key":  Authentication_credentials_non_existing_access_key,
		"Authentication_invalid_signed_headers":               Authentication_invalid_signed_headers,
		"Authentication_missing_date_header":                  Authentication_missing_date_header,
		"Authentication_invalid_date_header":                  Authentication_invalid_date_header,
		"Authentication_date_mismatch":                        Authentication_date_mismatch,
		"Authentication_incorrect_payload_hash":               Authentication_incorrect_payload_hash,
		"Authentication_incorrect_md5":                        Authentication_incorrect_md5,
		"Authentication_signature_error_incorrect_secret_key": Authentication_signature_error_incorrect_secret_key,
		"CreateBucket_invalid_bucket_name":                    CreateBucket_invalid_bucket_name,
		"CreateBucket_existing_bucket":                        CreateBucket_existing_bucket,
		"CreateBucket_as_user":                                CreateBucket_as_user,
		"CreateDeleteBucket_success":                          CreateDeleteBucket_success,
		"HeadBucket_non_existing_bucket":                      HeadBucket_non_existing_bucket,
		"HeadBucket_success":                                  HeadBucket_success,
		"ListBuckets_as_user":                                 ListBuckets_as_user,
		"ListBuckets_as_admin":                                ListBuckets_as_admin,
		"ListBuckets_success":                                 ListBuckets_success,
		"DeleteBucket_non_existing_bucket":                    DeleteBucket_non_existing_bucket,
		"DeleteBucket_non_empty_bucket":                       DeleteBucket_non_empty_bucket,
		"DeleteBucket_success_status_code":                    DeleteBucket_success_status_code,
		"PutObject_non_existing_bucket":                       PutObject_non_existing_bucket,
		"PutObject_special_chars":                             PutObject_special_chars,
		"PutObject_invalid_long_tags":                         PutObject_invalid_long_tags,
		"PutObject_success":                                   PutObject_success,
		"PutObject_invalid_credentials":                       PutObject_invalid_credentials,
		"HeadObject_non_existing_object":                      HeadObject_non_existing_object,
		"HeadObject_success":                                  HeadObject_success,
		"GetObject_non_existing_key":                          GetObject_non_existing_key,
		"GetObject_invalid_ranges":                            GetObject_invalid_ranges,
		"GetObject_with_meta":                                 GetObject_with_meta,
		"GetObject_success":                                   GetObject_success,
		"GetObject_by_range_success":                          GetObject_by_range_success,
		"ListObjects_non_existing_bucket":                     ListObjects_non_existing_bucket,
		"ListObjects_with_prefix":                             ListObjects_with_prefix,
		"ListObject_truncated":                                ListObject_truncated,
		"ListObjects_invalid_max_keys":                        ListObjects_invalid_max_keys,
		"ListObjects_max_keys_0":                              ListObjects_max_keys_0,
		"ListObjects_delimiter":                               ListObjects_delimiter,
		"ListObjects_max_keys_none":                           ListObjects_max_keys_none,
		"ListObjects_marker_not_from_obj_list":                ListObjects_marker_not_from_obj_list,
		"DeleteObject_non_existing_object":                    DeleteObject_non_existing_object,
		"DeleteObject_success":                                DeleteObject_success,
		"DeleteObject_success_status_code":                    DeleteObject_success_status_code,
		"DeleteObjects_empty_input":                           DeleteObjects_empty_input,
		"DeleteObjects_non_existing_objects":                  DeleteObjects_non_existing_objects,
		"DeleteObjects_success":                               DeleteObjects_success,
		"CopyObject_non_existing_dst_bucket":                  CopyObject_non_existing_dst_bucket,
		"CopyObject_not_owned_source_bucket":                  CopyObject_not_owned_source_bucket,
		"CopyObject_copy_to_itself":                           CopyObject_copy_to_itself,
		"CopyObject_to_itself_with_new_metadata":              CopyObject_to_itself_with_new_metadata,
		"CopyObject_success":                                  CopyObject_success,
		"PutObjectTagging_non_existing_object":                PutObjectTagging_non_existing_object,
		"PutObjectTagging_long_tags":                          PutObjectTagging_long_tags,
		"PutObjectTagging_success":                            PutObjectTagging_success,
		"GetObjectTagging_non_existing_object":                GetObjectTagging_non_existing_object,
		"GetObjectTagging_success":                            GetObjectTagging_success,
		"DeleteObjectTagging_non_existing_object":             DeleteObjectTagging_non_existing_object,
		"DeleteObjectTagging_success_status":                  DeleteObjectTagging_success_status,
		"DeleteObjectTagging_success":                         DeleteObjectTagging_success,
		"CreateMultipartUpload_non_existing_bucket":           CreateMultipartUpload_non_existing_bucket,
		"CreateMultipartUpload_success":                       CreateMultipartUpload_success,
		"UploadPart_non_existing_bucket":                      UploadPart_non_existing_bucket,
		"UploadPart_invalid_part_number":                      UploadPart_invalid_part_number,
		"UploadPart_non_existing_key":                         UploadPart_non_existing_key,
		"UploadPart_non_existing_mp_upload":                   UploadPart_non_existing_mp_upload,
		"UploadPart_success":                                  UploadPart_success,
		"UploadPartCopy_non_existing_bucket":                  UploadPartCopy_non_existing_bucket,
		"UploadPartCopy_incorrect_uploadId":                   UploadPartCopy_incorrect_uploadId,
		"UploadPartCopy_incorrect_object_key":                 UploadPartCopy_incorrect_object_key,
		"UploadPartCopy_invalid_part_number":                  UploadPartCopy_invalid_part_number,
		"UploadPartCopy_invalid_copy_source":                  UploadPartCopy_invalid_copy_source,
		"UploadPartCopy_non_existing_source_bucket":           UploadPartCopy_non_existing_source_bucket,
		"UploadPartCopy_non_existing_source_object_key":       UploadPartCopy_non_existing_source_object_key,
		"UploadPartCopy_success":                              UploadPartCopy_success,
		"UploadPartCopy_by_range_invalid_range":               UploadPartCopy_by_range_invalid_range,
		"UploadPartCopy_greater_range_than_obj_size":          UploadPartCopy_greater_range_than_obj_size,
		"UploadPartCopy_by_range_success":                     UploadPartCopy_by_range_success,
		"ListParts_incorrect_uploadId":                        ListParts_incorrect_uploadId,
		"ListParts_incorrect_object_key":                      ListParts_incorrect_object_key,
		"ListParts_success":                                   ListParts_success,
		"ListMultipartUploads_non_existing_bucket":            ListMultipartUploads_non_existing_bucket,
		"ListMultipartUploads_empty_result":                   ListMultipartUploads_empty_result,
		"ListMultipartUploads_invalid_max_uploads":            ListMultipartUploads_invalid_max_uploads,
		"ListMultipartUploads_max_uploads":                    ListMultipartUploads_max_uploads,
		"ListMultipartUploads_incorrect_next_key_marker":      ListMultipartUploads_incorrect_next_key_marker,
		"ListMultipartUploads_ignore_upload_id_marker":        ListMultipartUploads_ignore_upload_id_marker,
		"ListMultipartUploads_success":                        ListMultipartUploads_success,
		"AbortMultipartUpload_non_existing_bucket":            AbortMultipartUpload_non_existing_bucket,
		"AbortMultipartUpload_incorrect_uploadId":             AbortMultipartUpload_incorrect_uploadId,
		"AbortMultipartUpload_incorrect_object_key":           AbortMultipartUpload_incorrect_object_key,
		"AbortMultipartUpload_success":                        AbortMultipartUpload_success,
		"AbortMultipartUpload_success_status_code":            AbortMultipartUpload_success_status_code,
		"CompletedMultipartUpload_non_existing_bucket":        CompletedMultipartUpload_non_existing_bucket,
		"CompleteMultipartUpload_invalid_part_number":         CompleteMultipartUpload_invalid_part_number,
		"CompleteMultipartUpload_invalid_ETag":                CompleteMultipartUpload_invalid_ETag,
		"CompleteMultipartUpload_success":                     CompleteMultipartUpload_success,
		"PutBucketAcl_non_existing_bucket":                    PutBucketAcl_non_existing_bucket,
		"PutBucketAcl_invalid_acl_canned_and_acp":             PutBucketAcl_invalid_acl_canned_and_acp,
		"PutBucketAcl_invalid_acl_canned_and_grants":          PutBucketAcl_invalid_acl_canned_and_grants,
		"PutBucketAcl_invalid_acl_acp_and_grants":             PutBucketAcl_invalid_acl_acp_and_grants,
		"PutBucketAcl_invalid_owner":                          PutBucketAcl_invalid_owner,
		"PutBucketAcl_success_access_denied":                  PutBucketAcl_success_access_denied,
		"PutBucketAcl_success_grants":                         PutBucketAcl_success_grants,
		"PutBucketAcl_success_canned_acl":                     PutBucketAcl_success_canned_acl,
		"PutBucketAcl_success_acp":                            PutBucketAcl_success_acp,
		"GetBucketAcl_non_existing_bucket":                    GetBucketAcl_non_existing_bucket,
		"GetBucketAcl_access_denied":                          GetBucketAcl_access_denied,
		"GetBucketAcl_success":                                GetBucketAcl_success,
		"PutObject_overwrite_dir_obj":                         PutObject_overwrite_dir_obj,
		"PutObject_overwrite_file_obj":                        PutObject_overwrite_file_obj,
		"PutObject_dir_obj_with_data":                         PutObject_dir_obj_with_data,
		"CreateMultipartUpload_dir_obj":                       CreateMultipartUpload_dir_obj,
	}
}
