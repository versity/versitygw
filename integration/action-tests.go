package integration

func TestCreateBucket(s *S3Conf) {
	CreateBucket_invalid_bucket_name(s)
	CreateBucket_existing_bucket(s)
	CreateDeleteBucket_success(s)
}

func TestHeadBucket(s *S3Conf) {
	HeadBucket_non_existing_bucket(s)
	HeadBucket_success(s)
}

func TestDeleteBucket(s *S3Conf) {
	DeleteBucket_non_existing_bucket(s)
	DeleteBucket_non_empty_bucket(s)
}

func TestPutObject(s *S3Conf) {
	PutObject_non_existing_bucket(s)
	PutObject_special_chars(s)
	PutObject_existing_dir_obj(s)
	PutObject_obj_parent_is_file(s)
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
}

func TestDeleteObject(s *S3Conf) {
	DeleteObject_non_existing_object(s)
	DeleteObject_success(s)
}

func TestDeleteObjects(s *S3Conf) {
	DeleteObjects_empty_input(s)
	//TODO: Uncomment this after fixing the bug: #195
	// DeleteObjects_non_existing_objects(s)
	DeleteObjects_success(s)
}

func TestCopyObject(s *S3Conf) {
	CopyObject_non_existing_dst_bucket(s)
	CopyObject_success(s)
}

func TestPutObjectTagging(s *S3Conf) {
	PutObjectTagging_non_existing_object(s)
	PutObjectTagging_success(s)
}

func TestGetObjectTagging(s *S3Conf) {
	GetObjectTagging_non_existing_object(s)
	GetObjectTagging_success(s)
}

func TestDeleteObjectTagging(s *S3Conf) {
	DeleteObjectTagging_non_existing_object(s)
	DeleteObjectTagging_success(s)
}

func TestFullFlow(s *S3Conf) {
	TestCreateBucket(s)
	TestHeadBucket(s)
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
}
