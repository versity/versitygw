#!/usr/bin/env bats

source ./tests/setup.sh
source ./tests/test_common.sh
source ./tests/util.sh

export RUN_S3CMD=true

# test s3cmd bucket creation/deletion
@test "test_create_delete_bucket_s3cmd" {
  test_common_create_delete_bucket "s3cmd"
}

# test s3cmd put object
@test "test_put_object_with_data_s3cmd" {
  test_common_put_object_with_data "s3cmd"
}

@test "test_put_object_no_data_s3cmd" {
  test_common_put_object_no_data "s3cmd"
}

# test listing buckets on versitygw
@test "test_list_buckets_s3cmd" {
  test_common_list_buckets "s3cmd"
}

@test "test_list_objects_s3cmd" {
  test_common_list_objects "s3cmd"
}

@test "test_multipart_upload_s3cmd" {
  test_common_multipart_upload "s3cmd"
}

#@test "test_presigned_url_utf8_chars_s3cmd" {
#  test_common_presigned_url_utf8_chars "s3cmd"
#}