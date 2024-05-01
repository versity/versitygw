#!/usr/bin/env bats

source ./tests/test_common.sh

@test "test_multipart_upload" {
  test_common_multipart_upload "s3"
}

@test "test_put_object" {
  test_common_put_object_no_data "s3"
}

@test "test_list_buckets" {
  test_common_list_buckets "s3"
}

@test "test_list_objects_file_count" {
  test_common_list_objects_file_count "s3"
}