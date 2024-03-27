#!/usr/bin/env bats

source ./tests/test_common.sh
source ./tests/setup.sh

export RUN_MC=true

# test mc bucket creation/deletion
@test "test_create_delete_bucket_mc" {
  test_common_create_delete_bucket "mc"
}

@test "test_put_object-with-data-mc" {
  test_common_put_object_with_data "mc"
}

@test "test_put_object-no-data-mc" {
  test_common_put_object_no_data "mc"
}

@test "test_list_buckets_mc" {
  test_common_list_buckets "mc"
}

@test "test_list_objects_mc" {
  test_common_list_objects "mc"
}

@test "test_set_get_bucket_tags_mc" {
  test_common_set_get_bucket_tags "mc"
}

@test "test_set_get_object_tags_mc" {
  test_common_set_get_object_tags "mc"
}

@test "test_multipart_upload_mc" {
  test_common_multipart_upload "mc"
}

@test "test_presigned_url_utf8_chars_mc" {
  test_common_presigned_url_utf8_chars "mc"
}
