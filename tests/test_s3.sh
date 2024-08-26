#!/usr/bin/env bats

source ./tests/test_common.sh

# complete-multipart-upload
@test "test_complete_multipart_upload" {
  test_common_multipart_upload "s3"
}

# copy-object
@test "test_copy_object" {
  test_common_copy_object "s3"
}

# create-bucket
@test "test_create_delete_bucket" {
  test_common_create_delete_bucket "s3"
}

# delete-bucket - test_create_delete_bucket

# delete-object - test_put_object

# delete-objects - tested with recursive bucket delete

# get-object
@test "test_copy_get_object" {
  test_common_put_get_object "s3"
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

@test "test_delete_bucket" {
  if [[ $RECREATE_BUCKETS == "false" ]]; then
    skip "will not test bucket deletion in static bucket test config"
  fi
  setup_bucket "s3" "$BUCKET_ONE_NAME"
  delete_bucket "s3" "$BUCKET_ONE_NAME" || fail "error deleting bucket"
}
