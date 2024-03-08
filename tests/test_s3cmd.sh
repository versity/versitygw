#!/usr/bin/env bats

source ./tests/setup.sh
source ./tests/test_common.sh
source ./tests/util.sh

# test s3cmd bucket creation/deletion
@test "test_create_delete_bucket_s3cmd" {
  test_common_create_delete_bucket "s3cmd"
}

# test s3cmd put object
@test "test_put_object_s3cmd" {
  test_common_put_object "s3cmd"
}

# test listing buckets on versitygw
@test "test_list_buckets_s3cmd" {
  test_common_list_buckets "s3cmd"
}

@test "test_list_objects_s3cmd" {
  test_common_list_objects "s3cmd"
}

@test "test_multipart_upload_s3cmd" {

  bucket_file="largefile"

  create_large_file "$bucket_file" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating test file for multipart upload"

  setup_bucket "s3cmd" "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Failed to create bucket '$BUCKET_ONE_NAME'"

  put_object "s3cmd" "$test_file_folder"/$bucket_file "$BUCKET_ONE_NAME/$bucket_file" || local put_result=$?
  [[ $put_result -eq 0 ]] || fail "failed to copy file"

  delete_bucket_or_contents "s3cmd" "$BUCKET_ONE_NAME"
  delete_test_files $bucket_file
}