#!/usr/bin/env bats

source ./tests/setup.sh
source ./tests/test_common.sh
source ./tests/util.sh
source ./tests/util_bucket_create.sh
source ./tests/util_users.sh
source ./tests/commands/delete_bucket_policy.sh
source ./tests/commands/get_bucket_policy.sh
source ./tests/commands/put_bucket_policy.sh

export RUN_S3CMD=true

@test "test_complete_multipart_upload" {
  test_common_multipart_upload "s3cmd"
}

# test s3cmd put object
@test "test_copy_object_with_data" {
  test_common_put_object_with_data "s3cmd"
}

@test "test_copy_object_no_data" {
  test_common_put_object_no_data "s3cmd"
}

# test s3cmd bucket creation/deletion
@test "test_create_delete_bucket" {
  test_common_create_delete_bucket "s3cmd"
}

#@test "test_put_bucket_acl" {
#  test_common_put_bucket_acl "s3cmd"
#}

# test listing buckets on versitygw
@test "test_list_buckets_s3cmd" {
  test_common_list_buckets "s3cmd"
}

@test "test_list_objects_s3cmd" {
  test_common_list_objects "s3cmd"
}

#@test "test_presigned_url_utf8_chars_s3cmd" {
#  test_common_presigned_url_utf8_chars "s3cmd"
#}

@test "test_list_objects_file_count" {
  test_common_list_objects_file_count "s3cmd"
}

@test "test_create_bucket_invalid_name_s3cmd" {
  if [[ $RECREATE_BUCKETS != "true" ]]; then
    return
  fi

  create_bucket_invalid_name "s3cmd" || local create_result=$?
  [[ $create_result -eq 0 ]] || fail "Invalid name test failed"

  [[ "$bucket_create_error" == *"just the bucket name"* ]] || fail "unexpected error:  $bucket_create_error"

  delete_bucket_or_contents "s3cmd" "$BUCKET_ONE_NAME"
}

@test "test_get_bucket_info_s3cmd" {
  setup_bucket "s3cmd" "$BUCKET_ONE_NAME" || local setup_result=$?
  [[ $setup_result -eq 0 ]] || fail "error setting up bucket"
  head_bucket "s3cmd" "$BUCKET_ONE_NAME"
  [[ $bucket_info == *"s3://$BUCKET_ONE_NAME"* ]] || fail "failure to retrieve correct bucket info: $bucket_info"
  delete_bucket_or_contents "s3cmd" "$BUCKET_ONE_NAME"
}

@test "test_get_bucket_info_doesnt_exist_s3cmd" {
  setup_bucket "s3cmd" "$BUCKET_ONE_NAME" || local setup_result=$?
  [[ $setup_result -eq 0 ]] || fail "error setting up bucket"
  head_bucket "s3cmd" "$BUCKET_ONE_NAME"a || local info_result=$?
  [[ $info_result -eq 1 ]] || fail "bucket info for non-existent bucket returned"
  [[ $bucket_info == *"404"* ]] || fail "404 not returned for non-existent bucket info"
  delete_bucket_or_contents "s3cmd" "$BUCKET_ONE_NAME"
}

@test "test_get_bucket_location" {
  test_common_get_bucket_location "s3cmd"
}

@test "test_get_put_delete_bucket_policy" {
  test_common_get_put_delete_bucket_policy "s3cmd"
}
