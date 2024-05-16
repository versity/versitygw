#!/usr/bin/env bats

source ./tests/test_common.sh
source ./tests/setup.sh
source ./tests/util_bucket_create.sh
source ./tests/commands/delete_bucket_policy.sh
source ./tests/commands/get_bucket_policy.sh
source ./tests/commands/put_bucket_policy.sh

export RUN_MC=true

@test "test_multipart_upload_mc" {
  test_common_multipart_upload "mc"
}

@test "test_copy_object" {
  test_common_copy_object "mc"
}

# test mc bucket creation/deletion
@test "test_create_delete_bucket" {
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
  test_common_set_get_delete_bucket_tags "mc"
}

@test "test_set_get_object_tags_mc" {
  test_common_set_get_object_tags "mc"
}

@test "test_presigned_url_utf8_chars_mc" {
  test_common_presigned_url_utf8_chars "mc"
}

@test "test_list_objects_file_count" {
  test_common_list_objects_file_count "mc"
}

@test "test_create_bucket_invalid_name_mc" {
  if [[ $RECREATE_BUCKETS != "true" ]]; then
    return
  fi

  create_bucket_invalid_name "mc" || local create_result=$?
  [[ $create_result -eq 0 ]] || fail "Invalid name test failed"

  [[ "$bucket_create_error" == *"Bucket name cannot be empty"* ]] || fail "unexpected error:  $bucket_create_error"

  delete_bucket_or_contents "mc" "$BUCKET_ONE_NAME"
}

@test "test_get_bucket_info_mc" {
  setup_bucket "mc" "$BUCKET_ONE_NAME" || local setup_result=$?
  [[ $setup_result -eq 0 ]] || fail "error setting up bucket"
  head_bucket "mc" "$BUCKET_ONE_NAME"
  [[ $bucket_info == *"$BUCKET_ONE_NAME"* ]] || fail "failure to retrieve correct bucket info: $bucket_info"
  delete_bucket_or_contents "mc" "$BUCKET_ONE_NAME"
}

@test "test_get_bucket_info_doesnt_exist_mc" {
  setup_bucket "mc" "$BUCKET_ONE_NAME" || local setup_result=$?
  [[ $setup_result -eq 0 ]] || fail "error setting up bucket"
  head_bucket "mc" "$BUCKET_ONE_NAME"a || local info_result=$?
  [[ $info_result -eq 1 ]] || fail "bucket info for non-existent bucket returned"
  [[ $bucket_info == *"does not exist"* ]] || fail "404 not returned for non-existent bucket info"
  delete_bucket_or_contents "mc" "$BUCKET_ONE_NAME"
}

@test "test_delete_object_tagging" {
  test_common_delete_object_tagging "mc"
}

@test "test_get_bucket_location" {
  test_common_get_bucket_location "mc"
}

@test "test_get_put_delete_bucket_policy" {
  test_common_get_put_delete_bucket_policy "mc"
}
