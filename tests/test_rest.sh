#!/usr/bin/env bats

source ./tests/commands/list_buckets.sh
source ./tests/commands/put_object.sh
source ./tests/logger.sh
source ./tests/setup.sh
source ./tests/util.sh
source ./tests/util_rest.sh
source ./tests/util_list_buckets.sh
source ./tests/util_list_objects.sh

@test "test_rest_list_objects" {
  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  test_file="test_file"
  run create_test_files "$test_file"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run list_check_objects_rest "$BUCKET_ONE_NAME"
  assert_success
}

@test "test_authorization_list_buckets" {
  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run list_check_buckets_rest
  assert_success
}
