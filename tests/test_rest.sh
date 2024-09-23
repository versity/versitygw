#!/usr/bin/env bats

source ./tests/commands/delete_object_tagging.sh
source ./tests/commands/get_bucket_versioning.sh
source ./tests/commands/get_object.sh
source ./tests/commands/get_object_lock_configuration.sh
source ./tests/commands/get_object_retention.sh
source ./tests/commands/list_buckets.sh
source ./tests/commands/list_object_versions.sh
source ./tests/commands/put_bucket_versioning.sh
source ./tests/commands/put_object.sh
source ./tests/commands/put_object_retention.sh
source ./tests/commands/put_object_tagging.sh
source ./tests/logger.sh
source ./tests/setup.sh
source ./tests/util.sh
source ./tests/util_list_buckets.sh
source ./tests/util_list_objects.sh
source ./tests/util_lock_config.sh
source ./tests/util_rest.sh
source ./tests/util_tags.sh
source ./tests/util_time.sh
source ./tests/util_versioning.sh

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

@test "test_rest_list_buckets" {
  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run list_check_buckets_rest
  assert_success
}

@test "test_rest_delete_object" {
  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  test_file="test_file"
  run create_test_files "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run get_object "rest" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy"
  assert_success

  run compare_files "$TEST_FILE_FOLDER/$test_file" "$TEST_FILE_FOLDER/$test_file-copy"
  assert_success

  run delete_object "rest" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run get_object "rest" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy"
  assert_failure
}

@test "test_rest_tagging" {
  test_file="test_file"
  test_key="TestKey"
  test_value="TestValue"

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run create_test_files "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object_tagging "rest" "$BUCKET_ONE_NAME" "$test_file" "$test_key" "$test_value"
  assert_success

  run check_verify_object_tags "rest" "$BUCKET_ONE_NAME" "$test_file" "$test_key" "$test_value"
  assert_success

  run delete_object_tagging "rest" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run verify_no_object_tags "rest" "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}

@test "test_rest_retention" {
  test_file="test_file"
  test_key="TestKey"
  test_value="TestValue"

  run delete_bucket_or_contents_if_exists "s3api" "$BUCKET_ONE_NAME"
  assert_success
  # in static bucket config, bucket will still exist
  if ! bucket_exists "s3api" "$BUCKET_ONE_NAME"; then
    run create_bucket_object_lock_enabled "$BUCKET_ONE_NAME"
    assert_success
  fi

  run create_test_files "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  if ! five_seconds_later=$(get_time_seconds_in_future 5 "%z"); then
    log 2 "error getting future time"
    return 1
  fi
  log 5 "later: $five_seconds_later"
  run put_object_retention_rest "$BUCKET_ONE_NAME" "$test_file" "GOVERNANCE" "$five_seconds_later"
  assert_success
}

@test "test_rest_set_get_versioning" {
  skip "https://github.com/versity/versitygw/issues/866"

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  log 5 "get versioning"

  run check_versioning_status_rest "$BUCKET_ONE_NAME" ""
  assert_success

  run put_bucket_versioning_rest "$BUCKET_ONE_NAME" "Enabled"
  assert_success

  run check_versioning_status_rest "$BUCKET_ONE_NAME" "Enabled"
  assert_success

  run put_bucket_versioning_rest "$BUCKET_ONE_NAME" "Suspended"
  assert_success

  run check_versioning_status_rest "$BUCKET_ONE_NAME" "Suspended"
  assert_success
}

@test "test_rest_set_get_lock_config" {
  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run check_no_object_lock_config_rest "$BUCKET_ONE_NAME"
  assert_success

  run delete_bucket_or_contents_if_exists "s3api" "$BUCKET_ONE_NAME"
  assert_success

  # in static bucket config, bucket will still exist
  if ! bucket_exists "s3api" "$BUCKET_ONE_NAME"; then
    run create_bucket_object_lock_enabled "$BUCKET_ONE_NAME"
    assert_success
  fi

  run check_object_lock_config_enabled_rest "$BUCKET_ONE_NAME"
  assert_success
}

@test "test_rest_versioning" {
  skip "https://github.com/versity/versitygw/issues/864"
  test_file="test_file"

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  if [ "$DIRECT" == "true" ]; then
    sleep 10
  fi

  run create_test_file "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run get_and_check_versions_rest "$BUCKET_ONE_NAME" "$test_file" "1" "true" "true"
  assert_success

  run put_bucket_versioning "s3api" "$BUCKET_ONE_NAME" "Enabled"
  assert_success

  run get_and_check_versions_rest "$BUCKET_ONE_NAME" "$test_file" "1" "true" "true"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run get_and_check_versions_rest "$BUCKET_ONE_NAME" "$test_file" "2" "true" "false" "false" "true"
  assert_success
}
