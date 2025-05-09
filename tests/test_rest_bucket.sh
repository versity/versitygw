#!/usr/bin/env bats

# Copyright 2024 Versity Software
# This file is licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

load ./bats-support/load
load ./bats-assert/load

source ./tests/commands/get_object_lock_configuration.sh
source ./tests/commands/head_bucket.sh
source ./tests/commands/list_buckets.sh
source ./tests/logger.sh
source ./tests/setup.sh
source ./tests/util/util_bucket.sh
source ./tests/util/util_list_buckets.sh
source ./tests/util/util_lock_config.sh
source ./tests/util/util_ownership.sh
source ./tests/util/util_rest.sh
source ./tests/util/util_tags.sh

@test "REST - HeadBucket" {
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run head_bucket_rest "$BUCKET_ONE_NAME"
  assert_success
}

@test "REST - HeadBucket - doesn't exist" {
  run head_bucket_rest "$BUCKET_ONE_NAME"
  assert_failure 1
}

@test "REST - bucket tagging - no tags" {
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run verify_no_bucket_tags_rest "$BUCKET_ONE_NAME"
  assert_success
}

@test "REST - bucket tagging - tags" {
  test_key="testKey"
  test_value="testValue"

  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run add_verify_bucket_tags_rest "$BUCKET_ONE_NAME" "$test_key" "$test_value"
  assert_success
}

@test "test_rest_list_buckets" {
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run list_check_buckets_rest
  assert_success
}

@test "REST - get, put bucket ownership controls" {
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run get_and_check_ownership_controls "$BUCKET_ONE_NAME" "BucketOwnerEnforced"
  assert_success

  run put_bucket_ownership_controls_rest "$BUCKET_ONE_NAME" "BucketOwnerPreferred"
  assert_success

  run get_and_check_ownership_controls "$BUCKET_ONE_NAME" "BucketOwnerPreferred"
  assert_success
}

@test "test_rest_set_get_lock_config" {
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run check_no_object_lock_config_rest "$BUCKET_ONE_NAME"
  assert_success

  run bucket_cleanup_if_bucket_exists "$BUCKET_ONE_NAME"
  assert_success

  # in static bucket config, bucket will still exist
  if ! bucket_exists "$BUCKET_ONE_NAME"; then
    run create_bucket_object_lock_enabled "$BUCKET_ONE_NAME"
    assert_success
  fi

  run check_object_lock_config_enabled_rest "$BUCKET_ONE_NAME"
  assert_success
}
