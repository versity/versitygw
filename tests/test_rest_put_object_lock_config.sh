#!/usr/bin/env bats

# Copyright 2026 Versity Software
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

source ./tests/setup.sh
source ./tests/drivers/create_bucket/create_bucket_rest.sh

@test "REST - PutObjectLockConfig - missing payload" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run put_bucket_versioning_rest "$bucket_name" "Enabled"
  assert_success

  run send_rest_go_command_expect_error "400" "MissingRequestBodyError" "Request Body is empty" \
    "-bucketName" "$bucket_name" "-method" "PUT" "-query" "object-lock=" "-contentMD5"
  assert_success
}

@test "REST - PutObjectLockConfig - zero day config, correct error code" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run put_bucket_versioning_rest "$bucket_name" "Enabled"
  assert_success

  run put_object_lock_configuration_rest_expect_error "$bucket_name" "RETENTION_MODE=GOVERNANCE RETENTION_RULE=true \
    RETENTION_DAYS=0" "400" "InvalidArgument" "Default retention period must be a positive integer value"
  assert_success
}

@test "REST - PutObjectLockConfig - default retention period works" {
  test_file="test_file"

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  run put_bucket_versioning_rest "$bucket_name" "Enabled"
  assert_success

  run put_object_lock_configuration_rest "$bucket_name" "RETENTION_MODE=GOVERNANCE RETENTION_RULE=true RETENTION_DAYS=1"
  assert_success

  run attempt_to_delete_version_after_retention_policy "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success
}
