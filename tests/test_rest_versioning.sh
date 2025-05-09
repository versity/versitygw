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

source ./tests/setup.sh
source ./tests/commands/get_object.sh
source ./tests/commands/put_object.sh
source ./tests/util/util_rest.sh
source ./tests/util/util_setup.sh

test_file="test_file"

@test "REST - check, enable, suspend versioning" {
  run setup_bucket "$BUCKET_ONE_NAME"
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

@test "test_rest_versioning" {
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
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

@test "versioning - add version, then delete and check for marker" {
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_bucket_versioning "s3api" "$BUCKET_ONE_NAME" "Enabled"
  assert_success

  run delete_object_rest "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run check_versions_after_file_deletion "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}

@test "versioning - retrieve after delete" {
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_bucket_versioning "s3api" "$BUCKET_ONE_NAME" "Enabled"
  assert_success

  run delete_object "s3api" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run get_object "s3api" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy"
  assert_failure
}
