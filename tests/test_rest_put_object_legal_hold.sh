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

@test "REST - PutObjectLegalHold - missing content-md5" {
  run get_file_name
  assert_success
  test_file="$output"

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_object_lock_enabled_v2 "$bucket_name"
  assert_success

  run create_test_file "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success

  run check_legal_hold_without_content_md5 "$bucket_name" "$test_file"
  assert_success
}

@test "REST - PutObjectLegalHold w/o payload" {
  run get_file_name
  assert_success
  test_file="$output"

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_object_lock_enabled_v2 "$bucket_name"
  assert_success

  run create_test_file "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success

  run check_legal_hold_without_payload "$bucket_name" "$test_file"
  assert_success
}

@test "REST - PutObjectLegalHold - success" {
  run get_file_name
  assert_success
  test_file="$output"

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_object_lock_enabled_v2 "$bucket_name"
  assert_success

  run create_test_file "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success

  run rest_check_legal_hold "$bucket_name" "$test_file"
  assert_success
}
