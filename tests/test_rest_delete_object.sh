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

source ./tests/drivers/create_bucket/create_bucket_rest.sh
source ./tests/util/util_delete_object.sh
source ./tests/setup.sh

@test "test_rest_delete_object" {
  run get_file_name
  assert_success
  test_file="$output"

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success

  run download_and_compare_file "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy"
  assert_success

  run delete_object "rest" "$bucket_name" "$test_file"
  assert_success

  run get_object "rest" "$bucket_name" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy"
  assert_failure
}

@test "REST - delete objects - no content-md5 header" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run delete_objects_no_content_md5_header "$bucket_name"
  assert_success
}

@test "REST - delete objects command" {
  run get_file_name
  assert_success
  test_file="$output"

  run get_file_name
  assert_success
  test_file_two="$output"

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_files_v2 "$bucket_name" "$test_file" "$test_file_two"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file_two" "$bucket_name" "$test_file_two"
  assert_success

  run verify_object_exists "$bucket_name" "$test_file"
  assert_success

  run verify_object_exists "$bucket_name" "$test_file_two"
  assert_success

  run delete_objects_verify_success "$bucket_name" "$test_file" "$test_file_two"
  assert_success

  run verify_object_not_found "$bucket_name" "$test_file"
  assert_success

  run verify_object_not_found "$bucket_name" "$test_file_two"
  assert_success
}
