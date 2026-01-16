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
source ./tests/setup.sh

@test "REST - range download and compare" {
  run get_file_name
  assert_success
  test_file="$output"

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_large_file_v2 "$bucket_name" "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success

  download_chunk_size="2000000"
  run download_and_compare_file "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy" "$download_chunk_size"
  assert_success
}

@test "REST - put, get object, encoded name" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  file_name=" \"<>\\^\`{}|+&?%"
  run setup_bucket_and_file_v2 "$bucket_name" "$file_name"
  assert_success

  run put_object_rest_special_chars "$TEST_FILE_FOLDER/$file_name" "$bucket_name" "$file_name/$file_name"
  assert_success

  run list_check_single_object "$bucket_name" "$file_name/$file_name"
  assert_success

  run get_object_rest_special_chars "$bucket_name" "$file_name/$file_name" "$TEST_FILE_FOLDER/${file_name}-copy"
  assert_success

  run compare_files "$TEST_FILE_FOLDER/$file_name" "$TEST_FILE_FOLDER/${file_name}-copy"
  assert_success

  run delete_object_rest "$bucket_name" "$file_name/$file_name"
  assert_success
}

@test "REST - GetObject w/STREAMING-AWS4-HMAC-SHA256-PAYLOAD type" {
  run get_file_name
  assert_success
  test_file="$output"

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  run get_object_rest_with_invalid_streaming_type "$bucket_name" "$test_file"
  assert_success
}
