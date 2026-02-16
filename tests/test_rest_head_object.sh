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
source ./tests/drivers/get_object_attributes/get_object_attributes_rest.sh

@test "REST - head object" {
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

  run get_etag_rest "$bucket_name" "$test_file"
  assert_success
  expected_etag=$output

  run get_etag_attribute_rest "$bucket_name" "$test_file" "$expected_etag"
  assert_success
}

@test "REST - HeadObject - default Content-Type is binary/octet-stream" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1849"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run get_file_name
  assert_success
  test_file="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  run put_object_rest "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success

  run head_object_check_header_key_and_value "$bucket_name" "$test_file" "Content-Type" "binary/octet-stream"
  assert_success
}
