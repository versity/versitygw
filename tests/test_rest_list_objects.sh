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

@test "test_rest_list_objects" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run get_file_name
  assert_success
  test_file="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success

  run list_check_objects_rest "$bucket_name"
  assert_success
}

@test "REST - list objects v2 - invalid continuation token" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/993"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run get_file_name
  assert_success
  test_file="$output"

  run get_file_name
  assert_success
  test_file_two="$output"

  run get_file_name
  assert_success
  test_file_three="$output"

  run setup_bucket_and_files_v2 "$bucket_name" "$test_file" "$test_file_two" "$test_file_three"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file_two" "$bucket_name" "$test_file_two"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file_three" "$bucket_name" "$test_file_three"
  assert_success

  run list_objects_check_params_get_token "$bucket_name" "$test_file" "$test_file_two" "TRUE"
  assert_success
  continuation_token=$output

  # interestingly, AWS appears to accept continuation tokens that are a few characters off, so have to remove three chars
  run list_objects_check_continuation_error "$bucket_name" "${continuation_token:0:${#continuation_token}-3}"
  assert_success
}

@test "REST - ListObjectsV2 - includes bucket header" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1814"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run get_file_name
  assert_success
  test_file="$output"

  run get_file_name
  assert_success
  test_file_two="$output"

  run setup_bucket_and_add_files "$bucket_name" "$test_file" "$test_file_two"
  assert_success

  run send_rest_go_command_check_header_key_and_value "200" "x-amz-bucket-region" "$AWS_REGION" "-method" "GET" \
    "-bucketName" "$bucket_name" "-query" "list-type=2"
  assert_success
}

@test "REST - ListObjectsV2 - success" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run get_file_name
  assert_success
  test_file="$output"

  run get_file_name
  assert_success
  test_file_two="$output"

  run setup_bucket_and_add_files "$bucket_name" "$test_file" "$test_file_two"
  assert_success

  run list_check_objects_rest_v2 "$bucket_name" 2 "$test_file" "$test_file_two"
  assert_success
}

@test "REST - list objects v1 - no NextMarker without delimiter" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/999"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run get_file_name
  assert_success
  test_file="$output"

  run get_file_name
  assert_success
  test_file_two="$output"

  run setup_bucket_and_files_v2 "$bucket_name" "$test_file" "$test_file_two"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file_two" "$bucket_name" "$test_file_two"
  assert_success

  run list_objects_v1_check_nextmarker_empty "$bucket_name"
  assert_success
}

@test "REST - ListObjects - delimiter" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  local bucket_name="$output"

  file_names=("a-b-1.txt" "a-b-2.txt" "a-b/c-1.txt" "a-b/c-2.txt" "a-b/d.txt" "a/c.txt")
  local prefix="a-"
  run create_test_files_and_folders "${file_names[@]}"
  assert_success

  run setup_bucket_v2 "$bucket_name"
  assert_success

  for file_name in "${file_names[@]}"; do
    run put_object "rest" "$TEST_FILE_FOLDER/$file_name" "$bucket_name" "$file_name"
    assert_success
  done

  run list_objects_with_prefix_and_delimiter_check_results "$bucket_name" "$prefix" "/" "a-b/" "--" "a-b-1.txt" "a-b-2.txt"
  assert_success
}

@test "REST - ListObjects - invalid encoding" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1984"
  fi
  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name file_name <<< "$output"

  run send_rest_go_command "200" "-method" PUT "-bucketName" "$bucket_name" "-payloadFile" "$TEST_FILE_FOLDER/$file_name" "-objectKey" "$file_name"
  assert_success

  local bad_encoding="jdfkllaj"
  run send_rest_go_command_expect_error_with_arg_name_value "400" "InvalidArgument" "Invalid Encoding Method specified in Request" \
    "encoding-type" "$bad_encoding" "-bucketName" "$bucket_name" "-query" "encoding-type=$bad_encoding"
  assert_success
}

@test "REST - ListObjects - encoding success" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1985"
  fi
  run setup_bucket_v3 "$BUCKET_ONE_NAME"
  assert_success
  bucket_name=$output

  file_name="a+ b.txt"
  expected_encoding="a%2B+b.txt"
  run create_test_file "$file_name"
  assert_success

  payload_file="$TEST_FILE_FOLDER/$file_name"
  run send_rest_go_command "200" "-method" "PUT" "-payloadFile" "$payload_file" "-bucketName" "$bucket_name" "-objectKey" "$file_name"
  assert_success

  run list_objects_check_key "$bucket_name" "$expected_encoding" "url"
  assert_success

  run list_objects_check_key "$bucket_name" "$file_name" ""
  assert_success
}
