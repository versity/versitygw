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

source ./tests/commands/list_buckets.sh
source ./tests/drivers/list_buckets/list_buckets_rest.sh
source ./tests/logger.sh
source ./tests/setup.sh

@test "REST - empty message" {
  test_file="test_file"
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1249"
  fi
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  echo -en "\r\n" > "$TEST_FILE_FOLDER/empty.txt"
  run send_via_openssl_with_timeout "$TEST_FILE_FOLDER/empty.txt"
  assert_success
}

@test "REST - deformed message" {
  test_file="test_file"
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1364"
  fi
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  echo -en "abcdefg\r\n\r\n" > "$TEST_FILE_FOLDER/deformed.txt"
  run send_via_openssl_check_code_error_contains "$TEST_FILE_FOLDER/deformed.txt" 400 "BadRequest" "An error occurred when parsing the HTTP request."
  assert_success
}

@test "test_rest_list_buckets" {
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run list_check_buckets_rest "$BUCKET_ONE_NAME"
  assert_success
}

@test "REST - list buckets - continuation token isn't bucket name" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1399"
  fi
  run setup_buckets "$BUCKET_ONE_NAME" "$BUCKET_TWO_NAME"
  assert_success

  run check_continuation_token
  assert_success
}

@test "REST - list buckets - success (multiple pages)" {
  run setup_buckets "$BUCKET_ONE_NAME" "$BUCKET_TWO_NAME"
  assert_success

  run check_for_buckets_with_multiple_pages "$BUCKET_ONE_NAME" "$BUCKET_TWO_NAME"
  assert_success
}

@test "REST - list buckets w/prefix" {
  run setup_buckets "$BUCKET_ONE_NAME" "$BUCKET_TWO_NAME"
  assert_success

  run list_check_buckets_rest "$BUCKET_ONE_NAME" "$BUCKET_TWO_NAME"
  assert_success

  run list_check_buckets_rest_with_prefix "$BUCKET_ONE_NAME"
  assert_success

  run list_check_buckets_rest_with_prefix "$BUCKET_TWO_NAME"
  assert_success
}
