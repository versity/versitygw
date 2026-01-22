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
source ./tests/commands/put_object_retention.sh
source ./tests/drivers/create_bucket/create_bucket_rest.sh
source ./tests/util/util_time.sh

@test "test_rest_retention" {
  run get_file_name
  assert_success
  test_file="$output"

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_object_lock_enabled_v2 "$bucket_name"
  assert_success

  run create_test_files "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success

  run get_time_seconds_in_future 5 "%z"
  assert_success
  five_seconds_later=${output}

  log 5 "later: $five_seconds_later"
  run put_object_retention_rest "$bucket_name" "$test_file" "GOVERNANCE" "$five_seconds_later"
  assert_success
}

@test "REST - PutObjectRetention - w/o request body" {
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

  run retention_rest_without_request_body "$bucket_name" "$test_file"
  assert_success
}

