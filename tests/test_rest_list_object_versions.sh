#!/usr/bin/env bats

# Copyright 2025 Versity Software
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
source ./tests/drivers/list_object_versions/list_object_versions_rest.sh
source ./tests/util/util_time.sh

@test "ListObjectVersions - accidental query of versions on object returns correct error" {
  test_file="test_file"

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_add_file "$bucket_name" "$test_file"
  assert_success

  run send_rest_go_command_expect_error "400" "InvalidRequest" "There is no such thing as the ?versions sub-resource for a key" \
    "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-query" "versions="
  assert_success
}

@test "ListObjectVersions - version changes after deletion w/retention policy" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1741"
  fi
  test_file="test_file"

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  run put_bucket_versioning_rest "$bucket_name" "Enabled"
  assert_success

  run put_object_lock_configuration_rest "$bucket_name" ""
  assert_success

  run get_time_seconds_in_future 30
  assert_success
  later_date=${output}Z

  run send_rest_go_command "200" \
    "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-method" "PUT" "-contentMD5" "-signedParams" "x-amz-object-lock-mode:GOVERNANCE,x-amz-object-lock-retain-until-date:$later_date"
  assert_success

  run list_object_versions_before_and_after_retention_deletion "$bucket_name" "$test_file"
  assert_success
}