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
source ./tests/drivers/create_bucket/create_bucket_rest.sh
source ./tests/util/util_time.sh

# tags: curl, PutObject, object-lock, retention, x-amz-object-lock-retain-until-date, x-amz-object-lock-mode, content-md5, invalid-header
@test "REST - PutObject - x-amz-object-lock-retain-until-date - invalid format" {
  local bucket_name test_file

  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  run send_rest_go_command_expect_error "400" "InvalidArgument" "must be provided in ISO 8601 format" "-bucketName" "$bucket_name" \
    "-objectKey" "$test_file" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-method" "PUT" "-contentMD5" "-signedParams" "x-amz-object-lock-mode:abc,x-amz-object-lock-retain-until-date:abc"
  assert_success
}

# tags: curl, PutObject, object-lock, retention, x-amz-object-lock-retain-until-date, x-amz-object-lock-mode, content-md5, invalid-header
@test "REST - PutObject - x-amz-object-lock-retain-until-date - earlier date" {
  local bucket_name test_file earlier_date

  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  earlier_date="2025-12-25T12:00:00Z"
  run send_rest_go_command_expect_error_with_arg_name_value "400" "InvalidArgument" "must be in the future" \
    "x-amz-object-lock-retain-until-date" "$earlier_date" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-method" "PUT" "-contentMD5" "-signedParams" "x-amz-object-lock-mode:abc,x-amz-object-lock-retain-until-date:$earlier_date"
  assert_success
}

# tags: curl, PutObject, object-lock, retention, x-amz-object-lock-mode, x-amz-object-lock-retain-until-date, content-md5, invalid-header
@test "REST - PutObject - x-amz-object-lock-mode - invalid mode" {
  local bucket_name test_file later_date lock_mode

  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  run get_time_seconds_in_future 10
  assert_success
  later_date=${output}Z

  lock_mode="abc"
  run send_rest_go_command_expect_error_with_arg_name_value "400" "InvalidArgument" "Unknown wormMode directive" \
    "x-amz-object-lock-mode" "$lock_mode" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-method" "PUT" "-contentMD5" "-signedParams" "x-amz-object-lock-mode:$lock_mode,x-amz-object-lock-retain-until-date:$later_date"
  assert_success
}

# tags: curl, PutObject, object-lock, retention, versioning, content-md5, invalid-header
@test "TEST - REST - PutObject - not allowed without content-MD5 with lock configuration" {
  local bucket_name test_file

  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  run put_bucket_versioning_rest "$bucket_name" "Enabled"
  assert_success

  run put_object_lock_configuration_rest "$bucket_name" "RETENTION_MODE=GOVERNANCE RETENTION_RULE=true RETENTION_DAYS=1"
  assert_success

  run send_rest_go_command_expect_error "400" "InvalidRequest" "is required for Put Object requests with Object Lock parameters" \
    "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-method" "PUT"
  assert_success
}

# tags: curl, PutObject, object-lock, retention, versioning, content-md5, x-amz-object-lock-mode, x-amz-object-lock-retain-until-date
@test "REST - PutObject - object lock - success" {
  local bucket_name test_file later_date

  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  run put_bucket_versioning_rest "$bucket_name" "Enabled"
  assert_success

  run put_object_lock_configuration_rest "$bucket_name" ""
  assert_success

  run get_time_seconds_in_future 15
  assert_success
  later_date=${output}Z

  run put_object_with_lock_mode_and_delete_latest_version "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file" "$later_date"
  assert_success
}

# tags: curl, PutObject, object-lock, legal-hold, x-amz-object-lock-legal-hold, invalid-header
@test "PutObject - x-amz-object-lock-legal-hold - invalid value" {
  local bucket_name test_file

  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  local legal_hold_value="wrong"
  run send_rest_go_command_expect_error_with_arg_name_value "400" "InvalidArgument" "Legal Hold must be either of" \
    "x-amz-object-lock-legal-hold" "$legal_hold_value" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-signedParams" "x-amz-object-lock-legal-hold:$legal_hold_value"
  assert_success
}

# tags: curl, PutObject, object-lock, legal-hold, x-amz-object-lock-legal-hold, content-md5, invalid-header
@test "PutObject - x-amz-object-lock-legal-hold - no Content-MD5" {
  local bucket_name test_file

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run get_file_name
  assert_success
  test_file=$output

  run setup_bucket_object_lock_enabled_v2 "$bucket_name"
  assert_success

  run create_test_file "$test_file"
  assert_success

  run send_rest_go_command_expect_error "400" "InvalidRequest" "Content-MD5" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" "-bucketName" "$bucket_name" \
    "-objectKey" "$test_file" "-signedParams" "x-amz-object-lock-legal-hold:ON"
  assert_success
}

# tags: curl, PutObject, object-lock, legal-hold, x-amz-object-lock-legal-hold, content-md5
@test "PutObject - x-amz-object-lock-legal-hold - success" {
  local bucket_name test_file

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run get_file_name
  assert_success
  test_file=$output

  run setup_bucket_object_lock_enabled_v2 "$bucket_name"
  assert_success

  run create_test_file "$test_file"
  assert_success

  run send_rest_go_command "200" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" "-bucketName" "$bucket_name" \
    "-objectKey" "$test_file" "-signedParams" "x-amz-object-lock-legal-hold:ON" "-contentMD5"
  assert_success

  run rest_check_legal_hold "$bucket_name" "$test_file"
  assert_success
}
