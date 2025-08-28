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

source ./tests/drivers/head_object/head_object_rest.sh
source ./tests/drivers/put_object/put_object_rest.sh
source ./tests/setup.sh
source ./tests/util/util_setup.sh

test_file="test_file"
export RUN_USERS=true

@test "REST - put object w/STREAMING-AWS4-HMAC-SHA256-PAYLOAD without content length" {
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object_rest_chunked_payload_type_without_content_length "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}

@test "REST - PutObject - invalid 'Expires' parameter" {
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object_rest_check_expires_header "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}

@test "REST - PutObject with user permission - admin user" {
  if [ "$SKIP_USERS_TEST" == "true" ]; then
    skip "skipping versity-specific users tests"
  fi
  run setup_bucket_file_and_user "$BUCKET_ONE_NAME" "$test_file" "$USERNAME_ONE" "$PASSWORD_ONE" "admin"
  assert_success
  username="${lines[${#lines[@]}-2]}"
  password="${lines[${#lines[@]}-1]}"
  log 5 "username: $username, password: $password"

  run put_object_rest_with_user "$username" "$password" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}

@test "REST - PutObject with no permission - 'user' user" {
  if [ "$SKIP_USERS_TEST" == "true" ]; then
    skip "skipping versity-specific users tests"
  fi
  run setup_bucket_file_and_user "$BUCKET_ONE_NAME" "$test_file" "$USERNAME_ONE" "$PASSWORD_ONE" "user"
  assert_success
  username="${lines[${#lines[@]}-2]}"
  password="${lines[${#lines[@]}-1]}"

  run put_object_rest_with_user_and_code "$username" "$password" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file" "403"
  assert_success
}

@test "REST - put object, missing Content-Length" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1321"
  fi
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object_without_content_length "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file"
  assert_success
}

@test "REST - PutObject w/x-amz-checksum-algorithm" {
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object_rest_with_unneeded_algorithm_param "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file" "crc32c"
  assert_success
}

@test "REST - PutObject - If-None-Match - no asterisk" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/821"
  fi
  run setup_bucket_and_add_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run send_rest_go_command_expect_error "501" "NotImplemented" "not implemented" "-bucketName" "$BUCKET_ONE_NAME" "-objectKey" "$test_file" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-signedParams" "if-none-match:true"
  assert_success
}

@test "REST - PutObject - If-None-Match - block copy" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/821"
  fi
  run setup_bucket_and_add_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run send_rest_go_command_expect_error "412" "PreconditionFailed" "did not hold" "-bucketName" "$BUCKET_ONE_NAME" "-objectKey" "$test_file" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-signedParams" "if-none-match:*"
  assert_success
}

@test "REST - PutObject - If-None-Match - success" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/821"
  fi
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run create_test_files "$test_file"
  assert_success

  run send_rest_go_command "200" "-bucketName" "$BUCKET_ONE_NAME" "-objectKey" "$test_file" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-signedParams" "if-none-match:*"
  assert_success
}

@test "REST - PutObject - If-Match - file doesn't exist on server" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/821"
  fi
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run send_rest_go_command_expect_error "404" "NoSuchKey" "key does not exist" "-bucketName" "$BUCKET_ONE_NAME" "-objectKey" "$test_file" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-signedParams" "if-match:abc"
  assert_success
}

@test "REST - PutObject - If-Match - incorrect etag" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/821"
  fi
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run create_test_files "$test_file"
  assert_success

  run put_object_rest "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run send_rest_go_command_expect_error "412" "PreconditionFailed" "did not hold" "-bucketName" "$BUCKET_ONE_NAME" "-objectKey" "$test_file" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-signedParams" "if-match:abc"
  assert_success
}

@test "REST - PutObject - If-Match - correct etag" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/821"
  fi
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run create_test_files "$test_file"
  assert_success

  run put_object_rest "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run get_etag_rest "$BUCKET_ONE_NAME" "$test_file"
  assert_success
  etag=${lines[${#lines[@]}-1]}
  log 5 "etag: $etag"

  run send_rest_go_command "200" "-bucketName" "$BUCKET_ONE_NAME" "-objectKey" "$test_file" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-signedParams" "if-match:$etag"
  assert_success
}

@test "PutObject - metadata keys are made lowercase" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1482"
  fi
  uppercase_key="CAPITAL"
  uppercase_value="DUMMY"

  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run create_test_files "$test_file"
  assert_success

  run send_rest_go_command "200" "-bucketName" "$BUCKET_ONE_NAME" "-objectKey" "$test_file" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
      "-signedParams" "x-amz-meta-$uppercase_key:$uppercase_value"
  assert_success

  run check_metadata_key_case "$BUCKET_ONE_NAME" "$test_file" "$uppercase_key" "$uppercase_value"
  assert_success
}

@test "REST - PutObject - user permission, bad signature" {
  if [ "$SKIP_USERS_TESTS" == "true" ]; then
    skip
  fi
  run setup_bucket_file_and_user "$BUCKET_ONE_NAME" "$test_file" "$USERNAME_ONE" "$PASSWORD_ONE" "admin"
  assert_success
  username="${lines[${#lines[@]}-2]}"
  password="${lines[${#lines[@]}-1]}"

  run put_object_rest_user_bad_signature "$username" "$password" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}
