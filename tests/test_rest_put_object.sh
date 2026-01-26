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
source ./tests/drivers/file.sh
source ./tests/drivers/create_bucket/create_bucket_rest.sh
source ./tests/drivers/head_object/head_object_rest.sh
source ./tests/drivers/list_object_versions/list_object_versions_rest.sh
source ./tests/drivers/put_object/put_object_rest.sh
source ./tests/util/util_public_access_block.sh
source ./tests/util/util_time.sh

test_file="test_file"
export RUN_USERS=true

@test "REST - put object w/STREAMING-AWS4-HMAC-SHA256-PAYLOAD without content length" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  run put_object_rest_chunked_payload_type_without_content_length "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success
}

@test "REST - PutObject - invalid 'Expires' parameter" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  run put_object_rest_check_expires_header "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success
}

@test "REST - PutObject with user permission - admin user" {
  if [ "$SKIP_USERS_TEST" == "true" ]; then
    skip "skipping versity-specific users tests"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_file_and_user_v2 "$bucket_name" "$test_file" "$USERNAME_ONE" "$PASSWORD_ONE" "admin"
  assert_success
  username="${lines[${#lines[@]}-2]}"
  password="${lines[${#lines[@]}-1]}"
  log 5 "username: $username, password: $password"

  run put_object_rest_with_user "$username" "$password" "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success
}

@test "REST - PutObject with no permission - 'user' user" {
  if [ "$SKIP_USERS_TEST" == "true" ]; then
    skip "skipping versity-specific users tests"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_file_and_user_v2 "$bucket_name" "$test_file" "$USERNAME_ONE" "$PASSWORD_ONE" "user"
  assert_success
  username="${lines[${#lines[@]}-2]}"
  password="${lines[${#lines[@]}-1]}"

  run put_object_rest_with_user_and_code "$username" "$password" "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file" "403"
  assert_success
}

@test "REST - put object, missing Content-Length" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1321"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  run put_object_without_content_length "$bucket_name" "$test_file" "$TEST_FILE_FOLDER/$test_file"
  assert_success
}

@test "REST - PutObject w/x-amz-checksum-algorithm" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  run put_object_rest_with_unneeded_algorithm_param "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file" "crc32c"
  assert_success
}

@test "REST - PutObject - If-None-Match - no asterisk" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_add_file "$bucket_name" "$test_file"
  assert_success

  run send_rest_go_command_expect_error "501" "NotImplemented" "not implemented" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-signedParams" "If-None-Match:true"
  assert_success
}

@test "REST - PutObject - If-None-Match - block copy" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_add_file "$bucket_name" "$test_file"
  assert_success

  run send_rest_go_command_expect_error "412" "PreconditionFailed" "did not hold" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-signedParams" "If-None-Match:*"
  assert_success
}

@test "REST - PutObject - If-None-Match - success" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  run send_rest_go_command "200" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-signedParams" "if-none-match:*"
  assert_success
}

@test "REST - PutObject - If-Match - file doesn't exist on server" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  send_rest_go_command_expect_error "404" "NoSuchKey" "key does not exist" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-signedParams" "if-match:abc"
  assert_success
}

@test "REST - PutObject - If-Match - incorrect etag" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_add_file "$bucket_name" "$test_file"
  assert_success

  run send_rest_go_command_expect_error "412" "PreconditionFailed" "did not hold" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-signedParams" "if-match:abc"
  assert_success
}

@test "REST - PutObject - If-Match - correct etag" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_add_file "$bucket_name" "$test_file"
  assert_success

  run get_etag_rest "$bucket_name" "$test_file"
  assert_success
  etag=${lines[${#lines[@]}-1]}
  log 5 "etag: $etag"

  run send_rest_go_command "200" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-signedParams" "if-match:$etag"
  assert_success
}

@test "PutObject - metadata keys are made lowercase" {
  uppercase_key="CAPITAL"
  uppercase_value="DUMMY"

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  run send_rest_go_command "200" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
      "-signedParams" "x-amz-meta-$uppercase_key:$uppercase_value"
  assert_success

  run check_metadata_key_case "$bucket_name" "$test_file" "$uppercase_key" "$uppercase_value"
  assert_success
}

@test "REST - PutObject - user permission, bad signature" {
  if [ "$SKIP_USERS_TESTS" == "true" ]; then
    skip "skipping versitygw-specific users tests"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_file_and_user_v2 "$bucket_name" "$test_file" "$USERNAME_ONE" "$PASSWORD_ONE" "admin"
  assert_success
  username="${lines[${#lines[@]}-2]}"
  password="${lines[${#lines[@]}-1]}"

  run put_object_rest_user_bad_signature "$username" "$password" "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success
}

@test "REST - PutObject - expect continue - success" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  run send_rest_go_command "200" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
        "-signedParams" "Expect:100-continue"
  assert_success
}

@test "REST - PutObject - invalid x-amz-request-payer" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run create_versitygw_acl_user_or_get_direct_user "$USERNAME_ONE" "$PASSWORD_ONE"
  assert_success
  username=${lines[2]}
  password=${lines[3]}

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  run put_bucket_ownership_controls "$bucket_name" "BucketOwnerPreferred"
  assert_success

  if [ "$DIRECT" == "true" ]; then
    run allow_public_access "$bucket_name"
    assert_success
  fi

  run put_canned_acl_rest "$bucket_name" "public-read-write"
  assert_success

  run send_rest_go_command "200" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-method" "PUT" "-contentMD5" "-awsAccessKeyId" "$username" "-awsSecretAccessKey" "$password" "-signedParams" "x-amz-request-payer:dummy"
  assert_success
}

@test "REST - PutObject - content disposition" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  run send_rest_go_command "200" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-method" "PUT" "-contentMD5" "-signedParams" "Content-Disposition:dummy"
  assert_success

  run head_object_check_header_key_and_value "$bucket_name" "$test_file" "Content-Disposition" "dummy"
  assert_success
}

@test "REST - PutObject - x-amz-object-lock-retain-until-date - invalid format" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  run send_rest_go_command_expect_error "400" "InvalidArgument" "must be provided in ISO 8601 format" "-bucketName" "$bucket_name" \
    "-objectKey" "$test_file" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-method" "PUT" "-contentMD5" "-signedParams" "x-amz-object-lock-mode:abc,x-amz-object-lock-retain-until-date:abc"
  assert_success
}

@test "REST - PutObject - x-amz-object-lock-retain-until-date - earlier date" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1734"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  earlier_date="2025-12-25T12:00:00Z"
  run send_rest_go_command_expect_error_with_arg_name_value "400" "InvalidArgument" "must be in the future" \
    "x-amz-object-lock-retain-until-date" "$earlier_date" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-method" "PUT" "-contentMD5" "-signedParams" "x-amz-object-lock-mode:abc,x-amz-object-lock-retain-until-date:$earlier_date"
  assert_success
}

@test "REST - PutObject - x-amz-object-lock-mode - invalid mode" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1736"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  run get_time_seconds_in_future 10
  assert_success
  later_date=${output}Z

  lock_mode="abc"
  run send_rest_go_command_expect_error_with_arg_name_value "400" "InvalidArgument" "Unknown wormMode directive" \
    "x-amz-object-lock-mode" "$lock_mode" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-method" "PUT" "-contentMD5" "-signedParams" "x-amz-object-lock-mode:$lock_mode,x-amz-object-lock-retain-until-date:$later_date"
  assert_success
}

@test "TEST - REST - PutObject - not allowed without content-MD5 with lock configuration" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1740"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  run put_bucket_versioning_rest "$bucket_name" "Enabled"
  assert_success

  run put_object_lock_configuration_rest "$bucket_name" "RETENTION_MODE=GOVERNANCE RETENTION_RULE=true RETENTION_DAYS=1"
  assert_success

  run send_rest_go_command_expect_error "400" "InvalidRequest" "is required for Put Object requests with Object Lock parameters" \
    "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-method" "PUT"
  assert_success
}

@test "REST - PutObject - object lock - success" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

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

@test "PutObject - x-amz-acl - not implemented" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1767"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run get_file_name
  assert_success
  test_file="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  run put_bucket_ownership_controls_rest "$bucket_name" "BucketOwnerPreferred"
  assert_success

  if [ "$DIRECT" == "true" ]; then
    run allow_public_access "$bucket_name"
    assert_success
  fi

  run send_rest_go_command_expect_error "501" "NotImplemented" "not implemented" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" "-bucketName" "$bucket_name" \
    "-objectKey" "$test_file" "-signedParams" "x-amz-acl:public-read"
  assert_success
}

@test "PutObject - x-amz-grant-full-control - not implemented" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1773"
  fi
  run attempt_put_object_with_specific_acl "x-amz-grant-full-control"
  assert_success
}

@test "PutObject - x-amz-grant-read - not implemented" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1773"
  fi
  run attempt_put_object_with_specific_acl "x-amz-grant-read"
  assert_success
}
@test "PutObject - x-amz-grant-read-acp - not implemented" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1773"
  fi
  run attempt_put_object_with_specific_acl "x-amz-grant-read-acp"
  assert_success
}

@test "PutObject - x-amz-grant-write-acp - not implemented" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1773"
  fi
  run attempt_put_object_with_specific_acl "x-amz-grant-write-acp"
  assert_success
}

@test "PutObject - x-amz-object-lock-legal-hold - invalid value" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1775"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run get_file_name
  assert_success
  test_file="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  local legal_hold_value="wrong"
  run send_rest_go_command_expect_error_with_arg_name_value "400" "InvalidArgument" "Legal Hold must be either of" \
    "x-amz-object-lock-legal-hold" "$legal_hold_value" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-signedParams" "x-amz-object-lock-legal-hold:$legal_hold_value"
  assert_success
}

@test "PutObject - x-amz-object-lock-legal-hold - no Content-MD5" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1776"
  fi
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

@test "PutObject - x-amz-object-lock-legal-hold - success" {
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
