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
source ./tests/drivers/put_object/put_object_rest.sh

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
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/821"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_add_file "$bucket_name" "$test_file"
  assert_success

  run send_rest_go_command_expect_error "501" "NotImplemented" "not implemented" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-signedParams" "if-none-match:true"
  assert_success
}

@test "REST - PutObject - If-None-Match - block copy" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/821"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_add_file "$bucket_name" "$test_file"
  assert_success

  run send_rest_go_command_expect_error "412" "PreconditionFailed" "did not hold" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-signedParams" "if-none-match:*"
  assert_success
}

@test "REST - PutObject - If-None-Match - success" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/821"
  fi
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
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/821"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run send_rest_go_command_expect_error "404" "NoSuchKey" "key does not exist" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-signedParams" "if-match:abc"
  assert_success
}

@test "REST - PutObject - If-Match - incorrect etag" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/821"
  fi
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
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/821"
  fi
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
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1482"
  fi
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
    skip
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
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1517"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  run send_rest_go_command "200" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
        "-signedParams" "Expect:100-continue" "-debug" "-logFile" "tagging.log"
  assert_success
}

@test "REST - PutObject - STREAMING-UNSIGNED-PAYLOAD-TRAILER, x-amz-trailer of crc32, trailer missing" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1600"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run send_openssl_go_command_expect_error "400" "MalformedTrailerError" "The request contained trailing data that was not well-formed" \
    "-client" "openssl" "-commandType" "putObject" "-bucketName" "$bucket_name" "-payload" "abcdefg" \
    "-omitPayloadTrailer" "-checksumType" "crc32" \
    "-payloadType" "STREAMING-UNSIGNED-PAYLOAD-TRAILER" "-chunkSize" "8192" "-objectKey" "key" "-signedParams" "x-amz-trailer:x-amz-checksum-crc32"
  assert_success
}

@test "REST - PutObject - STREAMING-UNSIGNED-PAYLOAD-TRAILER - 200 header returns correct checksum type" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1607"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  checksum="$(sha256sum "$TEST_FILE_FOLDER/$test_file" | awk '{print $1}' | xxd -r -p | base64)"

  run send_openssl_go_command_check_header "200" "x-amz-checksum-sha256" "$checksum" \
    "-client" "openssl" "-commandType" "putObject" "-bucketName" "$bucket_name" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" "-checksumType" "sha256" \
    "-payloadType" "STREAMING-UNSIGNED-PAYLOAD-TRAILER" "-chunkSize" "8192" "-objectKey" "key" "-signedParams" "x-amz-trailer:x-amz-checksum-sha256"
  assert_success
}

@test "REST - PutObject - STREAMING-UNSIGNED-PAYLOAD-TRAILER - success (sha1)" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1607"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run create_test_file "$test_file" 10000
  assert_success

  checksum="$(sha1sum "$TEST_FILE_FOLDER/$test_file" | awk '{print $1}' | xxd -r -p | base64)"

  run send_openssl_go_command_check_header "200" "x-amz-checksum-sha1" "$checksum" \
    "-client" "openssl" "-commandType" "putObject" "-bucketName" "$bucket_name" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" "-checksumType" "sha1" \
    "-payloadType" "STREAMING-UNSIGNED-PAYLOAD-TRAILER" "-chunkSize" "8192" "-objectKey" "key" "-signedParams" "x-amz-trailer:x-amz-checksum-sha1"
  assert_success
}

@test "REST - PutObject - STREAMING-UNSIGNED-PAYLOAD-TRAILER - success (crc32)" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1607"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run create_test_file "$test_file" 10000
  assert_success

  checksum="$(gzip -c -1 "$TEST_FILE_FOLDER/$test_file" | tail -c8 | od -t x4 -N 4 -A n | awk '{print $1}' | xxd -r -p | base64)"

  run send_openssl_go_command_check_header "200" "x-amz-checksum-crc32" "$checksum" \
    "-client" "openssl" "-commandType" "putObject" "-bucketName" "$bucket_name" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" "-checksumType" "crc32" \
    "-payloadType" "STREAMING-UNSIGNED-PAYLOAD-TRAILER" "-chunkSize" "8192" "-objectKey" "key" "-signedParams" "x-amz-trailer:x-amz-checksum-crc32"
  assert_success
}

@test "REST - PutObject - STREAMING-UNSIGNED-PAYLOAD-TRAILER - success (crc32c)" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1607"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run create_test_file "$test_file" 10000
  assert_success

  if ! checksum=$(DATA_FILE="$TEST_FILE_FOLDER/$test_file" CHECKSUM_TYPE="crc32c" ./tests/rest_scripts/calculate_checksum.sh 2>&1); then
    log 2 "error calculating checksum: $checksum"
    return 1
  fi

  run send_openssl_go_command_check_header "200" "x-amz-checksum-crc32c" "$checksum" \
    "-client" "openssl" "-commandType" "putObject" "-bucketName" "$bucket_name" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" "-checksumType" "crc32c" \
    "-payloadType" "STREAMING-UNSIGNED-PAYLOAD-TRAILER" "-chunkSize" "8192" "-objectKey" "key" "-checksumType" "crc32c" "-signedParams" "x-amz-trailer:x-amz-checksum-crc32c"
  assert_success
}

@test "REST - PutObject - STREAMING-UNSIGNED-PAYLOAD-TRAILER - success (crc64nvme)" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run create_test_file "$test_file" 10000
  assert_success

  if ! checksum=$(DATA_FILE="$TEST_FILE_FOLDER/$test_file" CHECKSUM_TYPE="crc64nvme" ./tests/rest_scripts/calculate_checksum.sh 2>&1); then
    log 2 "error calculating checksum: $checksum"
    return 1
  fi

  run send_openssl_go_command_check_header "200" "x-amz-checksum-crc64nvme" "$checksum" \
    "-client" "openssl" "-commandType" "putObject" "-bucketName" "$bucket_name" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" "-checksumType" "crc64nvme" \
    "-payloadType" "STREAMING-UNSIGNED-PAYLOAD-TRAILER" "-chunkSize" "8192" "-objectKey" "key" "-signedParams" "x-amz-trailer:x-amz-checksum-crc64nvme"
  assert_success
}

@test "REST - PutObject - STREAMING-AWS4-HMAC-SHA256-PAYLOAD - missing content length" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1623"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run send_openssl_go_command_chunked_no_content_length "$bucket_name" "key"
  assert_success
}

@test "REST - PutObject - STREAMING-UNSIGNED-PAYLOAD-TRAILER, x-amz-trailer of crc32, trailer key missing" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1626"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run send_openssl_go_command_expect_error "400" "MalformedTrailerError" "The request contained trailing data that was not well-formed" \
    "-client" "openssl" "-commandType" "putObject" "-bucketName" "$bucket_name" "-objectKey" "key" "-payload" "abcdefg" "-checksumType" "crc32c" \
    "-omitPayloadTrailerKey" \
    "-payloadType" "STREAMING-UNSIGNED-PAYLOAD-TRAILER" "-chunkSize" "8192" "-objectKey" "key" "-signedParams" "x-amz-trailer:x-amz-checksum-crc32"
  assert_success
}

@test "REST - PutObject - STREAMING-UNSIGNED-PAYLOAD-TRAILER - default crc64nvme" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1632"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  run send_openssl_go_command "200" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-commandType" "putObject" \
    "-payloadFile" "$TEST_FILE_FOLDER/$test_file" "-omitPayloadTrailer" \
    "-debug" "-logFile" "tagging.log" "-checksumType" "crc64nvme" \
    "-payloadType" "STREAMING-UNSIGNED-PAYLOAD-TRAILER" "-chunkSize" "8192"
  assert_success
}
