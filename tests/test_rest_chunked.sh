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

source ./tests/logger.sh
source ./tests/setup.sh
source ./tests/drivers/file.sh
source ./tests/drivers/create_bucket/create_bucket_rest.sh
source ./tests/drivers/get_object_lock_config/get_object_lock_config_rest.sh
source ./tests/drivers/put_bucket_ownership_controls/put_bucket_ownership_controls_rest.sh
source ./tests/util/util_file.sh

@test "REST - chunked upload, no content length" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run get_file_name
  assert_success
  test_file="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  run attempt_seed_signature_without_content_length "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success
}

@test "REST - chunked upload, signature error" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run get_file_name
  assert_success
  test_file="$output"

  run create_test_file "$test_file" 8192
  assert_success

  run attempt_chunked_upload_with_bad_first_signature "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success
}

@test "REST - chunked upload, final signature error" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run get_file_name
  assert_success
  test_file="$output"

  run create_test_file "$test_file" 0
  assert_success

  run attempt_chunked_upload_with_bad_final_signature "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success
}

@test "REST - chunked upload, success (file with just a's)" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run get_file_name
  assert_success
  test_file="$output"

  run create_file_single_char "$test_file" 8192 'a'
  assert_success

  run chunked_upload_success "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success

  run download_and_compare_file "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy"
  assert_success
}

@test "REST - chunked upload, success (null bytes)" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run get_file_name
  assert_success
  test_file="$output"

  run create_file_single_char "$test_file" 8192 '\0'
  assert_success

  run chunked_upload_success "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success

  run download_and_compare_file "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy"
  assert_success
}

@test "REST - chunked upload, success (random bytes)" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run get_file_name
  assert_success
  test_file="$output"

  run create_test_file "$test_file" 10000
  assert_success

  run chunked_upload_success "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success

  run download_and_compare_file "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy"
  assert_success
}

@test "REST - chunked upload, success (zero-byte file)" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run get_file_name
  assert_success
  test_file="$output"

  run create_test_file "$test_file" 0
  assert_success

  run chunked_upload_success "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success

  run download_and_compare_file "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy"
  assert_success
}

@test "REST - chunked upload - crc32c trailer - success" {
  run chunked_upload_trailer_success "crc32c"
  assert_success
}

@test "test - REST chunked upload - sha1 trailer - success" {
  run chunked_upload_trailer_success "sha1"
  assert_success
}

@test "test - REST chunked upload - sha256 trailer - success" {
  run chunked_upload_trailer_success "sha256"
  assert_success
}

@test "test - REST chunked upload - crc64nvme trailer - success" {
  run chunked_upload_trailer_success "crc64nvme"
  assert_success
}

@test "test - REST chunked upload - crc32 trailer - success" {
  run chunked_upload_trailer_success "crc32"
  assert_success
}

@test "test - REST chunked upload - invalid trailer" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run get_file_name
  assert_success
  test_file="$output"

  run setup_bucket_and_file "$bucket_name" "$test_file"
  assert_success

  run put_chunked_upload_trailer_invalid "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success
}

@test "test - REST chunked upload - sha1 trailer - invalid" {
  run chunked_upload_trailer_invalid_checksum "sha1"
  assert_success
}

@test "test - REST chunked upload - sha256 trailer - invalid" {
  run chunked_upload_trailer_invalid_checksum "sha256"
  assert_success
}

@test "test - REST chunked upload - crc32 trailer - invalid" {
  run chunked_upload_trailer_invalid_checksum "crc32"
  assert_success
}

@test "test - REST chunked upload - crc32c trailer - invalid" {
  run chunked_upload_trailer_invalid_checksum "crc32c"
  assert_success
}

@test "test - REST chunked upload - crc64nvme trailer - invalid" {
  run chunked_upload_trailer_invalid_checksum "crc64nvme"
  assert_success
}

@test "test - REST chunked upload - sha1 trailer - incorrect" {
  run chunked_upload_trailer_incorrect_checksum "sha1"
  assert_success
}

@test "test - REST chunked upload - sha256 trailer - incorrect" {
  run chunked_upload_trailer_incorrect_checksum "sha256"
  assert_success
}

@test "test - REST chunked upload - crc32 trailer - incorrect" {
  run chunked_upload_trailer_incorrect_checksum "crc32"
  assert_success
}

@test "test - REST chunked upload - crc32c trailer - incorrect" {
  run chunked_upload_trailer_incorrect_checksum "crc32c"
  assert_success
}

@test "test - REST chunked upload - crc64nvme trailer - incorrect" {
  run chunked_upload_trailer_incorrect_checksum "crc64nvme"
  assert_success
}

@test "REST chunked upload - smaller chunk size" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket "$bucket_name"
  assert_success

  run get_file_name
  assert_success
  test_file="$output"

  run create_test_file "$test_file" 200000
  assert_success

  run chunked_upload_trailer_different_chunk_size "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file" "sha256"
  assert_success

  run download_and_compare_file "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy"
  assert_success
}

@test "REST - PutObject - STREAMING-UNSIGNED-PAYLOAD-TRAILER, x-amz-trailer of crc32, trailer missing" {
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
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run get_file_name
  assert_success
  test_file="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  run bash -c "sha256sum $TEST_FILE_FOLDER/$test_file | awk '{print $1}' | xxd -r -p | base64"
  assert_success
  checksum=${output}

  run send_openssl_go_command_check_header "200" "x-amz-checksum-sha256" "$checksum" \
    "-client" "openssl" "-commandType" "putObject" "-bucketName" "$bucket_name" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" "-checksumType" "sha256" \
    "-payloadType" "STREAMING-UNSIGNED-PAYLOAD-TRAILER" "-chunkSize" "8192" "-objectKey" "key" "-signedParams" "x-amz-trailer:x-amz-checksum-sha256"
  assert_success
}

@test "REST - PutObject - STREAMING-UNSIGNED-PAYLOAD-TRAILER - success (sha1)" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run get_file_name
  assert_success
  test_file="$output"

  run create_test_file "$test_file" 10000
  assert_success

  run bash -c "sha1sum $TEST_FILE_FOLDER/$test_file | awk '{print $1}' | xxd -r -p | base64"
  assert_success
  checksum=${output}

  run send_openssl_go_command_check_header "200" "x-amz-checksum-sha1" "$checksum" \
    "-client" "openssl" "-commandType" "putObject" "-bucketName" "$bucket_name" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" "-checksumType" "sha1" \
    "-payloadType" "STREAMING-UNSIGNED-PAYLOAD-TRAILER" "-chunkSize" "8192" "-objectKey" "key" "-signedParams" "x-amz-trailer:x-amz-checksum-sha1"
  assert_success
}

@test "REST - PutObject - STREAMING-UNSIGNED-PAYLOAD-TRAILER - success (crc32)" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run get_file_name
  assert_success
  test_file="$output"

  run create_test_file "$test_file" 10000
  assert_success

  run bash -c "gzip -c -1 $TEST_FILE_FOLDER/$test_file | tail -c8 | od -t x4 -N 4 -A n | awk '{print $1}' | xxd -r -p | base64"
  assert_success
  checksum=${output}

  run send_openssl_go_command_check_header "200" "x-amz-checksum-crc32" "$checksum" \
    "-client" "openssl" "-commandType" "putObject" "-bucketName" "$bucket_name" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" "-checksumType" "crc32" \
    "-payloadType" "STREAMING-UNSIGNED-PAYLOAD-TRAILER" "-chunkSize" "8192" "-objectKey" "key" "-signedParams" "x-amz-trailer:x-amz-checksum-crc32"
  assert_success
}

@test "REST - PutObject - STREAMING-UNSIGNED-PAYLOAD-TRAILER - success (crc32c)" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run get_file_name
  assert_success
  test_file="$output"

  run create_test_file "$test_file" 10000
  assert_success

  run bash -c "DATA_FILE=$TEST_FILE_FOLDER/$test_file CHECKSUM_TYPE=crc32c ./tests/rest_scripts/calculate_checksum.sh"
  assert_success
  checksum=$output

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

  run get_file_name
  assert_success
  test_file="$output"

  run create_test_file "$test_file" 10000
  assert_success

  run bash -c "DATA_FILE=$TEST_FILE_FOLDER/$test_file CHECKSUM_TYPE=crc64nvme ./tests/rest_scripts/calculate_checksum.sh"
  assert_success
  checksum=$output

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
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run get_file_name
  assert_success
  test_file="$output"

  run create_test_file "$test_file" 1024
  assert_success

  run send_openssl_go_command "200" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-commandType" "putObject" \
    "-payloadFile" "$TEST_FILE_FOLDER/$test_file" "-omitPayloadTrailer" \
    "-debug" "-logFile" "tagging.log" "-checksumType" "crc64nvme" \
    "-payloadType" "STREAMING-UNSIGNED-PAYLOAD-TRAILER" "-chunkSize" "8192"
  assert_success
}
