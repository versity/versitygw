#!/usr/bin/env bash

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

source ./tests/drivers/rest.sh
source ./tests/drivers/openssl.sh

put_object_success_or_access_denied() {
  if ! check_param_count_v2 "username, password, data file, bucket, key, expect success" 6 $#; then
    return 1
  fi
  if [ "$6" == "true" ]; then
    if ! put_object_rest_with_user "$1" "$2" "$3" "$4" "$5"; then
      log 2 "expected PutObject to succeed, didn't"
      return 1
    fi
  else
    if ! put_object_rest_expect_error "$3" "$4" "$5" "AWS_ACCESS_KEY_ID=$1 AWS_SECRET_ACCESS_KEY=$2" "403" "AccessDenied" "Access Denied"; then
      log 2 "expected GetBucketAcl access denied"
      return 1
    fi
    if ! put_object_rest "$3" "$4" "$5"; then
      log 2 "error putting object with root account"
      return 1
    fi
  fi
  return 0
}

setup_bucket_and_add_file() {
  if ! check_param_count_v2 "bucket, filename" 2 $#; then
    return 1
  fi
  if ! setup_bucket_and_add_files "$1" "$2"; then
    log 2 "error setting up bucket and adding file"
    return 1
  fi
  return 0
}

setup_bucket_and_add_files() {
  if ! check_param_count_gt "bucket, filenames" 2 $#; then
    return 1
  fi
  if ! setup_bucket_v2 "$1"; then
    log 2 "error setting up bucket"
    return 1
  fi
  if ! create_test_files "${@:2}"; then
    log 2 "error creating test files"
    return 1
  fi
  for file in "${@:2}"; do
    if ! put_object_rest "$TEST_FILE_FOLDER/$file" "$1" "$file"; then
      log 2 "error adding file '$TEST_FILE_FOLDER/$file' to bucket '$1'"
      return 1
    fi
  done
  return 0
}

send_openssl_go_command_chunked_no_content_length() {
  if ! check_param_count_gt "bucket name, key" 2 $#; then
    return 1
  fi
  run send_openssl_go_command_expect_error "400" "IncompleteBody" "The request body terminated unexpectedly" \
      "-client" "openssl" "-commandType" "putObject" "-bucketName" "$1" "-payload" "abcdefg" "-omitContentLength" \
      "-payloadType" "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" "-chunkSize" "8192" "-objectKey" "$2"
    assert_success
}

put_bucket_object_run_command() {
  if ! check_param_count_gt "bucket, key, expected success val, params" 3 $#; then
    return 1
  fi
  if ! setup_bucket_and_add_file "$1" "$2"; then
    log 2 "error setting up bucket and adding file"
    return 1
  fi
  if ! send_rest_go_command "$3" "-bucketName" "$1" "-objectKey" "$2" "${@:4}"; then
    log 2 "error sending go command"
    return 1
  fi
  return 0
}

put_bucket_object_run_command_expect_error() {
  if ! check_param_count_gt "bucket, key, expected response code, error code, message, params" 5 $#; then
    return 1
  fi
  if ! setup_bucket_and_add_file "$1" "$2"; then
    log 2 "error setting up bucket and adding file"
    return 1
  fi
  if ! send_rest_go_command_expect_error "$3" "$4" "$5" "-bucketName" "$1" "-objectKey" "$2" "${@:6}"; then
    log 2 "error sending go command and parsing error"
    return 1
  fi
  return 0
}

attempt_seed_signature_without_content_length() {
  if ! check_param_count_v2 "bucket, key, data file" 3 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" \
         AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
         AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
         AWS_ENDPOINT_URL="$AWS_ENDPOINT_URL" \
         DATA_FILE="$1" \
         BUCKET_NAME="$2" \
         OBJECT_KEY="$3" CHUNK_SIZE=8192 TEST_MODE=false COMMAND_FILE="$TEST_FILE_FOLDER/command.txt" NO_CONTENT_LENGTH="true" ./tests/rest_scripts/put_object_openssl_chunked_example.sh 2>&1); then
    log 2 "error creating command: $result"
    return 1
  fi
  if ! send_via_openssl_and_check_code "$TEST_FILE_FOLDER/command.txt" 411; then
    log 2 "error in sending or checking response code"
    return 1
  fi
  return 0
}

attempt_chunked_upload_with_bad_first_signature() {
  if ! check_param_count_v2 "data file, bucket name, key" 3 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" \
         AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
         AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
         AWS_ENDPOINT_URL="$AWS_ENDPOINT_URL" \
         DATA_FILE="$1" \
         BUCKET_NAME="$2" \
         OBJECT_KEY="$3" CHUNK_SIZE=8192 TEST_MODE=false COMMAND_FILE="$TEST_FILE_FOLDER/command.txt" FIRST_SIGNATURE="xxxxxxxx" ./tests/rest_scripts/put_object_openssl_chunked_example.sh 2>&1); then
    log 2 "error creating command: $result"
    return 1
  fi

  if ! result=$(send_via_openssl "$TEST_FILE_FOLDER/command.txt"); then
    log 2 "error sending command via openssl"
    return 1
  fi
  log 5 "result: $result"
  echo -n "$result" > "$TEST_FILE_FOLDER/result.txt"
  if ! get_xml_data "$TEST_FILE_FOLDER/result.txt" "$TEST_FILE_FOLDER/error_data.txt"; then
    log 2 "error parsing XML data from result"
    return 1
  fi
  response_code="$(echo "$result" | grep "HTTP" | awk '{print $2}')"
  if ! check_rest_expected_error "$response_code" "$TEST_FILE_FOLDER/error_data.txt" "403" "SignatureDoesNotMatch" "does not match"; then
    log 2 "error checking expected REST error"
    return 1
  fi
  return 0
}

chunked_upload_success() {
  if ! check_param_count_v2 "data file, bucket name, key" 3 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" \
         AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
         AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
         AWS_ENDPOINT_URL="$AWS_ENDPOINT_URL" \
         DATA_FILE="$1" \
         BUCKET_NAME="$2" \
         OBJECT_KEY="$3" CHUNK_SIZE=8192 TEST_MODE=false COMMAND_FILE="$TEST_FILE_FOLDER/command.txt" ./tests/rest_scripts/put_object_openssl_chunked_example.sh 2>&1); then
    log 2 "error creating command: $result"
    return 1
  fi

  if ! send_via_openssl_and_check_code "$TEST_FILE_FOLDER/command.txt" 200; then
    log 2 "error sending command via openssl or checking response code"
    return 1
  fi
  return 0
}

attempt_chunked_upload_with_bad_final_signature() {
  if ! check_param_count_v2 "data file, bucket name, key" 3 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" \
         AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
         AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
         AWS_ENDPOINT_URL="$AWS_ENDPOINT_URL" \
         DATA_FILE="$1" \
         BUCKET_NAME="$2" \
         OBJECT_KEY="$3" \
         CHUNK_SIZE=8192 \
         TEST_MODE=false \
         COMMAND_FILE="$TEST_FILE_FOLDER/command.txt" \
         FINAL_SIGNATURE="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" ./tests/rest_scripts/put_object_openssl_chunked_example.sh 2>&1); then
    log 2 "error creating command: $result"
    return 1
  fi
  if ! result=$(send_via_openssl "$TEST_FILE_FOLDER/command.txt"); then
    log 2 "error sending command via openssl"
    return 1
  fi
  log 5 "response: $result"
  echo -n "$result" > "$TEST_FILE_FOLDER/result.txt"
  if ! get_xml_data "$TEST_FILE_FOLDER/result.txt" "$TEST_FILE_FOLDER/error_data.txt"; then
    log 2 "error parsing XML data from result"
    return 1
  fi
  log 5 "xml data: $(cat "$TEST_FILE_FOLDER/error_data.txt")"
  response_code="$(echo "$result" | grep "HTTP" | awk '{print $2}')"
  if ! check_rest_expected_error "$response_code" "$TEST_FILE_FOLDER/error_data.txt" "403" "SignatureDoesNotMatch" "does not match"; then
    log 2 "error checking expected REST error"
    return 1
  fi
  return 0
}

put_object_chunked_trailer_success() {
  if ! check_param_count_v2 "data file, bucket name, key, checksum type" 4 $#; then
    return 1
  fi
  # shellcheck disable=SC2097,SC2098
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" \
           AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
           AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
           AWS_ENDPOINT_URL="$AWS_ENDPOINT_URL" \
           DATA_FILE="$1" \
           BUCKET_NAME="$2" \
           OBJECT_KEY="$3" CHUNK_SIZE=8192 TEST_MODE=false TRAILER="x-amz-checksum-$4" TEST_FILE_FOLDER="$TEST_FILE_FOLDER" COMMAND_FILE="$TEST_FILE_FOLDER/command.txt" ./tests/rest_scripts/put_object_openssl_chunked_trailer_example.sh 2>&1); then
    log 2 "error creating command: $result"
    return 1
  fi

  if ! send_via_openssl_and_check_code "$TEST_FILE_FOLDER/command.txt" 200; then
    log 2 "error sending command via openssl or checking response code"
    return 1
  fi
  return 0
}

put_chunked_upload_trailer_invalid() {
  if ! check_param_count_v2 "data file, bucket name, key" 3 $#; then
    return 1
  fi
  # shellcheck disable=SC2097,SC2098
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" \
         AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
         AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
         AWS_ENDPOINT_URL="$AWS_ENDPOINT_URL" \
         DATA_FILE="$1" \
         BUCKET_NAME="$2" \
         OBJECT_KEY="$3" CHUNK_SIZE=8192 TEST_MODE=false \
         TRAILER="x-amz-checksum-sha10" \
         INVALID_CHECKSUM_TYPE="true" CHECKSUM="abc" \
         TEST_FILE_FOLDER="$TEST_FILE_FOLDER" COMMAND_FILE="$TEST_FILE_FOLDER/command.txt" ./tests/rest_scripts/put_object_openssl_chunked_trailer_example.sh 2>&1); then
    log 2 "error creating command: $result"
    return 1
  fi

  if ! result=$(send_via_openssl "$TEST_FILE_FOLDER/command.txt"); then
    log 2 "error sending command via openssl"
    return 1
  fi
  response_code="$(echo "$result" | grep "HTTP" | awk '{print $2}')"
  if [ "$response_code" != "400" ]; then
    log 2 "expected response '400', was '$response_code'"
    return 1
  fi
  error_data="$(echo "$result" | grep "<Error>" | sed 's/---//g')"
  echo -n "$error_data" > "$TEST_FILE_FOLDER/error-data.txt"
  if ! check_xml_error_contains "$TEST_FILE_FOLDER/error-data.txt" "InvalidRequest" "The value specified in the x-amz-trailer header is not supported"; then
    log 2 "error checking xml error, message"
    return 1
  fi
  return 0
}

chunked_upload_trailer_invalid_checksum() {
  if ! check_param_count_v2 "checksum" 1 $#; then
    return 1
  fi
  if ! bucket_name=$(get_bucket_name "$BUCKET_ONE_NAME" 2>&1); then
    log 2 "error getting bucket name: $bucket_name"
    return 1
  fi
  if ! setup_bucket "$bucket_name"; then
    log 2 "error setting up bucket"
    return 1
  fi
  test_file="test-file"
  if ! create_test_file "$test_file" 10000; then
    log 2 "error creating test file"
    return 1
  fi
  # shellcheck disable=SC2097,SC2098
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" \
         AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
         AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
         AWS_ENDPOINT_URL="$AWS_ENDPOINT_URL" \
         DATA_FILE="$TEST_FILE_FOLDER/$test_file" \
         BUCKET_NAME="$bucket_name" \
         OBJECT_KEY="$test_file" CHUNK_SIZE=8192 TEST_MODE=false TRAILER="x-amz-checksum-$1" CHECKSUM="a" TEST_FILE_FOLDER="$TEST_FILE_FOLDER" COMMAND_FILE="$TEST_FILE_FOLDER/command.txt" ./tests/rest_scripts/put_object_openssl_chunked_trailer_example.sh 2>&1); then
    log 2 "error creating command: $result"
    return 1
  fi
  if ! send_via_openssl_check_code_error_contains "$TEST_FILE_FOLDER/command.txt" "400" "InvalidRequest" "Value for x-amz-checksum-$1 trailing header is invalid."; then
    log 2 "error sending openssl and checking response"
    return 1
  fi
  return 0
}

chunked_upload_trailer_incorrect_checksum() {
  if ! check_param_count_v2 "checksum" 1 $#; then
    return 1
  fi
  if ! bucket_name=$(get_bucket_name "$BUCKET_ONE_NAME" 2>&1); then
    log 2 "error getting bucket name: $bucket_name"
    return 1
  fi
  if ! setup_bucket "$bucket_name"; then
    log 2 "error setting up bucket"
    return 1
  fi
  test_file="test-file"
  if ! create_test_file "$test_file" 10000; then
    log 2 "error creating test file"
    return 1
  fi
  if ! checksum=$(calculate_incorrect_checksum "$1" "$TEST_FILE_FOLDER/$test_file"); then
    log 2 "error calculating incorrect checksum"
    return 1
  fi
  # shellcheck disable=SC2097,SC2098
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" \
         AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
         AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
         AWS_ENDPOINT_URL="$AWS_ENDPOINT_URL" \
         DATA_FILE="$TEST_FILE_FOLDER/$test_file" \
         BUCKET_NAME="$bucket_name" \
         OBJECT_KEY="$test_file" CHUNK_SIZE=8192 TEST_MODE=false TRAILER="x-amz-checksum-$1" CHECKSUM="$checksum" TEST_FILE_FOLDER="$TEST_FILE_FOLDER" COMMAND_FILE="$TEST_FILE_FOLDER/command.txt" ./tests/rest_scripts/put_object_openssl_chunked_trailer_example.sh 2>&1); then
    log 2 "error creating command: $result"
    return 1
  fi
  uppercase_type="$(echo "$1" | tr '[:lower:]' '[:upper:]')"
  if ! send_via_openssl_check_code_error_contains "$TEST_FILE_FOLDER/command.txt" "400" "BadDigest" "The $uppercase_type you specified did not match the calculated checksum."; then
    log 2 "error sending openssl and checking response"
    return 1
  fi
  return 0
}

chunked_upload_trailer_different_chunk_size() {
  if ! check_param_count_v2 "data file, bucket, key, checksum type" 4 $#; then
    return 1
  fi
  # shellcheck disable=SC2097,SC2098
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" \
           AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
           AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
           AWS_ENDPOINT_URL="$AWS_ENDPOINT_URL" \
           DATA_FILE="$1" \
           BUCKET_NAME="$2" \
           OBJECT_KEY="$3" CHUNK_SIZE=16384 TEST_MODE=false TRAILER="x-amz-checksum-$4" TEST_FILE_FOLDER="$TEST_FILE_FOLDER" COMMAND_FILE="$TEST_FILE_FOLDER/command.txt" ./tests/rest_scripts/put_object_openssl_chunked_trailer_example.sh 2>&1); then
    log 2 "error creating command: $result"
    return 1
  fi

  if ! send_via_openssl_and_check_code "$TEST_FILE_FOLDER/command.txt" 200; then
    log 2 "error sending command via openssl or checking response code"
    return 1
  fi
  return 0
}

setup_bucket_versioning_file_two_versions() {
  if ! check_param_count_v2 "bucket, key" 2 $#; then
    return 1
  fi
  if ! setup_bucket_and_file_v2 "$1" "$2"; then
    log 2 "error setting up bucket"
    return 1
  fi
  if ! put_bucket_versioning_rest "$1" "Enabled"; then
    log 2 "error enabling bucket versioning"
    return 1
  fi
  if ! put_object "rest" "$TEST_FILE_FOLDER/$2" "$1" "$2"; then
    log 2 "error putting object"
    return 1
  fi
  if ! put_object "rest" "$TEST_FILE_FOLDER/$2" "$1" "$2"; then
    log 2 "error putting object second time"
    return 1
  fi
  return 0
}

attempt_put_object_with_specific_acl() {
  if ! check_param_count_v2 "acl header" 1 $#; then
    return 1
  fi
  if ! bucket_name=$(get_bucket_name "$BUCKET_ONE_NAME" 2>&1); then
    log 2 "error getting bucket name: $bucket_name"
    return 1
  fi

  if ! test_file=$(get_file_name 2>&1); then
    log 2 "error retrieving file name: $test_file"
    return 1
  fi

  if ! setup_bucket_and_file_v2 "$bucket_name" "$test_file"; then
    log 2 "error setting up bucket and file"
    return 1
  fi

  if ! put_bucket_ownership_controls_rest "$bucket_name" "BucketOwnerPreferred"; then
    log 2 "error changing bucket ownership controls"
    return 1
  fi

  if [ "$DIRECT" == "true" ]; then
    if ! allow_public_access "$bucket_name"; then
      log 2 "error allowing public access"
      return 1
    fi
    id="id=$ACL_AWS_CANONICAL_ID"
  else
    id="$AWS_ACCESS_KEY_ID"
  fi

  if ! send_rest_go_command_expect_error "501" "NotImplemented" "not implemented" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" "-bucketName" "$bucket_name" \
    "-objectKey" "$test_file" "-signedParams" "$1:$id"; then
    log 2 "error sending put object command with header '$1' and checking response"
    return 1
  fi
  return 0
}
