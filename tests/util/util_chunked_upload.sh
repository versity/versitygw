#!/usr/bin/env bash

source ./tests/drivers/rest.sh
source ./tests/drivers/openssl.sh

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
  if [ $# -ne 3 ]; then
    log 2 "'attempt_chunked_upload_with_bad_first_signature' requires data file, bucket name, key"
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
  response_code="$(echo "$result" | grep "HTTP" | awk '{print $2}')"
  log 5 "response code: $response_code"
  if [ "$response_code" != "403" ]; then
    log 2 "expected code '403', was '$response_code'"
    return 1
  fi
  log 5 "result: $result"
  response_data="$(echo "$result" | grep "<Error>")"
  response_data="${response_data/---/}"
  log 5 "response data: $response_data"
  log 5 "END"
  echo -n "$response_data" > "$TEST_FILE_FOLDER/response_data.txt"
  if ! check_xml_element "$TEST_FILE_FOLDER/response_data.txt" "SignatureDoesNotMatch" "Error" "Code"; then
    log 2 "error checking XML element"
    return 1
  fi
  return 0
}

chunked_upload_success() {
  if [ $# -ne 3 ]; then
    log 2 "'chunked_upload_success_as' requires data file, bucket name, key"
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
  if [ $# -ne 3 ]; then
    log 2 "'attempt_chunked_upload_with_bad_first_signature' requires data file, bucket name, key"
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
  if [ $# -ne 4 ]; then
    log 2 "'put_object_chunked_trailer_success' requires data file, bucket, key, checksum type"
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
  if [ $# -ne 3 ]; then
    log 2 "'put_object_chunked_trailer_success' requires data file, bucket, key"
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

chunked_upload_trailer_success() {
  if [ $# -ne 1 ]; then
    log 2 "'chunked_upload_trailer_success' requires checksum"
    return 1
  fi
  if ! setup_bucket "$BUCKET_ONE_NAME"; then
    log 2 "error setting up bucket"
    return 1
  fi
  test_file="test-file"
  if ! create_test_file "$test_file" 10000; then
    log 2 "error creating test file"
    return 1
  fi
  if ! put_object_chunked_trailer_success "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file" "$1"; then
    log 2 "error performing chunked upload w/trailer"
    return 1
  fi
  if ! download_and_compare_file "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy"; then
    log 2 "error downloading and comparing file"
    return 1
  fi
  return 0
}

chunked_upload_trailer_invalid_checksum() {
  if [ "$#" -ne 1 ]; then
    log 2 "'chunked_upload_trailer_invalid_checksum' requires checksum"
    return 1
  fi
  if ! setup_bucket "$BUCKET_ONE_NAME"; then
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
         BUCKET_NAME="$BUCKET_ONE_NAME" \
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
  if [ "$#" -ne 1 ]; then
    log 2 "'chunked_upload_trailer_invalid_checksum' requires checksum"
    return 1
  fi
  if ! setup_bucket "$BUCKET_ONE_NAME"; then
    log 2 "error setting up bucket"
    return 1
  fi
  test_file="test-file"
  if ! create_test_file "$test_file" 10000; then
    log 2 "error creating test file"
    return 1
  fi
  if ! checksum=$(calculate_incorrect_checksum "$1" "$test_file"); then
    log 2 "error calculating incorrect checksum"
    return 1
  fi
  # shellcheck disable=SC2097,SC2098
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" \
         AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
         AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
         AWS_ENDPOINT_URL="$AWS_ENDPOINT_URL" \
         DATA_FILE="$TEST_FILE_FOLDER/$test_file" \
         BUCKET_NAME="$BUCKET_ONE_NAME" \
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
