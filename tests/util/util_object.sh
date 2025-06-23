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

source ./tests/util/util_bucket.sh
source ./tests/util/util_create_bucket.sh
source ./tests/util/util_head_object.sh
source ./tests/util/util_mc.sh
source ./tests/util/util_multipart.sh
source ./tests/util/util_versioning.sh
source ./tests/logger.sh
source ./tests/commands/abort_multipart_upload.sh
source ./tests/commands/complete_multipart_upload.sh
source ./tests/commands/create_multipart_upload.sh
source ./tests/commands/create_bucket.sh
source ./tests/commands/delete_bucket.sh
source ./tests/commands/delete_bucket_policy.sh
source ./tests/commands/delete_object.sh
source ./tests/commands/get_bucket_acl.sh
source ./tests/commands/get_bucket_ownership_controls.sh
source ./tests/commands/get_bucket_policy.sh
source ./tests/commands/get_object_legal_hold.sh
source ./tests/commands/get_object_lock_configuration.sh
source ./tests/commands/head_bucket.sh
source ./tests/commands/head_object.sh
source ./tests/commands/list_multipart_uploads.sh
source ./tests/commands/list_objects.sh
source ./tests/commands/list_parts.sh
source ./tests/commands/put_bucket_acl.sh
source ./tests/commands/put_bucket_ownership_controls.sh
source ./tests/commands/put_bucket_policy.sh
source ./tests/commands/put_bucket_versioning.sh
source ./tests/commands/put_object_legal_hold.sh
source ./tests/commands/put_object_lock_configuration.sh
source ./tests/commands/upload_part_copy.sh
source ./tests/commands/upload_part.sh
source ./tests/util/util_users.sh

# params: bucket, object name
# return 0 for success, 1 for error
clear_object_in_bucket() {
  log 6 "clear_object_in_bucket"
  if ! check_param_count "clear_object_in_bucket" "bucket, key" 2 $#; then
    return 1
  fi
  if ! delete_object 'rest' "$1" "$2"; then
    # shellcheck disable=SC2154
    log 2 "error deleting object $2: $delete_object_error"
    if ! check_for_and_remove_worm_protection "$1" "$2" "$delete_object_error"; then
      log 2 "error checking for and removing worm protection if needed"
      return 1
    fi
  fi
  return 0
}

# check if object exists on S3 via gateway
# param:  command, object path
# return 0 for true, 1 for false, 2 for error
object_exists() {
  log 6 "object_exists"
  if ! check_param_count "object_exists" "command type, bucket, key" 3 $#; then
    return 2
  fi
  head_object "$1" "$2" "$3" || local head_object_result=$?
  if [[ $head_object_result -eq 2 ]]; then
    log 2 "error checking if object exists"
    return 2
  fi
  # shellcheck disable=SC2086
  return $head_object_result
}

put_object_with_metadata() {
  log 6 "put_object_with_metadata"
  if ! check_param_count "put_object_with_metadata" "command type, source, destination, key, metadata key, metadata value" 6 $#; then
    return 1
  fi

  local exit_code=0
  local error
  if [[ $1 == 's3api' ]]; then
    error=$(aws --no-verify-ssl s3api put-object --body "$2" --bucket "$3" --key "$4" --metadata "{\"$5\":\"$6\"}") || exit_code=$?
  else
    log 2 "invalid command type $1"
    return 1
  fi
  log 5 "put object exit code: $exit_code"
  if [ $exit_code -ne 0 ]; then
    log 2 "error copying object to bucket: $error"
    return 1
  fi
  return 0
}

get_object_metadata() {
  log 6 "get_object_metadata"
  if ! check_param_count "get_object_metadata" "command type, bucket, key" 3 $#; then
    return 1
  fi

  local exit_code=0
  if [[ $1 == 's3api' ]]; then
    metadata_struct=$(aws --no-verify-ssl s3api head-object --bucket "$2" --key "$3") || exit_code=$?
  else
    log 2 "invalid command type $1"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    log 2 "error copying object to bucket: $error"
    return 1
  fi
  log 5 "raw metadata: $metadata_struct"
  metadata=$(echo "$metadata_struct" | jq '.Metadata')
  log 5 "metadata: $metadata"
  export metadata
  return 0
}

# add object to versitygw if it doesn't exist
# params:  source file, destination copy location
# return 0 for success or already exists, 1 for failure
check_and_put_object() {
  log 6 "check_and_put_object"
  if ! check_param_count "check_and_put_object" "source, bucket, destination" 3 $#; then
    return 1
  fi
  object_exists "s3api" "$2" "$3" || local exists_result=$?
  if [ "$exists_result" -eq 2 ]; then
    log 2 "error checking if object exists"
    return 1
  fi
  if [ "$exists_result" -eq 1 ]; then
    copy_object "$1" "$2" || local copy_result=$?
    if [ "$copy_result" -ne 0 ]; then
      log 2 "error adding object"
      return 1
    fi
  fi
  return 0
}

# check if object info (etag) is accessible
# param:  path of object
# return 0 for yes, 1 for no, 2 for error
object_is_accessible() {
  log 6 "object_is_accessible"
  if ! check_param_count "object_is_accessible" "bucket, key" 2 $#; then
    return 1
  fi
  local exit_code=0
  object_data=$(aws --no-verify-ssl s3api head-object --bucket "$1" --key "$2" 2>&1) || exit_code="$?"
  if [ $exit_code -ne 0 ]; then
    log 2 "Error obtaining object data: $object_data"
    return 2
  fi
  etag=$(echo "$object_data" | grep -v "InsecureRequestWarning" | jq '.ETag')
  if [[ "$etag" == '""' ]]; then
    return 1
  fi
  return 0
}

# copy a file to/from S3
# params:  source, destination
# return 0 for success, 1 for failure
copy_file() {
  log 6 "copy_file"
  if ! check_param_count "copy_file" "source, destination" 2 $#; then
    return 1
  fi

  local result
  error=$(aws --no-verify-ssl s3 cp "$1" "$2") || result=$?
  if [[ $result -ne 0 ]]; then
    log 2 "error copying file: $error"
    return 1
  fi
  return 0
}

list_and_check_directory_obj() {
  log 6 "list_and_check_directory_obj"
  if ! check_param_count "list_and_check_directory_obj" "client, file name" 2 $#; then
    return 1
  fi
  if ! list_objects_with_prefix "$1" "$BUCKET_ONE_NAME" "$2/"; then
    log 2 "error listing objects with prefix"
    return 1
  fi
  if [ "$1" == "s3api" ]; then
    # shellcheck disable=SC2154
    if ! key=$(echo "$objects" | grep -v "InsecureRequestWarning" | jq -r ".Contents[0].Key" 2>&1); then
      log 2 "error getting key: $key"
      return 1
    fi
    if [ "$key" != "$2/" ]; then
      log 2 "key mismatch ($key, $2)"
      return 1
    fi
  elif [ "$1" == "s3" ]; then
    log 5 "$objects"
    filename=$(echo "$objects" | grep -v "InsecureRequestWarning" | awk '{print $4}')
    if [ "$filename" != "$2" ]; then
      log 2 "filename mismatch ($filename, $2)"
      return 1
    fi
  fi
  return 0
}

check_checksum_invalid_or_incorrect() {
  log 6 "check_checksum_invalid_or_incorrect"
  if ! check_param_count "check_checksum_invalid_or_incorrect" "data file, bucket name, key, checksum type, checksum, expected error" 6 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" DATA_FILE="$1" BUCKET_NAME="$2" OBJECT_KEY="$3" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" CHECKSUM_TYPE="$4" CHECKSUM="$5" ./tests/rest_scripts/put_object.sh 2>&1); then
    log 2 "error: $result"
    return 1
  fi
  if [ "$result" != "400" ]; then
    log 2 "expected response code of '400', was '$result' (response: $(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  if ! check_xml_element "$TEST_FILE_FOLDER/result.txt" "$6" "Error" "Message"; then
    log 2 "xml error message mismatch"
    return 1
  fi
  return 0
}

put_object_rest_checksum() {
  log 6 "put_object_rest_checksum"
  if ! check_param_count "put_object_rest_checksum" "data file, bucket name, key, checksum type" 4 $#; then
    return 1
  fi
  # shellcheck disable=SC2097,SC2098
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" DATA_FILE="$1" BUCKET_NAME="$2" OBJECT_KEY="$3" TEST_FILE_FOLDER="$TEST_FILE_FOLDER" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" CHECKSUM_TYPE="$4" ./tests/rest_scripts/put_object.sh 2>&1); then
    log 2 "error: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected response code of '200', was '$result' ($(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  return 0
}

check_checksum_rest_invalid() {
  log 6 "check_checksum_rest_invalid"
  if ! check_param_count "check_checksum_rest_invalid" "checksum type" 1 $#; then
    return 1
  fi
  test_file="test_file"
  if ! setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"; then
    log 2 "error setting up bucket and file"
    return 1
  fi
  if ! check_checksum_invalid_or_incorrect "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file" "$1" "dummy" "Value for x-amz-checksum-$1 header is invalid."; then
    log 2 "error checking checksum"
    return 1
  fi
  return 0
}

check_checksum_rest_incorrect() {
  if ! check_param_count "check_checksum_rest_incorrect" "checksum type" 1 $#; then
    return 1
  fi
  test_file="test_file"
  if ! setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"; then
    log 2 "error setting up bucket and file"
    return 1
  fi
  error_cs_str="$(echo "$1" | tr '[:lower:]' '[:upper:]')"
  error_message="The $error_cs_str you specified did not match the calculated checksum."
  if ! calculate_incorrect_checksum "$1" "$(cat "$TEST_FILE_FOLDER/$test_file")"; then
    log 2 "error calculating incorrect checksum"
    return 1
  fi
  if ! check_checksum_invalid_or_incorrect "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file" "$1" "$incorrect_checksum" "$error_message"; then
    log 2 "error checking checksum"
    return 1
  fi
  return 0
}

calculate_incorrect_checksum() {
  if ! check_param_count "calculate_incorrect_checksum" "checksum type, data" 2 $#; then
    return 1
  fi
  case "$1" in
  "sha1")
    incorrect_checksum="$(echo -n "$2"a | sha1sum | awk '{print $1}' | xxd -r -p | base64)"
    ;;
  "sha256")
    incorrect_checksum="$(echo -n "$2"a | sha256sum | awk '{print $1}' | xxd -r -p | base64)"
    ;;
  "crc32")
    incorrect_checksum="$(echo -n "$2"a | gzip -c -1 | tail -c8 | od -t x4 -N 4 -A n | awk '{print $1}' | xxd -r -p | base64)"
    ;;
  "crc32c")
    if ! incorrect_checksum=$(DATA_FILE=<(echo -n "$2"a) TEST_FILE_FOLDER="$TEST_FILE_FOLDER" CHECKSUM_TYPE="crc32c" ./tests/rest_scripts/calculate_checksum.sh 2>&1); then
      log 2 "error calculating checksum: $incorrect_checksum"
      return 1
    fi
    ;;
  "crc64nvme")
    if ! incorrect_checksum=$(DATA_FILE=<(echo -n "$2"a) TEST_FILE_FOLDER="$TEST_FILE_FOLDER" CHECKSUM_TYPE="crc64nvme" ./tests/rest_scripts/calculate_checksum.sh 2>&1); then
      log 2 "error calculating checksum: $incorrect_checksum"
      return 1
    fi
    ;;
  *)
    log 2 "invalid checksum type: $1"
    return 1
  esac
  echo "$incorrect_checksum"
  return 0
}

put_object_rest_chunked_payload_type_without_content_length() {
  if ! check_param_count "put_object_rest_chunked_payload_type_without_content_length" "data file, bucket name, key" 3 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" DATA_FILE="$1" BUCKET_NAME="$2" OBJECT_KEY="$3" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" PAYLOAD="STREAMING-AWS4-HMAC-SHA256-PAYLOAD" ./tests/rest_scripts/put_object.sh 2>&1); then
    log 2 "error: $result"
    return 1
  fi
  if [ "$result" != "411" ]; then
    log 2 "expected response code of '411', was '$result' ($(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  return 0
}

add_correct_checksum() {
  if ! check_param_count "add_correct_checksum" "checksum type" 1 $#; then
    return 1
  fi
  test_file="test_file"
  if ! setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"; then
    log 2 "error setting up bucket and file"
    return 1
  fi

  if ! put_object_rest_checksum "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file" "$1"; then
    log 2 "error adding file with checksum to s3"
    return 1
  fi
  return 0
}

check_invalid_checksum_type() {
  if ! check_param_count "check_invalid_checksum_type" "data file, bucket name, file" 3 $#; then
    return 1
  fi
  error_message='The algorithm type you specified in x-amz-checksum- header is invalid.'
  if ! check_checksum_invalid_or_incorrect "$1" "$2" "$3" "sha256a" "dummy" "$error_message"; then
    log 2 "error checking checksum"
    return 1
  fi
}

put_object_rest_check_expires_header() {
  if ! check_param_count "put_object_rest_check_expires_header" "data file, bucket name, key" 3 $#; then
    return 1
  fi
  expiry_date="Tue, 11 Mar 2025 16:00:00 GMT"
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" DATA_FILE="$1" BUCKET_NAME="$2" OBJECT_KEY="$3" EXPIRES="$expiry_date" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/put_object.sh 2>&1); then
    log 2 "error: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected response code of '200', was '$result' ($(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$BUCKET_ONE_NAME" OBJECT_KEY="$test_file" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/head_object.sh 2>&1); then
    log 2 "error: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected response code of '200', was '$result' ($(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  returned_expiry_date="$(grep "Expires" "$TEST_FILE_FOLDER/result.txt" | cut -d' ' -f2- | tr -d '\r')"
  if [ "$returned_expiry_date" != "$expiry_date" ]; then
    log 2 "expected expiry date '$expiry_date', actual '$returned_expiry_date'"
    return 1
  fi
  return 0
}

download_file_with_user() {
  if ! check_param_count_gt "username, password, bucket, key, destination, chunk size (optional)" 5 $#; then
    return 1
  fi
  if ! file_size=$(get_object_size_with_user "$1" "$2" "$3" "$4" 2>&1); then
    log 2 "error getting object size: $file_size"
    return 1
  fi
  if [ "$6" != "" ]; then
    chunk_size="$6"
  elif [ "$MAX_FILE_DOWNLOAD_CHUNK_SIZE" != "" ]; then
    chunk_size="$MAX_FILE_DOWNLOAD_CHUNK_SIZE"
  else
    chunk_size="$file_size"
  fi
  if [ "$file_size" -le "$chunk_size" ]; then
    if ! get_object_rest_with_user "$1" "$2" "$3" "$4" "$5"; then
      log 2 "error downloading file"
      return 1
    fi
  else
    if ! get_object_with_ranged_download "$1" "$2" "$3" "$4" "$5" "$file_size" "$chunk_size"; then
      log 2 "error downloading object"
      return 1
    fi
  fi
  return 0
}

get_object_with_ranged_download() {
  if ! check_param_count "get_object_with_ranged_download" "username, password, bucket, key, destination, file size, chunk size" 7 $#; then
    return 1
  fi
  number_of_chunks=$(($6/$7))
  log 5 "number of chunks: $number_of_chunks"
  if ! result=$(truncate -s "$6" "$5" 2>&1); then
    log 2 "error allocating file space: $result"
    return 1
  fi

  file_byte_idx=0
  while [ $file_byte_idx -lt "$6" ]; do
    last_byte=$((file_byte_idx + $7 - 1))
    [ $last_byte -ge "$6" ] && last_byte=$(($6 - 1))
    range_value="bytes=${file_byte_idx}-${last_byte}"
    log 5 "downloading part of file, range $range_value"

    if ! result=$(AWS_ACCESS_KEY_ID="$1" AWS_SECRET_ACCESS_KEY="$2" COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$3" OBJECT_KEY="$4" RANGE="$range_value" OUTPUT_FILE="$5.tmp" ./tests/rest_scripts/get_object.sh 2>&1); then
      log 2 "error getting file data: $result"
      return 1
    fi
    if [ "$result" != "206" ]; then
      log 2 "expected '206', was '$result' ($(cat "$5.tmp"))"
      return 1
    fi
    if ! dd if="$5.tmp" of="$5" bs=1 seek="$file_byte_idx" count="$7" conv=notrunc 2>"$TEST_FILE_FOLDER/dd_error.txt"; then
      log 2 "error writing file segment: $(cat "$TEST_FILE_FOLDER/dd_error.txt")"
      return 1
    fi

    file_byte_idx=$((last_byte + 1))
  done
}

put_object_without_content_length() {
  if ! check_param_count "put_object_without_content_length" "bucket, key, data file" 3 $#; then
    return 1
  fi
  if ! result=$(BUCKET_NAME="$1" OBJECT_KEY="$2" DATA_FILE="$3" OMIT_CONTENT_LENGTH="true" COMMAND_FILE="$TEST_FILE_FOLDER/command.txt" ./tests/rest_scripts/put_object_openssl.sh 2>&1); then
    log 2 "error getting result: $result"
    return 1
  fi
  if ! send_via_openssl_and_check_code "$TEST_FILE_FOLDER/command.txt" 411; then
    log 2 "error in sending or checking response code"
    return 1
  fi
}
