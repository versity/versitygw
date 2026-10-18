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

source ./tests/drivers/complete_multipart_upload/complete_multipart_upload_rest.sh

upload_and_check_attributes() {
  if ! check_param_count_v2 "bucket, test file, file size, parts one to four" 7 $#; then
    return 1
  fi
  local bucket="$1" test_file="$2" file_size="$3" part_one="$4" part_two="$5" part_three="$6" part_four="$7"
  local result attributes_file

  if ! perform_multipart_upload_rest "$bucket" "$test_file" "$part_one" "$part_two" "$part_three" "$part_four"; then
    log 2 "error uploading and checking parts"
    return 1
  fi
  if ! result=$(get_file_name 2>&1); then
    log 2 "error getting file name: $result"
    return 1
  fi
  attributes_file="$result"

  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$bucket" OBJECT_KEY="$test_file" ATTRIBUTES="ETag,StorageClass,ObjectParts,ObjectSize" OUTPUT_FILE="$TEST_FILE_FOLDER/$attributes_file" ./tests/rest_scripts/get_object_attributes.sh 2>&1); then
    log 2 "error listing object attributes: $result"
    return 1
  fi
  if ! check_attributes_after_upload "$TEST_FILE_FOLDER/$attributes_file" "$file_size"; then
    log 2 "error checking attributes after upload"
    return 1
  fi
  return 0
}

check_attributes_after_upload() {
  if ! check_param_count_v2 "data file, expected file size" 2 $#; then
    return 1
  fi
  local data_file="$1" expected_size="$2"
  local response object_size etag parts_count

  log 5 "attributes: $(cat "$data_file")"
  if ! response=$(xmllint --xpath '//*[local-name()="ObjectSize"]/text()' "$data_file" 2>&1); then
    log 2 "error getting checksum: $response"
    return 1
  fi
  object_size="$response"

  # shellcheck disable=SC2154
  if [ "$object_size" != "$expected_size" ]; then
    log 2 "expected file size of '$expected_size', was '$object_size'"
    return 1
  fi
  if ! response=$(xmllint --xpath '//*[local-name()="StorageClass"]/text()' "$data_file" 2>&1); then
    log 2 "error getting storage class: $response"
    return 1
  fi

  if ! response=$(xmllint --xpath '//*[local-name()="ETag"]/text()' "$data_file" 2>&1); then
    log 2 "error getting etag: $response"
    return 1
  fi
  etag="$response"
  if ! [[ $etag =~ ^[a-fA-F0-9]{32}-4$ ]]; then
    log 2 "unexpected etag pattern ($etag)"
    return 1
  fi

  if ! response=$(xmllint --xpath '//*[local-name()="PartsCount"]/text()' "$data_file" 2>&1); then
    log 2 "error getting parts_count: $response"
    return 1
  fi
  parts_count="$response"
  if [[ $parts_count != 4 ]]; then
    log 2 "unexpected parts count, expected 4, was $parts_count"
    return 1
  fi
  return 0
}

check_attributes_invalid_param() {
  if ! check_param_count_v2 "bucket name, test file" 2 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" ATTRIBUTES="ETags" OUTPUT_FILE="$TEST_FILE_FOLDER/attributes.txt" ./tests/rest_scripts/get_object_attributes.sh); then
    log 2 "error listing object attributes: $result"
    return 1
  fi
  if [ "$result" != "400" ]; then
    log 2 "expected response code of '400', was '$result'"
    return 1
  fi
  log 5 "attributes: $(cat "$TEST_FILE_FOLDER/attributes.txt")"
  if ! code=$(xmllint --xpath '//*[local-name()="Code"]/text()' "$TEST_FILE_FOLDER/attributes.txt" 2>&1); then
    log 2 "error getting code: $code"
    return 1
  fi
  if [ "$code" != "InvalidArgument" ]; then
    log 2 "expected 'InvalidArgument', was '$code'"
    return 1
  fi
}

add_and_check_checksum() {
  if ! check_param_count_v2 "data file, bucket, key" 3 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" DATA_FILE="$1" BUCKET_NAME="$2" OBJECT_KEY="$3" CHECKSUM_TYPE="sha256" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/put_object.sh); then
    log 2 "error sending object file: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected response code of '200', was '$result' (output: $(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$2" OBJECT_KEY="$3" ATTRIBUTES="Checksum" OUTPUT_FILE="$TEST_FILE_FOLDER/attributes.txt" ./tests/rest_scripts/get_object_attributes.sh); then
    log 2 "error listing object attributes: $result (output: $(cat "$TEST_FILE_FOLDER/attributes.txt")"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected response code of '200', was '$result' ($(cat "$TEST_FILE_FOLDER/attributes.txt"))"
    return 1
  fi
  log 5 "attributes: $(cat "$TEST_FILE_FOLDER/attributes.txt")"
  if ! checksum=$(xmllint --xpath '//*[local-name()="ChecksumSHA256"]/text()' "$TEST_FILE_FOLDER/attributes.txt" 2>&1); then
    log 2 "error getting checksum: $checksum"
    return 1
  fi
  if [ "$checksum" == "" ]; then
    log 2 "empty checksum"
    return 1
  fi
}

check_etag_attribute_rest() {
  if ! check_param_count_v2 "bucket name, object key, expected etag" 3 $#; then
    return 1
  fi
  if ! response=$(get_file_name 2>&1); then
    log 2 "error getting file name: $response"
    return 1
  fi
  file_name="$response"

  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" ATTRIBUTES="ETag" OUTPUT_FILE="$TEST_FILE_FOLDER/$file_name" ./tests/rest_scripts/get_object_attributes.sh); then
    log 2 "error attempting to get object info: $result"
    return 1
  fi
  log 5 "attributes: $(cat "$TEST_FILE_FOLDER/$file_name")"
  if ! check_xml_element "$TEST_FILE_FOLDER/$file_name" "$3" "GetObjectAttributesResponse" "ETag"; then
    log 2 "etag mismatch"
    return 1
  fi
  return 0
}
