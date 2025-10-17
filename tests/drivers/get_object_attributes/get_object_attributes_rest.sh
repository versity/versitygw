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

upload_and_check_attributes() {
  if ! check_param_count_v2 "bucket, test file, file size" 3 $#; then
    return 1
  fi
  if ! perform_multipart_upload_rest "$1" "$2" "$TEST_FILE_FOLDER/$2-0" "$TEST_FILE_FOLDER/$2-1" \
      "$TEST_FILE_FOLDER/$2-2" "$TEST_FILE_FOLDER/$2-3"; then
    log 2 "error uploading and checking parts"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" ATTRIBUTES="ETag,StorageClass,ObjectParts,ObjectSize" OUTPUT_FILE="$TEST_FILE_FOLDER/attributes.txt" ./tests/rest_scripts/get_object_attributes.sh); then
    log 2 "error listing object attributes: $result"
    return 1
  fi
  if ! check_attributes_after_upload "$3"; then
    log 2 "error checking attributes after upload"
    return 1
  fi
  return 0
}

check_attributes_after_upload() {
  if [ $# -ne 1 ]; then
    log 2 "'check_attributes_after_upload' requires file size"
    return 1
  fi
  log 5 "attributes: $(cat "$TEST_FILE_FOLDER/attributes.txt")"
  if ! object_size=$(xmllint --xpath '//*[local-name()="ObjectSize"]/text()' "$TEST_FILE_FOLDER/attributes.txt" 2>&1); then
    log 2 "error getting checksum: $object_size"
    return 1
  fi
  # shellcheck disable=SC2154
  if [ "$object_size" != "$1" ]; then
    log 2 "expected file size of '$file_size', was '$object_size'"
    return 1
  fi
  if ! error=$(xmllint --xpath '//*[local-name()="StorageClass"]/text()' "$TEST_FILE_FOLDER/attributes.txt" 2>&1); then
    log 2 "error getting storage class: $error"
    return 1
  fi
  if ! etag=$(xmllint --xpath '//*[local-name()="ETag"]/text()' "$TEST_FILE_FOLDER/attributes.txt" 2>&1); then
    log 2 "error getting etag: $etag"
    return 1
  fi
  if ! [[ $etag =~ ^[a-fA-F0-9]{32}-4$ ]]; then
    log 2 "unexpected etag pattern ($etag)"
    return 1
  fi
  if ! parts_count=$(xmllint --xpath '//*[local-name()="PartsCount"]/text()' "$TEST_FILE_FOLDER/attributes.txt" 2>&1); then
    log 2 "error getting parts_count: $parts_count"
    return 1
  fi
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

get_etag_attribute_rest() {
  if [ $# -ne 3 ]; then
    log 2 "'get_etag_attribute_rest' requires bucket name, object key, expected etag"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" ATTRIBUTES="ETag" OUTPUT_FILE="$TEST_FILE_FOLDER/attributes.txt" ./tests/rest_scripts/get_object_attributes.sh); then
    log 2 "error attempting to get object info: $result"
    return 1
  fi
  log 5 "attributes: $(cat "$TEST_FILE_FOLDER/attributes.txt")"
  if ! check_xml_element "$TEST_FILE_FOLDER/attributes.txt" "$3" "GetObjectAttributesResponse" "ETag"; then
    log 2 "etag mismatch"
    return 1
  fi
  return 0
}
