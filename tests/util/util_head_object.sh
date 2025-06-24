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

get_and_verify_metadata() {
  if [ $# -ne 7 ]; then
    log 2 "'get_and_verify_metadata' requires bucket file, expected content type,
     expected metadata key, expected metadata val, expected hold status, expected retention mode, expected retention date"
    return 1
  fi
  if ! head_object "s3api" "$BUCKET_ONE_NAME" "$1"; then
    log 2 "error retrieving metadata"
    return 1
  fi
  # shellcheck disable=SC2154
  raw_metadata=$(echo "$metadata" | grep -v "InsecureRequestWarning")
  log 5 "raw metadata: $raw_metadata"

  if ! content_type=$(echo "$raw_metadata" | jq -r ".ContentType" 2>&1); then
    log 2 "error retrieving content type: $content_type"
    return 1
  fi
  if [[ $content_type != "$2" ]]; then
    log 2 "content type mismatch ($content_type, $2)"
    return 1
  fi
  if ! meta_val=$(echo "$raw_metadata" | jq -r ".Metadata.$3" 2>&1); then
    log 2 "error retrieving metadata val: $meta_val"
    return 1
  fi
  if [[ $meta_val != "$4" ]]; then
    log 2 "metadata val mismatch ($meta_val, $4)"
    return 1
  fi
  if ! hold_status=$(echo "$raw_metadata" | jq -r ".ObjectLockLegalHoldStatus" 2>&1); then
    log 2 "error retrieving hold status: $hold_status"
    return 1
  fi
  if [[ $hold_status != "$5" ]]; then
    log 2 "hold status mismatch ($hold_status, $5)"
    return 1
  fi
  if ! retention_mode=$(echo "$raw_metadata" | jq -r ".ObjectLockMode" 2>&1); then
    log 2 "error retrieving retention mode: $retention_mode"
    return 1
  fi
  if [[ $retention_mode != "$6" ]]; then
    log 2 "retention mode mismatch ($retention_mode, $6)"
    return 1
  fi
  if ! retain_until_date=$(echo "$raw_metadata" | jq -r ".ObjectLockRetainUntilDate" 2>&1); then
    log 2 "error retrieving retain until date: $retain_until_date"
    return 1
  fi
  if [[ $retain_until_date != "$7"* ]]; then
    log 2"retention date mismatch ($retain_until_date, $7)"
    return 1
  fi
  return 0
}

get_etag_rest() {
  if [ $# -ne 2 ]; then
    log 2 "'get_etag_rest' requires bucket name, object key"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" OUTPUT_FILE="$TEST_FILE_FOLDER/head_object.txt" ./tests/rest_scripts/head_object.sh); then
    log 2 "error attempting to get object info: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "response code '$result', data: $(cat "$TEST_FILE_FOLDER/head_object.txt")"
    return 1
  fi
  log 5 "head object data: $(cat "$TEST_FILE_FOLDER/head_object.txt")"
  etag_value=$(grep "E[Tt]ag:" "$TEST_FILE_FOLDER/head_object.txt" | sed -n 's/E[Tt]ag: "\([^"]*\)"/\1/p' | tr -d '\r')
  echo "$etag_value"
}

verify_object_not_found() {
  if [ $# -ne 2 ]; then
    log 2 "'verify_object_not_found' requires bucket name, object key"
    return 1
  fi
  if ! result=$(OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" ./tests/rest_scripts/head_object.sh); then
    log 2 "error getting result: $result"
    return 1
  fi
  if [ "$result" != "404" ]; then
    log 2 "expected '404', was '$result' ($(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  return 0
}

verify_object_exists() {
  if [ $# -ne 2 ]; then
    log 2 "'verify_object_not_found' requires bucket name, object key"
    return 1
  fi
  if ! result=$(OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" ./tests/rest_scripts/head_object.sh); then
    log 2 "error getting result: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected '200', was '$result' ($(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  return 0
}

check_checksum_rest() {
  if [ $# -ne 4 ]; then
    log 2 "'check_checksum_rest' requires bucket, file, expected checksum, header key"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" CHECKSUM="true" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/head_object.sh 2>&1); then
    log 2 "error: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected response code '200', was '$result'"
    return 1
  fi
  head_checksum=$(grep -i "$4" "$TEST_FILE_FOLDER/result.txt" | awk '{print $2}' | sed 's/\r$//')
  if [ "$3" != "$head_checksum" ]; then
    log 2 "'checksum mismatch (head '$head_checksum', local '$file_checksum')"
    return 1
  fi
}

check_checksum_rest_sha256() {
  if [ $# -ne 3 ]; then
    log 2 "'check_checksum_rest_sha256' requires bucket, file, local file"
    return 1
  fi
  file_checksum="$(sha256sum "$3" | awk '{print $1}' | xxd -r -p | base64)"
  if ! check_checksum_rest "$1" "$2" "$file_checksum" "x-amz-checksum-sha256"; then
    log 2 "error checking checksum"
    return 1
  fi
  return 0
}

check_checksum_rest_crc32() {
  if [ $# -ne 3 ]; then
    log 2 "'check_checksum_rest_crc32' requires bucket, file, local file"
    return 1
  fi
  file_checksum="$(gzip -c -1 "$3" | tail -c8 | od -t x4 -N 4 -A n | awk '{print $1}' | xxd -r -p | base64)"
  if ! check_checksum_rest "$1" "$2" "$file_checksum" "x-amz-checksum-crc32"; then
    log 2 "error checking checksum"
    return 1
  fi
  return 0
}

head_object_without_and_with_checksum() {
  if [ $# -ne 2 ]; then
    log 2 "'head_object_without_checksum' requires bucket, file"
    return 1
  fi
  if ! result=$(OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" ./tests/rest_scripts/head_object.sh); then
    log 2 "error getting result: $result"
    return 1
  fi
  head_checksum=$(grep -i "x-amz-checksum-sha256" "$TEST_FILE_FOLDER/result.txt" | awk '{print $2}' | sed 's/\r$//')
  if [ "$head_checksum" != "" ]; then
    log 2 "head checksum shouldn't be returned, is $head_checksum"
    return 1
  fi
  if ! result=$(OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" CHECKSUM="true" ./tests/rest_scripts/head_object.sh); then
    log 2 "error getting result: $result"
    return 1
  fi
  head_checksum=$(grep -i "x-amz-checksum-sha256" "$TEST_FILE_FOLDER/result.txt" | awk '{print $2}' | sed 's/\r$//')
  if [ "$head_checksum" == "" ]; then
    log 2 "head checksum should be returned"
    return 1
  fi
  return 0
}

check_default_checksum() {
  if [ $# -ne 3 ]; then
    log 2 "'head_object_without_checksum' requires bucket, file, local file"
    return 1
  fi
  if ! result=$(OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" ./tests/rest_scripts/head_object.sh); then
    log 2 "error getting result: $result"
    return 1
  fi
  if ! result=$(OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" CHECKSUM="true" ./tests/rest_scripts/head_object.sh); then
    log 2 "error getting result: $result"
    return 1
  fi
  log 5 "result: $(cat "$TEST_FILE_FOLDER/result.txt")"
  head_checksum=$(grep -i "x-amz-checksum-crc64nvme" "$TEST_FILE_FOLDER/result.txt" | awk '{print $2}' | sed 's/\r$//')
  log 5 "checksum: $head_checksum"
  if ! checksum=$(CHECKSUM_TYPE="crc64nvme" DATA_FILE="$3" TEST_FILE_FOLDER="$TEST_FILE_FOLDER" ./tests/rest_scripts/calculate_checksum.sh); then
    log 2 "error calculating local checksum: $checksum"
    return 1
  fi
  if [ "$head_checksum" != "$checksum" ]; then
    log 2 "checksum mismatch (returned:  '$head_checksum', local:  '$checksum')"
    return 1
  fi
  return 0
}

get_object_size_with_user() {
  if ! check_param_count "get_object_size_with_user" "username, password, bucket, key" 4 $#; then
    return 1
  fi
  if ! result=$(AWS_ACCESS_KEY_ID="$1" AWS_SECRET_ACCESS_KEY="$2" COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$3" OBJECT_KEY="$4" OUTPUT_FILE="$TEST_FILE_FOLDER/head_object.txt" ./tests/rest_scripts/head_object.sh 2>&1); then
    log 2 "error attempting to get object info: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "response code '$result', data: $(cat "$TEST_FILE_FOLDER/head_object.txt")"
    return 1
  fi
  log 5 "head object data: $(cat "$TEST_FILE_FOLDER/head_object.txt")"
  content_length=$(grep "Content-Length:" "$TEST_FILE_FOLDER/head_object.txt" | awk '{print $2}' | tr -d '\r')
  log 5 "file size: $content_length"
  echo "$content_length"
}
