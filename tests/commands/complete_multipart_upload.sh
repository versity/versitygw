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

complete_multipart_upload() {
  if [[ $# -ne 4 ]]; then
    log 2 "'complete multipart upload' command requires bucket, key, upload ID, parts list"
    return 1
  fi
  log 5 "complete multipart upload id: $3, parts: $4"
  record_command "complete-multipart-upload" "client:s3api"
  error=$(send_command aws --no-verify-ssl s3api complete-multipart-upload --bucket "$1" --key "$2" --upload-id "$3" --multipart-upload '{"Parts": '"$4"'}' 2>&1) || local completed=$?
  if [[ $completed -ne 0 ]]; then
    log 2 "error completing multipart upload: $error"
    return 1
  fi
  log 5 "complete multipart upload error: $error"
  return 0
}

complete_multipart_upload_rest() {
  if ! check_param_count_v2 "bucket, key, upload ID, parts payload" 4 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" UPLOAD_ID="$3" PARTS="$4" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/complete_multipart_upload.sh); then
    log 2 "error completing multipart upload: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "complete multipart upload returned code $result: $(cat "$TEST_FILE_FOLDER/result.txt")"
    return 1
  fi
}

complete_multipart_upload_rest_nonexistent_param() {
  if ! check_param_count_v2 "bucket, key, upload ID, parts payload" 4 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" UPLOAD_ID="$3" PARTS="$4" ALGORITHM_PARAMETER="true" CHECKSUM_ALGORITHM="crc32c" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/complete_multipart_upload.sh 2>&1); then
    log 2 "error completing multipart upload: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "complete multipart upload returned code $result: $(cat "$TEST_FILE_FOLDER/result.txt")"
    return 1
  fi
}

complete_multipart_upload_rest_incorrect_checksum() {
  if ! check_param_count_v2 "bucket, key, upload ID, parts payload, type, algorithm, correct hash" 7 $#; then
    return 1
  fi
  checksum="$7"
  if [ "${checksum:0:1}" == "a" ]; then
    checksum="b${checksum:1}"
  else
    checksum="a${checksum:1}"
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" UPLOAD_ID="$3" PARTS="$4" CHECKSUM_TYPE="$5" CHECKSUM_ALGORITHM="$6" CHECKSUM_HASH="$checksum" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/complete_multipart_upload.sh 2>&1); then
    log 2 "error completing multipart upload: $result"
    return 1
  fi
  if ! check_rest_expected_error "$result" "$TEST_FILE_FOLDER/result.txt" 400 "BadDigest" "did not match"; then
    log 2 "expected '400', was $result: $(cat "$TEST_FILE_FOLDER/result.txt")"
    return 1
  fi
}

complete_multipart_upload_rest_invalid_checksum() {
  if ! check_param_count_v2 "bucket, key, upload ID, parts payload, type, algorithm, correct hash" 7 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" UPLOAD_ID="$3" PARTS="$4" CHECKSUM_TYPE="$5" CHECKSUM_ALGORITHM="$6" CHECKSUM_HASH="$7" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/complete_multipart_upload.sh 2>&1); then
    log 2 "error completing multipart upload: $result"
    return 1
  fi
  if ! check_rest_expected_error "$result" "$TEST_FILE_FOLDER/result.txt" 400 "InvalidRequest" "header is invalid"; then
    log 2 "expected '400', was $result: $(cat "$TEST_FILE_FOLDER/result.txt")"
    return 1
  fi
}