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

calculate_multipart_checksum() {
  if ! check_param_count_gt "checksum type, part count, data file, checksums" 4 $#; then
    return 1
  fi
  log 5 "checksums: ${*:4}"
  if [ "$1" == "COMPOSITE" ]; then
    if ! calculate_composite_checksum "$lowercase_checksum_algorithm" ${@:4}; then
      log 2 "error calculating checksum"
      return 1
    fi
    checksum="$composite-$2"
    return 0
  fi

  if [ "$1" != "FULL_OBJECT" ]; then
    log 2 "unrecognized checksum type: $1"
    return 1
  fi
  if ! checksum=$(DATA_FILE="$3" CHECKSUM_TYPE="$lowercase_checksum_algorithm" TEST_FILE_FOLDER="$TEST_FILE_FOLDER" ./tests/rest_scripts/calculate_checksum.sh 2>&1); then
    log 2 "error calculating checksum: $checksum"
    return 1
  fi
  return 0
}

complete_multipart_upload_with_checksum() {
  if ! check_param_count_v2 "bucket, key, file, upload ID, part count, checksum type, checksum algorithm" 7 $#; then
    return 1
  fi
  lowercase_checksum_algorithm=$(echo -n "$7" | tr '[:upper:]' '[:lower:]')
  if ! upload_parts_rest_with_checksum_before_completion "$1" "$2" "$3" "$4" "$5" "$lowercase_checksum_algorithm"; then
    log 2 "error uploading parts"
    return 1
  fi
  log 5 "parts payload: $parts_payload"
  log 5 "checksums: ${checksums[*]}"
  if ! calculate_multipart_checksum "$6" "$5" "$3" ${checksums[@]}; then
    log 2 "error calculating multipart checksum"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" UPLOAD_ID="$4" PARTS="$parts_payload" CHECKSUM_TYPE="$6" CHECKSUM_ALGORITHM="$7" CHECKSUM_HASH="$checksum" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/complete_multipart_upload.sh); then
    log 2 "error completing multipart upload"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected '200', was '$result' ($(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  log 5 "result: $(cat "$TEST_FILE_FOLDER/result.txt")"
  return 0
}

calculate_composite_checksum() {
  if ! check_param_count_gt "algorithm, at least two checksums" 3 $#; then
    return 1
  fi
  if ! result=$(truncate -s 0 "$TEST_FILE_FOLDER/all_checksums.bin" 2>&1); then
    log 2 "error truncating file: $result"
    return 1
  fi
  log 5 "checksums: ${*:2}"
  for checksum in ${@:2}; do
    if ! binary_checksum=$(echo -n "$checksum" | base64 -d 2>&1); then
      log 2 "error calculating binary checksum: $binary_checksum"
      return 1
    fi
    log 5 "binary checksum: $binary_checksum"
    printf "%s" "$binary_checksum" | cat >> "$TEST_FILE_FOLDER/all_checksums.bin"
  done
  if [ "$1" == "sha256" ]; then
    composite=$(openssl dgst -sha256 -binary "$TEST_FILE_FOLDER/all_checksums.bin" | base64)
  elif [ "$1" == "sha1" ]; then
    composite=$(openssl dgst -sha1 -binary "$TEST_FILE_FOLDER/all_checksums.bin" | base64)
  elif [ "$1" == "crc32" ]; then
    composite="$(gzip -c -1 "$TEST_FILE_FOLDER/all_checksums.bin" | tail -c8 | od -t x4 -N 4 -A n | awk '{print $1}' | xxd -r -p | base64)"
  elif [ "$1" == "crc32c" ]; then
    if ! composite=$(CHECKSUM_TYPE="$1" DATA_FILE="$TEST_FILE_FOLDER/all_checksums.bin" TEST_FILE_FOLDER="$TEST_FILE_FOLDER" ./tests/rest_scripts/calculate_checksum.sh 2>&1); then
      log 2 "error calculating crc32c checksum: $composite"
      return 1
    fi
  fi
  log 5 "composite: $composite"
}

test_multipart_upload_with_checksum() {
  if ! check_param_count_v2 "bucket, filename, checksum type, algorithm" 4 $#; then
    return 1
  fi
  if ! perform_full_multipart_upload_with_checksum_before_completion "$1" "$2" "$3" "$4"; then
    log 2 "error performing multipart upload with checksum before completion"
    return 1
  fi
  if ! calculate_multipart_checksum "$3" 2 "$TEST_FILE_FOLDER/$2" ${checksums[@]}; then
    log 2 "error calculating multipart checksum"
    return 1
  fi
  if ! complete_multipart_upload_with_checksum "$1" "$2" "$TEST_FILE_FOLDER/$2" "$upload_id" 2 "$3" "$4"; then
    log 2 "error completing multipart upload"
    return 1
  fi
  return 0
}

test_complete_multipart_upload_unneeded_algorithm_parameter() {
  if ! check_param_count_v2 "bucket, filename, checksum type, algorithm" 4 $#; then
    return 1
  fi
  if ! perform_full_multipart_upload_with_checksum_before_completion "$1" "$2" "$3" "$4"; then
    log 2 "error performing multipart upload with checksum before completion"
    return 1
  fi
  if ! complete_multipart_upload_rest_nonexistent_param "$1" "$2" "$upload_id" "$parts_payload"; then
    log 2 "error completing multipart upload with nonexistent param"
    return 1
  fi
  return 0
}

test_complete_multipart_upload_incorrect_checksum() {
  if ! check_param_count_v2 "bucket, filename, checksum type, algorithm" 4 $#; then
    return 1
  fi
  if ! perform_full_multipart_upload_with_checksum_before_completion "$1" "$2" "$3" "$4"; then
    log 2 "error performing multipart upload with checksum before completion"
    return 1
  fi
  if ! calculate_multipart_checksum "$3" 2 "$TEST_FILE_FOLDER/$2" ${checksums[@]}; then
    log 2 "error calculating multipart checksum"
    return 1
  fi
  if ! complete_multipart_upload_rest_incorrect_checksum "$1" "$2" "$upload_id" "$parts_payload" "$3" "$4" "$checksum"; then
    log 2 "error completing multipart upload with nonexistent param"
    return 1
  fi
  return 0
}

test_complete_multipart_upload_invalid_checksum() {
  if ! check_param_count_v2 "bucket, filename, checksum type, algorithm" 4 $#; then
    return 1
  fi
  if ! perform_full_multipart_upload_with_checksum_before_completion "$1" "$2" "$3" "$4"; then
    log 2 "error performing multipart upload with checksum before completion"
    return 1
  fi
  if ! complete_multipart_upload_rest_invalid_checksum "$1" "$2" "$upload_id" "$parts_payload" "$3" "$4" "wrong"; then
    log 2 "error completing multipart upload with nonexistent param"
    return 1
  fi
  return 0
}
