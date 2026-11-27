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

parse_upload_id() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  if ! upload_id=$(get_element_text "$1" "InitiateMultipartUploadResult" "UploadId"); then
    log 2 "error getting upload ID: $upload_id"
    return 1
  fi
  echo "$upload_id"
  return 0
}

start_two_part_multipart_upload_with_checksum() {
  if ! check_param_count_v2 "checksum type, checksum algorithm" 2 $#; then
    return 1
  fi
  local checksum_type="$1" checksum_algorithm="$2"
  local response bucket_name file_name part_one part_two upload_id

  if ! response=$(setup_bucket_and_large_file_v3 "$BUCKET_ONE_NAME" 2>&1); then
    log 2 "error setting up file and bucket"
    return 1
  fi
  read -r bucket_name file_name <<< "$response"
  log 5 "file name: $file_name, file info:  $(ls -l "$TEST_FILE_FOLDER/$file_name")"
  if ! response=$(DATA_FILE="$TEST_FILE_FOLDER/$file_name" CHECKSUM_TYPE="$checksum_algorithm" TEST_FILE_FOLDER="$TEST_FILE_FOLDER" ./tests/rest_scripts/calculate_checksum.sh 2>&1); then
    log 2 "error calculating checksum: $response"
    return 1
  fi
  log 5 "initial calculation:  $response"

  if ! response=$(split_file "$TEST_FILE_FOLDER/$file_name" 2 2>&1); then
    log 2 "error splitting file: $response"
    return 1
  fi
  read -r part_one part_two <<< "$response"

  if ! response=$(create_multipart_upload_rest "$bucket_name" "$file_name" "CHECKSUM_TYPE=$checksum_type CHECKSUM_ALGORITHM=$checksum_algorithm" "parse_upload_id" 2>&1); then
    log 2 "error creating multipart upload: $response"
    return 1
  fi
  upload_id="$response"
  printf '%s %s %s %s %s\n' "$bucket_name" "$file_name" "$upload_id" "$part_one" "$part_two"
  return 0
}