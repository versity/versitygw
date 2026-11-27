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

upload_part_copy() {
  if ! check_param_count_v2 "bucket, key, upload ID, file name, part number" 5 $#; then
    return 1
  fi
  local bucket="$1" key="$2" upload_id="$3" file_name="$4" part_number="$5"
  local response response_without_warning

  if ! response=$(send_command aws --no-verify-ssl s3api upload-part-copy --bucket "$1" --key "$2" --upload-id "$3" --part-number "$5" --copy-source "$1/$4-$(($5-1))" 2>&1); then
    log 2 "UploadPartCopy command error: $response"
    return 1
  fi
  log 5 "UploadPartCopy response: $response"
  response_without_warning=$(grep -v "InsecureRequestWarning" - <<< "$response")
  etag=$(jq -r '.CopyPartResult.ETag' - <<< "$response_without_warning" 2>&1)
  printf '%s\n' "$etag"
  return 0
}

upload_part_copy_with_range() {
  if ! check_param_count_v2 "bucket, key, upload ID, file name, part number, range" 6 $#; then
    return 1
  fi
  local bucket="$1" key="$2" upload_id="$3" file_name="$4" part_number="$5" range="$6"
  local response etag

  if ! response=$(send_command aws --no-verify-ssl s3api upload-part-copy --bucket "$bucket" --key "$key" --upload-id "$upload_id" \
      --part-number "$part_number" --copy-source "${bucket}/${file_name}-$((part_number-1))" --copy-source-range "$range" 2>&1); then
    printf "s3api UploadPartCopy command error: %s\n" "$response"
    return 1
  fi
  log 5 "UploadPartCopy with range response: $response"
  etag=$(echo "$response" | grep -v "InsecureRequestWarning" | jq -r '.CopyPartResult.ETag')
  printf '%s\n' "$etag"
  return 0
}

upload_part_copy_rest() {
  if ! check_param_count_v2 "bucket, key, upload ID, part number, part location" 5 $#; then
    return 1
  fi
  local bucket="$1" key="$2" upload_id="$3" part_number="$4" part_location="$5"
  local response response_file etag

  if ! response=$(get_file_name 2>&1); then
    log 2 "error getting file name: $response"
    return 1
  fi
  response_file="$response"

  if ! response=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$bucket" OBJECT_KEY="$key" PART_NUMBER="$part_number" UPLOAD_ID="$upload_id" PART_LOCATION="$part_location" OUTPUT_FILE="$TEST_FILE_FOLDER/$response_file" ./tests/rest_scripts/upload_part_copy.sh 2>&1); then
    log 2 "error uploading part number '$part_number': $response"
    return 1
  fi
  if [ "$response" != "200" ]; then
    log 2 "UploadPartCopy command returned error '$response': $(cat "$TEST_FILE_FOLDER/$response_file")"
    return 1
  fi
  if ! response=$(get_element_text "$TEST_FILE_FOLDER/$response_file" "CopyPartResult" "ETag" 2>&1); then
    log 2 "error getting etag: $response"
    return 1
  fi
  etag="$response"
  printf '%s\n' "$etag"
  return 0
}
