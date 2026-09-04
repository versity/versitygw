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
  if [ $# -ne 5 ]; then
    log 2 "upload multipart part copy function must have bucket, key, upload ID, file name, part number"
    return 1
  fi

  local etag_json
  log 5 "parameters:  '$1' '$2' '$3' '$4' '$5'"
  etag_json=$(send_command aws --no-verify-ssl s3api upload-part-copy --bucket "$1" --key "$2" --upload-id "$3" --part-number "$5" --copy-source "$1/$4-$(($5-1))") || local uploaded=$?
  if [[ $uploaded -ne 0 ]]; then
    log 2 "Error uploading part $5: $etag_json"
    return 1
  fi
  etag=$(echo "$etag_json" | jq '.CopyPartResult.ETag')
  return 0
}

upload_part_copy_with_range() {
  if [ $# -ne 6 ]; then
    log 2 "upload multipart part copy function must have bucket, key, upload ID, file name, part number, range"
    return 1
  fi
  local bucket="$1" key="$2" upload_id="$3" file_name="$4" part_number="$5" range="$6"
  local etag_json

  if ! response=$(send_command aws --no-verify-ssl s3api upload-part-copy --bucket "$bucket" --key "$key" --upload-id "$upload_id" \
      --part-number "$part_number" --copy-source "${bucket}/${file_name}-$((part_number-1))" --copy-source-range "$range" 2>&1); then
    printf "s3api UploadPartCopy command error: %s\n" "$response"
    return 1
  fi
  etag=$(echo "$response" | grep -v "InsecureRequestWarning" | jq '.CopyPartResult.ETag')
  printf '%s\n' "$etag"
  return 0
}