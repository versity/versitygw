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

upload_part() {
  if [ $# -ne 5 ]; then
    log 2 "upload multipart part function must have bucket, key, upload ID, file name, part number"
    return 1
  fi
  if ! upload_part_with_user "$1" "$2" "$3" "$4" "$5" "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY"; then
    log 2 "error uploading part with user"
    return 1
  fi
  return 0
}

upload_part_with_user() {
  if [ $# -ne 7 ]; then
    log 2 "upload multipart part function must have bucket, key, upload ID, file name, part number, username, password"
    return 1
  fi
  local etag_json
  record_command "upload-part" "client:s3api"
  if ! etag_json=$(AWS_ACCESS_KEY_ID="$6" AWS_SECRET_ACCESS_KEY="$7" send_command aws --no-verify-ssl s3api upload-part --bucket "$1" --key "$2" --upload-id "$3" --part-number "$5" --body "$4-$(($5-1))" 2>&1); then
    log 2 "Error uploading part $5: $etag_json"
    return 1
  fi
  if ! etag=$(echo "$etag_json" | grep -v "InsecureRequestWarning" | jq '.ETag' 2>&1); then
    log 2 "error obtaining etag: $etag"
    return 1
  fi
  export etag
}

upload_part_and_get_etag_rest() {
  if [ $# -ne 5 ]; then
    log 2 "'upload_part_rest' requires bucket name, key, part number, upload ID, part"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" PART_NUMBER="$4" UPLOAD_ID="$3" DATA_FILE="$5" OUTPUT_FILE="$TEST_FILE_FOLDER/etag.txt" ./tests/rest_scripts/upload_part.sh); then
    log 2 "error sending upload-part REST command: $result"
    return 1
  fi
  if [[ "$result" != "200" ]]; then
    log 2 "upload-part command returned error $result: $(cat "$TEST_FILE_FOLDER/etag.txt")"
    return 1
  fi
  log 5 "$(cat "$TEST_FILE_FOLDER/etag.txt")"
  etag=$(grep -i "etag" "$TEST_FILE_FOLDER/etag.txt" | awk '{print $2}' | tr -d '\r')
  log 5 "etag:  $etag"
  return 0
}
