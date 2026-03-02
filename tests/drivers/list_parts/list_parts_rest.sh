#!/usr/bin/env bash

# Copyright 2026 Versity Software
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

check_part_list_rest_etags() {
  if ! check_param_count_gt "data file name, etags" 2 $#; then
    return 1
  fi
  if ! etags_raw=$(xmllint --xpath '//*[local-name()="ETag"]/text()' "$1" 2>&1); then
    log 2 "error retrieving etags: $etags"
    return 1
  fi
  etags=$(echo "$etags_raw" | tr '\n' ' ')
  read -ra etags_array <<< "$etags"

  idx=0
  shift
  if [ $# -ne ${#etags_array[@]} ]; then
    log 2 "expected tag size of '$#', actual ${#etags_array[@]}"
    return 1
  fi
  while [ $# -gt 0 ]; do
    if [ "$1" != "${etags_array[$idx]}" ]; then
      log 2 "etag mismatch (expected '$1', actual ${etags_array[$idx]})"
      return 1
    fi
    ((idx++))
    shift
  done
  return 0
}

check_part_list_rest() {
  if ! check_param_count_gt "bucket, key name, upload ID, expected etag count, expected etags" 4 $#; then
    return 1
  fi
  if ! file_name=$(get_file_name 2>&1); then
    log 2 "error getting file name: $file_name"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" UPLOAD_ID="$3" OUTPUT_FILE="$TEST_FILE_FOLDER/$file_name" ./tests/rest_scripts/list_parts.sh); then
    log 2 "error listing multipart upload parts: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "list-parts returned response code: $result, reply:  $(cat "$TEST_FILE_FOLDER/$file_name")"
    return 1
  fi
  log 5 "parts list: $(cat "$TEST_FILE_FOLDER/$file_name")"
  if ! parts_upload_id=$(xmllint --xpath '//*[local-name()="UploadId"]/text()' "$TEST_FILE_FOLDER/$file_name" 2>&1); then
    log 2 "error retrieving UploadId: $parts_upload_id"
    return 1
  fi
  if [ "$parts_upload_id" != "$3" ]; then
    log 2 "expected '$3', UploadId value is '$parts_upload_id'"
    return 1
  fi
  if ! part_count=$(xmllint --xpath 'count(//*[local-name()="Part"])' "$TEST_FILE_FOLDER/$file_name" 2>&1); then
    log 2 "error retrieving part count: $part_count"
    return 1
  fi
  if [ "$part_count" != "$4" ]; then
    log 2 "expected $4, 'Part' count is '$part_count'"
    return 1
  fi
  if [ "$4" == 0 ]; then
    return 0
  fi
  if ! check_part_list_rest_etags "$TEST_FILE_FOLDER/$file_name" "${@:5}"; then
    log 2 "error checking etags"
    return 1
  fi
  return 0
}

upload_each_part_and_check() {
  if ! check_param_count_gt "bucket, key, upload ID, parts" 5 $#; then
    return 1
  fi

  local part_count=$(($#-3))
  local parts_payload=""
  local etags=()

  for ((idx=1; idx<=part_count; idx++)); do
    local payload_section=""
    part_number=$((idx+3))

    if ! etag_and_payload_section=$(upload_check_part "$1" "$2" "$3" "$idx" "${!part_number}" "${etags[@]}" 2>&1); then
      log 2 "error uploading and checking part '$idx': $etag_and_payload_section"
      return 1
    fi

    IFS=$'\n' read -r -d '' etag payload_section < <(printf '%s\0' "$etag_and_payload_section")
    parts_payload+="$payload_section"
    etags+=("$etag")
  done
  echo "$parts_payload"
  return 0
}

upload_check_part() {
  if ! check_param_count_gt "bucket, key, upload ID, part number, part, etags (if any)" 5 $#; then
    return 1
  fi
  if ! etag=$(upload_part_rest "$1" "$2" "$3" "$4" "$5" 2>&1); then
    log 2 "error uploading part '$4': $etag"
    return 1
  fi
  local payload_part="<Part><ETag>$etag</ETag><PartNumber>$4</PartNumber></Part>"
  # shellcheck disable=SC2068
  if ! check_part_list_rest "$1" "$2" "$3" "$4" "${@:6}" "$etag"; then
    log 2 "error checking part list after upload $4"
    return 1
  fi
  echo "$etag"
  echo "$payload_part"
  return 0
}
