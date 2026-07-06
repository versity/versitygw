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

check_part_elements() {
  if ! check_param_count_v2 "part, part number, etag, size" 4 $#; then
    return 1
  fi
  local part="$1" part_number="$2" etag="$3" size="$4"

  if ! response=$(check_xml_element_inside_string "$part" "$part_number" "PartNumber" 2>&1); then
    log 2 "error checking PartNumber: $response"
    return 1
  fi
  if ! response=$(check_xml_element_inside_string "$part" "$etag" "ETag" 2>&1); then
    log 2 "error checking ETag for part '$part_number' in array: $response"
    return 1
  fi
  if ! response=$(check_xml_element_inside_string "$part" "$size" "Size" 2>&1); then
    log 2 "error checking Size for part '$part_number' in array: $response"
    return 1
  fi
  return 0
}

check_list_parts_parts() {
  if ! check_param_count_gt "data string, part number marker, next part number, etag/size pairs" 3 $#; then
    return 1
  fi
  local data_string="$1" part_number_marker="$2" next_part_number_marker="$3"
  local -a etag_size_pairs=("${@:4}")
  local response part_number
  local -a parts=()

  if ! response=$(get_elements_inside_string "$data_string" "Part" 2>&1); then
    log 2 "error getting Part elements: $response"
    return 1
  fi
  log 5 "parts: $response"
  if [ "$response" != "" ]; then
    mapfile -t parts <<< "$response"
  fi

  local part_count=$((next_part_number_marker-part_number_marker))
  if [ $part_count -lt 0 ]; then
    part_count=0
  fi
  if [ ${#parts[@]} -ne "$part_count" ]; then
    log 2 "part count mismatch, expected '$part_count', actual '${#parts[@]}'"
    return 1
  fi
  if [ $((part_count*2)) -ne "${#etag_size_pairs[@]}" ]; then
    log 2 "part count and etag/size mismatch, expected '$((part_count*2))' fields, actual is '${#etag_size_pairs[@]}'"
    return 1
  fi

  for ((i=0; i<part_count; i++)); do
    part_number=$((part_number_marker+1+i))
    etag="${etag_size_pairs[((i*2))]}"
    if ! check_part_elements "${parts[$i]}" "$part_number" "${etag_size_pairs[((i*2))]}" "${etag_size_pairs[((i*2+1))]}"; then
      log 2 "error checking part '$part_number' element: $response"
      return 1
    fi
  done
  return 0
}

check_list_with_marker_and_max_parts() {
  if ! check_param_count_gt "data file, bucket, key, upload ID, max parts, part number marker, expected next part number marker, etag/size pairs" 7 $#; then
    return 1
  fi
  local data_file="$1"
  local bucket="$2"
  local key="$3"
  local upload_id="$4"
  local max_parts="$5"
  local part_number_marker="$6"
  local next_part_number_marker="$7"
  local -a etag_size_pairs=("${@:8}")

  local response list_parts_result
  local -a element_names=() expected_values=() parts=()

  if ! response=$(get_element "$data_file" "ListPartsResult" 2>&1); then
    log 2 "error getting response: $response"
    return 1
  fi
  list_parts_result="$response"

  element_names=("Bucket" "Key" "UploadId" "MaxParts" "PartNumberMarker" "NextPartNumberMarker")
  expected_values=("$bucket" "$key" "$upload_id" "$max_parts" "$part_number_marker" "$next_part_number_marker")
  for ((i=0; i<${#element_names[@]}; i++))do
    if ! response=$(check_xml_element_inside_string "$list_parts_result" "${expected_values[$i]}" "${element_names[$i]}" 2>&1); then
      log 2 "error checking element with name '${element_names[$i]}': $response"
      return 1
    fi
  done

  if ! check_list_parts_parts "$list_parts_result" "$part_number_marker" "$next_part_number_marker" "${etag_size_pairs[@]}"; then
    log 2 "error checking parts in parts list"
    return 1
  fi
  return 0
}

list_parts_check_with_marker_and_max_parts() {
  if ! check_param_count_gt "bucket name, key, upload ID, max parts, part number marker, expected next part number marker, etag/size pairs" 6 $#; then
    return 1
  fi
  if ! send_rest_go_command_callback "200" "check_list_with_marker_and_max_parts" "-bucketName" "$1" "-objectKey" "$2" "-query" "part-number-marker=$5&max-parts=$4&uploadId=$3" "--" "$@"; then
    log 2 "error sending ListParts command and checking callback"
    return 1
  fi
  return 0
}
