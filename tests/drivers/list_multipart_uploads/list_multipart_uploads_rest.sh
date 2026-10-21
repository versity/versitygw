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
# under the License.#

source ./tests/drivers/list.sh
source ./tests/util/util_multipart_before_completion.sh

check_multipart_upload_user_data() {
  if ! check_param_count_v2 "data file, expected upload ID, owner ID, initiator ID" 4 $#; then
    return 1
  fi
  local response upload_data

  if ! response=$(get_element_with_matching_inner_value "$1" "$2" "ListMultipartUploadsResult" "Upload" "--" "UploadId" 2>&1); then
    log 2 "error getting info with upload ID: $response"
    return 1
  fi
  upload_data="$response"

  if ! check_xml_element_inside_string "$upload_data" "$3" "Owner" "ID"; then
    log 2 "error checking Owner ID"
    return 1
  fi
  if ! check_xml_element_inside_string "$upload_data" "$4" "Initiator" "ID"; then
    log 2 "error checking Initiator ID"
    return 1
  fi
  return 0
}

list_multipart_uploads_check_user_data() {
  if ! check_param_count_v2 "bucket, uploadID, owner ID, initiator ID" 4 $#; then
    return 1
  fi
  local response

  if ! response=$(send_rest_go_command_callback "200" "check_multipart_upload_user_data" "-bucketName" "$1" "-query" "uploads" \
      "--" "$2" "$3" "$4" 2>&1); then
    log 2 "error listing multipart upload and checking owner data: $response"
    return 1
  fi
  return 0
}

check_multipart_upload_next_key_upload_id() {
  if ! check_param_count_v2 "data file, expected next key, next upload ID" 3 $#; then
    return 1
  fi
  if ! check_xml_element "$1" "$2" "ListMultipartUploadsResult" "NextKeyMarker"; then
    log 2 "error checking NextKeyMarker"
    return 1
  fi
  if ! check_xml_element "$1" "$3" "ListMultipartUploadsResult" "NextUploadIdMarker"; then
    log 2 "error checking NextUploadIdMarker"
    return 1
  fi
  return 0
}

list_multipart_uploads_check_next_values() {
  if ! check_param_count_v2 "bucket, expected next key, expected upload ID" 3 $#; then
    return 1
  fi
  local response

  if ! response=$(send_rest_go_command_callback "200" "check_multipart_upload_next_key_upload_id" "-bucketName" "$1" "-query" "uploads" \
      "--" "$2" "$3" 2>&1); then
    log 2 "error listing multipart upload and checking expected NextKeyMarker and NextUploadIdMarker: $response"
    return 1
  fi
  return 0
}

get_next_values() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  local data_file="$1"
  local response next_key_marker next_upload_id_marker

  if ! response=$(get_element_text "$data_file" "NextKeyMarker" 2>&1); then
    log 2 "error checking NextKeyMarker: $response"
    return 1
  fi
  next_key_marker="$response"

  if ! response=$(get_element_text "$data_file" "NextUploadIdMarker" 2>&1); then
    log 2 "error checking NextUploadIdMarker: $response"
    return 1
  fi
  next_upload_id_marker="$response"

  echo "$next_key_marker"
  echo "$next_upload_id_marker"
  return 0
}

list_multipart_uploads_get_check_next_values() {
  if ! check_param_count_ge_le "bucket, expected key, expected upload ID, next key (optional), next upload ID (optional)" 3 5 $#; then
    return 1
  fi
  local bucket="$1" expected_key="$2" expected_upload_id="$3" next_key="$4" next_upload_id="$5"
  local query_val="max-uploads=1&uploads" response key_marker upload_id_marker
  local -a response_lines

  if [ -n "$next_key" ]; then
    query_val+="&key-marker=${next_key}"
  fi
  if [ -n "$next_upload_id" ]; then
    query_val+="&upload-id-marker=${next_upload_id}"
  fi
  if ! response=$(send_rest_go_command_callback "200" "get_next_values" "-bucketName" "$bucket" "-query" "$query_val" 2>&1); then
    log 2 "error sending multipart upload and checking key and upload ID vals"
    return 1
  fi
  mapfile -t response_lines <<< "$response"
  key_marker="${response_lines[0]}"
  upload_id_marker="${response_lines[1]}"

  if [ "$expected_key" != "$key_marker" ]; then
    log 2 "expected key marker '$expected_key', was '$key_marker'"
    return 1
  fi
  if [ "$expected_upload_id" != "$upload_id_marker" ]; then
    log 2 "expected upload ID marker '$expected_upload_id', was '$upload_id_marker'"
    return 1
  fi
  return 0
}

check_for_no_upload_id() {
  if ! check_param_count_v2 "data file, unexpected upload ID, first upload ID" 3 $#; then
    return 1
  fi
  local data_file="$1" second_upload_id="$2" first_upload_id="$3"

  check_if_element_exists "$data_file" "$second_upload_id" "UploadIdMarker"
  if [ "$?" -ne 1 ]; then
    log 2 "error checking for element, or '$second_upload_id' actually exists in 'UploadIdMarker' (data: $(cat "$data_file"))"
    return 1
  fi
  if ! check_xml_element "$data_file" "$first_upload_id" "Upload" "UploadId"; then
    log 2 "error checking upload ID"
    return 1
  fi
  return 0
}

list_multipart_uploads_check_no_upload_id_in_response() {
  if ! check_param_count_v2 "bucket, upload ID query, first upload ID" 3 $#; then
    return 1
  fi
  local bucket="$1" second_upload_id="$2" first_upload_id="$3"
  local response

  if ! response=$(send_rest_go_command_callback "200" "check_for_no_upload_id" "-bucketName" "$bucket" "-query" "uploads&max-uploads=1&upload-id-marker=$second_upload_id" "--" "$second_upload_id" "$first_upload_id" 2>&1); then
    log 2 "error sending multipart upload and checking for no upload ID marker in response"
    return 1
  fi
  return 0
}

check_encoding() {
  if ! check_param_count_v2 "data file, expected encoding" 2 $#; then
    return 1
  fi
  log 5 "data: $(cat "$1")"
  if ! check_xml_element "$1" "$2" "ListMultipartUploadsResult" "Upload" "Key"; then
    log 2 "error checking encoded key"
    return 1
  fi
  return 0
}

list_multipart_uploads_check_encoding() {
  if ! check_param_count_v2 "bucket, encoding type query add-on, expected encoding" 3 $#; then
    return 1
  fi
  local response

  if ! response=$(send_rest_go_command_callback "200" "check_encoding" "-query" "uploads${2}" "-bucketName" "$1" "--" "$3" 2>&1); then
    log 2 "error listing uploads and checking encoding: $response"
    return 1
  fi
  return 0
}

list_uploads_with_prefix_and_delimiter_check_results() {
  if ! check_param_count_gt "bucket name, prefix, delimiter, expected common prefixes, --, expected keys" 6 $#; then
    return 1
  fi
  if ! send_rest_go_command_callback "200" "check_prefixes_delimiters_and_keys" "-bucketName" "$1" "-query" "uploads&delimiter=$3&prefix=$2" "--" "ListMultipartUploadsResult" "Upload" "${@:2}"; then
    log 2 "error sending command to list objects or receiving prefix and delimiter response"
    return 1
  fi
  return 0
}

create_abort_multipart_upload_rest() {
  if [ $# -ne 2 ]; then
    log 2 "'create_abort_upload_rest' requires bucket, key"
    return 1
  fi
  if ! list_and_check_upload "$1" "$2"; then
    log 2 "error listing multipart uploads before creation"
    return 1
  fi
  log 5 "uploads before upload: $(cat "$TEST_FILE_FOLDER/uploads.txt")"
  local response
  if ! response=$(create_multipart_upload_rest "$1" "$2" "" "parse_upload_id" 2>&1); then
    log 2 "error creating upload: $response"
    return 1
  fi
  upload_id="$response"

  if ! list_and_check_upload "$1" "$2" "$upload_id"; then
    log 2 "error listing multipart uploads after upload creation"
    return 1
  fi
  log 5 "uploads after upload creation: $(cat "$TEST_FILE_FOLDER/uploads.txt")"
  if ! abort_multipart_upload_rest "$1" "$2" "$upload_id"; then
    log 2 "error aborting multipart upload"
    return 1
  fi
  log 5 "final uploads: $(cat "$TEST_FILE_FOLDER/uploads.txt")"
  if ! list_and_check_upload "$1" "$2"; then
    log 2 "error listing multipart uploads after abort"
    return 1
  fi
  return 0
}
