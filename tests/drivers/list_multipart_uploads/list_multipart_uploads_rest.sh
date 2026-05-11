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
  local response next_key_marker next_upload_id_marker

  if ! response=$(get_element_text "$1" "NextKeyMarker" 2>&1); then
    log 2 "error checking NextKeyMarker: $response"
    return 1
  fi
  next_key_marker="$response"

  if ! response=$(get_element_text "$1" "NextUploadIdMarker" 2>&1); then
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
  local query_val="max-uploads=1&uploads" response
  if [ "$4" != "" ]; then
    query_val+="&key-marker=$4"
  fi
  if [ "$5" != "" ]; then
    query_val+="&upload-id-marker=$5"
  fi
  if ! response=$(send_rest_go_command_callback "200" "get_next_values" "-bucketName" "$1" "-query" "$query_val" 2>&1); then
    log 2 "error sending multipart upload and checking key and upload ID vals"
    return 1
  fi
  return 0
}

check_for_no_upload_id() {
  if ! check_param_count_v2 "data file, unexpected upload ID, first upload ID" 3 $#; then
    return 1
  fi
  check_if_element_exists "$1" "$2" "UploadIdMarker"
  if [ "$?" -ne 1 ]; then
    log 2 "error checking for element, or '$2' actually exists in 'UploadIdMarker' (data: $(cat "$1"))"
    return 1
  fi
  if ! check_xml_element "$1" "$3" "Upload" "UploadId"; then
    log 2 "error checking upload ID"
    return 1
  fi
  return 0
}

list_multipart_uploads_check_no_upload_id_in_response() {
  if ! check_param_count_v2 "bucket, upload ID query, second upload ID" 3 $#; then
    return 1
  fi
  local response

  if ! response=$(send_rest_go_command_callback "200" "check_for_no_upload_id" "-bucketName" "$1" "-query" "uploads&max-uploads=1&upload-id-marker=$2" "--" "$2" "$3" 2>&1); then
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
