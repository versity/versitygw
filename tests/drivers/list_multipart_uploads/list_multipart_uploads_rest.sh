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

check_multipart_upload_user_data() {
  if ! check_param_count_v2 "data file, expected upload ID, owner ID, initiator ID" 4 $#; then
    return 1
  fi
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
  if ! result=$(send_rest_go_command_callback "200" "check_multipart_upload_user_data" "-bucketName" "$1" "-query" "uploads" \
      "--" "$2" "$3" "$4" 2>&1); then
    log 2 "error listing multipart upload and checking owner data: $result"
    return 1
  fi
  return 0
}

check_multipart_upload_next_key_upload_id() {
  if ! check_param_count_v2 "data file, expected next key, next upload ID" 3 $#; then
    return 1
  fi
}

list_multipart_uploads_check_next_values() {

}