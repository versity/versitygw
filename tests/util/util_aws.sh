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

abort_all_multipart_uploads() {
  if [[ $# -ne 1 ]]; then
    log 2 "abort all multipart uploads command missing bucket name"
    return 1
  fi

  upload_list=$(aws --no-verify-ssl s3api list-multipart-uploads --bucket "$1" 2>&1) || list_result=$?
  if [[ $list_result -ne 0 ]]; then
    log 2 "error listing multipart uploads: $upload_list"
    return 1
  fi
  log 5 "$upload_list"
  while IFS= read -r line; do
    if [[ $line != *"InsecureRequestWarning"* ]]; then
      modified_upload_list+=("$line")
    fi
  done <<< "$upload_list"

  log 5 "Modified upload list: ${modified_upload_list[*]}"
  has_uploads=$(echo "${modified_upload_list[*]}" | jq 'has("Uploads")')
  if [[ $has_uploads == false ]]; then
    return 0
  fi
  if ! lines=$(echo "${modified_upload_list[*]}" | jq -r '.Uploads[] | "--key \(.Key) --upload-id \(.UploadId)"' 2>&1); then
    log 2 "error getting lines for multipart upload delete: $lines"
    return 1
  fi

  log 5 "$lines"
  while read -r line; do
    # shellcheck disable=SC2086
    if ! error=$(aws --no-verify-ssl s3api abort-multipart-upload --bucket "$1" $line 2>&1); then
      log 2 "error aborting multipart upload: $error"
      return 1
    fi
  done <<< "$lines"
  return 0
}

remove_insecure_request_warning() {
  if [[ $# -ne 1 ]]; then
    log 2 "remove insecure request warning requires input lines"
    return 1
  fi
  parsed_output=()
  while IFS= read -r line; do
    if [[ $line != *InsecureRequestWarning* ]]; then
      parsed_output+=("$line")
    fi
  done <<< "$1"
  export parsed_output
}
