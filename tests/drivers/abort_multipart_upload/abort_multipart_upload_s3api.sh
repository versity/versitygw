#!/usr/bin/env bash

# Copyright 2025 Versity Software
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

check_abort_access_denied() {
  if ! check_param_count_v2 "bucket, key, upload ID, username, password" 5 $#; then
    return 1
  fi
  local bucket="$1" key="$2" upload_id="$3" username="$4" password="$5"
  local response

  if response=$(abort_multipart_upload_with_user "$bucket" "$key" "$upload_id" "$username" "$password" 2>&1); then
    log 2 "abort multipart upload succeeded despite lack of permissions"
    return 1
  fi
  # shellcheck disable=SC2154
  if [[ "$response" != *"AccessDenied"* ]]; then
    log 2 "unexpected abort error:  $response"
    return 1
  fi
  return 0
}

# param: bucket name
# return 0 for success, 1 for error
abort_all_multipart_uploads() {
  if ! check_param_count_v2 "bucket" 1 $#; then
    return 1
  fi
  local bucket="$1"
  local response

  if ! list_multipart_uploads "$bucket"; then
    log 2 "error listing multipart uploads"
    return 1
  fi
  # shellcheck disable=SC2154
  log 5 "UPLOADS: $uploads"
  if ! upload_set=$(echo "$uploads" | grep -v "InsecureRequestWarning" | jq -c '.Uploads[]' 2>&1); then
    if [[ $upload_set == *"Cannot iterate over null"* ]]; then
      return 0
    else
      log 2 "error getting upload set: $upload_set"
      return 1
    fi
  fi
  log 5 "UPLOAD SET: $upload_set"
  for upload in $upload_set; do
    log 5 "UPLOAD: $upload"
    if ! upload_id=$(echo "$upload" | jq -r ".UploadId" 2>&1); then
      log 2 "error getting upload ID: $upload_id"
      return 1
    fi
    log 5 "upload ID: $upload_id"
    if ! key=$(echo "$upload" | jq -r ".Key" 2>&1); then
      log 2 "error getting key: $key"
      return 1
    fi
    log 5 "Aborting multipart upload for key: $key, UploadId: $upload_id"
    if ! abort_multipart_upload "$bucket" "$key" "$upload_id"; then
      log 2 "error aborting multipart upload"
      return 1
    fi
  done
}

# run upload, then abort it
# params:  bucket, key, local file location, number of parts to split into before uploading
# return 0 for success, 1 for failure
run_then_abort_multipart_upload() {
  if [ $# -ne 4 ]; then
    log 2 "run then abort multipart upload command missing bucket, key, file, and/or part count"
    return 1
  fi

  if ! multipart_upload_before_completion "$1" "$2" "$3" "$4"; then
    log 2 "error performing pre-completion multipart upload"
    return 1
  fi

  if ! abort_multipart_upload "$1" "$2" "$upload_id"; then
    log 2 "error aborting multipart upload"
    return 1
  fi
  return 0
}
