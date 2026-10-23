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

# param: bucket name
# return 0 for success, 1 for error
abort_all_multipart_uploads_rest() {
  if ! check_param_count "abort_all_multipart_uploads_rest" "bucket" 1 $#; then
    return 1
  fi
  local bucket="$1"
  local response uploads key upload_id
  local -a upload_data

  if ! response=$(list_multipart_uploads_rest "$bucket" 2>&1); then
    log 2 "error listing multipart uploads: $response"
    return 1
  fi
  uploads="$response"

  # shellcheck disable=SC2154
  log 5 "UPLOADS: $uploads"
  if ! response=$(echo -n "$uploads" | xmllint --xpath '//*[local-name()="Upload"]' - 2>&1); then
    if [[ "$response" == *"XPath set is empty"* ]]; then
      return 0
    fi
    log 2 "error retrieving upload data: $response"
    return 1
  fi
  mapfile -t upload_data <<< "$response"

  for upload in "${upload_data[@]}"; do
    log 5 "upload: $upload"
    if ! key=$(echo -n "$upload" | xmllint --xpath '//*[local-name()="Key"]/text()' - 2>&1); then
      log 2 "error retrieving key: $key"
      return 1
    fi
    if ! upload_id=$(echo -n "$upload" | xmllint --xpath '//*[local-name()="UploadId"]/text()' - 2>&1); then
      log 2 "error retrieving upload ID: $upload_id"
      return 1
    fi
    log 5 "Aborting multipart upload for key: $key, UploadId: $upload_id"
    if ! abort_multipart_upload_rest "$1" "$key" "$upload_id"; then
      log 2 "error aborting multipart upload"
      return 1
    fi
  done
  return 0
}
