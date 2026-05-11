#!/usr/bin/env bats

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

list_multipart_uploads_check_key_id_get_next_token() {
  if ! check_param_count_gt "bucket, expected key, expected upload ID, starting token (optional)" 3 $#; then
    return 1
  fi
  local starting_token_param=() response upload_json upload upload_id key next_token
  if [ "$4" != "" ]; then
    starting_token_param=("--starting-token" "$4")
  fi
  if ! response=$(list_multipart_uploads "$1" "--max-items" "1" "${starting_token_param[@]}" 2>&1); then
    log 2 "error listing multipart uploads: $response"
    return 1
  fi

  upload_json=$(echo "$response" | grep -v "InsecureRequestWarning")
  log 5 "JSON: $upload_json"
  upload="$(echo "$upload_json" | jq -r '.Uploads[0]')"
  upload_id="$(echo "$upload" | jq -r '.UploadId')"
  key="$(echo "$upload" | jq -r '.Key')"

  if [ "$key" != "$2" ]; then
    log 2 "expected key of '$2', was '$key'"
    return 1
  fi
  if [ "$upload_id" != "$3" ]; then
    log 2 "expected upload ID of '$3', was '$upload_id'"
    return 1
  fi

  next_token="$(echo "$upload_json" | jq -r '.NextToken')"
  echo "$next_token"
  return 0
}