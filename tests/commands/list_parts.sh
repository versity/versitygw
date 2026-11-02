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

list_parts() {
  if ! check_param_count_v2 "bucket, key, upload ID" 3 $#; then
    return 1
  fi
  local bucket="$1" key="$2" upload_id="$3"
  local response listed_parts

  if ! response=$(list_parts_with_user "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$bucket" "$key" "$upload_id" 2>&1); then
    log 2 "error listing parts with user: $response"
    return 1
  fi
  listed_parts="$response"
  printf '%s\n' "$listed_parts"
  return 0
}

list_parts_with_user() {
  if ! check_param_count_v2 "username, password, bucket, key, upload ID" 5 $#; then
    return 1
  fi
  local username="$1" password="$2" bucket="$3" key="$4" upload_id="$5"
  local response listed_parts

  if ! response=$(AWS_ACCESS_KEY_ID="$username" AWS_SECRET_ACCESS_KEY="$password" send_command aws --no-verify-ssl \
      s3api list-parts --bucket "$bucket" --key "$key" --upload-id "$upload_id" 2>&1); then
    log 2 "Error listing multipart upload parts: $response"
    return 1
  fi
  listed_parts="$(echo -n "$response" | grep -v "InsecureRequestWarning")"
  log 5 "listed parts: $listed_parts"
  printf '%s\n' "$listed_parts"
  return 0
}

list_parts_rest() {
  if ! check_param_count_gt "bucket name, key, upload ID, callback, other params" 4 $#; then
    return 1
  fi
  local bucket_name="$1" key="$2" upload_id="$3" callback="$4" params=("${@:5}")
  local response

  if ! response=$(send_rest_go_command_callback "200" "$callback" "-bucketName" "$bucket_name" "-objectKey" "$key" "-query" "uploadId=$upload_id" "${params[@]}" 2>&1); then
    log 2 "error sending REST ListParts command or checking response: $response"
    return 1
  fi
  return 0
}
