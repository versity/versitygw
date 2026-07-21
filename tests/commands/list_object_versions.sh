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

list_object_versions() {
  if ! check_param_count "list_object_versions" "client, bucket name" 2 $#; then
    return 1
  fi
  local client="$1" bucket="$2"
  local list_result=0 response response_with_warning versions

  if [ "$client" == "rest" ]; then
    response=$(list_object_versions_rest "$bucket" 2>&1) || list_result=$?
  else
    response_with_warning=$(send_command aws --no-verify-ssl s3api list-object-versions --bucket "$2" 2>&1) || list_result=$?
    response=$(echo "$response_with_warning" | grep -v "InsecureRequestWarning")
  fi
  if [[ $list_result -ne 0 ]]; then
    log 2 "error listing object versions: $versions"
    return 1
  fi
  versions="$response"
  echo "$versions"
  return 0
}

list_object_versions_rest() {
  if [ $# -ne 1 ]; then
    log 2 "'list_object_versions_rest' requires bucket name"
    return 1
  fi
  if ! response=$(get_file_name 2>&1); then
    log 2 "error getting file name: $response"
    return 1
  fi
  file_name="$response"

  if ! result=$(BUCKET_NAME="$1" OUTPUT_FILE="$TEST_FILE_FOLDER/$file_name" ./tests/rest_scripts/list_object_versions.sh 2>&1); then
    log 2 "error listing object versions: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected '200', was '$result' ($(cat "$TEST_FILE_FOLDER/$file_name"))"
    return 1
  fi
  cat "$TEST_FILE_FOLDER/$file_name"
  return 0
}

list_object_versions_rest_v2() {
  if ! check_param_count_gt "bucket name, callback, params (optional)" 2 $#; then
    return 1
  fi
  local bucket="$1" callback="$2" params=("${@:3}")
  local response

  if ! response=$(send_rest_go_command_callback "200" "$callback" "-bucketName" "$bucket" "-query" "versions=" "${params[@]}" 2>&1); then
    log 2 "error sending REST list object versions command: $response"
    return 1
  fi
  echo "$response"
  return 0
}