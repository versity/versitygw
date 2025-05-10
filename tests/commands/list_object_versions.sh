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
  record_command "list-object-versions" "client:s3api"
  if ! check_param_count "list_object_versions" "client, bucket name" 2 $#; then
    return 1
  fi
  local list_result=0
  if [ "$1" == "rest" ]; then
    list_object_versions_rest "$2" || list_result=$?
  else
    versions=$(send_command aws --no-verify-ssl s3api list-object-versions --bucket "$2" 2>&1) || list_result=$?
  fi
  if [[ $list_result -ne 0 ]]; then
    log 2 "error listing object versions: $versions"
    return 1
  fi
  versions=$(echo "$versions" | grep -v "InsecureRequestWarning")
  return 0
}

list_object_versions_rest() {
  if [ $# -ne 1 ]; then
    log 2 "'list_object_versions_rest' requires bucket name"
    return 1
  fi
  if ! result=$(BUCKET_NAME="$1" OUTPUT_FILE="$TEST_FILE_FOLDER/object_versions.txt" ./tests/rest_scripts/list_object_versions.sh 2>&1); then
    log 2 "error listing object versions: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected '200', was '$result' ($(cat "$TEST_FILE_FOLDER/object_versions.txt"))"
    return 1
  fi
  versions=$(cat "$TEST_FILE_FOLDER/object_versions.txt")
  return 0
}