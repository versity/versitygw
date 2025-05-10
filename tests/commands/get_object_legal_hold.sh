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

get_object_legal_hold() {
  if [[ $# -ne 2 ]]; then
    log 2 "'get object legal hold' command requires bucket, key"
    return 1
  fi
  record_command "get-object-legal-hold" "client:s3api"
  legal_hold=$(send_command aws --no-verify-ssl s3api get-object-legal-hold --bucket "$1" --key "$2" 2>&1) || local get_result=$?
  if [[ $get_result -ne 0 ]]; then
    log 2 "error getting object legal hold: $legal_hold"
    return 1
  fi
  return 0
}

get_object_legal_hold_rest() {
  if [ $# -ne 2 ]; then
    log 2 "'get_object_legal_hold_rest' requires bucket, key"
    return 1
  fi
  if ! result=$(COMMAND_LOG=$COMMAND_LOG BUCKET_NAME=$1 OBJECT_KEY="$2" OUTPUT_FILE="$TEST_FILE_FOLDER/legal_hold.txt" ./tests/rest_scripts/get_object_legal_hold.sh); then
    log 2 "error getting object legal hold: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "get-object-legal-hold returned code $result: $(cat "$TEST_FILE_FOLDER/legal_hold.txt")"
    return 1
  fi
  return 0
}

get_object_legal_hold_version_id() {
  if [[ $# -ne 3 ]]; then
    log 2 "'get_object_legal_hold_version_id' command requires bucket, key, version id"
    return 1
  fi
  record_command "get-object-legal-hold" "client:s3api"
  if ! legal_hold=$(send_command aws --no-verify-ssl s3api get-object-legal-hold --bucket "$1" --key "$2" --version-id "$3" 2>&1); then
    log 2 "error getting object legal hold w/version id: $legal_hold"
    return 1
  fi
  echo "$legal_hold"
  return 0
}

get_object_legal_hold_rest_version_id() {
  if ! check_param_count "get_object_legal_hold_rest_version_id" "bucket, key, version ID" 3 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" VERSION_ID="$3" OUTPUT_FILE="$TEST_FILE_FOLDER/legal_hold.txt" ./tests/rest_scripts/get_object_legal_hold.sh); then
    log 2 "error getting object legal hold: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "get-object-legal-hold returned code $result: $(cat "$TEST_FILE_FOLDER/legal_hold.txt")"
    return 1
  fi
  legal_hold=$(cat "$TEST_FILE_FOLDER/legal_hold.txt")
  return 0
}
