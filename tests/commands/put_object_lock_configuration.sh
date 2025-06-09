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

put_object_lock_configuration() {
  if [[ $# -ne 4 ]]; then
    log 2 "'put-object-lock-configuration' command requires bucket name, enabled, mode, period"
    return 1
  fi
  local config="{\"ObjectLockEnabled\": \"$2\", \"Rule\": {\"DefaultRetention\": {\"Mode\": \"$3\", \"Days\": $4}}}"
  if ! error=$(send_command aws --no-verify-ssl s3api put-object-lock-configuration --bucket "$1" --object-lock-configuration "$config" 2>&1); then
    log 2 "error putting object lock configuration: $error"
    return 1
  fi
  return 0
}

remove_retention_policy_rest() {
  if ! check_param_count "remove_retention_policy_rest" "bucket" 1 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/put_object_lock_configuration.sh 2>&1); then
    log 2 "error putting object lock configuration: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected '200', was '$result' ($(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  return 0
}

remove_retention_policy() {
  if ! check_param_count "remove_retention_policy" "bucket" 1 $#; then
    return 1
  fi
  if ! error=$(aws --no-verify-ssl s3api put-object-lock-configuration --bucket "$1" --object-lock-configuration "$config" 2>&1); then
    log 2 "error putting object lock configuration: $error"
    return 1
  fi
  return 0
}

put_object_lock_config_without_content_md5() {
  if ! check_param_count "remove_retention_policy_rest" "bucket" 1 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OMIT_CONTENT_MD5="true" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/put_object_lock_configuration.sh 2>&1); then
    log 2 "error putting object lock configuration: $result"
    return 1
  fi
  if [ "$result" != "400" ]; then
    log 2 "expected '400', was '$result' ($(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  if ! check_xml_error_contains "$TEST_FILE_FOLDER/result.txt" "InvalidRequest" "Content-MD5"; then
    log 2 "error checking XML response"
    return 1
  fi
  return 0
}
