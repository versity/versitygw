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

check_legal_hold_without_lock_enabled() {
  if ! check_param_count_v2 "bucket, key, expected code, expected error" 4 $#; then
    return 1
  fi
  local env_vars

  env_vars="BUCKET_NAME=$1 OBJECT_KEY=$2"

  if ! send_rest_command_expect_error "$env_vars" ./tests/rest_scripts/get_object_legal_hold.sh "400" "$3" "$4"; then
    log 2 "error sending get object legal hold command, checking error"
    return 1
  fi
  return 0
}

check_remove_legal_hold_versions() {
  if ! check_param_count_gt "bucket, key, version ID" 3 $#; then
    return 1
  fi
  local bucket="$1" key="$2" version_id="$3"
  local response legal_hold_data

  if ! response=$(get_object_legal_hold_rest_version_id "$bucket" "$key" "$version_id" 2>&1); then
    # shellcheck disable=SC2154
    log 5 "legal hold: $response"
    if [[ "$response" != *"MethodNotAllowed"* ]] && [[ "$response" != *"NoSuchObjectLockConfiguration"* ]]; then
      log 2 "error getting object legal hold status with version id: $response"
      return 1
    fi
    return 0
  fi
  legal_hold_data="$response"

  if check_xml_element_inside_string "$legal_hold_data" "ON" "LegalHold" "Status"; then
    if ! put_object_legal_hold_rest_version_id "$1" "$2" "$3" "OFF"; then
      log 2 "error removing legal hold of version ID"
      return 1
    fi
  fi
  return 0
}

check_legal_hold_without_payload() {
  if ! check_param_count "check_legal_hold_without_payload" "bucket, key" 2 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" OMIT_PAYLOAD="true" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/put_object_legal_hold.sh); then
    log 2 "error: $result"
    return 1
  fi
  if [ "$result" != "400" ]; then
    log 2 "expected '400', was '$result' ($(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  if ! check_xml_error_contains "$TEST_FILE_FOLDER/result.txt" "MalformedXML" "The XML you provided"; then
    log 2 "error checking xml error, message ($(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  return 0
}

check_legal_hold_without_content_md5() {
  if ! check_param_count "check_legal_hold_without_content_md5" "bucket, key" 2 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" OMIT_CONTENT_MD5="true" STATUS="OFF" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/put_object_legal_hold.sh); then
    log 2 "error: $result"
    return 1
  fi
  if [ "$result" != "400" ]; then
    log 2 "expected '400', was '$result' ($(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  if ! check_xml_error_contains "$TEST_FILE_FOLDER/result.txt" "InvalidRequest" "Content-MD5"; then
    log 2 "error checking xml error, message ($(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  return 0
}

rest_check_legal_hold() {
  if ! check_param_count "rest_check_legal_hold" "bucket, key" 2 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" STATUS="ON" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/put_object_legal_hold.sh); then
    log 2 "error: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected '200', was '$result' ($(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/get_object_legal_hold.sh); then
    log 2 "error: $result"
    return 1
  fi
  if ! check_xml_element "$TEST_FILE_FOLDER/result.txt" "ON" "LegalHold" "Status"; then
    log 2 "error checking legal hold status"
    return 1
  fi
  return 0
}
