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

get_and_check_legal_hold() {
  if [ $# -ne 4 ]; then
    log 2 "'get_and_check_legal_hold' requires client, bucket, key, expected status"
    return 1
  fi
  if ! head_object "$1" "$2" "$3"; then
    log 2 "error getting object metadata"
    return 1
  fi
  # shellcheck disable=SC2154
  raw_metadata=$(echo "$metadata" | grep -v "InsecureRequestWarning")
  log 5 "raw metadata: $raw_metadata"
  if ! hold_status=$(echo "$raw_metadata" | jq -r ".ObjectLockLegalHoldStatus" 2>&1); then
    log 2 "error retrieving hold status: $hold_status"
    return 1
  fi
  if [[ "$hold_status" != "$4" ]]; then
    log 2 "hold status mismatch ($hold_status, $4)"
    return 1
  fi
  return 0
}

check_legal_hold_without_lock_enabled() {
  if [ $# -ne 2 ]; then
    log 2 "'check_legal_hold_without_lock_enabled' requires bucket, key names"
    return 1
  fi
  if get_object_legal_hold_rest "$1" "$2"; then
    log 2 "get legal hold using REST succeeded without lock enabled"
    return 1
  fi
  log 5 "legal hold info: $(cat "$TEST_FILE_FOLDER/legal_hold.txt")"
  if ! code=$(xmllint --xpath '//*[local-name()="Code"]/text()' "$TEST_FILE_FOLDER/legal_hold.txt" 2>&1); then
    log 2 "error getting error code: $code"
    return 1
  fi
  if [ "$code" != "InvalidRequest" ]; then
    log 2 "code mismatch (expected 'InvalidRequest', actual '$code')"
    return 1
  fi
  return 0
}

check_remove_legal_hold_versions() {
  if [ $# -ne 4 ]; then
    log 2 "'check_remove_legal_hold_versions' requires client, bucket, key, version ID"
    return 1
  fi
  if ! legal_hold=$(get_object_legal_hold_rest_version_id "$2" "$3" "$4"); then
    if [[ "$legal_hold" != *"MethodNotAllowed"* ]]; then
      log 2 "error getting object legal hold status with version id"
      return 1
    fi
    return 0
  fi
  log 5 "legal hold: $legal_hold"
  if ! status="$(echo "$legal_hold" | grep -v "InsecureRequestWarning" | jq -r '.LegalHold.Status' 2>&1)"; then
    log 2 "error getting legal hold status: $status"
    return 1
  fi
  if [ "$status" == "ON" ]; then
    if ! put_object_legal_hold_version_id "$1" "$2" "$3" "OFF"; then
      log 2 "error removing legal hold of version ID"
      return 1
    fi
  fi
  return 0
}

check_legal_hold_without_payload() {
  if [ $# -ne 2 ]; then
    log 2 "'check_legal_hold_without_payload' requires bucket name, key"
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
    log 2 "error checking xml error, message"
    return 1
  fi
  return 0
}

rest_check_legal_hold() {
  if [ $# -ne 2 ]; then
    log 2 "'rest_check_legal_hold' requires bucket name, key"
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
