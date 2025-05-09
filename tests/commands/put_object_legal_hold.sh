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

put_object_legal_hold() {
  record_command "put-object-legal-hold" "client:s3api"
  if ! check_param_count "put_object_legal_hold" "client, bucket, key, hold status ('ON' or 'OFF')" 4 $#; then
    return 1
  fi
  if [ "$1" == "rest" ]; then
    if ! put_object_legal_hold_rest "$2" "$3" "$4"; then
      log 2 "error updating legal hold status w/REST"
      return 1
    fi
  else
    if ! error=$(send_command aws --no-verify-ssl s3api put-object-legal-hold --bucket "$2" --key "$3" --legal-hold "{\"Status\": \"$4\"}" 2>&1); then
      log 2 "error putting object legal hold: $error"
      return 1
    fi
  fi
  return 0
}

put_object_legal_hold_rest() {
  if ! check_param_count "put_object_legal_hold_rest" "bucket, key, hold status ('ON' or 'OFF')" 3 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" STATUS="$3" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/put_object_legal_hold.sh 2>&1); then
    log 2 "error putting object legal hold: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected '200', was '$result' ($(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  return 0
}

put_object_legal_hold_version_id() {
  record_command "put-object-legal-hold" "client:s3api"
  if ! check_param_count "put_object_legal_hold_version_id" "bucket, key, version ID, hold status ('ON' or 'OFF')" 4 $#; then
    return 1
  fi
  local error=""
  if ! error=$(send_command aws --no-verify-ssl s3api put-object-legal-hold --bucket "$1" --key "$2" --version-id "$3" --legal-hold "{\"Status\": \"$4\"}" 2>&1); then
    log 2 "error putting object legal hold w/version ID: $error"
    return 1
  fi
  return 0
}

put_object_legal_hold_rest_version_id() {
  if ! check_param_count "put_object_legal_hold_rest" "bucket, key, version ID, hold status" 4 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" VERSION_ID="$3" STATUS="$4" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/put_object_legal_hold.sh 2>&1); then
    log 2 "error putting object legal hold: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected '200', was '$result' ($(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  return 0
}
