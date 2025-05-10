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

# params:  client, bucket, key
delete_object() {
  log 6 "delete_object"
  record_command "delete-object" "client:$1"
  if ! check_param_count "delete_object" "command type, bucket, key" 3 $#; then
    return 1
  fi
  local exit_code=0
  if [[ $1 == 's3' ]]; then
    delete_object_error=$(send_command aws --no-verify-ssl s3 rm "s3://$2/$3" 2>&1) || exit_code=$?
  elif [[ $1 == 's3api' ]]; then
    delete_object_error=$(send_command aws --no-verify-ssl s3api delete-object --bucket "$2" --key "$3" 2>&1) || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    delete_object_error=$(send_command s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate rm "s3://$2/$3" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    delete_object_error=$(send_command mc --insecure rm "$MC_ALIAS/$2/$3" 2>&1) || exit_code=$?
  elif [[ $1 == 'rest' ]]; then
    delete_object_rest "$2" "$3" || exit_code=$?
  else
    log 2 "invalid command type $1"
    return 1
  fi
  log 5 "delete object exit code: $exit_code"
  if [ $exit_code -ne 0 ]; then
    log 2 "error deleting object: $delete_object_error"
    export delete_object_error
    return 1
  fi
  return 0
}

delete_object_bypass_retention() {
  if ! check_param_count "delete_object_bypass_retention" "bucket, key, user, password" 4 $#; then
    return 1
  fi
  if ! result=$(AWS_ACCESS_KEY_ID="$3" AWS_SECRET_ACCESS_KEY="$4" \
      COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" BYPASS_GOVERNANCE_RETENTION="true" \
      OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/delete_object.sh 2>&1); then
    log 2 "error deleting object: $result"
    return 1
  fi
  return 0
}

delete_object_version() {
  if ! check_param_count "delete_object_version" "bucket, key, version ID" 3 $#; then
    return 1
  fi
  if ! delete_object_error=$(send_command aws --no-verify-ssl s3api delete-object --bucket "$1" --key "$2" --version-id "$3" 2>&1); then
    log 2 "error deleting object version: $delete_object_error"
    return 1
  fi
  return 0
}

delete_object_version_rest() {
  if ! check_param_count "delete_object_version_rest" "bucket name, object name, version ID" 3 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" VERSION_ID="$3" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/delete_object.sh 2>&1); then
    log 2 "error deleting object: $result"
    return 1
  fi
  if [ "$result" != "204" ]; then
    delete_object_error=$(cat "$TEST_FILE_FOLDER/result.txt")
    log 2 "expected '204', was '$result' ($delete_object_error)"
    return 1
  fi
  return 0
}

delete_object_version_bypass_retention() {
  if ! check_param_count "delete_object_version_bypass_retention" "bucket, key, version ID" 3 $#; then
    return 1
  fi
  if ! delete_object_error=$(send_command aws --no-verify-ssl s3api delete-object --bucket "$1" --key "$2" --version-id "$3" --bypass-governance-retention 2>&1); then
    log 2 "error deleting object version with bypass retention: $delete_object_error"
    return 1
  fi
  return 0
}

delete_object_version_rest_bypass_retention() {
  if ! check_param_count "delete_object_version_rest_bypass_retention" "bucket, key, version ID" 3 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" VERSION_ID="$3" BYPASS_GOVERNANCE_RETENTION="true" \
      OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/delete_object.sh 2>&1); then
    log 2 "error deleting object: $result"
    return 1
  fi
  if [ "$result" != "204" ]; then
    log 2 "expected '204', was '$result' ($(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  return 0
}

delete_object_with_user() {
  record_command "delete-object" "client:$1"
  if ! check_param_count "delete_object_version_bypass_retention" "command type, bucket, key, access ID, secret key" 5 $#; then
    return 1
  fi
  local exit_code=0
  if [[ $1 == 's3' ]]; then
    delete_object_error=$(AWS_ACCESS_KEY_ID="$4" AWS_SECRET_ACCESS_KEY="$5" send_command aws --no-verify-ssl s3 rm "s3://$2/$3" 2>&1) || exit_code=$?
  elif [[ $1 == 's3api' ]] || [[ $1 == 'aws' ]]; then
    delete_object_error=$(AWS_ACCESS_KEY_ID="$4" AWS_SECRET_ACCESS_KEY="$5" send_command aws --no-verify-ssl s3api delete-object --bucket "$2" --key "$3" 2>&1) || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    delete_object_error=$(send_command s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate rm --access_key="$4" --secret_key="$5" "s3://$2/$3" 2>&1) || exit_code=$?
  else
    log 2 "command 'delete object with user' not implemented for '$1'"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    log 2 "error deleting object: $delete_object_error"
    return 1
  fi
  return 0
}

delete_object_rest() {
  if ! check_param_count "delete_object_rest" "bucket, key" 2 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/delete_object.sh 2>&1); then
    log 2 "error deleting object: $result"
    return 1
  fi
  if [ "$result" != "204" ]; then
    delete_object_error=$(cat "$TEST_FILE_FOLDER/result.txt")
    log 2 "expected '204', was '$result' ($delete_object_error)"
    return 1
  fi
  return 0
}
