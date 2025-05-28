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

delete_bucket_policy() {
  record_command "delete-bucket-policy" "client:$1"
  if [[ $# -ne 2 ]]; then
    log 2 "delete bucket policy command requires command type, bucket"
    return 1
  fi
  local delete_result=0
  if [[ $1 == 's3api' ]] || [[ $1 == 's3' ]]; then
    error=$(send_command aws --no-verify-ssl s3api delete-bucket-policy --bucket "$2" 2>&1) || delete_result=$?
  elif [[ $1 == 's3cmd' ]]; then
    error=$(send_command s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate delpolicy "s3://$2" 2>&1) || delete_result=$?
  elif [[ $1 == 'mc' ]]; then
    error=$(send_command mc --insecure anonymous set none "$MC_ALIAS/$2" 2>&1) || delete_result=$?
  else
    log 2 "command 'delete bucket policy' not implemented for '$1'"
    return 1
  fi
  if [[ $delete_result -ne 0 ]]; then
    log 2 "error deleting bucket policy: $error"
    return 1
  fi
  return 0
}

delete_bucket_policy_rest() {
  if ! check_param_count "delete_bucket_policy_rest" "bucket" 1 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/delete_bucket_policy.sh 2>&1); then
    log 2 "error deleting bucket policy: $result"
    return 1
  fi
  if [ "$result" != "204" ]; then
    log 2 "expected '204', was '$result' ($(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  return 0
}

delete_bucket_policy_with_user() {
  record_command "delete-bucket-policy" "client:s3api"
  if [[ $# -ne 3 ]]; then
    log 2 "'delete bucket policy with user' command requires bucket, username, password"
    return 1
  fi
  if ! delete_bucket_policy_error=$(AWS_ACCESS_KEY_ID="$2" AWS_SECRET_ACCESS_KEY="$3" send_command aws --no-verify-ssl s3api delete-bucket-policy --bucket "$1" 2>&1); then
    log 2 "error deleting bucket policy: $delete_bucket_policy_error"
    export delete_bucket_policy_error
    return 1
  fi
  return 0
}