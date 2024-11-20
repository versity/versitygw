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

source ./tests/report.sh

put_object() {
  log 6 "put_object"
  record_command "put-object" "client:$1"
  if [ $# -ne 4 ]; then
    log 2 "put object command requires command type, source, destination bucket, destination key"
    return 1
  fi
  local exit_code=0
  local error
  if [[ $1 == 's3' ]]; then
    error=$(send_command aws --no-verify-ssl s3 mv "$2" s3://"$3/$4" 2>&1) || exit_code=$?
  elif [[ $1 == 's3api' ]]; then
    error=$(send_command aws --no-verify-ssl s3api put-object --body "$2" --bucket "$3" --key "$4" 2>&1) || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    error=$(send_command s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate put "$2" s3://"$3/$4" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    error=$(send_command mc --insecure put "$2" "$MC_ALIAS/$3/$4" 2>&1) || exit_code=$?
  elif [[ $1 == 'rest' ]]; then
    put_object_rest "$2" "$3" "$4" || exit_code=$?
  else
    log 2 "'put object' command not implemented for '$1'"
    return 1
  fi
  log 5 "put object exit code: $exit_code"
  if [ $exit_code -ne 0 ]; then
    log 2 "error putting object into bucket: $error"
    return 1
  fi
  return 0
}

put_object_with_user() {
  record_command "put-object" "client:$1"
  if [ $# -ne 6 ]; then
    log 2 "put object command requires command type, source, destination bucket, destination key, aws ID, aws secret key"
    return 1
  fi
  local exit_code=0
  if [[ $1 == 's3api' ]] || [[ $1 == 'aws' ]]; then
    put_object_error=$(AWS_ACCESS_KEY_ID="$5" AWS_SECRET_ACCESS_KEY="$6" send_command aws --no-verify-ssl s3api put-object --body "$2" --bucket "$3" --key "$4" 2>&1) || exit_code=$?
  else
    log 2 "'put object with user' command not implemented for '$1'"
    return 1
  fi
  log 5 "put object exit code: $exit_code"
  if [ $exit_code -ne 0 ]; then
    log 2 "error putting object into bucket: $put_object_error"
    export put_object_error
    return 1
  fi
  return 0
}

put_object_rest() {
  if [ $# -ne 3 ]; then
    log 2 "'put_object_rest' requires local file, bucket name, key"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" DATA_FILE="$1" BUCKET_NAME="$2" OBJECT_KEY="$3" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/put_object.sh); then
    log 2 "error sending object file: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected response code of '200', was '$result' (output: $(cat "$TEST_FILE_FOLDER/result.txt")"
    return 1
  fi
  return 0
}
