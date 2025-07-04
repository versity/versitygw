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

get_object() {
  log 6 "get_object"
  record_command "get-object" "client:$1"
  if [ $# -ne 4 ]; then
    log 2 "get object command requires command type, bucket, key, destination"
    return 1
  fi
  local exit_code=0
  if [[ $1 == 's3' ]]; then
    get_object_error=$(send_command aws --no-verify-ssl s3 mv "s3://$2/$3" "$4" 2>&1) || exit_code=$?
  elif [[ $1 == 's3api' ]]; then
    get_object_error=$(send_command aws --no-verify-ssl s3api get-object --bucket "$2" --key "$3" "$4" 2>&1) || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    get_object_error=$(send_command s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate get "s3://$2/$3" "$4" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    get_object_error=$(send_command mc --insecure get "$MC_ALIAS/$2/$3" "$4" 2>&1) || exit_code=$?
  elif [[ $1 == 'rest' ]]; then
    get_object_rest "$2" "$3" "$4" || exit_code=$?
  else
    log 2 "'get object' command not implemented for '$1'"
    return 1
  fi
  log 5 "get object exit code: $exit_code"
  if [ $exit_code -ne 0 ]; then
    log 2 "error getting object: $get_object_error"
    return 1
  fi
  return 0
}

get_object_with_range() {
  record_command "get-object" "client:s3api"
  if [[ $# -ne 4 ]]; then
    log 2 "'get object with range' requires bucket, key, range, outfile"
    return 1
  fi
  if ! get_object_error=$(send_command aws --no-verify-ssl s3api get-object --bucket "$1" --key "$2" --range "$3" "$4" 2>&1); then
    log 2 "error getting object with range: $get_object_error"
    return 1
  fi
  return 0
}

get_object_with_user() {
  log 6 "get_object_with_user"
  record_command "get-object" "client:$1"
  if [ $# -ne 6 ]; then
    log 2 "'get object with user' command requires command type, bucket, key, save location, aws ID, aws secret key"
    return 1
  fi
  local exit_code=0
  if [[ $1 == 's3' ]] || [[ $1 == 's3api' ]] || [[ $1 == 'aws' ]]; then
    get_object_error=$(AWS_ACCESS_KEY_ID="$5" AWS_SECRET_ACCESS_KEY="$6" send_command aws --no-verify-ssl s3api get-object --bucket "$2" --key "$3" "$4" 2>&1) || exit_code=$?
  elif [[ $1 == "s3cmd" ]]; then
    log 5 "s3cmd filename: $3"
    get_object_error=$(send_command s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate --access_key="$5" --secret_key="$6" get "s3://$2/$3" "$4" 2>&1) || exit_code=$?
  elif [[ $1 == "mc" ]]; then
    log 5 "save location: $4"
    get_object_error=$(send_command mc --insecure get "$MC_ALIAS/$2/$3" "$4" 2>&1) || exit_code=$?
  elif [[ $1 == "rest" ]]; then
    get_object_rest_with_user "$5" "$6" "$2" "$3" "$4" || exit_code=$?
  else
    log 2 "'get_object_with_user' not implemented for client '$1'"
    return 1
  fi
  log 5 "get object exit code: $exit_code"
  if [ $exit_code -ne 0 ]; then
    log 2 "error getting object: $get_object_error"
    return 1
  fi
  return 0
}

get_object_rest() {
  log 6 "get_object_rest"
  if [ $# -ne 3 ]; then
    log 2 "'get_object_rest' requires bucket name, object name, output file"
    return 1
  fi
  if ! get_object_rest_with_user "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$1" "$2" "$3"; then
    log 2 "error getting REST object with root user"
    return 1
  fi
  return 0
}

get_object_rest_with_user() {
  if [ $# -ne 5 ]; then
    log 2 "'get_object_rest_with_user' requires username, password, bucket name, object name, output file"
    return 1
  fi
  if ! result=$(AWS_ACCESS_KEY_ID="$1" AWS_SECRET_ACCESS_KEY="$2" COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$3" OBJECT_KEY="$4" OUTPUT_FILE="$5" ./tests/rest_scripts/get_object.sh 2>&1); then
    log 2 "error getting object: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected '200', was '$result' ($(cat "$3"))"
    return 1
  fi
  return 0
}

get_object_rest_with_invalid_streaming_type() {
  if ! check_param_count_v2 "bucket, key" 2 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" OUTPUT_FILE="$TEST_FILE_FOLDER/$2_copy" PAYLOAD="GIBBERISH" ./tests/rest_scripts/get_object.sh 2>&1); then
    log 2 "error: $result"
    return 1
  fi
  if ! check_rest_expected_error "$result" "$TEST_FILE_FOLDER/$2_copy" "400" "InvalidArgument" "x-amz-content-sha256 must be"; then
    log 2 "error checking response"
    return 1
  fi
  return 0
}
