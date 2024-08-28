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
  record_command "get-object" "client:$1"
  if [ $# -ne 4 ]; then
    log 2 "get object command requires command type, bucket, key, destination"
    return 1
  fi
  local exit_code=0
  local error
  if [[ $1 == 's3' ]]; then
    get_object_error=$(aws --no-verify-ssl s3 mv "s3://$2/$3" "$4" 2>&1) || exit_code=$?
  elif [[ $1 == 's3api' ]] || [[ $1 == 'aws' ]]; then
    get_object_error=$(aws --no-verify-ssl s3api get-object --bucket "$2" --key "$3" "$4" 2>&1) || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    get_object_error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate get "s3://$2/$3" "$4" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    get_object_error=$(mc --insecure get "$MC_ALIAS/$2/$3" "$4" 2>&1) || exit_code=$?
  else
    log 2 "'get object' command not implemented for '$1'"
    return 1
  fi
  log 5 "get object exit code: $exit_code"
  if [ $exit_code -ne 0 ]; then
    log 2 "error getting object: $get_object_error"
    export get_object_error
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
  error=$(aws --no-verify-ssl s3api get-object --bucket "$1" --key "$2" --range "$3" "$4" 2>&1) || local exit_code=$?
  if [[ $exit_code -ne 0 ]]; then
    log 2 "error getting object with range: $error"
    return 1
  fi
  return 0
}

get_object_with_user() {
  record_command "get-object" "client:$1"
  if [ $# -ne 6 ]; then
    log 2 "'get object with user' command requires command type, bucket, key, save location, aws ID, aws secret key"
    return 1
  fi
  local exit_code=0
  if [[ $1 == 's3api' ]] || [[ $1 == 'aws' ]]; then
    get_object_error=$(AWS_ACCESS_KEY_ID="$5" AWS_SECRET_ACCESS_KEY="$6" aws --no-verify-ssl s3api get-object --bucket "$2" --key "$3" "$4" 2>&1) || exit_code=$?
  else
    log 2 "'get object with user' command not implemented for '$1'"
    return 1
  fi
  log 5 "put object exit code: $exit_code"
  if [ $exit_code -ne 0 ]; then
    log 2 "error getting object: $get_object_error"
    return 1
  fi
  return 0
}
