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
  if [ $# -ne 3 ]; then
    log 2 "delete object command requires command type, bucket, key"
    return 1
  fi
  local exit_code=0
  if [[ $1 == 's3' ]]; then
    delete_object_error=$(aws --no-verify-ssl s3 rm "s3://$2/$3" 2>&1) || exit_code=$?
  elif [[ $1 == 's3api' ]] || [[ $1 == 'aws' ]]; then
    delete_object_error=$(aws --no-verify-ssl s3api delete-object --bucket "$2" --key "$3" 2>&1) || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    delete_object_error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate rm "s3://$2/$3" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    delete_object_error=$(mc --insecure rm "$MC_ALIAS/$2/$3" 2>&1) || exit_code=$?
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
  if [[ $# -ne 4 ]]; then
    log 2 "'delete-object with bypass retention' requires bucket, key, user, password"
    return 1
  fi
  if ! delete_object_error=$(AWS_ACCESS_KEY_ID="$3" AWS_SECRET_ACCESS_KEY="$4" aws --no-verify-ssl s3api delete-object --bucket "$1" --key "$2" --bypass-governance-retention 2>&1); then
    log 2 "error deleting object with bypass retention: $delete_object_error"
    return 1
  fi
  return 0
}

delete_object_with_user() {
  record_command "delete-object" "client:$1"
  if [ $# -ne 5 ]; then
    log 2 "delete object with user command requires command type, bucket, key, access ID, secret key"
    return 1
  fi
  local exit_code=0
  if [[ $1 == 's3' ]]; then
    delete_object_error=$(AWS_ACCESS_KEY_ID="$4" AWS_SECRET_ACCESS_KEY="$5" aws --no-verify-ssl s3 rm "s3://$2/$3" 2>&1) || exit_code=$?
  elif [[ $1 == 's3api' ]] || [[ $1 == 'aws' ]]; then
    delete_object_error=$(AWS_ACCESS_KEY_ID="$4" AWS_SECRET_ACCESS_KEY="$5" aws --no-verify-ssl s3api delete-object --bucket "$2" --key "$3" --bypass-governance-retention 2>&1) || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    delete_object_error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate rm --access_key="$4" --secret_key="$5" "s3://$2/$3" 2>&1) || exit_code=$?
  else
    log 2 "command 'delete object with user' not implemented for '$1'"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    log 2 "error deleting object: $delete_object_error"
    export delete_object_error
    return 1
  fi
  return 0
}