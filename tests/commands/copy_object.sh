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

copy_object() {
  if [ $# -ne 4 ]; then
    log 2 "copy object command requires command type, source, bucket, key"
    return 1
  fi
  local exit_code=0
  local error
  record_command "copy-object" "client:$1"
  if [[ $1 == 's3' ]]; then
    error=$(send_command aws --no-verify-ssl s3 cp "$2" s3://"$3/$4" 2>&1) || exit_code=$?
  elif [[ $1 == 's3api' ]]; then
    error=$(send_command aws --no-verify-ssl s3api copy-object --copy-source "$2" --bucket "$3" --key "$4" 2>&1) || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    log 5 "s3cmd ${S3CMD_OPTS[*]} --no-check-certificate cp s3://$2 s3://$3/$4"
    error=$(send_command s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate cp "s3://$2" s3://"$3/$4" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    error=$(send_command mc --insecure cp "$MC_ALIAS/$2" "$MC_ALIAS/$3/$4" 2>&1) || exit_code=$?
  else
    log 2 "'copy-object' not implemented for '$1'"
    return 1
  fi
  log 5 "copy object exit code: $exit_code"
  if [ $exit_code -ne 0 ]; then
    log 2 "error copying object to bucket: $error"
    return 1
  fi
  return 0
}

copy_object_empty() {
  record_command "copy-object" "client:s3api"
  error=$(send_command aws --no-verify-ssl s3api copy-object 2>&1) || local result=$?
  if [[ $result -eq 0 ]]; then
    log 2 "copy object with empty parameters returned no error"
    return 1
  fi
  if [[ $error != *"the following arguments are required: --bucket, --copy-source, --key"* ]]; then
    log 2 "copy object with no params returned mismatching error: $error"
    return 1
  fi
  return 0
}
