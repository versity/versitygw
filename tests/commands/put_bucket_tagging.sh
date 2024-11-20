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

put_bucket_tagging() {
  log 6 "put_bucket_tagging"
  if [ $# -ne 4 ]; then
    log 2 "bucket tag command missing command type, bucket name, key, value"
    return 1
  fi
  local error
  local result=0
  record_command "put-bucket-tagging" "client:$1"
  if [[ $1 == 's3api' ]]; then
    error=$(send_command aws --no-verify-ssl s3api put-bucket-tagging --bucket "$2" --tagging "TagSet=[{Key=$3,Value=$4}]") || result=$?
  elif [[ $1 == 'mc' ]]; then
    error=$(send_command mc --insecure tag set "$MC_ALIAS"/"$2" "$3=$4" 2>&1) || result=$?
  else
    log 2 "invalid command type $1"
    return 1
  fi
  if [[ $result -ne 0 ]]; then
    log 2 "Error adding bucket tag: $error"
    return 1
  fi
  return 0
}

put_bucket_tagging_with_user() {
  log 6 "put_bucket_tagging_with_user"
  assert [ $# -eq 5 ]
  record_command "put-bucket-tagging" "client:$1"
  if ! error=$(AWS_ACCESS_KEY_ID="$4" AWS_SECRET_ACCESS_KEY="$5" send_command aws --no-verify-ssl s3api put-bucket-tagging --bucket "$1" --tagging "TagSet=[{Key=$2,Value=$3}]"); then
    log 2 "error putting bucket tagging: $error"
    return 1
  fi
  return 0
}
