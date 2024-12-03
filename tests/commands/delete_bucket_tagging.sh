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

delete_bucket_tagging() {
  record_command "delete-bucket-tagging" "client:$1"
  if [ $# -ne 2 ]; then
    log 2 "delete bucket tagging command missing command type, bucket name"
    return 1
  fi
  local result
  if [[ $1 == 's3api' ]]; then
    tags=$(send_command aws --no-verify-ssl s3api delete-bucket-tagging --bucket "$2" 2>&1) || result=$?
  elif [[ $1 == 'mc' ]]; then
    tags=$(send_command mc --insecure tag remove "$MC_ALIAS"/"$2" 2>&1) || result=$?
  else
    log 2 "invalid command type $1"
    return 1
  fi
  if [[ $result -ne 0 ]]; then
    log 2 "error deleting bucket tagging: $tags"
    return 1
  fi
  return 0
}

delete_bucket_tagging_with_user() {
  log 6 "delete_bucket_tagging_with_user"
  record_command "delete-bucket-tagging" "client:s3api"
  if [ $# -ne 3 ]; then
    log 2 "delete bucket tagging command missing username, password, bucket name"
    return 1
  fi
  if ! error=$(send_command AWS_ACCESS_KEY_ID="$1" AWS_SECRET_ACCESS_KEY="$2" aws --no-verify-ssl s3api delete-bucket-tagging --bucket "$3" 2>&1); then
    log 2 "error deleting bucket tagging with user: $error"
    return 1
  fi
  return 0
}
