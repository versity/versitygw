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

get_bucket_versioning() {
  record_command "get-bucket-versioning" "client:s3api"
  if [[ $# -ne 2 ]]; then
    log 2 "get bucket versioning command requires command type, bucket name"
    return 1
  fi
  local get_result=0
  if [[ $1 == 's3api' ]]; then
    versioning=$(send_command aws --no-verify-ssl s3api get-bucket-versioning --bucket "$2" 2>&1) || get_result=$?
  fi
  if [[ $get_result -ne 0 ]]; then
    log 2 "error getting bucket versioning: $versioning"
    return 1
  fi
  return 0
}

get_bucket_versioning_rest() {
  log 6 "get_object_rest"
  if [ $# -ne 1 ]; then
    log 2 "'get_bucket_versioning_rest' requires bucket name"
    return 1
  fi
  if ! result=$(COMMAND_LOG=$COMMAND_LOG BUCKET_NAME=$1 OUTPUT_FILE="$TEST_FILE_FOLDER/versioning.txt" ./tests/rest_scripts/get_bucket_versioning.sh); then
    log 2 "error getting bucket versioning: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "get-bucket-versioning returned code $result: $(cat "$TEST_FILE_FOLDER/versioning.txt")"
    return 1
  fi
  return 0
}