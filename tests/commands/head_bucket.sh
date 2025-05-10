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

# params: client, bucket name
# fail for invalid params, return
#   0 - bucket exists
#   1 - bucket does not exist
#   2 - misc error
head_bucket() {
  log 6 "head_bucket '$1' '$2'"
  record_command "head-bucket" "client:$1"
  if ! check_param_count "head_bucket" "client, bucket name" 2 $#; then
    return 1
  fi
  local exit_code=0
  if [[ $1 == 's3api' ]] || [[ $1 == 's3' ]]; then
    bucket_info=$(send_command aws --no-verify-ssl s3api head-bucket --bucket "$2" 2>&1) || exit_code=$?
  elif [[ $1 == "s3cmd" ]]; then
    bucket_info=$(send_command s3cmd --no-check-certificate info "s3://$2" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    bucket_info=$(send_command mc --insecure stat "$MC_ALIAS"/"$2" 2>&1) || exit_code=$?
  elif [[ $1 == 'rest' ]]; then
    bucket_info=$(head_bucket_rest "$2") || exit_code=$?
    log 5 "head bucket rest exit code: $exit_code"
    return $exit_code
  else
    log 2 "invalid command type $1"
  fi
  if [ $exit_code -ne 0 ]; then
    if [[ "$bucket_info" == *"404"* ]] || [[ "$bucket_info" == *"does not exist"* ]]; then
      return 1
    fi
    log 2 "error getting bucket info: $bucket_info"
    return 2
  fi
  bucket_info="$(echo -n "$bucket_info" | grep -v "InsecureRequestWarning")"
  echo "$bucket_info"
  return 0
}

head_bucket_rest() {
  log 6 "head_bucket_rest '$1'"
  if ! check_param_count "head_bucket_rest" "bucket" 1 $#; then
    return 2
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/head_bucket.sh 2>&1); then
    log 2 "error getting head bucket: $result"
    return 2
  fi
  if [ "$result" == "200" ]; then
    bucket_info="$(cat "$TEST_FILE_FOLDER/result.txt")"
    echo "$bucket_info"
    log 5 "bucket info: $bucket_info"
    return 0
  elif [ "$result" == "404" ]; then
    log 5 "bucket '$1' not found"
    return 1
  fi
  log 2 "unexpected response code '$result' ($(cat "$TEST_FILE_FOLDER/result.txt"))"
  return 2
}
