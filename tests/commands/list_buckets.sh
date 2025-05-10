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

list_buckets() {
  log 6 "list_buckets"
  record_command "list-buckets" "client:$1"
  if [ $# -ne 1 ]; then
    log 2 "list buckets command missing command type"
    return 1
  fi

  local exit_code=0
  if [[ $1 == 's3' ]]; then
    buckets=$(send_command aws --no-verify-ssl s3 ls 2>&1 s3://) || exit_code=$?
  elif [[ $1 == 's3api' ]]; then
    list_buckets_s3api "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    buckets=$(send_command s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate ls s3:// 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    buckets=$(send_command mc --insecure ls "$MC_ALIAS" 2>&1) || exit_code=$?
  elif [[ $1 == 'rest' ]]; then
    list_buckets_rest || exit_code=$?
  else
    log 2 "list buckets command not implemented for '$1'"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    log 2 "error listing buckets: $buckets"
    return 1
  fi

  if [[ $1 == 's3api' ]] || [[ $1 == 'aws' ]] || [[ $1 == 'rest' ]]; then
    return 0
  fi

  bucket_array=()
  while IFS= read -r line; do
    bucket_name=$(echo "$line" | awk '{print $NF}')
    bucket_array+=("${bucket_name%/}")
  done <<< "$buckets"
  return 0
}

list_buckets_with_user() {
  record_command "list-buckets" "client:$1"
  if [ $# -ne 3 ]; then
    log 2 "'list buckets as user' command missing command type, username, password"
    return 1
  fi

  local exit_code=0
  if [[ $1 == 's3' ]]; then
    buckets=$(AWS_ACCESS_KEY_ID="$2" AWS_SECRET_ACCESS_KEY="$3" send_command aws --no-verify-ssl s3 ls 2>&1 s3://) || exit_code=$?
  elif [[ $1 == 's3api' ]] || [[ $1 == 'aws' ]]; then
    list_buckets_s3api "$2" "$3" || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    buckets=$(send_command s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate --access_key="$2" --secret_key="$3" ls s3:// 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    buckets=$(send_command mc --insecure ls "$MC_ALIAS" 2>&1) || exit_code=$?
  else
    log 2 "list buckets command not implemented for '$1'"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    log 2 "error listing buckets: $buckets"
    return 1
  fi

  if [[ $1 == 's3api' ]] || [[ $1 == 'aws' ]]; then
    return 0
  fi

  bucket_array=()
  while IFS= read -r line; do
    bucket_name=$(echo "$line" | awk '{print $NF}')
    bucket_array+=("${bucket_name%/}")
  done <<< "$buckets"
  return 0
}

list_buckets_s3api() {
  if [[ $# -ne 2 ]]; then
    log 2 "'list_buckets_s3api' requires username, password"
    return 1
  fi
  if ! output=$(AWS_ACCESS_KEY_ID="$1" AWS_SECRET_ACCESS_KEY="$2" send_command aws --no-verify-ssl s3api list-buckets 2>&1); then
    log 2 "error listing buckets: $output"
    return 1
  fi
  log 5 "bucket data: $output"

  modified_output=""
  while IFS= read -r line; do
    if [[ $line != *InsecureRequestWarning* ]]; then
      modified_output+="$line"
    fi
  done <<< "$output"

  bucket_array=()
  names=$(jq -r '.Buckets[].Name' <<<"$modified_output")
  IFS=$'\n' read -rd '' -a bucket_array <<<"$names"

  return 0
}

list_buckets_rest() {
  if ! result=$(COMMAND_LOG=$COMMAND_LOG OUTPUT_FILE="$TEST_FILE_FOLDER/buckets.txt" ./tests/rest_scripts/list_buckets.sh); then
    log 2 "error listing buckets: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "list-buckets returned code $result: $(cat "$TEST_FILE_FOLDER/buckets.txt")"
    return 1
  fi
  if ! parse_bucket_list "$TEST_FILE_FOLDER/buckets.txt"; then
    log 2 "error parsing bucket list"
    return 1
  fi
  return 0
}

list_buckets_rest_prefix() {
  if ! check_param_count_v2 "prefix" 1 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" PREFIX="$1" ./tests/rest_scripts/list_buckets.sh 2>&1); then
    log 2 "error getting result: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected '200', was '$result' ($(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  log 5 "buckets w/prefix $1: $(cat "$TEST_FILE_FOLDER/result.txt")"
  if ! parse_bucket_list "$TEST_FILE_FOLDER/result.txt"; then
    log 2 "error parsing bucket list"
    return 1
  fi
  return 0
}
