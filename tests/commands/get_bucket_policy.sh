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

get_bucket_policy() {
  log 6 "get_bucket_policy '$1' '$2'"
  record_command "get-bucket-policy" "client:$1"
  if ! check_param_count "get_bucket_policy" "command type, bucket" 2 $#; then
    return 1
  fi
  local get_bucket_policy_result=0
  if [[ $1 == 's3api' ]]; then
    get_bucket_policy_s3api "$2" || get_bucket_policy_result=$?
  elif [[ $1 == 's3cmd' ]]; then
    get_bucket_policy_s3cmd "$2" || get_bucket_policy_result=$?
  elif [[ $1 == 'mc' ]]; then
    get_bucket_policy_mc "$2" || get_bucket_policy_result=$?
  elif [ "$1" == 'rest' ]; then
    get_bucket_policy_rest "$2" || get_bucket_policy_result=$?
  else
    log 2 "command 'get bucket policy' not implemented for '$1'"
    return 1
  fi
  if [[ $get_bucket_policy_result -ne 0 ]]; then
    log 2 "error getting policy: $bucket_policy"
    return 1
  fi
  return 0
}

get_bucket_policy_s3api() {
  log 6 "get_bucket_policy_s3api '$1'"
  record_command "get-bucket-policy" "client:s3api"
  if ! check_param_count "get_bucket_policy_s3api" "bucket" 1 $#; then
    return 1
  fi
  policy_json=$(send_command aws --no-verify-ssl s3api get-bucket-policy --bucket "$1" 2>&1) || local get_result=$?
  policy_json=$(echo "$policy_json" | grep -v "InsecureRequestWarning")
  log 5 "$policy_json"
  if [[ $get_result -ne 0 ]]; then
    if [[ "$policy_json" == *"(NoSuchBucketPolicy)"* ]]; then
      bucket_policy=
    else
      log 2 "error getting policy: $policy_json"
      return 1
    fi
  else
    bucket_policy=$(echo "$policy_json" | jq -r '.Policy')
  fi
  return 0
}

get_bucket_policy_with_user() {
  record_command "get-bucket-policy" "client:s3api"
  if ! check_param_count "get_bucket_policy_with_user" "bucket, username, password" 3 $#; then
    return 1
  fi
  if policy_json=$(AWS_ACCESS_KEY_ID="$2" AWS_SECRET_ACCESS_KEY="$3" send_command aws --no-verify-ssl s3api get-bucket-policy --bucket "$1" 2>&1); then
    policy_json=$(echo "$policy_json" | grep -v "InsecureRequestWarning")
    bucket_policy=$(echo "$policy_json" | jq -r '.Policy')
  else
    if [[ "$policy_json" == *"(NoSuchBucketPolicy)"* ]]; then
      bucket_policy=
    else
      log 2 "error getting policy for user $2: $policy_json"
      return 1
    fi
  fi
  return 0
}

get_bucket_policy_s3cmd() {
  record_command "get-bucket-policy" "client:s3cmd"
  if ! check_param_count "get_bucket_policy_s3cmd" "bucket" 1 $#; then
    return 1
  fi

  if ! info=$(send_command s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate info "s3://$1" 2>&1); then
    log 2 "error getting bucket policy: $info"
    return 1
  fi

  log 5 "policy info: $info"
  bucket_policy=""
  policy_brackets=false
  # NOTE:  versitygw sends policies back in multiple lines here, direct in single line
  while IFS= read -r line; do
    if check_and_load_policy_info; then
      break
    fi
  done <<< "$info"
  log 5 "bucket policy: $bucket_policy"
  return 0
}

get_bucket_policy_rest() {
  if ! check_param_count "get_bucket_policy_rest" "bucket" 1 $#; then
    return 1
  fi
  if ! get_bucket_policy_rest_expect_code "$1" "200"; then
    log 2 "error getting REST bucket policy"
    return 1
  fi
  return 0
}

get_bucket_policy_rest_expect_code() {
  if ! check_param_count "get_bucket_policy_rest_expect_code" "bucket, code" 2 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OUTPUT_FILE="$TEST_FILE_FOLDER/policy.txt" ./tests/rest_scripts/get_bucket_policy.sh); then
    log 2 "error attempting to get bucket policy response: $result"
    return 1
  fi
  if [ "$result" != "$2" ]; then
    log 2 "unexpected response code, expected '$2', actual '$result' (reply: $(cat "$TEST_FILE_FOLDER/policy.txt"))"
    return 1
  fi
  bucket_policy="$(cat "$TEST_FILE_FOLDER/policy.txt")"
}

# return 0 for no policy, single-line policy, or loading complete, 1 for still searching or loading
check_and_load_policy_info() {
  if [[ $policy_brackets == false ]]; then
    if search_for_first_policy_line_or_full_policy; then
      return 0
    fi
  else
    bucket_policy+=$line
    if [[ $line == "}" ]]; then
      return 0
    fi
  fi
  return 1
}

# return 0 for empty or single-line policy, 1 for other cases
search_for_first_policy_line_or_full_policy() {
  policy_line=$(echo "$line" | grep 'Policy: ')
  if [[ $policy_line != "" ]]; then
    if [[ $policy_line != *'{'* ]]; then
      return 0
    fi
    if [[ $policy_line == *'}'* ]]; then
      log 5 "policy on single line"
      bucket_policy=${policy_line//Policy:/}
      return 0
    else
      policy_brackets=true
      bucket_policy+="{"
    fi
  fi
  return 1
}

get_bucket_policy_mc() {
  record_command "get-bucket-policy" "client:mc"
  if ! check_param_count "get_bucket_policy_mc" "bucket" 1 $#; then
    return 1
  fi
  bucket_policy=$(send_command mc --insecure anonymous get-json "$MC_ALIAS/$1") || get_result=$?
  if [[ $get_result -ne 0 ]]; then
    log 2 "error getting policy: $bucket_policy"
    return 1
  fi
  return 0
}