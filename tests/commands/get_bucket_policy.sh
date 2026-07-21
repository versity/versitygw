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
  if ! check_param_count "get_bucket_policy" "command type, bucket" 2 $#; then
    return 1
  fi
  local command_type="$1" bucket="$2"
  local response get_bucket_policy_result=0

  if [[ $command_type == 's3api' ]]; then
    response=$(get_bucket_policy_s3api "$bucket" 2>&1) || get_bucket_policy_result=$?
  elif [[ $command_type == 's3cmd' ]]; then
    response=$(get_bucket_policy_s3cmd "$bucket" 2>&1) || get_bucket_policy_result=$?
  elif [[ $command_type == 'mc' ]]; then
    response=$(get_bucket_policy_mc "$bucket" 2>&1) || get_bucket_policy_result=$?
  elif [ "$command_type" == 'rest' ]; then
    response=$(get_bucket_policy_rest "$bucket" 2>&1) || get_bucket_policy_result=$?
  else
    log 2 "command 'get bucket policy' not implemented for '$command_type'"
    return 1
  fi
  if [[ $get_bucket_policy_result -ne 0 ]]; then
    log 2 "error getting policy: $response"
    return 1
  fi
  echo "$response"
  return 0
}

get_bucket_policy_s3api() {
  log 6 "get_bucket_policy_s3api '$1'"
  if ! check_param_count "get_bucket_policy_s3api" "bucket" 1 $#; then
    return 1
  fi
  local bucket="$1"
  local response policy_json bucket_policy

  if ! response=$(send_command aws --no-verify-ssl s3api get-bucket-policy --bucket "$bucket" 2>&1); then
    if [[ "$response" == *"(NoSuchBucketPolicy)"* ]]; then
      bucket_policy=
    else
      log 2 "error getting policy: $response"
      return 1
    fi
  fi
  policy_json=$(echo "$response" | grep -v "InsecureRequestWarning")
  bucket_policy=$(echo "$policy_json" | jq -r '.Policy')
  echo "$bucket_policy"
  return 0
}

get_bucket_policy_with_user() {
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
  if ! check_param_count "get_bucket_policy_s3cmd" "bucket" 1 $#; then
    return 1
  fi
  local bucket="$1"
  local response s3cmd_response bucket_policy

  if ! response=$(send_command s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate --region "$AWS_REGION" info "s3://$bucket" 2>&1); then
    log 2 "error getting bucket policy: $response"
    return 1
  fi
  s3cmd_response="$response"

  log 5 "policy info: $response"
  # NOTE:  versitygw sends policies back in multiple lines here, direct in single line
  if ! response=$(parse_s3cmd_policy "$s3cmd_response"); then
    log 2 "error parsing s3cmd policy: $response"
    return 1
  fi
  log 5 "bucket policy: $response"
  echo "$response"
  return 0
}

parse_s3cmd_policy() {
  if ! check_param_count_v2 "response data" 1 $#; then
    return 1
  fi

  local response_data="$1"
  local line policy=""

  while IFS= read -r line; do
    if [[ -z $policy ]]; then
      [[ $line =~ ^[[:space:]]*Policy:[[:space:]]*(.*)$ ]] || continue
      policy=${BASH_REMATCH[1]}
    else
      policy+=$'\n'"$line"
    fi

    if [ "$policy" == "none" ]; then
      echo ""
      return 0
    elif jq -e . >/dev/null 2>&1 <<<"$policy"; then
      printf '%s\n' "$policy"
      return 0
    fi
  done <<< "$response_data"

  log 2 "policy data not found (data: '$response_data')"
  return 1
}

get_bucket_policy_rest() {
  if ! check_param_count_ge_le "bucket, region (optional)" 1 2 $#; then
    return 1
  fi
  local bucket="$1" region="$2"
  local response

  log 5 "aws region: $2"
  if ! response=$(get_bucket_policy_rest_expect_code "$bucket" "200" "$region" 2>&1); then
    log 2 "error getting REST bucket policy: $response"
    return 1
  fi
  echo "$response"
  return 0
}

get_bucket_policy_rest_go() {
  if ! check_param_count_gt "bucket, params (optional)" 1 $#; then
    return 1
  fi
  local bucket="$1" params=("${@:2}")
  local response

  if ! response=$(send_rest_go_command "200" "-bucketName" "$bucket" "-query" "policy" "${params[@]}" 2>&1); then
    log 2 "error getting bucket policy: $response"
    return 1
  fi
  echo "$response"
  return 0
}

get_bucket_policy_rest_expect_code() {
  if ! check_param_count_ge_le "bucket, code, region (optional)" 2 3 $#; then
    return 1
  fi
  local bucket_name="$1" expected_response_code="$2" region="$3"
  local region_string response file_name

  if [ "$region" != "" ]; then
    region_string="AWS_REGION=$3"
  else
    region_string="AWS_REGION=$AWS_REGION"
  fi

  if ! response=$(get_file_name 2>&1); then
    log 2 "error getting file name: $response"
    return 1
  fi
  file_name="$response"

  if ! response=$(env COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$bucket_name" OUTPUT_FILE="$TEST_FILE_FOLDER/$file_name" "$region_string" ./tests/rest_scripts/get_bucket_policy.sh 2>&1); then
    log 2 "error attempting to get bucket policy response: $response"
    return 1
  fi
  if [ "$response" != "$expected_response_code" ]; then
    log 2 "unexpected response code, expected '$expected_response_code', actual '$response' (reply: '$(cat "$TEST_FILE_FOLDER/$file_name")')"
    return 1
  fi
  bucket_policy="$(cat "$TEST_FILE_FOLDER/$file_name")"
  echo "$bucket_policy"
  return 0
}

# return 0 for empty or single-line policy, 1 for not found or in progress, 2 for error
search_for_first_policy_line_or_full_policy() {
  if ! check_param_count_v2 "line" 1 $#; then
    return 2
  fi
  local line="$1"
  local policy_line

  if grep 'Policy: ' "$line" >/dev/null; then
    if [[ $line != *'{'* ]]; then
      echo ""
      return 0
    fi
    if [[ $line == *'}'* ]]; then
      log 5 "policy on single line"
      policy_line=${line//Policy:/}
      echo "$policy_line"
      return 0
    else
      echo "{"
    fi
  fi
  return 1
}

get_bucket_policy_mc() {
  if ! check_param_count "get_bucket_policy_mc" "bucket" 1 $#; then
    return 1
  fi
  bucket_policy=$(send_command mc --insecure anonymous get-json "$MC_ALIAS/$1" 2>&1) || get_result=$?
  if [[ $get_result -ne 0 ]]; then
    log 2 "error getting policy: $bucket_policy"
    return 1
  fi
  return 0
}