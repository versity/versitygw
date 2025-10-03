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

bucket_exists_in_list() {
  if ! check_param_count_v2 "bucket" 1 $#; then
    return 1
  fi
  for bucket in "${bucket_array[@]}"; do
    if [ "$bucket" == "$1" ]; then
      return 0
    fi
  done
  return 1
}

list_check_buckets_rest() {
  if ! check_param_count_gt "expected buckets" 1 $#; then
    return 1
  fi
  if ! list_check_buckets_rest_with_params "" "$@"; then
    log 2 "error listing and checking buckets"
    return 1
  fi
  return 0
}

list_check_buckets_rest_with_params() {
  if ! check_param_count_gt "params, expected buckets" 2 $#; then
    return 1
  fi
  if ! list_buckets_rest "$1" "parse_bucket_list"; then
    log 2 "error listing buckets"
    return 1
  fi
  for bucket in "${@:2}"; do
    log 5 "bucket: $bucket"
    if ! bucket_exists_in_list "$bucket"; then
      log 2 "bucket $bucket not found"
      return 1
    fi
  done
    return 0
}

parse_bucket_list() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  # shellcheck disable=SC2154
  log 5 "bucket list: $(cat "$1")"
  bucket_list=$(xmllint --xpath '//*[local-name()="Bucket"]/*[local-name()="Name"]/text()' "$1")
  bucket_array=()
  while read -r bucket; do
    if [ -n "$bucket" ]; then
      log 5 "reading bucket '$bucket'"
      bucket_array+=("$bucket")
    fi
  done <<< "$bucket_list"
  log 5 "bucket array: ${bucket_array[*]}"
  log 5 "bucket array length: ${#bucket_array[@]}"
}

parse_buckets_and_continuation_token() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  if ! parse_bucket_list "$1"; then
    log 2 "error parsing bucket list"
    return 1
  fi
  continuation_token=$(xmllint --xpath '//*[local-name()="ListAllMyBucketsResult"]/*[local-name()="ContinuationToken"]/text()' "$1")
  log 5 "token: $continuation_token"
  return 0
}

check_continuation_token() {
  if ! list_buckets_rest "MAX_BUCKETS=1" "parse_buckets_and_continuation_token"; then
    log 2 "error listing buckets"
    return 1
  fi
  if [ ${#bucket_array[@]} != "1" ]; then
    log 2 "expected one bucket to be returned, was ${#bucket_array}"
    return 1
  fi
  if [ "${bucket_array[0]}" == "$continuation_token" ]; then
    log 2 "continuation token shouldn't be bucket name"
    return 1
  fi
}

check_for_buckets_with_multiple_pages() {
  if ! check_param_count_v2 "buckets" 2 $#; then
    return 1
  fi
  if ! list_buckets_rest "MAX_BUCKETS=1" "parse_buckets_and_continuation_token"; then
    log 2 "error listing buckets"
    return 1
  fi
  bucket_one_found="false"
  bucket_two_found="false"
  while true; do
    if [ "$bucket_one_found" == "false" ] && [ "${bucket_array[0]}" == "$1" ]; then
      bucket_one_found="true"
    elif [ "$bucket_two_found" == "false" ] && [ "${bucket_array[0]}" == "$2" ]; then
      bucket_two_found="true"
    fi
    if [ "$bucket_one_found" == "true" ] && [ "$bucket_two_found" == "true" ]; then
      break
    fi
    if [ "$continuation_token" == "" ]; then
      break
    fi
    if ! list_buckets_rest "MAX_BUCKETS=1 CONTINUATION_TOKEN=$continuation_token" "parse_buckets_and_continuation_token"; then
      log 2 "error"
      return 1
    fi
  done
  if [ "$bucket_one_found" == "false" ]; then
    log 2 "bucket '$1' not found in list"
    return 1
  fi
  if [ "$bucket_two_found" == "false" ]; then
    log 2 "bucket '$2' not found in list"
    return 1
  fi
  return 0
}

list_check_buckets_rest_with_prefix() {
  log 6 "list_check_buckets_rest_with_prefix"
  if ! check_param_count_v2 "prefix" 1 $#; then
    return 1
  fi
  if ! list_buckets_rest "PREFIX=$1" "parse_bucket_list"; then
    log 2 "error listing buckets with prefix"
    return 1
  fi
  log 5 "buckets: ${bucket_array[*]}"
  local buckets_found=false
  for bucket in "$@"; do
    log 5 "bucket: $bucket"
    if [[ "$bucket" != "$1"* ]]; then
      log 2 "bucket doesn't match prefix"
      return 1
    fi
    buckets_found="true"
  done
  if [ "$buckets_found" == "false" ]; then
    log 2 "no buckets with prefix '$1' found"
    return 1
  fi
  return 0
}

list_buckets_check_authorization_scheme_error() {
  bad_scheme_name="AWS-HMAC-SHA25"
  if ! send_rest_go_command_expect_error_callback "400" "InvalidArgument" "Unsupported Authorization Type" "parse_and_check_authorization_data" "-authorizationScheme" "$bad_scheme_name"; then
    log 2 "error sending command and checking results"
    return 1
  fi
}

parse_and_check_authorization_data() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  # shellcheck disable=SC2154
  log 5 "bucket list: $(cat "$1")"
  if ! argument_name=$(get_element_text "$1" "Error" "ArgumentName"); then
    log 2 "error getting argument name"
    return 1
  fi
  if [ "$argument_name" != "Authorization" ]; then
    log 2 "expected 'Authorization', was '$argument_name'"
    return 1
  fi
  if ! argument_value=$(get_element_text "$1" "Error" "ArgumentValue"); then
    log 2 "error getting argument value"
    return 1
  fi
  if [[ "$argument_value" != "$bad_scheme_name "* ]]; then
    log 2 "expected '$argument_value' to start with '$bad_scheme_name'"
    return 1
  fi
  return 0
}

list_buckets_check_request_time_too_skewed_error() {
  bad_scheme_name="AWS-HMAC-SHA25"
  if ! send_rest_go_command_expect_error_callback "403" "RequestTimeTooSkewed" "difference between the request time and the " \
      "parse_and_check_time_skew_parameters" "-incorrectYearMonthDay"; then
    log 2 "error sending command and checking results"
    return 1
  fi
}

is_iso8601() {
  if ! check_param_count_v2 "date" 1 $#; then
    return 1
  fi
  if [[ "$1" =~ ^[0-9]{8}[Tt\ ][0-9]{6}Z$ ]]; then
    return 0
  fi
  if [[ "$1" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}([Tt ][0-9]{2}:[0-9]{2}(:[0-9]{2})?(Z|[+-][0-9]{2}(:?[0-9]{2})?)?)?$ ]]; then
    return 0
  fi
  return 1
}

parse_and_check_time_skew_parameters() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  if ! request_time=$(get_element_text "$1" "Error" "RequestTime"); then
    log 2 "error getting request time"
    return 1
  fi
  if ! is_iso8601 "$request_time"; then
    log 2 "'$request_time' is not valid ISO-8601"
    return 1
  fi
  if ! server_time=$(get_element_text "$1" "Error" "ServerTime"); then
    log 2 "error getting request time"
    return 1
  fi
  if ! is_iso8601 "$server_time"; then
    log 2 "'$request_time' is not valid ISO-8601"
    return 1
  fi
  if ! max_allowed_skew_milliseconds=$(get_element_text "$1" "Error" "MaxAllowedSkewMilliseconds"); then
    log 2 "error getting max allowed skew milliseconds"
    return 1
  fi
  if ! [[ "$max_allowed_skew_milliseconds" =~ ^[0-9]+$ ]]; then
    log 2 "'$max_allowed_skew_milliseconds' is not a valid integer"
    return 1
  fi
  return 0
}

list_check_buckets_user() {
  if ! check_param_count_gt "username, password, minimum of one bucket" 3 $#; then
    return 1
  fi
  if ! list_check_buckets_rest_with_params "AWS_ACCESS_KEY_ID=$1 AWS_SECRET_ACCESS_KEY=$2" "${@:3}"; then
    log 2 "error sending go command"
    return 1
  fi
  if [ ${#bucket_array[@]} != ${#:3} ]; then
    log 2 "unexpected number of buckets"
    return 1
  fi
  return 0
}
