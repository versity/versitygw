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
  if ! list_buckets_rest "" "parse_bucket_list"; then
    log 2 "error listing buckets"
    return 1
  fi
  for bucket in "$@"; do
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
    bucket_array+=("$bucket")
  done <<< "$bucket_list"
  log 5 "bucket array: ${bucket_array[*]}"
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