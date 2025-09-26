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

source ./tests/commands/list_buckets.sh

delete_buckets_with_prefix() {
  if ! check_param_count_v2 "bucket prefix" 1 $#; then
    return 1
  fi
  if [ "$1" == "" ]; then
    log 2 "delete_buckets_with_prefix requires non-empty prefix"
    return 1
  fi
  if ! list_buckets_rest "PREFIX=$1" "parse_bucket_list"; then
    log 2 "error listing buckets with prefix"
    return 1
  fi
  # shellcheck disable=SC2154
  log 5 "buckets: ${bucket_array[*]}"
  for bucket in "${bucket_array[@]}"; do
    if ! delete_bucket_recursive "$bucket"; then
      log 2 "error with recursive bucket delete of bucket '$bucket'"
      return 1
    fi
  done
  return 0
}

cleanup_buckets() {
  if ! bucket_cleanup_if_bucket_exists_v2 "$BUCKET_ONE_NAME"; then
    log 3 "error deleting bucket $BUCKET_ONE_NAME or contents"
  fi
  if ! bucket_cleanup_if_bucket_exists_v2 "$BUCKET_TWO_NAME"; then
    log 3 "error deleting bucket $BUCKET_TWO_NAME or contents"
  fi
}

# params:  client, bucket name
# return 0 for success, 1 for error
bucket_cleanup() {
  log 6 "bucket_cleanup"
  if ! check_param_count "bucket_cleanup" "bucket name" 1 $#; then
    return 1
  fi
  if [[ $RECREATE_BUCKETS == "false" ]]; then
    if ! reset_bucket "$1"; then
      log 2 "error deleting bucket contents"
      return 1
    fi

    log 5 "bucket contents, policy, ACL deletion success"
    return 0
  fi
  if ! delete_bucket_recursive "$1"; then
    log 2 "error with recursive bucket delete"
    return 1
  fi
  log 5 "bucket deletion success"
  return 0
}

# params: client, bucket name
# return 0 for success, 1 for error
bucket_cleanup_if_bucket_exists() {
  log 6 "bucket_cleanup_if_bucket_exists"
  if ! check_param_count_gt "bucket name, bucket known to exist (optional)" 1 $#; then
    return 1
  fi

  if [ "$2" == "false" ]; then
    log 5 "skipping cleanup, since bucket doesn't exist"
    return 0
  fi

  if [ "$2" == "true" ] || bucket_exists "$1"; then
    if ! bucket_cleanup "$1"; then
      log 2 "error deleting bucket and/or contents"
      return 1
    fi
    log 5 "bucket and/or bucket data deletion success"
    return 0
  fi
  return 0
}

bucket_cleanup_if_bucket_exists_v2() {
  log 6 "bucket_cleanup_if_bucket_exists_v2"
  if ! check_param_count_gt "bucket name or prefix" 1 $#; then
    return 1
  fi
  if [[ "$RECREATE_BUCKETS" == "false" ]]; then
    if ! bucket_exists "$1"; then
      log 2 "When RECREATE_BUCKETS isn't set to \"true\", bucket with full env name should be pre-created by user"
      return 1
    fi
    if ! reset_bucket "$1"; then
      log 2 "error resetting bucket before tests"
      return 1
    fi
    return 0
  else
    if ! delete_buckets_with_prefix "$1"; then
      log 2 "error deleting buckets with prefix '$1'"
      return 1
    fi
  fi
  return 0
}
