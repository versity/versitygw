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

list_check_buckets_rest() {
  if ! list_buckets "rest"; then
    log 2 "error listing buckets"
    return 1
  fi
  bucket_found=false
  # shellcheck disable=SC2154
  for bucket in "${bucket_array[@]}"; do
    log 5 "bucket: $bucket"
    if [[ $bucket == "$BUCKET_ONE_NAME" ]]; then
      bucket_found=true
      break
    fi
  done
  if [[ $bucket_found == "false" ]]; then
    log 2 "bucket not found"
    return 1
  fi
  return 0
}

list_and_check_buckets_with_user() {
  if [ $# -ne 5 ]; then
    log 2 "'list_and_check_buckets' requires client, two bucket names, id, key"
    return 1
  fi
  if ! list_buckets_with_user "$1" "$4" "$5"; then
    log 2 "error listing buckets"
    return 1
  fi

  local bucket_one_found=false
  local bucket_two_found=false
  if [ -z "$bucket_array" ]; then
    log 2 "bucket_array parameter not exported"
    return 1
  fi
  log 5 "bucket array: ${bucket_array[*]}"
  for bucket in "${bucket_array[@]}"; do
    if [ "$bucket" == "$2" ] || [ "$bucket" == "s3://$2" ]; then
      bucket_one_found=true
    elif [ "$bucket" == "$3" ] || [ "$bucket" == "s3://$3" ]; then
      bucket_two_found=true
    fi
    if [ $bucket_one_found == true ] && [ $bucket_two_found == true ]; then
      break
    fi
  done
  log 5 "buckets found? one: $bucket_one_found, two: $bucket_two_found"
  if [ $bucket_one_found == false ] || [ $bucket_two_found == false ]; then
    log 2 "Not all buckets found"
    return 1
  fi
  return 0
}

list_and_check_buckets() {
  if [ $# -ne 3 ]; then
    log 2 "'list_and_check_buckets' requires client, two bucket names"
  fi
  if ! list_and_check_buckets_with_user "$1" "$2" "$3" "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY"; then
    log 2 "error listing and checking buckets"
    return 1
  fi
  return 0
}

list_and_check_buckets_omit_without_permission() {
  if [ $# -ne 4 ]; then
    log 2 "'list_and_check_buckets_with_user' requires username, password, non-visible bucket, visible bucket"
    return 1
  fi
  if ! list_buckets_with_user "s3api" "$1" "$2"; then
    log 2 "error listing buckets with user '$1'"
    return 1
  fi
  bucket_found=false
  for bucket in "${bucket_array[@]}"; do
    if [ "$bucket" == "$3" ]; then
      log 2 "bucket '$3' shouldn't show up in user '$1' bucket list"
      return 1
    elif [ "$bucket" == "$4" ]; then
      bucket_found=true
    fi
  done
  if [ $bucket_found == false ]; then
    log 2 "user-owned bucket '$4' not found in user list"
    return 1
  fi
  return 0
}