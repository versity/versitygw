#!/usr/bin/env bash

# Copyright 2026 Versity Software
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

list_check_objects_v1() {
  if ! check_param_count "list_check_objects_v1" "bucket, expected key one, expected size one, expected key two, expected size two" 5 $#; then
    return 1
  fi
  if ! list_objects_s3api_v1 "$1"; then
    log 2 "error listing objects (s3api, v1)"
    return 1
  fi
  if ! check_listed_objects "$2" "$3" "$4" "$5"; then
    log 2 "error checking listed objects"
    return 1
  fi
  return 0
}

check_listed_objects() {
  if ! check_param_count "check_listed_objects" "expected key one, expected size one, expected key two, expected size two" 4 $#; then
    return 1
  fi
  # shellcheck disable=SC2154
  if ! key_one=$(echo "$objects" | jq -r '.Contents[0].Key' 2>&1); then
    log 2 "error obtaining key one: $key_one"
    return 1
  fi
  if [[ $key_one != "$1" ]]; then
    log 2 "Object one mismatch ($key_one, $1)"
    return 1
  fi
  if ! size_one=$(echo "$objects" | jq -r '.Contents[0].Size' 2>&1); then
    log 2 "error obtaining size one: $size_one"
    return 1
  fi
  if [[ $size_one -ne "$2" ]]; then
    log 2 "Object one size mismatch ($size_one, $2)"
    return 1
  fi
  if ! key_two=$(echo "$objects" | jq -r '.Contents[1].Key' 2>&1); then
    log 2 "error obtaining key two: $key_two"
    return 1
  fi
  if [[ $key_two != "$3" ]]; then
    log 2 "Object two mismatch ($key_two, $3)"
    return 1
  fi
  if ! size_two=$(echo "$objects" | jq '.Contents[1].Size' 2>&1); then
    log 2 "error obtaining size two: $size_two"
    return 1
  fi
  if [[ $size_two -ne "$4" ]]; then
    log 2 "Object two size mismatch ($size_two, $4)"
    return 1
  fi
}

list_check_objects_v2() {
  if ! check_param_count "list_check_objects_v2" "bucket, expected key one, expected size one, expected key two, expected size two" 5 $#; then
    return 1
  fi
  if ! list_objects_v2 "$1"; then
    log 2 "error listing objects (s3api, v1)"
    return 1
  fi
  if ! check_listed_objects "$2" "$3" "$4" "$5"; then
    log 2 "error checking listed objects"
    return 1
  fi
  return 0
}

check_object_listing_with_prefixes() {
  if ! check_param_count "check_object_listing_with_prefixes" "bucket, folder name, object name" 3 $#; then
    return 1
  fi
  if ! list_objects_s3api_v1 "$BUCKET_ONE_NAME" "/"; then
    log 2 "error listing objects with delimiter '/'"
    return 1
  fi
  if ! prefix=$(echo "${objects[@]}" | jq -r ".CommonPrefixes[0].Prefix" 2>&1); then
    log 2 "error getting object prefix from object list: $prefix"
    return 1
  fi
  if [[ $prefix != "$2/" ]]; then
    log 2 "prefix doesn't match (expected $2, actual $prefix/)"
    return 1
  fi
  if ! list_objects_s3api_v1 "$BUCKET_ONE_NAME" "#"; then
    log 2 "error listing objects with delimiter '#"
    return 1
  fi
  if ! key=$(echo "${objects[@]}" | jq -r ".Contents[0].Key" 2>&1); then
    log 2 "error getting key from object list: $key"
    return 1
  fi
  if [[ $key != "$2/$3" ]]; then
    log 2 "key doesn't match (expected $key, actual $2/$3)"
    return 1
  fi
  return 0
}
