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
  if ! check_param_count_gt "bucket, expected keys" 1 $#; then
    return 1
  fi
  if ! response=$(list_objects_s3api_v1 "$1" 2>&1); then
    log 2 "error listing objects (s3api, v1): $response"
    return 1
  fi
  object_json="$response"
  log 5 "object JSON: $response"

  if ! check_listed_objects "$object_json" "${@:2}"; then
    log 2 "error checking listed objects v2"
    return 1
  fi
  return 0
}

check_listed_objects() {
  if ! check_param_count_gt "JSON data, expected keys (if any)" 1 $#; then
    return 1
  fi
  expected_key_count="$(($#-1))"
  if ! response=$(echo "$1" | jq '.Contents | length' 2>&1); then
    log 2 "error getting length: $response"
    return 1
  fi
  key_count="$response"
  if [ "$key_count" -ne "$expected_key_count" ]; then
    log 2 "expected key count of '$expected_key_count', was '$key_count'"
    return 1
  fi

  declare -A key_array size_array
  for ((i=0; i<key_count; i++)); do
    if ! response=$(echo "$1" | jq -r ".Contents[$i].Key" 2>&1); then
      log 2 "error obtaining key one: $response"
      return 1
    fi
    key="$response"
    key_array["$key"]="true"
    if ! response=$(echo "$1" | jq -r ".Contents[$i].Size" 2>&1); then
      log 2 "error obtaining key one: $response"
      return 1
    fi
    size_array["$key"]="$response"
  done

  for expected_key in "${@:2}"; do
    if [ "${key_array[$expected_key]}" != "true" ]; then
      continue
    fi
    if ! response=$(get_file_size "$TEST_FILE_FOLDER/$expected_key" 2>&1); then
      log 2 "error getting file size: $response"
      return 1
    fi
    if [ "${size_array[$expected_key]}" != "$response" ]; then
      log 2 "size mismatch, expected '${size_array[$expected_key]}', was $response"
      return 1
    fi
    unset key_array["$expected_key"]
  done
  if [ ${#key_array[@]} -ne 0 ]; then
    log 2 "key mismatch: keys left over: '${!key_array[*]}'"
    return 1
  fi
  return 0
}

list_check_objects_v2() {
  if ! check_param_count_gt "bucket, expected keys" 1 $#; then
    return 1
  fi
  if ! response=$(list_objects_v2 "$1" 2>&1); then
    log 2 "error listing objects (s3api, v2): $response"
    return 1
  fi
  object_json="$response"

  if ! check_listed_objects "$object_json" "${@:2}"; then
    log 2 "error checking listed objects"
    return 1
  fi
  return 0
}

check_object_listing_with_prefixes() {
  if ! check_param_count "check_object_listing_with_prefixes" "bucket, folder name, object name" 3 $#; then
    return 1
  fi
  if ! response=$(list_objects_s3api_v1 "$1" "/" 2>&1); then
    log 2 "error listing objects with delimiter '/': $response"
    return 1
  fi
  object_json="$response"

  if ! prefix=$(echo "$object_json" | jq -r ".CommonPrefixes[0].Prefix" 2>&1); then
    log 2 "error getting object prefix from object list: $prefix"
    return 1
  fi
  if [[ $prefix != "$2/" ]]; then
    log 2 "prefix doesn't match (expected $2, actual $prefix/)"
    return 1
  fi
  if ! response=$(list_objects_s3api_v1 "$1" "#" 2>&1); then
    log 2 "error listing objects with delimiter '#: $response"
    return 1
  fi
  objects="$response"

  if ! key=$(echo "$objects" | jq -r ".Contents[0].Key" 2>&1); then
    log 2 "error getting key from object list: $key"
    return 1
  fi
  if [[ $key != "$2/$3" ]]; then
    log 2 "key doesn't match (expected $key, actual $2/$3)"
    return 1
  fi
  return 0
}
