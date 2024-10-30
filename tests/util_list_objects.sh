#!/usr/bin/env bash

source ./tests/commands/list_objects_v2.sh

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

parse_objects_list_rest() {
  # shellcheck disable=SC2154
  object_list=$(echo "$reply" | xmllint --xpath '//*[local-name()="Key"]/text()' -)
  object_array=()
  while read -r object; do
    object_array+=("$object")
  done <<< "$object_list"
  log 5 "object array: ${object_array[*]}"
}

list_check_objects_v1() {
  if [ $# -ne 5 ]; then
    log 2 "'list_check_objects_v1' requires bucket, expected key one, expected size one, expected key two, expected size two"
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
  if [ $# -ne 4 ]; then
    log 2 "'check_listed_objects' requires expected key one, expected size one, expected key two, expected size two"
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
  if [ $# -ne 5 ]; then
    log 2 "'list_check_objects_v1' requires bucket, expected key one, expected size one, expected key two, expected size two"
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

list_check_objects_rest() {
  if [ $# -ne 1 ]; then
    log 2 "'list_check_objects_rest' requires bucket name"
    return 1
  fi
  list_objects "rest" "$1"
  object_found=false
  # shellcheck disable=SC2154
  for object in "${object_array[@]}"; do
    log 5 "object: $object"
    if [[ $object == "$test_file" ]]; then
      object_found=true
      break
    fi
  done
  if [[ $object_found == "false" ]]; then
    log 2 "object not found"
    return 1
  fi
  return 0
}

list_check_objects_common() {
  if [ $# -ne 4 ]; then
    log 2 "'list_check_objects_common' requires client, bucket, object one, object two"
    return 1
  fi
  if ! list_objects "$1" "$2"; then
    log 2 "error listing objects"
    return 1
  fi
  local object_one_found=false
  local object_two_found=false
  # shellcheck disable=SC2154
  for object in "${object_array[@]}"; do
    if [ "$object" == "$3" ] || [ "$object" == "s3://$2/$3" ]; then
      object_one_found=true
    elif [ "$object" == "$4" ] || [ "$object" == "s3://$2/$4" ]; then
      object_two_found=true
    fi
  done

  if [ $object_one_found != true ] || [ $object_two_found != true ]; then
    log 2 "$3 and/or $4 not listed (all objects: ${object_array[*]})"
    return 1
  fi
  return 0
}

list_objects_check_file_count() {
  if [ $# -ne 3 ]; then
    log 2 "'list_objects_check_file_count' requires client, bucket, count"
    return 1
  fi
  if ! list_objects "$1" "$2"; then
    log 2 "error listing objects"
    return 1
  fi
  if [[ $LOG_LEVEL -ge 5 ]]; then
    log 5 "Array: ${object_array[*]}"
  fi
  local file_count="${#object_array[@]}"
  if [[ $file_count != "$3" ]]; then
    log 2 "file count should be $3, is $file_count"
    return 1
  fi
  return 0
}

check_object_listing_with_prefixes() {
  if [ $# -ne 3 ]; then
    log 2 "'check_object_listing_with_prefixes' requires bucket name, folder name, object name"
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
