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

list_check_objects_common() {
  if ! check_param_count "list_check_objects_common" "client, bucket, object one, object two" 4 $#; then
    return 1
  fi
  if ! response=$(list_objects "$1" "$2" 2>&1); then
    log 2 "error listing objects: $response"
    return 1
  fi
  log 5 "response: $response"
  read -r -a object_array <<< "$response"

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
  if ! check_param_count "list_objects_check_file_count" "client, bucket, count" 3 $#; then
    return 1
  fi
  if ! response=$(list_objects "$1" "$2" 2>&1); then
    log 2 "error listing objects: $response"
    return 1
  fi
  read -r -a object_array <<< "$response"

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
