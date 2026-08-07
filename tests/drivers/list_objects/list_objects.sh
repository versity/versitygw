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
  local client="$1" bucket="$2" object_one="$3" object_two="$4"
  local response object_list object_data

  if ! response=$(list_objects "$client" "$bucket" 2>&1); then
    log 2 "error listing objects: $response"
    return 1
  fi
  log 5 "response: $response"
  mapfile -t object_list <<< "$response"
  log 5 "object list size: ${#object_list[@]}"

  local object_one_found=false
  local object_two_found=false
  for object_data in "${object_list[@]}"; do
    if [ "$client" == "s3cmd" ]; then
      object="$(awk '{ for (i=4; i<=NF; i++) printf "%s%s", $i, (i<NF ? OFS : ORS) }' <<< "$object_data")"
    elif [ "$client" == "mc" ]; then
      object="$(awk '{print $6}' <<< "$object_data")"
    else
      object="$object_data"
    fi
    if [ "$object" == "$object_one" ] || [ "$object" == "s3://$bucket/$object_one" ]; then
      object_one_found=true
    elif [ "$object" == "$object_two" ] || [ "$object" == "s3://$bucket/$object_two" ]; then
      object_two_found=true
    fi
  done

  if [ $object_one_found != true ] || [ $object_two_found != true ]; then
    log 2 "'$object_one' and/or '$object_two' not listed (all objects: ${object_list[*]})"
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
  mapfile -t object_array <<< "$response"

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
