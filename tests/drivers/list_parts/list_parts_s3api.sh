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

list_and_check_part_numbers_and_etags() {
  if ! check_param_count_gt "bucket, key, upload ID, etags in part number order" 4 $#; then
    return 1
  fi
  local bucket="$1" key="$2" upload_id="$3" etags=("${@:4}")
  local response parts part_num part_idx part returned_part_num returned_etag
  local -a part_array

  if ! response=$(list_parts "$bucket" "$key" "$upload_id" 2>&1); then
    log 2 "error listing parts: $response"
    return 1
  fi
  parts="$response"
  if ! response=$(echo "$parts" | grep -v "InsecureRequestWarning" | jq -r ".Parts | length" 2>&1); then
    log 2 "error getting part: $response"
    return 1
  fi
  part_length="$response"
  if [ "${#etags[@]}" != "$part_length" ]; then
    log 2 "etag/part count mismatch, '${#etags[@]}' etags, but '$part_length' parts"
    return 1
  fi
  for ((part_num=1; part_num<part_length; part_num++)); do
    part_idx=$((part_num-1))
    if ! response=$(echo "$parts" | jq ".Parts[$part_idx].PartNumber" 2>&1); then
      log 2 "error parsing part number: $response"
      return 1
    fi
    returned_part_num="$response"
    if [ "$part_num" != "$returned_part_num" ]; then
      log 2 "incorrect PartNumber, expected '$part_num', actual '$returned_part_num'"
      return 1
    fi

    if ! response=$(echo "$parts" | jq ".Parts[$part_idx].ETag" 2>&1); then
      log 2 "error parsing etag: $response"
      return 1
    fi
    returned_etag="$response"
    if [ "${etags[$part_idx]}" != "$returned_etag" ]; then
      log 2 "incorrect PartNumber, expected '${etags[$part_idx]}', actual '$returned_etag'"
      return 1
    fi
  done
  return 0
}