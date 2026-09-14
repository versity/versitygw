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

split_and_put_file() {
  if ! check_param_count_v2 "bucket, key, copy source, part count" 4 $#; then
    return 1
  fi
  local bucket="$1" key="$2" copy_source="$3" part_count="$4"
  local file_parts idx
  local -a part_array

  if ! file_parts=$(split_file "$copy_source" "$part_count" 2>&1); then
    log 2 "error splitting file: $file_parts"
    return 1
  fi
  read -r -a part_array <<< "$file_parts"

  for ((idx=0;idx<part_count;idx++)) {
    log 5 "key: $key, file info: $(ls -l "${part_array[$idx]}")"
    if ! put_object "s3api" "${part_array[$idx]}" "$bucket" "${key}-${idx}"; then
      log 2 "error copying object"
      return 1
    fi
  }
  return 0
}
