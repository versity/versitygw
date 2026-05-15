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

source ./tests/logger.sh

generate_random_string() {
  if ! check_param_count_v2 "min size, max size" 2 $#; then
    return 1
  fi
  local string="" range size response
  range=$(($2 - $1 + 1))
  size=$(($1 + RANDOM % range))

  if ! response=$(get_file_name 2>&1); then
    log 2 "error getting file name: $response"
    return 1
  fi
  pipe_error_file="$response"

  while [ "${#string}" -lt "$size" ]; do
    chunk="$(
      {
        dd if=/dev/urandom bs=128 count=1 |
          LC_ALL=C tr -d '\000' |
          LC_ALL=C tr -dc 'A-Za-z0-9'
      } 2>"$TEST_FILE_FOLDER/$pipe_error_file"
    )"
    status=$?

    if [ $status -ne 0 ]; then
      log 2 "error creating chunk: $(cat "$TEST_FILE_FOLDER/$pipe_error_file")"
      return 1
    fi

    string="${string}${chunk}"
  done

  printf '%s\n' "${string:0:size}"
  return 0
}
