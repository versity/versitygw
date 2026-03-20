#!/usr/bin/env bash

# Copyright 2025 Versity Software
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

bucket_exists() {
  if ! check_param_count "bucket_exists" "bucket name" 1 $#; then
    return 2
  fi
  local response_code=0
  exists=$(head_bucket_rest "$1" "check_bucket_existence_callback" 2>&1) || response_code=$?
  echo "$exists"
  return "$response_code"
}

check_bucket_existence_callback() {
  if ! check_param_count_v2 "response code, response data" 2 $#; then
    return 1
  fi
  if [ "$1" -eq 200 ]; then
    echo "true"
    return 0
  elif [ "$1" -eq 404 ]; then
    echo "false"
    return 1
  fi
  echo "error checking if bucket exists (data: $2)"
  return 2
}
