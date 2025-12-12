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

get_check_bucket_location_various() {
  if ! check_param_count_v2 "client, bucket" 2 $#; then
    return 1
  fi
  if ! get_bucket_location "$1" "$2"; then
    log 2 "error getting bucket location"
    return 1
  fi
  # shellcheck disable=SC2154
  if [[ $bucket_location != "null" ]] && [[ $bucket_location != "us-east-1" ]]; then
    log 2 "wrong location: '$bucket_location'"
    return 1
  fi
  return 0
}
