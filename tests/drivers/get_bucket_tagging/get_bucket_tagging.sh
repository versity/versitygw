#!/usr/bin/env bash

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

check_bucket_tags_empty() {
  if [[ $# -ne 2 ]]; then
    log 2 "bucket tags empty check requires command type, bucket"
    return 2
  fi
  if ! get_bucket_tagging "$1" "$2"; then
    log 2 "failed to get tags"
    return 2
  fi
  check_tags_empty "$1" || local check_result=$?
  # shellcheck disable=SC2086
  return $check_result
}

verify_no_bucket_tags() {
  if [ $# -ne 2 ]; then
    log 2 "'verify_no_bucket_tags' requires client, bucket name"
    return 1
  fi
  if ! get_bucket_tagging "$1" "$2"; then
    log 2 "error retrieving bucket tagging"
    return 1
  fi
  # shellcheck disable=SC2154
  if [[ "$tags" != "" ]]; then
    log 2 "tags should be empty, but are: $tags"
    return 1
  fi
  return 0
}
