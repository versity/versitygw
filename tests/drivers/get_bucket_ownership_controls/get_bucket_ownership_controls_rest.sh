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

get_bucket_ownership_controls_check_error_after_deletion() {
  if ! check_param_count_v2 "bucket name" 1 $#; then
    return 1
  fi
  bucket_name="$1"
  if ! get_bucket_ownership_controls_expect_error_callback "$1" "404" "OwnershipControlsNotFoundError" "were not found" "check_error_bucket_name"; then
    log 2 "error checking bucket ownership controls error"
    return 1
  fi
  return 0
}

check_error_bucket_name() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  if ! check_xml_element_contains "$1" "$bucket_name" "Error" "BucketName"; then
    log 2 "error checking BucketName XML element"
    return 1
  fi
  return 0
}

get_and_check_ownership_controls() {
  if ! check_param_count "get_and_check_ownership_controls" "bucket, expected result" 2 $#; then
    return 1
  fi
  if ! rule=$(get_bucket_ownership_controls_rest "$1" 2>&1); then
    log 2 "error getting ownership rule: $rule"
    return 1
  fi
  if [ "$rule" != "$2" ]; then
    log 2 "rule mismatch (expected '$2', actual '$rule')"
    return 1
  fi
  return 0
}
