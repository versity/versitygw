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

source ./tests/drivers/xml.sh

get_check_bucket_location() {
  if ! check_param_count_v2 "bucket name, expected value" 2 $#; then
    return 1
  fi
  expected_location="$2"
  if [ "$expected_location" == "us-east-1" ]; then
    expected_location=""
  fi
  if ! get_bucket_location_rest "$1" "check_location_constraint"; then
    log 2 "error getting and checking bucket location"
    return 1
  fi
  return 0
}

check_location_constraint() {
  if ! check_param_count_v2 "file" 1 $#; then
    return 1
  fi
  log 5 "location constraint: $(cat "$1")"
  if ! location_constraint=$(get_element_text "$1" "LocationConstraint" 2>&1); then
    log 2 "error getting location constraint: $location_constraint"
    return 1
  fi
  if [ "$location_constraint" != "$expected_location" ]; then
    log 2 "expected location constraint of '$expected_location', was '$location_constraint'"
    return 1
  fi
  return 0
}

parse_bucket_location() {
  if ! check_param_count_v2 "file" 1 $#; then
    return 1
  fi
  log 5 "file: $1"
  log 5 "data: $(cat "$1")"
  if ! location_constraint=$(get_element_text "$1" "LocationConstraint" 2>&1); then
    log 2 "error getting location constraint: $location_constraint"
    return 1
  fi
  echo "$location_constraint"
  return 0
}
