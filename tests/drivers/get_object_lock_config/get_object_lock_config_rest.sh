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

check_object_lock_config() {
  if ! check_param_count_v2 "bucket" 1 $#; then
    return 1
  fi
  local exists="true" response response_code output_file

  if ! response=$(get_object_lock_configuration_rest "$1" 2>&1); then
    log 2 "error checking object lock configuration: $response"
    return 1
  fi
  read -r response_code output_file <<< "$response"

  if [ "$response_code" != "200" ]; then
    if grep "ObjectLockConfigurationNotFoundError" "$output_file" >/dev/null; then
      exists="false"
    else
      log 2 "unexpected GetObjectLockConfiguration error: '$(cat "$output_file")'"
      return 1
    fi
  fi
  log 5 "check object lock config response: $response"
  echo "$exists"
  return 0
}

check_object_lock_config_enabled_rest() {
  if ! check_param_count "check_object_lock_config_enabled_rest" "bucket" 1 $#; then
    return 1
  fi
  local response response_code response_file enabled_value

  if ! response=$(get_object_lock_configuration_rest "$1" 2>&1); then
    log 2 "error getting object lock config: $response"
    return 1
  fi
  read -r response_code response_file <<< "$response"

  if ! response=$(xmllint --xpath '//*[local-name()="ObjectLockEnabled"]/text()' "$response_file" 2>&1); then
    log 2 "error getting object lock config enabled value: $response"
    return 1
  fi
  enabled_value="$response"

  if [[ "$enabled_value" != "Enabled" ]]; then
    log 2 "expected 'Enabled', is '$enabled_value'"
    return 1
  fi
  return 0
}

check_object_lock_config_go() {
  if ! check_param_count_gt "bucket, additional params (optional)" 1 $#; then
    return 1
  fi
  local bucket="$1" params=("${@:2}")
  local response

  if ! response=$(get_object_lock_configuration_rest_go "$bucket" "" "${params[@]}" 2>&1); then
    if [[ "$response" == *"HTTP/1.1 404 Not Found"* ]]; then
      echo "false"
      return 0
    fi
    log 2 "error checking object lock configuration: $response"
    return 1
  fi
  echo "true"
  return 0
}
