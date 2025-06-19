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

# params: bucket name, expected enabled value, expected governance mode, expected days
# return 0 for success, 1 for failure
get_and_check_object_lock_config() {
  if ! check_param_count "get_and_check_object_lock_config" "bucket, expected enabled value, expected governance mode, expected days" 4 $#; then
    return 1
  fi
  if ! get_object_lock_configuration "s3api" "$1"; then
    log 2 "error getting object lock config"
    return 1
  fi
  # shellcheck disable=SC2154
  log 5 "LOCK CONFIG: $lock_config"
  if ! object_lock_configuration=$(echo "$lock_config" | grep -v "InsecureRequestWarning" | jq -r ".ObjectLockConfiguration" 2>&1); then
    log 2 "error getting ObjectLockConfiguration: $object_lock_configuration"
    return 1
  fi
  if ! object_lock_enabled=$(echo "$object_lock_configuration" | jq -r ".ObjectLockEnabled" 2>&1); then
    log 2 "error getting object lock enabled status: $object_lock_enabled"
    return 1
  fi
  if [[ $object_lock_enabled != "$2" ]]; then
    log 2 "incorrect ObjectLockEnabled value: $object_lock_enabled"
    return 1
  fi
  if ! default_retention=$(echo "$object_lock_configuration" | jq -r ".Rule.DefaultRetention" 2>&1); then
    log 2 "error getting DefaultRetention: $default_retention"
    return 1
  fi
  if ! mode=$(echo "$default_retention" | jq -r ".Mode" 2>&1); then
    log 2 "error getting Mode: $mode"
    return 1
  fi
  if [[ $mode != "$3" ]]; then
    log 2 "incorrect Mode value: $mode"
    return 1
  fi
  if ! returned_days=$(echo "$default_retention" | jq -r ".Days" 2>&1); then
    log 2 "error getting Days: $returned_days"
    return 1
  fi
  if [[ $returned_days != "$4" ]]; then
    log 2 "incorrect Days value: $returned_days"
    return 1
  fi
  return 0
}

get_check_object_lock_config_enabled() {
  if ! check_param_count "get_check_object_lock_config_enabled" "bucket" 1 $#; then
    return 1
  fi
  if ! get_object_lock_configuration "s3api" "$1"; then
    log 2 "error getting lock configuration"
    return 1
  fi
  # shellcheck disable=SC2154
  log 5 "Lock config:  $lock_config"
  if ! enabled=$(echo "$lock_config" | jq -r ".ObjectLockConfiguration.ObjectLockEnabled" 2>&1); then
    log 2 "error parsing enabled value: $enabled"
    return 1
  fi
  if [[ $enabled != "Enabled" ]]; then
    log 2 "ObjectLockEnabled should be 'Enabled', is '$enabled'"
    return 1
  fi
  return 0
}

check_no_object_lock_config_rest() {
  if ! check_param_count "check_no_object_lock_config_rest" "bucket" 1 $#; then
    return 1
  fi
  if get_object_lock_configuration_rest "$1"; then
    log 2 "object lock config should be missing"
    return 1
  fi
  log 5 "object lock config: $(cat "$TEST_FILE_FOLDER/object-lock-config.txt")"
  # shellcheck disable=SC2154
  if [[ "$result" != "404" ]]; then
    log 2 "incorrect response code: $reply"
    return 1
  fi
  if ! error=$(xmllint --xpath '//*[local-name()="Code"]/text()' "$TEST_FILE_FOLDER/object-lock-config.txt" 2>&1); then
    log 2 "error getting object lock config error: $error"
    return 1
  fi
  if [[ "$error" != "ObjectLockConfigurationNotFoundError" ]]; then
    log 2 "unexpected error: $error"
    return 1
  fi
  return 0
}

check_object_lock_config_enabled_rest() {
  if ! check_param_count "check_object_lock_config_enabled_rest" "bucket" 1 $#; then
    return 1
  fi
  if ! get_object_lock_configuration_rest "$1"; then
    log 2 "error getting object lock config"
    return 1
  fi
  log 5 "object lock config: $(cat "$TEST_FILE_FOLDER/object-lock-config.txt")"
  if ! enabled=$(xmllint --xpath '//*[local-name()="ObjectLockEnabled"]/text()' "$TEST_FILE_FOLDER/object-lock-config.txt" 2>&1); then
    log 2 "error getting object lock config enabled value: $enabled"
    return 1
  fi
  if [[ "$enabled" != "Enabled" ]]; then
    log 2 "expected 'Enabled', is $enabled"
    return 1
  fi
  return 0
}
