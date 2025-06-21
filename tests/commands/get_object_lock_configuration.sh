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

source ./tests/drivers/params.sh

get_object_lock_configuration() {
  record_command "get-object-lock-configuration" "client:s3api"
  if ! check_param_count "get_object_lock_configuration" "client, bucket name" 2 $#; then
    return 1
  fi
  if [ "$1" == 'rest' ]; then
    if ! get_object_lock_configuration_rest "$2"; then
      log 2 "error getting REST object lock configuration"
      get_object_lock_config_err=$(cat "$TEST_FILE_FOLDER/object-lock-config.txt")
      return 1
    fi
  else
    if ! lock_config=$(send_command aws --no-verify-ssl s3api get-object-lock-configuration --bucket "$2" 2>&1); then
      log 2 "error obtaining lock config: $lock_config"
      # shellcheck disable=SC2034
      get_object_lock_config_err=$lock_config
      return 1
    fi
  fi
  lock_config=$(echo "$lock_config" | grep -v "InsecureRequestWarning")
  return 0
}

get_object_lock_configuration_rest() {
  log 6 "get_object_lock_configuration_rest"
  if ! check_param_count "get_object_lock_configuration_rest" "bucket name" 1 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OUTPUT_FILE="$TEST_FILE_FOLDER/object-lock-config.txt" ./tests/rest_scripts/get_object_lock_config.sh); then
    log 2 "error getting lock configuration: $result"
    return 1
  fi
  if [[ "$result" != "200" ]]; then
    log 2 "expected '200', returned '$result': $(cat "$TEST_FILE_FOLDER/object-lock-config.txt")"
    return 1
  fi
  lock_config="$(cat "$TEST_FILE_FOLDER/object-lock-config.txt")"
  return 0
}