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
  if ! check_param_count "get_object_lock_configuration" "client, bucket name" 2 $#; then
    return 1
  fi
  local response response_code response_data lock_config

  if [ "$1" == 'rest' ]; then
    if ! response=$(get_object_lock_configuration_rest "$2" 2>&1); then
      log 2 "error getting REST object lock configuration: $response"
      return 1
    fi
    read -r response_code response_data <<< "$response"
    if [ "$response_code" != "200" ]; then
      log 2 "get_object_lock_config returned error: $(cat "$response_data")"
      return 1
    fi
    lock_config="$(cat "$response_data")"
  else
    if ! response=$(send_command aws --no-verify-ssl s3api get-object-lock-configuration --bucket "$2" 2>&1); then
      log 2 "error obtaining lock config: $response"
      return 1
    fi
    lock_config=$(echo "$response" | grep -v "InsecureRequestWarning")
    echo "$lock_config"
  fi
  return 0
}

get_object_lock_configuration_rest() {
  log 6 "get_object_lock_configuration_rest"
  if ! check_param_count "get_object_lock_configuration_rest" "bucket name" 1 $#; then
    return 1
  fi
  local response output_file response_code return_code=0

  if ! response=$(get_file_name 2>&1); then
    log 2 "error getting file name: $response"
    return 1
  fi
  output_file="$response"

  if ! response=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OUTPUT_FILE="$TEST_FILE_FOLDER/$output_file" ./tests/rest_scripts/get_object_lock_config.sh 2>&1); then
    log 2 "error getting lock configuration: $response"
    return 1
  fi
  response_code="$response"

  echo "$response_code" "$TEST_FILE_FOLDER/$output_file"
  return $return_code
}

get_object_lock_configuration_rest_go() {
  if ! check_param_count_gt "bucket, callback, additional params" 2 $#; then
    return 1
  fi
  local bucket="$1" callback="$2"
  local response

  if ! response=$(send_rest_go_command_callback "200" "$callback" "-query" "object-lock" "-bucketName" "$bucket" "${@:3}" 2>&1); then
    log 2 "error getting object lock configuration: $response"
    return 1
  fi
  echo "$response"
  return 0
}