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

source ./tests/util/util_xml.sh

check_rest_expected_error() {
  if ! check_param_count_v2 "response, response file, expected http code, expected error code, expected error" 5 $#; then
    return 1
  fi
  if [ "$1" != "$3" ]; then
    log 2 "expected '$3', was '$1' ($(cat "$2"))"
    return 1
  fi
  if ! check_xml_error_contains "$2" "$4" "$5"; then
    log 2 "error checking XML response"
    return 1
  fi
  return 0
}

send_rest_command() {
  if ! check_param_count_v2 "env vars, script" 2 $#; then
    return 1
  fi
  if [[ "$1" == *"OUTPUT_FILE"* ]]; then
    if ! output_file=$(echo -n "$1" | sed -n 's/^.*OUTPUT_FILE=\([^ ]*\).*$/\1/p' 2>&1); then
      log 2 "error getting output file: $output_file"
    fi
    log 5 "output file: $output_file"
  else
    output_file="$TEST_FILE_FOLDER/output.txt"
  fi
  local env_array=("env" "COMMAND_LOG=$COMMAND_LOG" "OUTPUT_FILE=$output_file")
  if [ "$1" != "" ]; then
    IFS=' ' read -r -a env_vars <<< "$1"
    env_array+=("${env_vars[@]}")
  fi
  # shellcheck disable=SC2068
  if ! result=$(${env_array[@]} "$2" 2>&1); then
    log 2 "error sending command: $result"
    return 1
  fi
}

send_rest_command_expect_error() {
  if ! check_param_count_v2 "env vars, script, response code, error, message" 5 $#; then
    return 1
  fi
  if ! send_rest_command "$1" "$2"; then
    log 2 "error sending REST command"
    return 1
  fi
  if ! check_rest_expected_error "$result" "$output_file" "$3" "$4" "$5"; then
    log 2 "error checking REST error"
    return 1
  fi
  return 0
}

check_rest_expected_header_error() {
  if ! check_param_count_v2 "response code, file, expected response, expected error" 4 $#; then
    return 1
  fi
  status_line=$(head -n 1 "$2")

  # Parse the status code and message
  status_code=$(echo "$status_line" | awk '{print $2}')
  status_message=$(echo "$status_line" | cut -d' ' -f3- | tr -d '\r')
  log 5 "status code: $status_code, status message: $status_message"
  if [ "$1" != "$3" ]; then
    log 2 "expected curl response '$3', was '$1"
    return 1
  fi
  if [ "$status_code" != "$3" ]; then
    log 2 "expected HTTP response '$3', was '$status_code"
    return 1
  fi
  if [ "$status_message" != "$4" ]; then
    log 2 "expected message '$4', was '$status_message'"
    return 1
  fi
  return 0
}

send_rest_command_expect_header_error() {
  if ! check_param_count_v2 "env vars, script, response code, message" 4 $#; then
    return 1
  fi
  if ! send_rest_command "$1" "$2"; then
    log 2 "error sending REST command"
    return 1
  fi
  if ! check_rest_expected_header_error "$result" "$output_file" "$3" "$4"; then
    log 2 "error checking REST error"
    return 1
  fi
  return 0
}

send_rest_command_expect_success() {
if ! check_param_count_v2 "env vars, script, response code" 3 $#; then
  return 1
fi
if ! send_rest_command "$1" "$2"; then
  log 2 "error sending REST command"
  return 1
fi
if [ "$result" != "$3" ]; then
  log 2 "expected '$3', was '$result' ($(cat "$output_file"))"
  return 1
fi
return 0
}

send_rest_command_expect_success_callback() {
if ! check_param_count_v2 "env vars, script, response code, callback fn" 4 $#; then
  return 1
fi
output_file="$TEST_FILE_FOLDER/output.txt"
local env_array=("env" "COMMAND_LOG=$COMMAND_LOG" "OUTPUT_FILE=$output_file")
if [ "$1" != "" ]; then
  IFS=' ' read -r -a env_vars <<< "$1"
  env_array+=("${env_vars[@]}")
fi
# shellcheck disable=SC2068
if ! result=$(${env_array[@]} "$2" 2>&1); then
  log 2 "error sending command: $result"
  return 1
fi
if [ "$result" != "$3" ]; then
  log 2 "expected '$3', was '$result' ($(cat "$TEST_FILE_FOLDER/output.txt"))"
  return 1
fi
if [ "$4" != "" ] && ! "$4" "$TEST_FILE_FOLDER/output.txt"; then
  log 2 "callback error"
  return 1
fi
return 0
}
