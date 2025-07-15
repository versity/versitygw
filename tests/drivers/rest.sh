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
  if ! check_param_count_v2 "env vars, script, output file" 3 $#; then
    return 1
  fi
  local env_array=("env" "COMMAND_LOG=$COMMAND_LOG" "OUTPUT_FILE=$3")
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
  output_file="$TEST_FILE_FOLDER/error.txt"
  if ! send_rest_command "$1" "$2" "$output_file"; then
    log 2 "error sending REST command"
    return 1
  fi
  if ! check_rest_expected_error "$result" "$output_file" "$3" "$4" "$5"; then
    log 2 "error checking REST error"
    return 1
  fi
  return 0
}

send_rest_command_expect_success() {
  if ! check_param_count_v2 "env vars, script, response code" 3 $#; then
    return 1
  fi
  output_file="$TEST_FILE_FOLDER/error.txt"
  if ! send_rest_command "$1" "$2" "$output_file"; then
    log 2 "error sending REST command"
    return 1
  fi
  if [ "$result" != "$3" ]; then
    log 2 "expected '$3', was '$result' ($(cat "$TEST_FILE_FOLDER/error.txt"))"
    return 1
  fi
  return 0
}
