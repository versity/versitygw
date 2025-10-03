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

check_rest_go_expected_error() {
  if ! check_param_count_v2 "response file, expected http code, expected error code, expected error" 4 $#; then
    return 1
  fi
  result="$(cat "$1")"
  if ! bypass_continues; then
    log 2 "error bypassing continues"
    return 1
  fi
  if [ "$2" != "$status_code" ]; then
    log 2 "expected curl response '$2', was '$status_code'"
    return 1
  fi
  if ! check_xml_error_contains "$1" "$3" "$4"; then
    log 2 "error checking XML error"
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
  if ! check_param_count_v2 "file, expected response, expected error" 3 $#; then
    return 1
  fi
  result="$(cat "$1")"
  if ! bypass_continues; then
    log 2 "error bypassing continues"
    return 1
  fi
  log 5 "status line: $status_line"
  status_message=$(echo "$status_line" | cut -d' ' -f3- | tr -d '\r')
  log 5 "status code: $status_code, status message: $status_message"
  if [ "$2" != "$status_code" ]; then
    log 2 "expected curl response '$2', was '$status_code'"
    return 1
  fi
  if [ "$status_message" != "$3" ]; then
    log 2 "expected message '$3', was '$status_message'"
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
  if ! check_rest_expected_header_error "$output_file" "$3" "$4"; then
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
  response_code="$(echo "$result" | tail -n 1)"
  if [ "$response_code" != "$3" ]; then
    log 2 "expected '$3', was '$response_code' ($(cat "$TEST_FILE_FOLDER/output.txt"))"
    return 1
  fi
  if [ "$4" != "" ] && ! "$4" "$TEST_FILE_FOLDER/output.txt"; then
    log 2 "callback error"
    return 1
  fi
  return 0
}

rest_go_command_perform_send() {
  if ! curl_command=$(go run ./tests/rest_scripts/generateCommand.go -awsAccessKeyId "$AWS_ACCESS_KEY_ID" -awsSecretAccessKey "$AWS_SECRET_ACCESS_KEY" -url "$AWS_ENDPOINT_URL" "$@" 2>&1); then
    log 2 "error: $curl_command"
    return 1
  fi
  local full_command="send_command $curl_command"
  log 5 "full command: $full_command"
  if ! result=$(eval "${full_command[*]}" 2>&1); then
    log 3 "error sending command: $result"
    return 1
  fi
  log 5 "result: $result"
}

send_rest_go_command_expect_error() {
  if [ $# -lt 3 ]; then
    log 2 "'send_rest_go_command_expect_error' param count must be 3 or greater, odd (expected HTTP code, expected error code, expected message, go params)"
    return 1
  fi
  if ! send_rest_go_command_expect_error_callback "$1" "$2" "$3" "" "${@:4}"; then
    log 2 "error sending go command and checking error"
    return 1
  fi
  return 0
}

send_rest_go_command_expect_error_callback() {
  if [ $# -lt 4 ]; then
    log 2 "'send_rest_go_command_expect_error' param count must be 4 or greater, even (expected HTTP code, expected error code, expected message, callback, go params)"
    return 1
  fi
  if ! rest_go_command_perform_send "${@:5}"; then
    log 2 "error sending rest go command"
    return 1
  fi
  echo -n "$result" > "$TEST_FILE_FOLDER/result.txt"
  if ! check_rest_go_expected_error "$TEST_FILE_FOLDER/result.txt" "$1" "$2" "$3"; then
    log 2 "error checking expected header error"
    return 1
  fi
  if [ "$4" != "" ] && ! "$4" "$TEST_FILE_FOLDER/result.txt"; then
    log 2 "callback error"
    return 1
  fi
  return 0
}

bypass_continues() {
  status_line_idx=1
  status_code=""
  continue_count=0
  while ((continue_count<10)); do
    status_line=$(sed -n "${status_line_idx}p" <<< "$result")
    status_code=$(echo "$status_line" | awk '{print $2}')
    if [ "$status_code" != "100" ]; then
      break
    fi
    ((status_line_idx+=2))
    ((continue_count++))
  done
  if [ "$continue_count" -ge 10 ]; then
    log 2 "too many continues"
    return 1
  fi
  return 0
}

send_rest_go_command() {
  if [ $# -lt 1 ]; then
    log 2 "'send_rest_go_command_expect_failure' param count must be 1 or greater (expected response code, params)"
    return 1
  fi
  if ! send_rest_go_command_callback "$1" "" "${@:2}"; then
    log 2 "error sending rest go command"
    return 1
  fi
  return 0
}

send_rest_go_command_callback() {
  if ! check_param_count_gt "response code, callback, params" 2 $#; then
    return 1
  fi
  if ! rest_go_command_perform_send "${@:3}"; then
    log 2 "error sending rest go command"
    return 1
  fi
  if ! bypass_continues; then
    log 2 "error bypassing continues"
    return 1
  fi
  if [ "$1" != "$status_code" ]; then
    log 2 "expected curl response '$1', was '$status_code'"
    return 1
  fi
  echo -n "$result" > "$TEST_FILE_FOLDER/result.txt"
  if [ "$2" != "" ] && ! "$2" "$TEST_FILE_FOLDER/result.txt"; then
    log 2 "error in callback"
    return 1
  fi
  return 0
}
