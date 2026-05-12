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

  local response
  if ! response=$(bypass_continues "$1" 2>&1); then
    log 2 "error bypassing continues: $response"
    return 1
  fi
  status_code=$(echo -n "$response" | awk '{print $2}')
  if [ "$2" != "$status_code" ]; then
    log 2 "expected curl response '$2', was '$status_code' (response: '$(cat "$1")')"
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
    if ! file_name=$(get_file_name 2>&1); then
      log 2 "error getting file name: $file_name"
      return 1
    fi
    output_file="$TEST_FILE_FOLDER/$file_name"
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

  local response
  if ! response=$(bypass_continues "$1" 2>&1); then
    log 2 "error bypassing continues: $response"
    return 1
  fi
  status_code=$(echo "$response" | awk '{print $2}')
  status_message=$(echo "$response" | cut -d' ' -f3- | tr -d '\r')
  if [ "$2" != "$status_code" ]; then
    log 2 "expected curl response '$2', was '$status_code' ($(cat "$1"))"
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
  if ! output_file_name=$(get_file_name 2>&1); then
    log 2 "error generating output file name: $output_file_name"
    return 1
  fi
  output_file="$TEST_FILE_FOLDER/$output_file_name"
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
    log 2 "expected '$3', was '$response_code' ($(cat "$output_file"))"
    return 1
  fi
  if [ "$4" == "" ]; then
    cat "$output_file"
    return 0
  fi
  if ! callback_result=$("$4" "$output_file" 2>&1); then
    log 2 "callback error: $callback_result"
    return 1
  fi
  echo "$callback_result"
  return 0
}

rest_go_command_perform_send() {
  if ! xml_file=$(get_file_name 2>&1); then
    log 2 "error getting XML file name: $xml_file"
    return 1
  fi
  local header_file="" output_file="" params=("$@")
  for ((i=0; i < $#; i++)); do
    if [ "${!i}" == "-headerFile" ]; then
      next_idx=$((i+1))
      header_file=${!next_idx}
    elif [ "${!i}" == "-outputFile" ]; then
      next_idx=$((i+1))
      output_file=${!next_idx}
    fi
  done
  if [ "$output_file" == "" ]; then
    if ! response=$(get_file_name 2>&1); then
      log 2 "error getting output file name: $response"
      return 1
    fi
    output_file="$TEST_FILE_FOLDER/$response"
    params+=("-outputFile" "$output_file")
  fi
  if ! curl_command=$(go run ./tests/rest_scripts/generateCommand.go -awsAccessKeyId "$AWS_ACCESS_KEY_ID" -awsSecretAccessKey "$AWS_SECRET_ACCESS_KEY" -awsRegion "$AWS_REGION" -url "$AWS_ENDPOINT_URL" "-writeXMLPayloadToFile" "$TEST_FILE_FOLDER/$xml_file" "${params[@]}" 2>&1); then
    log 2 "error: $curl_command"
    return 1
  fi
  curl_command=$(echo -n "$curl_command" | tr -d '\n')
  mapfile -t curl_command_array < <(
    printf '%s' "$curl_command" | python3 -c 'import shlex, sys; [print(arg) for arg in shlex.split(sys.stdin.read())]'
  )
  if ! response=$(send_command "${curl_command_array[@]}" 2>&1); then
    log 2 "error sending command: $response"
    return 1
  fi
  if [ "$header_file" != "" ]; then
    response_file="$header_file"
  else
    response_file="$output_file"
  fi
  echo "$response_file"
  return 0
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

  local all_params=("${@:5}") no_callback_params=0 go_param_array=() callback_params=()

  if ! params_file=$(get_file_name 2>&1); then
    log 2 "error getting params file name: $params_file"
    return 1
  fi
  get_go_params "${all_params[@]}" > "$TEST_FILE_FOLDER/$params_file" || no_callback_params=$?
  mapfile -t go_param_array < "$TEST_FILE_FOLDER/$params_file"

  if [ "$no_callback_params" -eq 1 ]; then
    mapfile -t callback_params < <(get_callback_params "${all_params[@]}")
  fi

  if ! response=$(rest_go_command_perform_send "${go_param_array[@]}" 2>&1); then
    log 2 "error sending rest go command: $response"
    return 1
  fi
  response_file="$response"
  if ! check_rest_go_expected_error "$response_file" "$1" "$2" "$3"; then
    log 2 "error checking expected header error"
    return 1
  fi
  if [ "$4" != "" ] && ! "$4" "$TEST_FILE_FOLDER/$file_name" "${callback_params[@]}"; then
    log 2 "callback error"
    return 1
  fi
  return 0
}

bypass_continues() {
  if ! check_param_count_v2 "raw response file" 1 $#; then
    return 1
  fi

  local status_line_idx=1 status_code="" continue_count=0
  while ((continue_count<10)); do
    status_line=$(sed -n "${status_line_idx}p" < "$1")
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
  echo "$status_line"
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

# return 0 for callback params, 1 for only go params
get_go_params() {
  for param in "$@"; do
    if [[ "$param" == "--" ]]; then
      return 1
    fi
    echo "$param"
  done
  return 0
}

get_callback_params() {
  delimiter_found=false
  for param in "$@"; do
    if [ "$delimiter_found" == "true" ]; then
      echo "$param"
      continue
    fi
    if [ "$param" == "--" ]; then
      delimiter_found=true
    fi
  done
  return 0
}

send_rest_go_command_callback() {
  if ! check_param_count_gt "response code, callback, params" 2 $#; then
    return 1
  fi

  local all_params=("${@:3}") no_callback_params=0 go_param_array=() callback_params=() response

  if ! params_file=$(get_file_name 2>&1); then
    log 2 "error getting params file name: $params_file"
    return 1
  fi
  get_go_params "${all_params[@]}" > "$TEST_FILE_FOLDER/$params_file" || no_callback_params=$?
  mapfile -t go_param_array < "$TEST_FILE_FOLDER/$params_file"

  if [ "$no_callback_params" -eq 1 ]; then
    mapfile -t callback_params < <(get_callback_params "${all_params[@]}")
  fi

  if ! response=$(rest_go_command_perform_send "${go_param_array[@]}" 2>&1); then
    log 2 "error sending rest go command: $response"
    return 1
  fi
  response_file="$response"

  if ! response=$(bypass_continues "$response_file" 2>&1); then
    log 2 "error bypassing continues: $response"
    return 1
  fi
  status_code=$(echo -n "$response" | awk '{print $2}')
  if [ "$1" != "$status_code" ]; then
    log 2 "expected curl response '$1', was '$status_code' (response: '$(cat "$response_file")')"
    return 1
  fi
  if [ "$2" == "" ]; then
    echo "$response_file"
    return 0
  fi
  if ! response=$("$2" "$response_file" "${callback_params[@]}" 2>&1); then
    log 2 "callback error: $response"
    return 1
  fi
  callback_result="$response"
  echo "$callback_result"
  return 0
}

# return 0 for key match, 1 for no key match, 2 for value mismatch
check_key_and_value_pair_for_match() {
  if ! check_param_count_v2 "read key, read value, expected key, expected value" 4 $#; then
    return 2
  fi
  if [ "${1,,}" == "${3,,}" ]; then
    if [ "$2" != "$4" ]; then
      log 2 "expected value of '$4', was '$2'"
      return 2
    fi
    return 0
  fi
  return 1
}

check_for_header_key_and_value() {
  if ! check_param_count_v2 "data file, header key, header value" 3 $#; then
    return 1
  fi
  while IFS=$': \r' read -r key value; do
    local check_result=0
    value="${value%$'\r'}"
    check_key_and_value_pair_for_match "$key" "$value" "$2" "$3" || check_result=$?
    if [ "$check_result" -eq 2 ]; then
      return 1
    elif [ "$check_result" -eq 0 ]; then
      return 0
    fi
  done <<< "$(grep -aE '^.+: .+$' "$1")"
  log 2 "no header key '$2' found"
  return 1
}

check_argument_name_and_value() {
  if ! check_param_count_v2 "data file, argument name, argument value" 3 $#; then
    return 1
  fi
  if ! xml_data=$(print_xml_data_to_file "$1" 2>&1); then
    log 2 "error getting XML data: $xml_data"
    return 1
  fi
  if ! check_error_parameter "$xml_data" "ArgumentName" "$2"; then
    log 2 "error checking 'ArgumentName' parameter"
    return 1
  fi
  if ! check_error_parameter "$xml_data" "ArgumentValue" "$3"; then
    log 2 "error checking 'ArgumentValue' parameter"
    return 1
  fi
  return 0
}

send_rest_go_command_expect_error_with_arg_name_value() {
  if ! check_param_count_gt "response code, error code, message, arg name, arg value, params" 5 $#; then
    return 1
  fi
  if ! send_rest_go_command_expect_error_callback "$1" "$2" "$3" "check_argument_name_and_value" "${@:6}" "--" "$4" "$5"; then
    log 2 "error checking error response values"
    return 1
  fi
  return 0
}

check_specific_argument_name_and_value() {
  if ! check_param_count_v2 "data file, argument name, value" 3 $#; then
    return 1
  fi
  if ! check_error_parameter "$1" "$2" "$3"; then
    log 2 "error checking '$2' parameter"
    return 1
  fi
}

send_rest_go_command_expect_error_with_specific_arg_name_value() {
  if ! check_param_count_gt "response code, error code, message, arg name, arg value, params" 5 $#; then
    return 1
  fi
  if ! send_rest_go_command_expect_error_callback "$1" "$2" "$3" "check_specific_argument_name_and_value" "${@:6}" "--" "$4" "$5"; then
    log 2 "error checking error response values"
    return 1
  fi
  return 0
}

check_specific_argument_names_and_values() {
  if ! check_param_count_gt "data file, arg names and values" 1 $#; then
    return 1
  fi
  local data_file="$1"
  shift

  while [ "$1" != "" ]; do
    if ! check_error_parameter "$data_file" "$1" "$2"; then
      log 2 "error checking '$1' parameter with value '$2'"
      return 1
    fi
    shift 2
  done
  return 0
}

send_rest_go_command_expect_error_with_specific_arg_names_values() {
  if ! check_param_count_gt "response code, error code, message, arg count, pairs of arg names and values, params" 6 $#; then
    return 1
  fi
  if ! send_rest_go_command_expect_error_callback "$1" "$2" "$3" "check_specific_argument_names_and_values" "${@:((5+$4))}" "--" "${@:5:$4}"; then
    log 2 "error checking error response values"
    return 1
  fi
  return 0
}

check_header_key_and_value() {
  if ! check_param_count_v2 "data file, header key, header value" 3 $#; then
    return 1
  fi
  if ! check_for_header_key_and_value "$1" "$2" "$3"; then
    log 2 "error checking header key and value"
    return 1
  fi
  return 0
}

send_rest_go_command_check_header_key_and_value() {
  if ! check_param_count_gt "response code, header key, header values, params" 3 $#; then
    return 1
  fi
  if ! send_rest_go_command_callback "$1" "check_header_key_and_value" "${@:4}" "--" "$2" "$3"; then
    log 2 "error sending command and checking header key and value"
    return 1
  fi
  return 0
}

send_rest_go_command_write_response_to_file() {
  if ! check_param_count_gt "file, params" 2 $#; then
    return 1
  fi
  if ! response=$(rest_go_command_perform_send "${@:2}" "-outputFile" "$1" 2>&1); then
    log 2 "error sending rest go command: $response"
    return 1
  fi
  return 0
}

check_header_keys_and_values() {
  if ! check_param_count_gt "data file, header/key value pairs" 1 $#; then
    return 1
  fi

  local data_file="$1"
  local pairs=("${@:2}")
  local check_result=0
  local remaining_pairs=""
  local line=""
  local key=""
  local value=""

  # Parse header lines until the blank line separator.
  # - Split on the first ':'
  # - Allow empty values (e.g. "X-Foo:")
  # - Preserve spaces in values
  while IFS= read -r line; do
    line="${line%$'\r'}"

    # End of headers
    if [ -z "$line" ]; then
      break
    fi

    # Require at least one ':' to treat as a header field
    case "$line" in
      *:*) ;;
      *) continue ;;
    esac

    key="${line%%:*}"
    value="${line#*:}"
    value="${value# }"

    check_result=0
    if remaining_pairs=$(check_for_key_and_value_within_pairs "$key" "$value" "${pairs[@]}"); then
      # match found; remaining_pairs contains the updated list
      pairs=()
      if [ -n "$remaining_pairs" ]; then
        while IFS= read -r line; do
          pairs+=("$line")
        done <<< "$remaining_pairs"
      fi

      if [ "${#pairs[@]}" -eq 0 ]; then
        return 0
      fi
    else
      check_result=$?
      if [ "$check_result" -eq 2 ]; then
        log 2 "error checking pair"
        return 1
      fi
      # check_result==1 means no match; keep current pairs
    fi
  done < "$data_file"

  if [ "${#pairs[@]}" -eq 0 ]; then
    return 0
  fi
  log 2 "missing expected header key '${pairs[0]}'"
  return 1
}

# Check that a specific header key/value pair (or pairs) is NOT present.
# Returns:
#   0 - none of the specified pairs are present
#   1 - at least one specified pair is present
#   2 - other error (param count, malformed pairs)
check_header_keys_and_values_not_present() {
  if ! check_param_count_gt "data file, header/key value pairs" 1 $#; then
    return 2
  fi

  local data_file="$1"
  shift 1

  if [ $(( $# % 2 )) -ne 0 ]; then
    log 2 "header key/value pairs must be even count"
    return 2
  fi

  local expected_pairs=("$@")
  local line=""
  local key=""
  local value=""

  while IFS= read -r line; do
    line="${line%$'\r'}"

    # End of headers
    if [ -z "$line" ]; then
      break
    fi

    case "$line" in
      *:*) ;;
      *) continue ;;
    esac

    key="${line%%:*}"
    value="${line#*:}"
    value="${value# }"

    local idx
    for ((idx=0; idx<${#expected_pairs[@]}; idx+=2)); do
      local exp_key="${expected_pairs[$idx]}"
      local exp_val="${expected_pairs[$((idx+1))]}"

      if [ "${key,,}" = "${exp_key,,}" ] && [ "$value" = "$exp_val" ]; then
        log 2 "unexpected header pair present: '$exp_key: $exp_val'"
        return 1
      fi
    done
  done < "$data_file"

  return 0
}

check_for_key_and_value_within_pairs() {
  if ! check_param_count_gt "read key, read value, full set of key/value pairs" 2 $#; then
    return 2
  fi

  local read_key="$1"
  local read_value="$2"
  shift 2

  # Require an even number of remaining args (key/value pairs)
  if [ $(( $# % 2 )) -ne 0 ]; then
    log 2 "key/value pairs must be even count"
    return 2
  fi

  local pairs=()
  local omit_idx=-1
  local idx=0
  while [ $# -gt 0 ]; do
    local key="$1"
    local value="$2"
    local check_result=0

    pairs+=("$key" "$value")
    check_key_and_value_pair_for_match "$read_key" "$read_value" "$key" "$value" || check_result=$?
    if [ "$check_result" -eq 2 ]; then
      return 2
    elif [ "$check_result" -eq 0 ]; then
      # Omit the last matching pair (preserves previous behavior)
      omit_idx=$idx
    fi

    idx=$((idx + 2))
    shift 2
  done

  if [ "$omit_idx" -lt 0 ]; then
    return 1
  fi

  for ((idx=0; idx<${#pairs[@]}; idx+=2)); do
    if [ "$idx" -eq "$omit_idx" ]; then
      continue
    fi
    echo "${pairs[$idx]}"
    echo "${pairs[$((idx+1))]}"
  done
  return 0
}
