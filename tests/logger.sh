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

# levels:  1 - crit, 2 - err, 3 - warn, 4 - info, 5 - debug, 6 - trace

check_log_params() {
  if [ $# -ne 4 ]; then
    echo "'check_log_params' requires function name, params list, expected, actual"
    return 1
  fi
  if [ "$3" -ne "$4" ]; then
    echo "function $1 requires $2" 2
    return 1
  fi
  return 0
}

log() {
  if ! check_log_params "log" "level, message" 2 $#; then
    return 1
  fi
  if ! log_with_stack_ref "$1" "$2" 2; then
    echo "error logging with stack ref"
    return 1
  fi
  return 0
}

log_with_stack_ref() {
  if [[ $# -ne 3 ]]; then
    echo "log_with_stack_ref function requires level, message, stack reference"
    return 1
  fi
  # shellcheck disable=SC2153
  if [[ $1 -gt ${LOG_LEVEL_INT:=4} ]]; then
    return 0
  fi
  log_level=""
  case "$1" in
    1) log_level="CRIT";;
    2) log_level="ERROR";;
    3) log_level="WARN";;
    4) log_level="INFO";;
    5) log_level="DEBUG";;
    6) log_level="TRACE";;
    *) echo "invalid log level $1"; return 1
  esac
  if [[ ( "$2" == *"access"* ) || ( "$2" == *"secret"* ) || ( "$2" == *"Credential="* ) ]]; then
    log_mask "$log_level" "$2" "$3"
    return 0
  fi
  log_message "$log_level" "$2" "$3"
}

log_mask() {
  if ! check_log_params "log_mask" "level, string, stack reference" 3 $#; then
    return 1
  fi

  if ! mask_args "$2"; then
    echo "error masking args"
    return 1
  fi

  log_message "$log_level" "$masked_data" "$3"
}

mask_args() {
  if ! check_log_params "mask_args" "string" 1 $#; then
    return 1
  fi
  unmasked_array=()
  masked_data=""
  while IFS= read -r line; do
    unmasked_array+=("$line")
  done <<< "$1"

  # shellcheck disable=SC2068
  first_line=true
  for line in "${unmasked_array[@]}"; do
    if ! mask_arg_array "$line"; then
      echo "error masking arg array"
      return 1
    fi
    if [ "$first_line" == "true" ]; then
      masked_data="${masked_args[*]}"
      first_line="false"
    else
      masked_data+=$(printf "\n%s" "${masked_args[*]}")
    fi
  done
}

mask_arg_array() {
  if [ $# -eq 0 ]; then
    echo "'mask_arg_array' requires parameters"
    return 1
  fi
  mask_next=false
  is_access=false
  masked_args=()  # Initialize an array to hold the masked arguments
  # shellcheck disable=SC2068
  for arg in $@; do
    if ! check_arg_for_mask "$arg"; then
      echo "error checking arg for mask"
      return 1
    fi
  done
}

check_arg_for_mask() {
  if ! check_log_params "check_arg_for_mask" "arg" 1 $#; then
    return 1
  fi
  if [[ $mask_next == true ]]; then
    if [ "$is_access" == "true" ]; then
      masked_args+=("${arg:0:4}****")
      is_access=false
    else
      masked_args+=("********")
    fi
    mask_next=false
  elif [[ "$arg" == --secret_key=* ]]; then
    masked_args+=("--secret_key=********")
  elif [[ "$arg" == --secret=* ]]; then
    masked_args+=("--secret=********")
  elif [[ "$arg" == --access=* ]]; then
    masked_args+=("${arg:0:13}****")
  elif [[ "$arg" == --access_key=* ]]; then
    masked_args+=("${arg:0:17}****")
  elif [[ "$arg" == *"Credential="* ]]; then
    masked_args+=("$(echo "$arg" | sed -E 's/(Credential=[A-Z]{4})[^\/]*/\1****/g')")
  elif [[ "$arg" == *"AWS_ACCESS_KEY_ID="* ]]; then
    masked_args+=("AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:0:4}****")
  else
    if [[ "$arg" == "--secret_key" ]] || [[ "$arg" == "--secret" ]] || [[ "$arg" == "--s3-iam-secret" ]]; then
      mask_next=true
    elif [[ ( "$arg" == "--access" ) || ( "$arg" == "--owner") ]]; then
      mask_next=true
      is_access=true
    fi
    masked_args+=("$arg")
  fi
}

log_message() {
  if ! check_log_params "log_message" "level, message, stack reference" 3 $#; then
    return 1
  fi
  local bash_source_ref=$(($3+1))
  now="$(date "+%Y-%m-%d %H:%M:%S")"
  if [[ ( "$1" == "CRIT" ) || ( "$1" == "ERROR" ) ]]; then
    echo "$now $1 $2" >&2
  fi
  if [[ -n "$TEST_LOG_FILE" ]]; then
    echo "$now ${BASH_SOURCE[$bash_source_ref]}:${BASH_LINENO[$3]} $1 $2" >> "$TEST_LOG_FILE.tmp"
  fi
  sync
}
