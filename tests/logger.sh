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

export LOG_LEVEL_INT=4

log() {
  if [[ $# -ne 2 ]]; then
    echo "log function requires level, message"
    return 1
  fi
  # shellcheck disable=SC2153
  if [[ $1 -gt $LOG_LEVEL_INT ]]; then
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
    log_mask "$log_level" "$2"
    return 0
  fi
  log_message "$log_level" "$2"
}

log_mask() {
  if [[ $# -ne 2 ]]; then
    echo "mask and log requires level, string"
    return 1
  fi

  if ! mask_args "$2"; then
    echo "error masking args"
    return 1
  fi

  log_message "$log_level" "${masked_args[*]}"
}

mask_args() {
  if [ $# -ne 1 ]; then
    echo "'mask_args' requires string"
    return 1
  fi
  IFS=' ' read -r -a array <<< "$1"

  if ! mask_arg_array "${array[@]}"; then
    echo "error masking arg array"
    return 1
  fi
}

mask_arg_array() {
  masked_args=()  # Initialize an array to hold the masked arguments
  if [ $# -eq 0 ]; then
    echo "'mask_arg_array' requires parameters"
    return 1
  fi
  mask_next=false
  is_access=false
  for arg in "$@"; do
    if ! check_arg_for_mask "$arg"; then
      echo "error checking arg for mask"
      return 1
    fi
  done
}

check_arg_for_mask() {
  if [ $# -ne 1 ]; then
    echo "'check_arg_for_mask' requires arg"
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
  if [[ $# -ne 2 ]]; then
    echo "log message requires level, message"
    return 1
  fi
  now="$(date "+%Y-%m-%d %H:%M:%S")"
  if [[ ( "$1" == "CRIT" ) || ( "$1" == "ERROR" ) ]]; then
    echo "$now $1 $2" >&2
  fi
  if [[ -n "$TEST_LOG_FILE" ]]; then
    echo "$now $1 $2" >> "$TEST_LOG_FILE.tmp"
  fi
}
