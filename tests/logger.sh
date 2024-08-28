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
  if [[ "$2" == *"secret"* ]]; then
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
  local masked_args=()  # Initialize an array to hold the masked arguments

  IFS=' ' read -r -a array <<< "$2"

  mask_next=false
  for arg in "${array[@]}"; do
    if [[ $mask_next == true ]]; then
      masked_args+=("********")
      mask_next=false
    elif [[ "$arg" == --secret_key=* ]]; then
      masked_args+=("--secret_key=********")
    elif [[ "$arg" == --secret=* ]]; then
      masked_args+=("--secret=********")
    else
      if [[ "$arg" == "--secret_key" ]] || [[ "$arg" == "--secret" ]] || [[ "$arg" == "--s3-iam-secret" ]]; then
        mask_next=true
      fi
      masked_args+=("$arg")
    fi
  done
  log_message "$log_level" "${masked_args[*]}"
}

log_message() {
  if [[ $# -ne 2 ]]; then
    echo "log message requires level, message"
    return 1
  fi
  now="$(date "+%Y-%m-%d %H:%M:%S")"
  echo "$now $1 $2"
  if [[ -n "$TEST_LOG_FILE" ]]; then
    echo "$now $1 $2" >> "$TEST_LOG_FILE"
  fi
}
