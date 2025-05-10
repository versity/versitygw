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

source ./tests/logger.sh

send_command() {
  if [ $# -eq 0 ]; then
    return 1
  fi
  if [ -n "$COMMAND_LOG" ]; then
    args=(AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" "$@")
    if ! mask_arg_array "${args[@]}"; then
      return 1
    fi
    # shellcheck disable=SC2154
    echo "${masked_args[*]}" >> "$COMMAND_LOG"
  fi
  local command_result=0
  "$@" || command_result=$?
  if [ "$command_result" -ne 0 ]; then
    if [ "$1" == "curl" ]; then
      echo ", curl response code: $command_result"
    elif [ "$command_result" -ne 1 ]; then
      echo " ($1 response code: $command_result)"
    fi
  fi
  if [ "$DIRECT" == "true" ]; then
    sleep "$DIRECT_POST_COMMAND_DELAY"
  fi
  return $command_result
}