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

check_for_alias() {
  local alias_result
  aliases=$(mc alias list)
  if [[ $alias_result -ne 0 ]]; then
    log 2 "error checking for aliases: $aliases"
    return 2
  fi
  while IFS= read -r line; do
    if echo "$line" | grep -w "$MC_ALIAS "; then
      return 0
    fi
  done <<< "$aliases"
  return 1
}

check_add_mc_alias() {
  check_for_alias || alias_result=$?
  if [[ $alias_result -eq 2 ]]; then
    log 2 "error checking for aliases"
    return 1
  fi
  if [[ $alias_result -eq 0 ]]; then
    return 0
  fi
  local set_result
  error=$(mc alias set --insecure "$MC_ALIAS" "$AWS_ENDPOINT_URL" "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY") || set_result=$?
  if [[ $set_result -ne 0 ]]; then
    log 2 "error setting alias: $error"
    return 1
  fi
  return 0
}