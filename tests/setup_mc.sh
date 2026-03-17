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

# return 0 for match, 1 for set or replace, 2 for error
check_for_alias() {
  if ! aliases=$(mc alias list 2>&1); then
    log 2 "error checking for aliases: $aliases"
    return 2
  fi
  local alias_match="false" check_result=0
  while IFS= read -r line; do
    check_mc_aliases_line "$line" "$alias_match" || local check_result=$?
    if [ "$check_result" -eq 4 ]; then
      return 2
    elif [ "$check_result" -eq 3 ]; then
      continue
    elif [ "$check_result" -eq 2 ]; then
      return 1
    elif [ "$check_result" -eq 1 ]; then
      return 0
    else
      alias_match="true"
    fi
  done <<< "$aliases"
  return 1
}

# return 0 for alias name match, 1 for alias key match, 2 for alias key mismatch, 3 for keep looking, 4 for error
check_mc_aliases_line() {
  if ! check_param_count_v2 "line, alias found" 2 $#; then
    return 4
  fi
  if [ "$2" == "true" ]; then
    check_alias_access_key "$1" || local check_result=$?
    return "$((check_result+1))"
  else
    if echo "$1" | grep -w "$MC_ALIAS "; then
      return 0
    fi
  fi
}

# return 0 for match, 1 for mismatch, 2 for keep looking, 3 for error
check_alias_access_key() {
  if ! check_param_count_v2 "line" 1 $#; then
    return 3
  fi
  if [[ "$1" =~ ^[[:space:]]*$ ]]; then
    return 3
  fi
  alias_access_key_id=$(echo -n "$1" | awk -F': *' '/^AccessKey[[:space:]]*:/ {print $2; exit}')
  if [ "$alias_access_key_id" == "" ]; then
    return 2
  fi
  if [ "$alias_access_key_id" == "$AWS_ACCESS_KEY_ID" ]; then
    return 0
  fi
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
