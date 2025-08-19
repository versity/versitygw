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

get_check_default_acl_s3cmd() {
  if [ $# -ne 1 ]; then
    log 2 "'get_check_acl_s3cmd' requires bucket name"
    return 1
  fi
  if ! get_bucket_acl "s3cmd" "$BUCKET_ONE_NAME"; then
    log 2 "error retrieving acl"
    return 1
  fi
  # shellcheck disable=SC2154
  log 5 "Initial ACLs: $acl"
  acl_line=$(echo "$acl" | grep "ACL")
  user_id=$(echo "$acl_line" | awk '{print $2}')
  if [[ $DIRECT == "true" ]]; then
    if [[ $user_id != "$DIRECT_DISPLAY_NAME:" ]]; then
      log 2 "ID mismatch ($user_id, $DIRECT_DISPLAY_NAME)"
      return 1
    fi
  else
    if [[ $user_id != "$AWS_ACCESS_KEY_ID:" ]]; then
      log 2 "ID mismatch ($user_id, $AWS_ACCESS_KEY_ID)"
      return 1
    fi
  fi
  permission=$(echo "$acl_line" | awk '{print $3}')
  if [[ $permission != "FULL_CONTROL" ]]; then
    log 2 "Permission mismatch ($permission)"
    return 1
  fi
  return 0
}

get_check_post_change_acl_s3cmd() {
  if [ $# -ne 1 ]; then
    log 2 "'get_check_post_change_acl_s3cmd' requires bucket name"
    return 1
  fi
  if ! get_bucket_acl "s3cmd" "$1"; then
    log 2 "error retrieving acl"
    return 1
  fi
  log 5 "ACL after read put: $acl"
  acl_lines=$(echo "$acl" | grep "ACL")
  log 5 "ACL lines:  $acl_lines"
  lines=()
  while IFS= read -r line; do
    lines+=("$line")
  done <<< "$acl_lines"
  log 5 "lines: ${lines[*]}"
  if [[ ${#lines[@]} -ne 2 ]]; then
    log 2 "unexpected number of ACL lines: ${#lines[@]}"
    return 1
  fi
  anon_name=$(echo "${lines[1]}" | awk '{print $2}')
  anon_permission=$(echo "${lines[1]}" | awk '{print $3}')
  if [[ $anon_name != "*anon*:" ]]; then
    log 2 "unexpected anon name: $anon_name"
    return 1
  fi
  if [[ $anon_permission != "READ" ]]; then
    log 2 "unexpected anon permission: $anon_permission"
    return 1
  fi
  return 0
}
