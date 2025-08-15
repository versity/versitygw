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

get_check_acl_after_policy() {
  if [ $# -ne 1 ]; then
    log 2 "'get_check_acl_after_policy' requires bucket name"
    return 1
  fi
  if ! get_bucket_acl "s3api" "$1"; then
    log 2 "error getting bucket acl"
    return 1
  fi
  # shellcheck disable=SC2154
  log 5 "ACL: $acl"
  if ! second_grant=$(echo "$acl" | jq -r ".Grants[1]" 2>&1); then
    log 2 "error getting second grant: $second_grant"
    return 1
  fi
  if ! second_grantee=$(echo "$second_grant" | jq -r ".Grantee" 2>&1); then
    log 2 "error getting second grantee: $second_grantee"
    return 1
  fi
  if ! permission=$(echo "$second_grant" | jq -r ".Permission" 2>&1); then
    log 2 "error getting permission: $permission"
    return 1
  fi
  log 5 "second grantee: $second_grantee"
  if [[ $permission != "READ" ]]; then
    log 2 "incorrect permission: $permission"
    return 1
  fi
  if [[ $DIRECT == "true" ]]; then
    if ! uri=$(echo "$second_grantee" | jq -r ".URI" 2>&1); then
      log 2 "error getting uri: $uri"
      return 1
    fi
    if [[ $uri != "http://acs.amazonaws.com/groups/global/AllUsers" ]]; then
      log 2 "unexpected URI: $uri"
      return 1
    fi
  else
    if ! id=$(echo "$second_grantee" | jq -r ".ID" 2>&1); then
      log 2 "error getting ID: $id"
      return 1
    fi
    if [[ $id != "all-users" ]]; then
      log 2 "unexpected ID: $id"
      return 1
    fi
  fi
}
