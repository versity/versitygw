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

get_check_acl_id() {
  if [ $# -ne 2 ]; then
    log 2 "'get_check_acl_id' requires client, bucket"
    return 1
  fi
  if ! get_bucket_acl "$1" "$2"; then
    log 2 "error retrieving acl"
    return 1
  fi
  log 5 "Initial ACLs: $acl"
  if ! id=$(echo "$acl" | grep -v "InsecureRequestWarning" | jq -r '.Owner.ID' 2>&1); then
    log 2 "error getting ID: $id"
    return 1
  fi
  if [[ $id != "$AWS_ACCESS_KEY_ID" ]]; then
    # for direct, ID is canonical user ID rather than AWS_ACCESS_KEY_ID
    if ! canonical_id=$(aws --no-verify-ssl s3api list-buckets --query 'Owner.ID' 2>&1); then
      log 2 "error getting canonical ID: $canonical_id"
      return 1
    fi
    canonical_id="$(echo -n "$canonical_id" | grep -v "InsecureRequestWarning" | sed "s/\"//g")"
    log 5 "canonical ID: $canonical_id"
    if [[ $id != "$canonical_id" ]]; then
      log 2 "acl ID doesn't match AWS key or canonical ID"
      return 1
    fi
  fi
  return 0
}

get_check_acl_after_first_put() {
  if [ $# -ne 2 ]; then
    log 2 "'get_check_acl_after_first_put' requires client, bucket"
    return 1
  fi
  if ! get_bucket_acl "$1" "$2"; then
    log 2 "error retrieving second ACL"
    return 1
  fi
  log 5 "Acls after 1st put: $acl"
  if ! public_grants=$(echo "$acl" | grep -v "InsecureRequestWarning" | jq -r '.Grants[1]' 2>&1); then
    log 2 "error getting public grants: $public_grants"
    return 1
  fi
  if ! permission=$(echo "$public_grants" | jq -r '.Permission' 2>&1); then
    log 2 "error getting permission: $permission"
    return 1
  fi
  if [[ $permission != "READ" ]]; then
    log 2 "incorrect permission ($permission)"
    return 1
  fi
  return 0
}

get_check_acl_after_second_put() {
  if [ $# -ne 2 ]; then
    log 2 "'get_check_acl_after_second_put' requires client, bucket"
    return 1
  fi
  if ! get_bucket_acl "$1" "$2"; then
    log 2 "error retrieving third ACL"
    return 1
  fi
  if ! public_grants=$(echo "$acl" | grep -v "InsecureRequestWarning" | jq -r '.Grants' 2>&1); then
    log 2 "error retrieving public grants: $public_grants"
    return 1
  fi
  if ! public_grant_length=$(echo "$public_grants" | jq -r 'length' 2>&1); then
    log 2 "Error retrieving public grant length: $public_grant_length"
    return 1
  fi
  if [[ $public_grant_length -ne 2 ]]; then
    log 2 "incorrect grant length for private ACL ($public_grant_length)"
    return 1
  fi
  if ! permission=$(echo "$public_grants" | jq -r '.[0].Permission' 2>&1); then
    log 2 "Error retrieving permission: $permission"
    return 1
  fi
  if [[ $permission != "FULL_CONTROL" ]]; then
    log 2 "incorrect permission ($permission)"
    return 1
  fi
  return 0
}
