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

get_bucket_acl_success_or_access_denied() {
  if ! check_param_count_v2 "bucket, username, password, expect success" 4 $#; then
    return 1
  fi
  if [ "$4" == "true" ]; then
    if ! get_bucket_acl_rest "$1" "AWS_ACCESS_KEY_ID=$2 AWS_SECRET_ACCESS_KEY=$3" "get_bucket_acl_data"; then
      log 2 "expected GetBucketAcl to succeed, didn't"
      return 1
    fi
  else
    if ! get_bucket_acl_rest_expect_error "$1" "AWS_ACCESS_KEY_ID=$2 AWS_SECRET_ACCESS_KEY=$3" "403" "AccessDenied" "Access Denied"; then
      log 2 "expected GetBucketAcl access denied"
      return 1
    fi
  fi
  return 0
}

get_bucket_acl_data() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  bucket_acl_data="$(cat "$1")"
  log 5 "bucket acl data: $bucket_acl_data"
  return 0
}

check_that_acl_xml_does_not_have_owner_permission() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  if [ "$DIRECT" == "true" ]; then
    owner_id="$AWS_CANONICAL_ID"
  else
    owner_id="$AWS_ACCESS_KEY_ID"
  fi
  if ! grant="$(xmllint --xpath "//*[local-name()='AccessControlPolicy']/*[local-name()='AccessControlList']/*[local-name()='Grant'][*[local-name()='Grantee']/*[local-name()='ID' and text()='${owner_id}']]" "$1" 2>&1)"; then
    if [[ "$grant" != *"XPath set is empty"* ]]; then
      log 2 "error getting grant: $grant"
      return 1
    fi
  else
    log 2 "root account shouldn't have grant in this case (grant: $grant)"
    return 1
  fi
  return 0
}

check_for_display_name() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  log 5 "data: $(cat "$1")"
  if ! display_name="$(xmllint --xpath "//*[local-name()='AccessControlPolicy']/*[local-name()='Owner']/*[local-name()='DisplayName']" "$1" 2>&1)"; then
    log 2 "error getting display name: $display_name"
    return 1
  fi
  return 0
}

check_acl_rest() {
  if ! check_param_count_v2 "acl file" 1 $#; then
    return 1
  fi
  log 5 "acl: $(cat "$1")"
  if ! access_control_policy=$(xmllint --xpath '//*[local-name()="AccessControlPolicy"]' "$1" 2>&1); then
    log 2 "error getting access control policy: $access_control_policy"
    return 1
  fi
  if ! owner=$(echo "$access_control_policy" | xmllint --xpath '//*[local-name()="Owner"]' - 2>&1); then
    log 2 "error getting owner information: $owner"
    return 1
  fi
  if [ "$DIRECT" == "true" ]; then
    if ! check_direct_display_name; then
      log 2 "error checking direct display name"
      return 1
    fi
  else
    if ! id=$(echo "$owner" | xmllint --xpath '//*[local-name()="ID"]/text()' - 2>&1); then
      log 2 "error getting ID: $id"
      return 1
    fi
    if [ "$id" != "$AWS_ACCESS_KEY_ID" ]; then
      log 2 "ID mismatch"
      return 1
    fi
  fi
  return 0
}

get_and_check_acl_rest() {
  if [ $# -ne 1 ]; then
    log 2 "'get_and_check_acl_rest' requires bucket name"
    return 1
  fi
  if ! get_bucket_acl_rest "$1" "" "check_acl_rest"; then
    log 2 "error getting and checking acl"
    return 1
  fi
  return 0
}

check_direct_display_name() {
  if ! display_name=$(echo "$owner" | xmllint --xpath '//*[local-name()="DisplayName"]/text()' - 2>&1); then
    log 2 "error getting display name: $display_name"
    return 1
  fi
  if [ "$display_name" != "$DIRECT_DISPLAY_NAME" ]; then
    log 2 "display name mismatch (expected '$DIRECT_DISPLAY_NAME', actual '$display_name')"
    return 1
  fi
}
